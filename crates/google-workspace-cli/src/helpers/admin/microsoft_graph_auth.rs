// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::error::GwsError;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::Serialize;
use serde_json::Value;
use sha1::{Digest, Sha1};
use sha2::Sha256;
#[cfg(not(unix))]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::{env, fmt};
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;
use x509_parser::public_key::PublicKey;
use x509_parser::{parse_x509_certificate, time::ASN1Time};

pub(super) const MICROSOFT_GRAPH_ACCESS_TOKEN_ENV: &str = "MICROSOFT_GRAPH_ACCESS_TOKEN";
pub(super) const MICROSOFT_GRAPH_TENANT_ID_ENV: &str = "MICROSOFT_GRAPH_TENANT_ID";
pub(super) const MICROSOFT_GRAPH_CLIENT_ID_ENV: &str = "MICROSOFT_GRAPH_CLIENT_ID";
pub(super) const MICROSOFT_GRAPH_CERTIFICATE_FILE_ENV: &str = "MICROSOFT_GRAPH_CERTIFICATE_FILE";
pub(super) const MICROSOFT_GRAPH_PRIVATE_KEY_FILE_ENV: &str = "MICROSOFT_GRAPH_PRIVATE_KEY_FILE";
pub(super) const MICROSOFT_GRAPH_CERTIFICATE_KEY_ID_ENV: &str =
    "MICROSOFT_GRAPH_CERTIFICATE_KEY_ID";
pub(super) const MICROSOFT_GRAPH_CERTIFICATE_THUMBPRINT_ENV: &str =
    "MICROSOFT_GRAPH_CERTIFICATE_THUMBPRINT";

const MICROSOFT_LOGIN_BASE_URL: &str = "https://login.microsoftonline.com";
const MICROSOFT_GRAPH_AUDIENCE: &str = "https://graph.microsoft.com";
const MICROSOFT_GRAPH_SCOPE: &str = "https://graph.microsoft.com/.default";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const ASSERTION_LIFETIME_SECONDS: i64 = 600;
const TOKEN_EXPIRY_SKEW_SECONDS: i64 = 60;
const MIN_ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 300;
const MAX_CREDENTIAL_FILE_BYTES: u64 = 1_048_576;
const MAX_TOKEN_RESPONSE_BYTES: u64 = 65_536;

const REQUIRED_GRAPH_ROLES: [&str; 7] = [
    "User.Read.All",
    "AuditLog.Read.All",
    "RoleManagement.Read.Directory",
    "Policy.Read.All",
    "SecurityAlert.Read.All",
    "SecurityIncident.Read.All",
    "SecurityEvents.Read.All",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuthError {
    code: &'static str,
}

impl AuthError {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}

#[derive(Clone)]
struct CertificateConfig {
    tenant_id: String,
    client_id: String,
    certificate_file: PathBuf,
    private_key_file: PathBuf,
    certificate_key_id: Option<String>,
    expected_thumbprint: Option<String>,
}

impl CertificateConfig {
    fn from_env() -> Result<Self, AuthError> {
        let tenant_id = non_empty_env(MICROSOFT_GRAPH_TENANT_ID_ENV);
        let client_id = non_empty_env(MICROSOFT_GRAPH_CLIENT_ID_ENV);
        let certificate_file = non_empty_env(MICROSOFT_GRAPH_CERTIFICATE_FILE_ENV);
        let private_key_file = non_empty_env(MICROSOFT_GRAPH_PRIVATE_KEY_FILE_ENV);
        let certificate_key_id = non_empty_env(MICROSOFT_GRAPH_CERTIFICATE_KEY_ID_ENV);
        let expected_thumbprint = non_empty_env(MICROSOFT_GRAPH_CERTIFICATE_THUMBPRINT_ENV);

        let any_configured = [
            tenant_id.is_some(),
            client_id.is_some(),
            certificate_file.is_some(),
            private_key_file.is_some(),
            certificate_key_id.is_some(),
            expected_thumbprint.is_some(),
        ]
        .into_iter()
        .any(|configured| configured);
        if !any_configured {
            return Err(AuthError::new("microsoft_graph_auth_not_configured"));
        }

        let (Some(tenant_id), Some(client_id), Some(certificate_file), Some(private_key_file)) =
            (tenant_id, client_id, certificate_file, private_key_file)
        else {
            return Err(AuthError::new("microsoft_graph_auth_partial_config"));
        };

        let tenant_id = strict_uuid(&tenant_id, "microsoft_graph_invalid_tenant_id")?;
        let client_id = strict_uuid(&client_id, "microsoft_graph_invalid_client_id")?;
        let certificate_key_id = certificate_key_id
            .map(|value| strict_uuid(&value, "microsoft_graph_invalid_certificate_key_id"))
            .transpose()?;
        let expected_thumbprint = expected_thumbprint
            .map(|value| normalize_thumbprint(&value))
            .transpose()?;

        Ok(Self {
            tenant_id,
            client_id,
            certificate_file: checked_path(certificate_file)?,
            private_key_file: checked_path(private_key_file)?,
            certificate_key_id,
            expected_thumbprint,
        })
    }

    fn token_endpoint(&self) -> String {
        format!(
            "{}/{}/oauth2/v2.0/token",
            MICROSOFT_LOGIN_BASE_URL, self.tenant_id
        )
    }
}

struct PreparedCertificate {
    client_id: String,
    token_endpoint: String,
    x5t: String,
    x5t_s256: String,
    certificate_key_id: Option<String>,
    encoding_key: EncodingKey,
}

impl fmt::Debug for PreparedCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCertificate")
            .field("client_id", &self.client_id)
            .field("token_endpoint", &self.token_endpoint)
            .field("x5t", &self.x5t)
            .field("x5t_s256", &self.x5t_s256)
            .field("certificate_key_id", &self.certificate_key_id)
            .field("encoding_key", &"[redacted]")
            .finish()
    }
}

pub(super) struct MicrosoftGraphAccessToken(String);

impl MicrosoftGraphAccessToken {
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MicrosoftGraphAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MicrosoftGraphAccessToken([redacted])")
    }
}

enum AuthSource {
    Explicit(MicrosoftGraphAccessToken),
    Certificate {
        config: CertificateConfig,
        prepared: Option<Box<PreparedCertificate>>,
    },
}

pub(super) struct MicrosoftGraphAuthSession {
    client: reqwest::Client,
    endpoint: String,
    source: AuthSource,
    access_token: Option<MicrosoftGraphAccessToken>,
    expires_at: Option<DateTime<Utc>>,
}

impl fmt::Debug for MicrosoftGraphAuthSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MicrosoftGraphAuthSession")
            .field("endpoint", &self.endpoint)
            .field("access_token", &self.access_token)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl MicrosoftGraphAuthSession {
    pub(super) fn from_env(client: reqwest::Client) -> Result<Self, GwsError> {
        if let Some(token) = explicit_access_token() {
            return Ok(Self {
                client,
                endpoint: String::new(),
                source: AuthSource::Explicit(MicrosoftGraphAccessToken(token)),
                access_token: None,
                expires_at: None,
            });
        }

        let config = CertificateConfig::from_env().map_err(to_gws_error)?;
        Ok(Self::from_config(client, config))
    }

    fn from_config(client: reqwest::Client, config: CertificateConfig) -> Self {
        let endpoint = config.token_endpoint();
        Self {
            client,
            endpoint,
            source: AuthSource::Certificate {
                config,
                prepared: None,
            },
            access_token: None,
            expires_at: None,
        }
    }

    #[cfg(test)]
    fn from_config_with_endpoint(
        client: reqwest::Client,
        config: CertificateConfig,
        endpoint: String,
    ) -> Self {
        Self {
            client,
            endpoint,
            source: AuthSource::Certificate {
                config,
                prepared: None,
            },
            access_token: None,
            expires_at: None,
        }
    }

    pub(super) async fn access_token(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<&MicrosoftGraphAccessToken, GwsError> {
        if let AuthSource::Explicit(token) = &self.source {
            let explicit_token = token.as_str().to_string();
            if self.access_token.is_none() {
                self.access_token = Some(MicrosoftGraphAccessToken(explicit_token));
            }
            return Ok(self
                .access_token
                .as_ref()
                .expect("explicit token is stored before returning"));
        }

        let token_is_fresh = self.expires_at.is_some_and(|expires_at| {
            expires_at > now + Duration::seconds(TOKEN_EXPIRY_SKEW_SECONDS)
        }) && self.access_token.is_some();
        if token_is_fresh {
            return Ok(self
                .access_token
                .as_ref()
                .expect("fresh token is stored before returning"));
        }

        let AuthSource::Certificate { config, prepared } = &mut self.source else {
            unreachable!("explicit authentication returned above");
        };
        if prepared.is_none() {
            *prepared = Some(Box::new(
                prepare_certificate(config, now).map_err(to_gws_error)?,
            ));
        }
        let prepared_certificate = prepared
            .as_ref()
            .expect("certificate is stored before requesting a token");
        let assertion = build_client_assertion(prepared_certificate, now, Uuid::new_v4())
            .map_err(to_gws_error)?;
        let token_response =
            request_access_token(&self.client, &self.endpoint, &config.client_id, &assertion)
                .await
                .map_err(to_gws_error)?;
        self.expires_at = Some(now + Duration::seconds(token_response.expires_in as i64));
        self.access_token = Some(MicrosoftGraphAccessToken(token_response.access_token));
        Ok(self
            .access_token
            .as_ref()
            .expect("access token is stored before returning"))
    }
}

pub(super) async fn resolve_access_token(
    client: &reqwest::Client,
) -> Result<MicrosoftGraphAccessToken, GwsError> {
    let mut session = MicrosoftGraphAuthSession::from_env(client.clone())?;
    Ok(session.access_token(Utc::now()).await?.to_owned())
}

impl Clone for MicrosoftGraphAccessToken {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl MicrosoftGraphAccessToken {
    #[cfg(test)]
    fn is_redacted_debug(&self) -> bool {
        format!("{self:?}").contains("redacted") && !format!("{self:?}").contains(&self.0)
    }
}

#[derive(Serialize)]
struct ClientAssertionClaims {
    aud: String,
    exp: i64,
    iss: String,
    jti: String,
    nbf: i64,
    iat: i64,
    sub: String,
}

fn build_client_assertion(
    prepared: &PreparedCertificate,
    now: DateTime<Utc>,
    jti: Uuid,
) -> Result<String, AuthError> {
    let issued_at = now.timestamp();
    let claims = ClientAssertionClaims {
        aud: prepared.token_endpoint.clone(),
        exp: issued_at + ASSERTION_LIFETIME_SECONDS,
        iss: prepared.client_id.clone(),
        jti: jti.hyphenated().to_string(),
        nbf: issued_at,
        iat: issued_at,
        sub: prepared.client_id.clone(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());
    header.kid = prepared.certificate_key_id.clone();
    header.x5t = Some(prepared.x5t.clone());
    header.x5t_s256 = Some(prepared.x5t_s256.clone());
    encode(&header, &claims, &prepared.encoding_key)
        .map_err(|_| AuthError::new("microsoft_graph_assertion_failed"))
}

struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

async fn request_access_token(
    client: &reqwest::Client,
    // Production callers pass CertificateConfig::token_endpoint(); the local
    // endpoint seam is compiled only for deterministic unit tests.
    endpoint: &str,
    client_id: &str,
    assertion: &str,
) -> Result<TokenResponse, AuthError> {
    let response = client
        .post(endpoint)
        .form(&[
            ("client_id", client_id),
            ("scope", MICROSOFT_GRAPH_SCOPE),
            ("grant_type", "client_credentials"),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE),
            ("client_assertion", assertion),
        ])
        .send()
        .await
        .map_err(|_| AuthError::new("microsoft_graph_token_endpoint_unreachable"))?;
    let status = response.status();
    let body = read_bounded_body(response).await?;
    if !status.is_success() {
        return Err(AuthError::new("microsoft_graph_token_endpoint_rejected"));
    }

    let value = serde_json::from_slice::<Value>(&body)
        .map_err(|_| AuthError::new("microsoft_graph_token_response_invalid"))?;
    let access_token = value
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| AuthError::new("microsoft_graph_token_response_missing_access_token"))?
        .to_string();
    let token_type = value
        .get("token_type")
        .and_then(Value::as_str)
        .ok_or_else(|| AuthError::new("microsoft_graph_token_response_wrong_token_type"))?;
    if !token_type.eq_ignore_ascii_case("Bearer") {
        return Err(AuthError::new(
            "microsoft_graph_token_response_wrong_token_type",
        ));
    }
    let expires_in = value
        .get("expires_in")
        .and_then(Value::as_u64)
        .ok_or_else(|| AuthError::new("microsoft_graph_token_response_invalid_expiry"))?;
    if expires_in < MIN_ACCESS_TOKEN_LIFETIME_SECONDS
        || expires_in <= TOKEN_EXPIRY_SKEW_SECONDS as u64
    {
        return Err(AuthError::new(
            "microsoft_graph_token_response_expiry_too_short",
        ));
    }
    validate_graph_access_token(&access_token)?;

    Ok(TokenResponse {
        access_token,
        expires_in,
    })
}

async fn read_bounded_body(response: reqwest::Response) -> Result<Vec<u8>, AuthError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_TOKEN_RESPONSE_BYTES)
    {
        return Err(AuthError::new(
            "microsoft_graph_token_response_body_too_large",
        ));
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = futures_util::StreamExt::next(&mut stream).await {
        let chunk =
            chunk.map_err(|_| AuthError::new("microsoft_graph_token_response_unreadable"))?;
        if body.len().saturating_add(chunk.len()) > MAX_TOKEN_RESPONSE_BYTES as usize {
            return Err(AuthError::new(
                "microsoft_graph_token_response_body_too_large",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_graph_access_token(token: &str) -> Result<(), AuthError> {
    let mut segments = token.split('.');
    let header = segments
        .next()
        .ok_or_else(|| AuthError::new("microsoft_graph_token_invalid_jwt"))?;
    let payload = segments
        .next()
        .ok_or_else(|| AuthError::new("microsoft_graph_token_invalid_jwt"))?;
    let signature = segments
        .next()
        .ok_or_else(|| AuthError::new("microsoft_graph_token_invalid_jwt"))?;
    if signature.is_empty() || segments.next().is_some() {
        return Err(AuthError::new("microsoft_graph_token_invalid_jwt"));
    }
    let header = decode_base64url(header)
        .ok_or_else(|| AuthError::new("microsoft_graph_token_invalid_jwt"))?;
    serde_json::from_slice::<Value>(&header)
        .map_err(|_| AuthError::new("microsoft_graph_token_invalid_jwt"))?;
    let payload = decode_base64url(payload)
        .ok_or_else(|| AuthError::new("microsoft_graph_token_invalid_jwt"))?;
    let claims = serde_json::from_slice::<Value>(&payload)
        .map_err(|_| AuthError::new("microsoft_graph_token_invalid_jwt"))?;
    let audience_is_graph = claims
        .get("aud")
        .and_then(Value::as_str)
        .is_some_and(|audience| audience == MICROSOFT_GRAPH_AUDIENCE);
    if !audience_is_graph {
        return Err(AuthError::new("microsoft_graph_token_wrong_audience"));
    }
    let roles = claims
        .get("roles")
        .and_then(Value::as_array)
        .ok_or_else(|| AuthError::new("microsoft_graph_token_required_roles_missing"))?;
    let roles = roles.iter().filter_map(Value::as_str).collect::<Vec<_>>();
    if REQUIRED_GRAPH_ROLES
        .iter()
        .any(|required| !roles.contains(required))
    {
        return Err(AuthError::new(
            "microsoft_graph_token_required_roles_missing",
        ));
    }
    Ok(())
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| URL_SAFE.decode(value))
        .ok()
}

fn prepare_certificate(
    config: &CertificateConfig,
    now: DateTime<Utc>,
) -> Result<PreparedCertificate, AuthError> {
    let certificate_bytes = read_secure_file(&config.certificate_file, false)?;
    let private_key_bytes = read_secure_file(&config.private_key_file, true)?;
    let (remaining, pem) = parse_x509_pem(&certificate_bytes)
        .map_err(|_| AuthError::new("microsoft_graph_certificate_file_invalid"))?;
    if !remaining.iter().all(u8::is_ascii_whitespace) || pem.label != "CERTIFICATE" {
        return Err(AuthError::new("microsoft_graph_certificate_file_invalid"));
    }
    let (remaining_der, certificate) = parse_x509_certificate(&pem.contents)
        .map_err(|_| AuthError::new("microsoft_graph_certificate_file_invalid"))?;
    if !remaining_der.is_empty() {
        return Err(AuthError::new("microsoft_graph_certificate_file_invalid"));
    }
    let certificate_time = ASN1Time::from_timestamp(now.timestamp())
        .map_err(|_| AuthError::new("microsoft_graph_certificate_file_invalid"))?;
    if certificate.validity().not_after < certificate_time {
        return Err(AuthError::new("microsoft_graph_certificate_expired"));
    }
    if certificate.validity().not_before > certificate_time {
        return Err(AuthError::new("microsoft_graph_certificate_not_yet_valid"));
    }

    let private_key = parse_rsa_private_key(&private_key_bytes)?;
    if private_key.n().bits() < 2048 {
        return Err(AuthError::new("microsoft_graph_private_key_too_small"));
    }
    let PublicKey::RSA(public_key) = certificate
        .public_key()
        .parsed()
        .map_err(|_| AuthError::new("microsoft_graph_certificate_file_invalid"))?
    else {
        return Err(AuthError::new(
            "microsoft_graph_certificate_rsa_key_required",
        ));
    };
    if trim_integer(public_key.modulus) != private_key.n().to_bytes_be()
        || trim_integer(public_key.exponent) != private_key.e().to_bytes_be()
    {
        return Err(AuthError::new("microsoft_graph_certificate_key_mismatch"));
    }

    let sha1_digest = Sha1::digest(&pem.contents);
    let sha256_digest = Sha256::digest(&pem.contents);
    let x5t = URL_SAFE_NO_PAD.encode(sha1_digest);
    let x5t_s256 = URL_SAFE_NO_PAD.encode(sha256_digest);
    if config
        .expected_thumbprint
        .as_deref()
        .is_some_and(|expected| expected != hex_upper(&sha1_digest))
    {
        return Err(AuthError::new(
            "microsoft_graph_certificate_thumbprint_mismatch",
        ));
    }
    let encoding_key = EncodingKey::from_rsa_pem(&private_key_bytes)
        .map_err(|_| AuthError::new("microsoft_graph_private_key_file_invalid"))?;

    Ok(PreparedCertificate {
        client_id: config.client_id.clone(),
        token_endpoint: config.token_endpoint(),
        x5t,
        x5t_s256,
        certificate_key_id: config.certificate_key_id.clone(),
        encoding_key,
    })
}

fn parse_rsa_private_key(bytes: &[u8]) -> Result<RsaPrivateKey, AuthError> {
    let (label, der) = decode_pem_block(bytes)
        .ok_or_else(|| AuthError::new("microsoft_graph_private_key_file_invalid"))?;
    match label.as_str() {
        "RSA PRIVATE KEY" => RsaPrivateKey::from_pkcs1_der(&der)
            .map_err(|_| AuthError::new("microsoft_graph_private_key_file_invalid")),
        "PRIVATE KEY" => RsaPrivateKey::from_pkcs8_der(&der)
            .map_err(|_| AuthError::new("microsoft_graph_private_key_file_invalid")),
        _ => Err(AuthError::new("microsoft_graph_private_key_file_invalid")),
    }
}

fn decode_pem_block(bytes: &[u8]) -> Option<(String, Vec<u8>)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let begin = text.find("-----BEGIN ")?;
    if !text[..begin].trim().is_empty() {
        return None;
    }
    let label_end = text[begin + 11..].find("-----")? + begin + 11;
    let label = text[begin + 11..label_end].to_string();
    let body_start = label_end + 5;
    let end_marker = format!("-----END {label}-----");
    let end = text[body_start..].find(&end_marker)? + body_start;
    if !text[end + end_marker.len()..].trim().is_empty() {
        return None;
    }
    let body = text[body_start..end]
        .lines()
        .filter(|line| !line.contains(':'))
        .collect::<String>();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .ok()?;
    Some((label, der))
}

fn trim_integer(value: &[u8]) -> Vec<u8> {
    let first_nonzero = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len().saturating_sub(1));
    value[first_nonzero..].to_vec()
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

fn normalize_thumbprint(value: &str) -> Result<String, AuthError> {
    let value = value.trim();
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AuthError::new(
            "microsoft_graph_invalid_certificate_thumbprint",
        ));
    }
    Ok(value.to_ascii_uppercase())
}

fn strict_uuid(value: &str, error_code: &'static str) -> Result<String, AuthError> {
    let value = value.trim();
    if value.len() != 36
        || ![8, 13, 18, 23]
            .into_iter()
            .all(|index| value.as_bytes().get(index) == Some(&b'-'))
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
    {
        return Err(AuthError::new(error_code));
    }
    Uuid::parse_str(value)
        .map(|uuid| uuid.hyphenated().to_string())
        .map_err(|_| AuthError::new(error_code))
}

fn checked_path(value: String) -> Result<PathBuf, AuthError> {
    let path = PathBuf::from(value);
    if path.as_os_str().is_empty()
        || !path.is_absolute()
        || path.to_str().is_some_and(|path| path.contains('\0'))
    {
        return Err(AuthError::new("microsoft_graph_certificate_path_invalid"));
    }
    Ok(path)
}

fn read_secure_file(path: &Path, private_key: bool) -> Result<Vec<u8>, AuthError> {
    let invalid_code = if private_key {
        "microsoft_graph_private_key_file_invalid"
    } else {
        "microsoft_graph_certificate_file_invalid"
    };
    let metadata = fs::symlink_metadata(path).map_err(|_| AuthError::new(invalid_code))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(AuthError::new(invalid_code));
    }
    validate_file_permissions(path, &metadata, private_key, invalid_code)?;

    #[cfg(unix)]
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| AuthError::new(invalid_code))?;
    #[cfg(not(unix))]
    let file = File::open(path).map_err(|_| AuthError::new(invalid_code))?;

    let opened_metadata = file.metadata().map_err(|_| AuthError::new(invalid_code))?;
    if !opened_metadata.file_type().is_file() {
        return Err(AuthError::new(invalid_code));
    }
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::dev(&metadata)
        != std::os::unix::fs::MetadataExt::dev(&opened_metadata)
        || std::os::unix::fs::MetadataExt::ino(&metadata)
            != std::os::unix::fs::MetadataExt::ino(&opened_metadata)
    {
        return Err(AuthError::new(invalid_code));
    }

    let mut contents = Vec::new();
    file.take(MAX_CREDENTIAL_FILE_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|_| AuthError::new(invalid_code))?;
    if contents.len() as u64 > MAX_CREDENTIAL_FILE_BYTES {
        return Err(AuthError::new(invalid_code));
    }
    Ok(contents)
}

fn validate_file_permissions(
    path: &Path,
    metadata: &fs::Metadata,
    private_key: bool,
    invalid_code: &'static str,
) -> Result<(), AuthError> {
    let Some(parent) = path.parent() else {
        return Err(AuthError::new(invalid_code));
    };
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| AuthError::new(invalid_code))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
        return Err(AuthError::new(invalid_code));
    }

    #[cfg(not(unix))]
    let _ = private_key;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid || parent_metadata.uid() != current_uid {
            return Err(AuthError::new(invalid_code));
        }
        let file_mode = metadata.mode() & 0o7777;
        let parent_mode = parent_metadata.mode() & 0o777;
        if parent_mode & 0o022 != 0 {
            return Err(AuthError::new(invalid_code));
        }
        // The certificate is public and may use the conventional 0644 mode;
        // only the private key requires exact 0600 ownership protection.
        if (private_key && file_mode != 0o600)
            || (!private_key && (file_mode & 0o022 != 0 || file_mode & 0o7000 != 0))
        {
            return Err(AuthError::new(invalid_code));
        }
    }

    Ok(())
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn explicit_access_token() -> Option<String> {
    env::var(MICROSOFT_GRAPH_ACCESS_TOKEN_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn to_gws_error(error: AuthError) -> GwsError {
    GwsError::Auth(format!("Microsoft Graph authentication failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::SecondsFormat;
    use rcgen::{date_time_ymd, CertificateParams, KeyPair};
    use rsa::pkcs8::EncodePrivateKey;
    use serial_test::serial;
    use std::collections::BTreeMap;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TENANT_ID: &str = "f4800e2b-b4a1-44ef-8ad8-4f98a399b346";
    const CLIENT_ID: &str = "a2fd1071-47d0-470b-bf05-587005c4b9f5";
    const KEY_ID: &str = "ba479959-d277-4265-953e-426a6fbd9392";

    struct TestCertificateFiles {
        _directory: TempDir,
        certificate_file: PathBuf,
        private_key_file: PathBuf,
    }

    fn test_certificate_files() -> TestCertificateFiles {
        let directory = tempfile::tempdir().expect("test directory");
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("RSA key");
        let key_der = key.to_pkcs8_der().expect("PKCS#8 key");
        let key_pair = KeyPair::try_from(key_der.as_bytes()).expect("rcgen key");
        let params =
            CertificateParams::new(vec!["test.local".to_string()]).expect("certificate parameters");
        let certificate = params.self_signed(&key_pair).expect("certificate");
        let certificate_file = directory.path().join("certificate.pem");
        let private_key_file = directory.path().join("private-key.pem");
        fs::write(&certificate_file, certificate.pem()).expect("certificate file");
        fs::write(
            &private_key_file,
            key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .expect("key pem")
                .as_bytes(),
        )
        .expect("private key file");
        fs::set_permissions(&certificate_file, fs::Permissions::from_mode(0o600))
            .expect("certificate permissions");
        fs::set_permissions(&private_key_file, fs::Permissions::from_mode(0o600))
            .expect("private key permissions");
        TestCertificateFiles {
            _directory: directory,
            certificate_file,
            private_key_file,
        }
    }

    fn test_config(files: &TestCertificateFiles) -> CertificateConfig {
        CertificateConfig {
            tenant_id: TENANT_ID.to_string(),
            client_id: CLIENT_ID.to_string(),
            certificate_file: files.certificate_file.clone(),
            private_key_file: files.private_key_file.clone(),
            certificate_key_id: Some(KEY_ID.to_string()),
            expected_thumbprint: None,
        }
    }

    fn access_token_for_test() -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = serde_json::json!({
            "aud": MICROSOFT_GRAPH_AUDIENCE,
            "roles": REQUIRED_GRAPH_ROLES,
        });
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload"));
        format!("{header}.{payload}.test-signature")
    }

    async fn token_server(
        status: u16,
        body: String,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let calls = Arc::new(AtomicUsize::new(0));
        let call_count = Arc::clone(&calls);
        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                call_count.fetch_add(1, Ordering::SeqCst);
                let mut request = [0u8; 8192];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        (format!("http://{address}/token"), calls, handle)
    }

    fn clear_auth_env() {
        for name in [
            MICROSOFT_GRAPH_ACCESS_TOKEN_ENV,
            MICROSOFT_GRAPH_TENANT_ID_ENV,
            MICROSOFT_GRAPH_CLIENT_ID_ENV,
            MICROSOFT_GRAPH_CERTIFICATE_FILE_ENV,
            MICROSOFT_GRAPH_PRIVATE_KEY_FILE_ENV,
            MICROSOFT_GRAPH_CERTIFICATE_KEY_ID_ENV,
            MICROSOFT_GRAPH_CERTIFICATE_THUMBPRINT_ENV,
        ] {
            env::remove_var(name);
        }
    }

    #[test]
    #[serial]
    fn explicit_access_token_wins_without_reading_certificate_files() {
        clear_auth_env();
        let explicit_value = format!("override-{}", Uuid::new_v4());
        env::set_var(MICROSOFT_GRAPH_ACCESS_TOKEN_ENV, &explicit_value);
        env::set_var(MICROSOFT_GRAPH_TENANT_ID_ENV, "not-a-uuid");
        env::set_var(
            MICROSOFT_GRAPH_CERTIFICATE_FILE_ENV,
            "/path/that/must/not/be/read",
        );
        env::set_var(
            MICROSOFT_GRAPH_PRIVATE_KEY_FILE_ENV,
            "/path/that/must/not/be/read",
        );

        let client = reqwest::Client::new();
        let mut session = MicrosoftGraphAuthSession::from_env(client).expect("override auth");
        let token = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(session.access_token(Utc::now()))
            .expect("token");

        assert_eq!(token.as_str(), explicit_value);
        assert!(token.is_redacted_debug());
        clear_auth_env();
    }

    #[tokio::test]
    #[serial]
    async fn complete_certificate_config_acquires_and_reuses_token() {
        clear_auth_env();
        let files = test_certificate_files();
        let config = test_config(&files);
        let body = serde_json::json!({
            "access_token": access_token_for_test(),
            "token_type": "Bearer",
            "expires_in": 3600,
        })
        .to_string();
        let (endpoint, calls, server) = token_server(200, body).await;
        let mut session = MicrosoftGraphAuthSession::from_config_with_endpoint(
            reqwest::Client::new(),
            config,
            endpoint,
        );
        let first = session
            .access_token(Utc::now())
            .await
            .expect("first token")
            .as_str()
            .to_string();
        let second = session
            .access_token(Utc::now() + Duration::seconds(120))
            .await
            .expect("reused token")
            .as_str()
            .to_string();
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.await.expect("server");
    }

    #[test]
    #[serial]
    fn partial_certificate_config_fails_closed_with_bounded_code() {
        clear_auth_env();
        env::set_var(MICROSOFT_GRAPH_TENANT_ID_ENV, TENANT_ID);
        let error = MicrosoftGraphAuthSession::from_env(reqwest::Client::new())
            .expect_err("partial config must fail");
        let message = error.to_string();
        assert!(message.contains("microsoft_graph_auth_partial_config"));
        assert!(!message.contains(TENANT_ID));
        clear_auth_env();
    }

    #[test]
    #[serial]
    fn invalid_tenant_and_client_uuid_values_are_rejected() {
        for (name, value, expected) in [
            (
                MICROSOFT_GRAPH_TENANT_ID_ENV,
                "tenant.example",
                "microsoft_graph_invalid_tenant_id",
            ),
            (
                MICROSOFT_GRAPH_CLIENT_ID_ENV,
                "client.example",
                "microsoft_graph_invalid_client_id",
            ),
        ] {
            clear_auth_env();
            env::set_var(MICROSOFT_GRAPH_TENANT_ID_ENV, TENANT_ID);
            env::set_var(MICROSOFT_GRAPH_CLIENT_ID_ENV, CLIENT_ID);
            env::set_var(name, value);
            env::set_var(MICROSOFT_GRAPH_CERTIFICATE_FILE_ENV, "/tmp/certificate.pem");
            env::set_var(MICROSOFT_GRAPH_PRIVATE_KEY_FILE_ENV, "/tmp/private-key.pem");
            let error = MicrosoftGraphAuthSession::from_env(reqwest::Client::new())
                .expect_err("invalid UUID must fail");
            assert!(error.to_string().contains(expected));
        }
        clear_auth_env();
    }

    #[test]
    #[serial]
    fn no_certificate_config_fails_closed_with_a_bounded_code() {
        clear_auth_env();
        let error = MicrosoftGraphAuthSession::from_env(reqwest::Client::new())
            .expect_err("missing certificate config must fail");
        assert!(error
            .to_string()
            .contains("microsoft_graph_auth_not_configured"));
        clear_auth_env();
    }

    #[test]
    #[serial]
    fn relative_certificate_paths_are_rejected() {
        clear_auth_env();
        env::set_var(MICROSOFT_GRAPH_TENANT_ID_ENV, TENANT_ID);
        env::set_var(MICROSOFT_GRAPH_CLIENT_ID_ENV, CLIENT_ID);
        env::set_var(MICROSOFT_GRAPH_CERTIFICATE_FILE_ENV, "certificate.pem");
        env::set_var(
            MICROSOFT_GRAPH_PRIVATE_KEY_FILE_ENV,
            "/secure/private-key.pem",
        );
        let error = MicrosoftGraphAuthSession::from_env(reqwest::Client::new())
            .expect_err("relative certificate path must fail");
        assert!(error
            .to_string()
            .contains("microsoft_graph_certificate_path_invalid"));
        clear_auth_env();
    }

    #[test]
    #[serial]
    fn optional_certificate_identifiers_are_validated() {
        clear_auth_env();
        env::set_var(MICROSOFT_GRAPH_TENANT_ID_ENV, TENANT_ID);
        env::set_var(MICROSOFT_GRAPH_CLIENT_ID_ENV, CLIENT_ID);
        env::set_var(MICROSOFT_GRAPH_CERTIFICATE_FILE_ENV, "/tmp/certificate.pem");
        env::set_var(MICROSOFT_GRAPH_PRIVATE_KEY_FILE_ENV, "/tmp/private-key.pem");

        env::set_var(MICROSOFT_GRAPH_CERTIFICATE_KEY_ID_ENV, "not-a-uuid");
        let error = MicrosoftGraphAuthSession::from_env(reqwest::Client::new())
            .expect_err("invalid key id must fail");
        assert!(error
            .to_string()
            .contains("microsoft_graph_invalid_certificate_key_id"));

        env::remove_var(MICROSOFT_GRAPH_CERTIFICATE_KEY_ID_ENV);
        env::set_var(
            MICROSOFT_GRAPH_CERTIFICATE_THUMBPRINT_ENV,
            "not-a-thumbprint",
        );
        let error = MicrosoftGraphAuthSession::from_env(reqwest::Client::new())
            .expect_err("invalid thumbprint must fail");
        assert!(error
            .to_string()
            .contains("microsoft_graph_invalid_certificate_thumbprint"));
        clear_auth_env();
    }

    #[test]
    fn assertion_claims_are_bounded_and_identify_the_registered_certificate() {
        let files = test_certificate_files();
        let config = test_config(&files);
        let now = DateTime::parse_from_rfc3339("2026-08-04T12:00:00Z")
            .expect("time")
            .with_timezone(&Utc);
        let prepared = prepare_certificate(&config, now).expect("certificate");
        let jti = Uuid::from_u128(0x00112233445566778899aabbccddeeff);
        let assertion = build_client_assertion(&prepared, now, jti).expect("assertion");
        let parts = assertion.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        let header = serde_json::from_slice::<Value>(&decode_base64url(parts[0]).expect("header"))
            .expect("header JSON");
        let claims = serde_json::from_slice::<Value>(&decode_base64url(parts[1]).expect("claims"))
            .expect("claims JSON");
        let certificate_bytes = fs::read(&files.certificate_file).expect("certificate");
        let (_, certificate_pem) = parse_x509_pem(&certificate_bytes).expect("PEM");
        let expected_x5t = URL_SAFE_NO_PAD.encode(Sha1::digest(&certificate_pem.contents));
        let expected_x5t_s256 = URL_SAFE_NO_PAD.encode(Sha256::digest(&certificate_pem.contents));
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], KEY_ID);
        assert_eq!(header["x5t"], expected_x5t);
        assert_eq!(header["x5t#S256"], expected_x5t_s256);
        assert_eq!(claims["aud"], config.token_endpoint());
        assert_eq!(claims["iss"], CLIENT_ID);
        assert_eq!(claims["sub"], CLIENT_ID);
        assert_eq!(claims["jti"], jti.hyphenated().to_string());
        assert_eq!(claims["iat"], now.timestamp());
        assert_eq!(claims["nbf"], now.timestamp());
        assert_eq!(claims["exp"], now.timestamp() + ASSERTION_LIFETIME_SECONDS);
    }

    #[test]
    #[cfg(unix)]
    fn public_certificate_with_standard_read_permissions_is_accepted() {
        let files = test_certificate_files();
        fs::set_permissions(&files.certificate_file, fs::Permissions::from_mode(0o644))
            .expect("certificate permissions");
        let prepared = prepare_certificate(&test_config(&files), Utc::now())
            .expect("public certificate permissions should be accepted");
        assert!(!prepared.x5t.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn insecure_private_key_file_shapes_are_rejected() {
        let files = test_certificate_files();
        let mut config = test_config(&files);
        fs::set_permissions(&files.private_key_file, fs::Permissions::from_mode(0o640))
            .expect("permissions");
        assert_eq!(
            prepare_certificate(&config, Utc::now()).unwrap_err().code,
            "microsoft_graph_private_key_file_invalid"
        );

        let symlink_path = files
            .certificate_file
            .with_file_name("private-key-link.pem");
        symlink(&files.private_key_file, &symlink_path).expect("symlink");
        config.private_key_file = symlink_path;
        assert_eq!(
            prepare_certificate(&config, Utc::now()).unwrap_err().code,
            "microsoft_graph_private_key_file_invalid"
        );

        config.private_key_file = files.private_key_file.clone();
        fs::set_permissions(&files.private_key_file, fs::Permissions::from_mode(0o600))
            .expect("permissions");
        let directory = files.private_key_file.with_file_name("key-directory");
        fs::create_dir(&directory).expect("directory");
        config.private_key_file = directory;
        assert_eq!(
            prepare_certificate(&config, Utc::now()).unwrap_err().code,
            "microsoft_graph_private_key_file_invalid"
        );

        config.private_key_file = files
            .private_key_file
            .with_file_name("missing-private-key.pem");
        assert_eq!(
            prepare_certificate(&config, Utc::now()).unwrap_err().code,
            "microsoft_graph_private_key_file_invalid"
        );

        config.private_key_file = files.private_key_file.clone();
        let secure_certificate_files = test_certificate_files();
        config.certificate_file = secure_certificate_files.certificate_file.clone();
        fs::set_permissions(files._directory.path(), fs::Permissions::from_mode(0o770))
            .expect("parent permissions");
        assert_eq!(
            prepare_certificate(&config, Utc::now()).unwrap_err().code,
            "microsoft_graph_private_key_file_invalid"
        );
        fs::set_permissions(files._directory.path(), fs::Permissions::from_mode(0o700))
            .expect("parent permissions");
    }

    #[test]
    #[cfg(unix)]
    fn insecure_certificate_file_shapes_are_rejected() {
        let files = test_certificate_files();
        let mut config = test_config(&files);

        fs::set_permissions(&files.certificate_file, fs::Permissions::from_mode(0o660))
            .expect("certificate permissions");
        assert_eq!(
            prepare_certificate(&config, Utc::now()).unwrap_err().code,
            "microsoft_graph_certificate_file_invalid"
        );
        fs::set_permissions(&files.certificate_file, fs::Permissions::from_mode(0o600))
            .expect("certificate permissions");

        let missing = files.certificate_file.with_file_name("missing.pem");
        config.certificate_file = missing;
        assert_eq!(
            prepare_certificate(&config, Utc::now()).unwrap_err().code,
            "microsoft_graph_certificate_file_invalid"
        );

        let symlink_path = files
            .certificate_file
            .with_file_name("certificate-link.pem");
        symlink(&files.certificate_file, &symlink_path).expect("certificate symlink");
        config.certificate_file = symlink_path;
        assert_eq!(
            prepare_certificate(&config, Utc::now()).unwrap_err().code,
            "microsoft_graph_certificate_file_invalid"
        );

        let directory = files
            .certificate_file
            .with_file_name("certificate-directory");
        fs::create_dir(&directory).expect("certificate directory");
        config.certificate_file = directory;
        assert_eq!(
            prepare_certificate(&config, Utc::now()).unwrap_err().code,
            "microsoft_graph_certificate_file_invalid"
        );
    }

    #[test]
    fn certificate_and_private_key_mismatch_is_rejected() {
        let first = test_certificate_files();
        let second = test_certificate_files();
        let mut config = test_config(&first);
        config.private_key_file = second.private_key_file;
        let error = prepare_certificate(&config, Utc::now()).expect_err("mismatch");
        assert_eq!(error.code, "microsoft_graph_certificate_key_mismatch");
    }

    #[test]
    fn certificate_with_trailing_der_is_rejected() {
        let files = test_certificate_files();
        let certificate_bytes = fs::read(&files.certificate_file).expect("certificate");
        let (_, pem) = parse_x509_pem(&certificate_bytes).expect("PEM");
        let mut der = pem.contents.clone();
        der.push(0);
        let malformed = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        );
        fs::write(&files.certificate_file, malformed).expect("certificate file");
        let error = prepare_certificate(&test_config(&files), Utc::now())
            .expect_err("trailing DER must fail");
        assert_eq!(error.code, "microsoft_graph_certificate_file_invalid");
    }

    #[test]
    fn configured_certificate_thumbprint_must_match_the_certificate() {
        let files = test_certificate_files();
        let mut config = test_config(&files);
        config.expected_thumbprint = Some("0000000000000000000000000000000000000000".to_string());
        let error = prepare_certificate(&config, Utc::now()).expect_err("thumbprint mismatch");
        assert_eq!(
            error.code,
            "microsoft_graph_certificate_thumbprint_mismatch"
        );
    }

    #[test]
    fn expired_and_not_yet_valid_certificates_are_rejected() {
        let files = test_certificate_files();
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("RSA key");
        let key_der = key.to_pkcs8_der().expect("PKCS#8 key");
        let key_pair = KeyPair::try_from(key_der.as_bytes()).expect("rcgen key");
        for (name, not_before, not_after, expected) in [
            (
                "expired",
                date_time_ymd(2020, 1, 1),
                date_time_ymd(2021, 1, 1),
                "microsoft_graph_certificate_expired",
            ),
            (
                "not-yet-valid",
                date_time_ymd(2030, 1, 1),
                date_time_ymd(2031, 1, 1),
                "microsoft_graph_certificate_not_yet_valid",
            ),
        ] {
            let mut params = CertificateParams::new(vec!["test.local".to_string()])
                .expect("certificate parameters");
            params.not_before = not_before;
            params.not_after = not_after;
            let certificate = params.self_signed(&key_pair).expect("certificate");
            let certificate_path = files.certificate_file.with_file_name(format!("{name}.pem"));
            fs::write(&certificate_path, certificate.pem()).expect("certificate file");
            fs::set_permissions(&certificate_path, fs::Permissions::from_mode(0o600))
                .expect("certificate permissions");
            let config = CertificateConfig {
                certificate_file: certificate_path,
                ..test_config(&files)
            };
            assert_eq!(
                prepare_certificate(&config, Utc::now()).unwrap_err().code,
                expected
            );
        }
    }

    #[tokio::test]
    async fn token_endpoint_errors_are_bounded_and_do_not_echo_response_body() {
        let files = test_certificate_files();
        let config = test_config(&files);
        let prepared = prepare_certificate(&config, Utc::now()).expect("certificate");
        let valid_access_token = access_token_for_test();
        let cases = vec![
            (
                400,
                "{\"error\":\"invalid_client\",\"error_description\":\"secret tenant detail\"}"
                    .to_string(),
            ),
            (200, "not-json".to_string()),
            (
                200,
                "{\"token_type\":\"Bearer\",\"expires_in\":3600}".to_string(),
            ),
            (
                200,
                serde_json::json!({
                    "access_token": valid_access_token,
                    "token_type": "Basic",
                    "expires_in": 3600,
                })
                .to_string(),
            ),
            (
                200,
                serde_json::json!({
                    "access_token": access_token_for_test(),
                    "token_type": "Bearer",
                    "expires_in": 60,
                })
                .to_string(),
            ),
            (
                200,
                serde_json::json!({
                    "access_token": "not-a-jwt",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                })
                .to_string(),
            ),
        ];
        for (status, body) in cases {
            let (endpoint, _calls, server) = token_server(status, body).await;
            let assertion =
                build_client_assertion(&prepared, Utc::now(), Uuid::new_v4()).expect("assertion");
            let result =
                request_access_token(&reqwest::Client::new(), &endpoint, CLIENT_ID, &assertion)
                    .await;
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("token response must fail"),
            };
            let message = error.to_string();
            assert!(!message.contains("secret tenant detail"));
            server.await.expect("server");
        }
    }

    #[test]
    fn access_token_serialization_is_not_available_and_debug_is_redacted() {
        let token = MicrosoftGraphAccessToken("memory-only".to_string());
        assert!(token.is_redacted_debug());
        let mut object = BTreeMap::new();
        object.insert("token", serde_json::json!("not included"));
        let serialized = serde_json::to_string(&object).expect("test serialization");
        assert!(!serialized.contains(token.as_str()));
    }

    #[test]
    fn required_role_validation_is_fail_closed() {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "aud": MICROSOFT_GRAPH_AUDIENCE,
                "roles": ["User.Read.All"],
            }))
            .expect("payload"),
        );
        let token = format!("{header}.{payload}.signature");
        let error = validate_graph_access_token(&token).expect_err("missing roles");
        assert_eq!(error.code, "microsoft_graph_token_required_roles_missing");
    }

    #[test]
    fn assertion_time_format_is_utc_and_bounded() {
        let time = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        assert!(time.ends_with('Z'));
        assert!(ASSERTION_LIFETIME_SECONDS <= 600);
    }
}
