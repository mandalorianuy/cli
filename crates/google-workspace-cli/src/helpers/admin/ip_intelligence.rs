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

use chrono::{SecondsFormat, Utc};
use futures_util::{stream, StreamExt};
use ipnet::IpNet;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;

pub(super) const IPINFO_TOKEN_ENV: &str = "GOOGLE_WORKSPACE_CLI_IPINFO_TOKEN";

const IPV4_BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/ipv4.json";
const IPV6_BOOTSTRAP_URL: &str = "https://data.iana.org/rdap/ipv6.json";
const LOOKUP_CONCURRENCY: usize = 8;
const LOOKUP_TIMEOUT_SECONDS: u64 = 8;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DetectionStatus {
    Detected,
    NotDetected,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IpIntelligenceSource {
    provider: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    retrieved_at: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IpIntelligence {
    ip_version: u8,
    address_scope: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_end: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rdap_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    continent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    continent_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latitude: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    longitude: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_anonymous: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_anycast: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_hosting: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_mobile: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_satellite: Option<bool>,
    vpn: DetectionStatus,
    proxy: DetectionStatus,
    tor: DetectionStatus,
    relay: DetectionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    privacy_service: Option<String>,
    sources: Vec<IpIntelligenceSource>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IpIntelligenceSummary {
    enabled: bool,
    unique_ip_count: usize,
    public_ip_count: usize,
    enriched_ip_count: usize,
    partial_ip_count: usize,
    failed_ip_count: usize,
    ipinfo_configured: bool,
    providers: Vec<&'static str>,
}

impl IpIntelligenceSummary {
    pub(super) fn disabled() -> Self {
        Self {
            enabled: false,
            unique_ip_count: 0,
            public_ip_count: 0,
            enriched_ip_count: 0,
            partial_ip_count: 0,
            failed_ip_count: 0,
            ipinfo_configured: false,
            providers: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct RdapBootstrap {
    services: Vec<(Vec<String>, Vec<String>)>,
}

#[derive(Clone, Debug)]
struct ParsedRdap {
    network_owner: Option<String>,
    network_name: Option<String>,
    network_handle: Option<String>,
    network_type: Option<String>,
    network_start: Option<String>,
    network_end: Option<String>,
    registration_country: Option<String>,
    rir: Option<String>,
    rdap_url: Option<String>,
    referral_base: Option<Url>,
}

pub(super) async fn enrich_ip_addresses(
    client: &Client,
    addresses: impl IntoIterator<Item = String>,
    ipinfo_token: Option<&str>,
) -> (BTreeMap<String, IpIntelligence>, IpIntelligenceSummary) {
    let unique: BTreeSet<String> = addresses
        .into_iter()
        .filter(|address| !address.trim().is_empty())
        .collect();
    let parsed: Vec<(String, Result<IpAddr, _>)> = unique
        .iter()
        .cloned()
        .map(|address| {
            let parsed = address.parse::<IpAddr>();
            (address, parsed)
        })
        .collect();
    let needs_v4 = parsed.iter().any(|(_, ip)| {
        matches!(ip, Ok(IpAddr::V4(_))) && ip_scope(ip.as_ref().unwrap()) == "public"
    });
    let needs_v6 = parsed.iter().any(|(_, ip)| {
        matches!(ip, Ok(IpAddr::V6(_))) && ip_scope(ip.as_ref().unwrap()) == "public"
    });

    let (v4_bootstrap, v6_bootstrap) = tokio::join!(
        fetch_bootstrap(client, IPV4_BOOTSTRAP_URL, needs_v4),
        fetch_bootstrap(client, IPV6_BOOTSTRAP_URL, needs_v6)
    );
    let token = ipinfo_token.filter(|value| !value.trim().is_empty());
    let lookups = stream::iter(parsed.into_iter().map(|(address, parsed_ip)| {
        let v4_bootstrap = v4_bootstrap.clone();
        let v6_bootstrap = v6_bootstrap.clone();
        async move {
            let intelligence = match parsed_ip {
                Ok(ip) => {
                    let bootstrap = match ip {
                        IpAddr::V4(_) => v4_bootstrap.as_ref().ok().and_then(Option::as_ref),
                        IpAddr::V6(_) => v6_bootstrap.as_ref().ok().and_then(Option::as_ref),
                    };
                    lookup_ip(client, ip, bootstrap, token).await
                }
                Err(_) => invalid_ip_intelligence(),
            };
            (address, intelligence)
        }
    }))
    .buffer_unordered(LOOKUP_CONCURRENCY)
    .collect::<Vec<_>>()
    .await;

    let entries: BTreeMap<_, _> = lookups.into_iter().collect();
    let public_ip_count = entries
        .values()
        .filter(|entry| entry.address_scope == "public")
        .count();
    let enriched_ip_count = entries
        .values()
        .filter(|entry| entry.status == "complete")
        .count();
    let partial_ip_count = entries
        .values()
        .filter(|entry| entry.status == "partial")
        .count();
    let failed_ip_count = entries
        .values()
        .filter(|entry| entry.status == "unavailable")
        .count();
    let mut providers = vec!["IANA RDAP bootstrap", "Regional Internet Registry RDAP"];
    if token.is_some() {
        providers.push("IPinfo");
    }
    let summary = IpIntelligenceSummary {
        enabled: true,
        unique_ip_count: entries.len(),
        public_ip_count,
        enriched_ip_count,
        partial_ip_count,
        failed_ip_count,
        ipinfo_configured: token.is_some(),
        providers,
    };
    (entries, summary)
}

async fn fetch_bootstrap(
    client: &Client,
    url: &str,
    required: bool,
) -> Result<Option<RdapBootstrap>, ()> {
    if !required {
        return Ok(None);
    }
    let response = client
        .get(url)
        .timeout(Duration::from_secs(LOOKUP_TIMEOUT_SECONDS))
        .send()
        .await
        .map_err(|_| ())?;
    if !response.status().is_success() {
        return Err(());
    }
    response
        .json::<RdapBootstrap>()
        .await
        .map(Some)
        .map_err(|_| ())
}

async fn lookup_ip(
    client: &Client,
    ip: IpAddr,
    bootstrap: Option<&RdapBootstrap>,
    ipinfo_token: Option<&str>,
) -> IpIntelligence {
    let mut intelligence = IpIntelligence {
        ip_version: if ip.is_ipv4() { 4 } else { 6 },
        address_scope: ip_scope(&ip).to_string(),
        vpn: DetectionStatus::Unknown,
        proxy: DetectionStatus::Unknown,
        tor: DetectionStatus::Unknown,
        relay: DetectionStatus::Unknown,
        ..IpIntelligence::default()
    };
    if intelligence.address_scope != "public" {
        intelligence.status = "local".to_string();
        return intelligence;
    }

    if let Some(bootstrap) = bootstrap {
        match fetch_rdap(client, ip, bootstrap).await {
            Ok(rdap) => apply_rdap(&mut intelligence, rdap),
            Err(code) => intelligence.errors.push(code),
        }
    } else {
        intelligence
            .errors
            .push("rdap_bootstrap_unavailable".to_string());
    }

    if let Some(token) = ipinfo_token {
        match fetch_ipinfo(client, ip, token).await {
            Ok(value) => {
                let includes_privacy = apply_ipinfo(&mut intelligence, &value);
                if !includes_privacy {
                    match fetch_ipinfo_privacy(client, ip, token).await {
                        Ok(value) => apply_ipinfo_privacy(&mut intelligence, &value),
                        Err(code) => intelligence.errors.push(code),
                    }
                }
            }
            Err(code) => intelligence.errors.push(code),
        }
    }

    intelligence.status = if intelligence.sources.is_empty() {
        "unavailable"
    } else if intelligence.errors.is_empty() {
        "complete"
    } else {
        "partial"
    }
    .to_string();
    intelligence
}

fn invalid_ip_intelligence() -> IpIntelligence {
    IpIntelligence {
        address_scope: "invalid".to_string(),
        status: "unavailable".to_string(),
        vpn: DetectionStatus::Unknown,
        proxy: DetectionStatus::Unknown,
        tor: DetectionStatus::Unknown,
        relay: DetectionStatus::Unknown,
        errors: vec!["invalid_ip_address".to_string()],
        ..IpIntelligence::default()
    }
}

fn ip_scope(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(ip) => {
            let value = u32::from(*ip);
            let in_range = |network: u32, prefix: u8| {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                value & mask == network & mask
            };
            if ip.is_unspecified() {
                "unspecified"
            } else if ip.is_loopback() {
                "loopback"
            } else if ip.is_private() {
                "private"
            } else if ip.is_link_local() {
                "link_local"
            } else if ip.is_multicast() {
                "multicast"
            } else if ip.is_broadcast() {
                "broadcast"
            } else if ip.is_documentation() {
                "documentation"
            } else if in_range(u32::from_be_bytes([100, 64, 0, 0]), 10) {
                "shared"
            } else if in_range(u32::from_be_bytes([198, 18, 0, 0]), 15) {
                "benchmarking"
            } else if in_range(u32::from_be_bytes([240, 0, 0, 0]), 4) {
                "reserved"
            } else {
                "public"
            }
        }
        IpAddr::V6(ip) => {
            let value = u128::from(*ip);
            let in_range = |network: u128, prefix: u8| {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                value & mask == network & mask
            };
            if ip.is_unspecified() {
                "unspecified"
            } else if ip.is_loopback() {
                "loopback"
            } else if ip.is_multicast() {
                "multicast"
            } else if in_range(
                u128::from_be_bytes([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                7,
            ) {
                "private"
            } else if in_range(
                u128::from_be_bytes([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                10,
            ) {
                "link_local"
            } else if in_range(
                u128::from_be_bytes([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                32,
            ) {
                "documentation"
            } else if in_range(
                u128::from_be_bytes([0x20, 0x01, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                48,
            ) {
                "benchmarking"
            } else {
                "public"
            }
        }
    }
}

async fn fetch_rdap(
    client: &Client,
    ip: IpAddr,
    bootstrap: &RdapBootstrap,
) -> Result<ParsedRdap, String> {
    let base =
        select_rdap_base(ip, bootstrap).ok_or_else(|| "rdap_service_not_found".to_string())?;
    let first = fetch_rdap_from_base(client, ip, &base).await?;
    if let Some(referral) = first.referral_base.clone() {
        if referral.host_str() != base.host_str() {
            if let Ok(referred) = fetch_rdap_from_base(client, ip, &referral).await {
                return Ok(referred);
            }
        }
    }
    Ok(first)
}

async fn fetch_rdap_from_base(
    client: &Client,
    ip: IpAddr,
    base: &Url,
) -> Result<ParsedRdap, String> {
    let url = base
        .join(&format!("ip/{ip}"))
        .map_err(|_| "rdap_url_invalid".to_string())?;
    let response = client
        .get(url.clone())
        .header(
            reqwest::header::ACCEPT,
            "application/rdap+json, application/json",
        )
        .timeout(Duration::from_secs(LOOKUP_TIMEOUT_SECONDS))
        .send()
        .await
        .map_err(|_| "rdap_request_failed".to_string())?;
    if !response.status().is_success() {
        return Err(format!("rdap_http_{}", response.status().as_u16()));
    }
    let value = response
        .json::<Value>()
        .await
        .map_err(|_| "rdap_response_invalid".to_string())?;
    Ok(parse_rdap(&value, &url))
}

fn select_rdap_base(ip: IpAddr, bootstrap: &RdapBootstrap) -> Option<Url> {
    let mut matches = bootstrap
        .services
        .iter()
        .flat_map(|(networks, urls)| {
            networks.iter().filter_map(move |network| {
                let network = network.parse::<IpNet>().ok()?;
                if network.contains(&ip) {
                    Some((network.prefix_len(), urls))
                } else {
                    None
                }
            })
        })
        .collect::<Vec<_>>();
    matches.sort_by_key(|(prefix, _)| std::cmp::Reverse(*prefix));
    matches
        .into_iter()
        .flat_map(|(_, urls)| urls.iter())
        .find_map(|url| validated_rdap_base(url))
}

fn validated_rdap_base(raw: &str) -> Option<Url> {
    let mut url = Url::parse(raw).ok()?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    if !matches!(
        host.as_str(),
        "rdap.arin.net"
            | "rdap.apnic.net"
            | "rdap.db.ripe.net"
            | "rdap.lacnic.net"
            | "rdap.afrinic.net"
    ) {
        return None;
    }
    url.set_query(None);
    url.set_fragment(None);
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Some(url)
}

fn referral_base_from_port43(port43: Option<&str>) -> Option<Url> {
    let raw = match port43?.to_ascii_lowercase().as_str() {
        "whois.arin.net" => "https://rdap.arin.net/registry/",
        "whois.apnic.net" => "https://rdap.apnic.net/",
        "whois.ripe.net" => "https://rdap.db.ripe.net/",
        "whois.lacnic.net" => "https://rdap.lacnic.net/rdap/",
        "whois.afrinic.net" => "https://rdap.afrinic.net/rdap/",
        _ => return None,
    };
    validated_rdap_base(raw)
}

fn parse_rdap(value: &Value, requested_url: &Url) -> ParsedRdap {
    ParsedRdap {
        network_owner: rdap_network_owner(value),
        network_name: string_field(value, "name"),
        network_handle: string_field(value, "handle"),
        network_type: string_field(value, "type"),
        network_start: string_field(value, "startAddress"),
        network_end: string_field(value, "endAddress"),
        registration_country: string_field(value, "country"),
        rir: requested_url.host_str().and_then(rir_from_host),
        // Use the URL constructed from the allowlisted bootstrap/referral host.
        // RDAP response links are registry-controlled strings and are not
        // automatically safe for downstream spreadsheet or email links.
        rdap_url: Some(requested_url.to_string()),
        referral_base: referral_base_from_port43(value.get("port43").and_then(Value::as_str)),
    }
}

fn rdap_network_owner(value: &Value) -> Option<String> {
    value
        .get("entities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entity| {
            entity
                .get("roles")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|role| role.as_str() == Some("registrant"))
        })
        .find_map(vcard_organization_name)
}

fn vcard_organization_name(entity: &Value) -> Option<String> {
    let entries = entity
        .get("vcardArray")
        .and_then(Value::as_array)?
        .get(1)?
        .as_array()?;
    let kind = entries.iter().find_map(|entry| {
        let entry = entry.as_array()?;
        (entry.first()?.as_str()? == "kind")
            .then(|| entry.get(3)?.as_str().map(str::to_string))
            .flatten()
    });
    if !matches!(kind.as_deref(), Some("org" | "group")) {
        return None;
    }
    entries.iter().find_map(|entry| {
        let entry = entry.as_array()?;
        (entry.first()?.as_str()? == "fn")
            .then(|| entry.get(3)?.as_str().map(str::to_string))
            .flatten()
    })
}

fn rir_from_host(host: &str) -> Option<String> {
    match host {
        "rdap.arin.net" => Some("ARIN".to_string()),
        "rdap.apnic.net" => Some("APNIC".to_string()),
        "rdap.db.ripe.net" => Some("RIPE NCC".to_string()),
        "rdap.lacnic.net" => Some("LACNIC".to_string()),
        "rdap.afrinic.net" => Some("AFRINIC".to_string()),
        _ => None,
    }
}

fn apply_rdap(intelligence: &mut IpIntelligence, rdap: ParsedRdap) {
    intelligence.network_owner = rdap.network_owner;
    intelligence.network_name = rdap.network_name;
    intelligence.network_handle = rdap.network_handle;
    intelligence.network_type = rdap.network_type;
    intelligence.network_start = rdap.network_start;
    intelligence.network_end = rdap.network_end;
    intelligence.registration_country = rdap.registration_country;
    intelligence.rir = rdap.rir.clone();
    intelligence.rdap_url = rdap.rdap_url.clone();
    intelligence.sources.push(IpIntelligenceSource {
        provider: rdap.rir.unwrap_or_else(|| "RIR RDAP".to_string()),
        kind: "registration".to_string(),
        url: rdap.rdap_url,
        retrieved_at: now(),
    });
}

async fn fetch_ipinfo(client: &Client, ip: IpAddr, token: &str) -> Result<Value, String> {
    let core_url = Url::parse(&format!("https://api.ipinfo.io/lookup/{ip}"))
        .map_err(|_| "ipinfo_url_invalid".to_string())?;
    let response = client
        .get(core_url)
        .query(&[("token", token)])
        .timeout(Duration::from_secs(LOOKUP_TIMEOUT_SECONDS))
        .send()
        .await
        .map_err(|_| "ipinfo_request_failed".to_string())?;
    if response.status().is_success() {
        return response
            .json::<Value>()
            .await
            .map_err(|_| "ipinfo_response_invalid".to_string());
    }
    if !matches!(response.status().as_u16(), 401 | 403 | 404) {
        return Err(format!("ipinfo_http_{}", response.status().as_u16()));
    }

    let lite_url = Url::parse(&format!("https://api.ipinfo.io/lite/{ip}"))
        .map_err(|_| "ipinfo_url_invalid".to_string())?;
    let response = client
        .get(lite_url)
        .query(&[("token", token)])
        .timeout(Duration::from_secs(LOOKUP_TIMEOUT_SECONDS))
        .send()
        .await
        .map_err(|_| "ipinfo_request_failed".to_string())?;
    if !response.status().is_success() {
        return Err(format!("ipinfo_http_{}", response.status().as_u16()));
    }
    response
        .json::<Value>()
        .await
        .map_err(|_| "ipinfo_response_invalid".to_string())
}

async fn fetch_ipinfo_privacy(client: &Client, ip: IpAddr, token: &str) -> Result<Value, String> {
    let url = Url::parse(&format!("https://ipinfo.io/{ip}/privacy"))
        .map_err(|_| "ipinfo_privacy_url_invalid".to_string())?;
    let response = client
        .get(url)
        .query(&[("token", token)])
        .timeout(Duration::from_secs(LOOKUP_TIMEOUT_SECONDS))
        .send()
        .await
        .map_err(|_| "ipinfo_privacy_request_failed".to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "ipinfo_privacy_http_{}",
            response.status().as_u16()
        ));
    }
    response
        .json::<Value>()
        .await
        .map_err(|_| "ipinfo_privacy_response_invalid".to_string())
}

fn apply_ipinfo(intelligence: &mut IpIntelligence, value: &Value) -> bool {
    intelligence.hostname = string_field(value, "hostname");
    intelligence.asn = value
        .pointer("/as/asn")
        .and_then(Value::as_str)
        .or_else(|| value.get("asn").and_then(Value::as_str))
        .map(str::to_string);
    intelligence.asn_name = value
        .pointer("/as/name")
        .and_then(Value::as_str)
        .or_else(|| value.get("as_name").and_then(Value::as_str))
        .map(str::to_string);
    intelligence.asn_domain = value
        .pointer("/as/domain")
        .and_then(Value::as_str)
        .or_else(|| value.get("as_domain").and_then(Value::as_str))
        .map(str::to_string);
    intelligence.asn_type = value
        .pointer("/as/type")
        .and_then(Value::as_str)
        .map(str::to_string);
    intelligence.country = value
        .pointer("/geo/country")
        .and_then(Value::as_str)
        .or_else(|| value.get("country").and_then(Value::as_str))
        .map(str::to_string);
    intelligence.country_code = value
        .pointer("/geo/country_code")
        .and_then(Value::as_str)
        .or_else(|| value.get("country_code").and_then(Value::as_str))
        .map(str::to_string);
    intelligence.continent = value
        .pointer("/geo/continent")
        .and_then(Value::as_str)
        .or_else(|| value.get("continent").and_then(Value::as_str))
        .map(str::to_string);
    intelligence.continent_code = value
        .pointer("/geo/continent_code")
        .and_then(Value::as_str)
        .or_else(|| value.get("continent_code").and_then(Value::as_str))
        .map(str::to_string);
    intelligence.city = pointer_string(value, "/geo/city");
    intelligence.region = pointer_string(value, "/geo/region");
    intelligence.timezone = pointer_string(value, "/geo/timezone");
    intelligence.latitude = pointer_number_string(value, "/geo/latitude");
    intelligence.longitude = pointer_number_string(value, "/geo/longitude");
    intelligence.is_anonymous = bool_field(value, "is_anonymous");
    intelligence.is_anycast = bool_field(value, "is_anycast");
    intelligence.is_hosting = bool_field(value, "is_hosting");
    intelligence.is_mobile = bool_field(value, "is_mobile");
    intelligence.is_satellite = bool_field(value, "is_satellite");
    let includes_privacy = if let Some(privacy) = value.get("privacy") {
        apply_ipinfo_privacy(intelligence, privacy);
        true
    } else {
        false
    };
    intelligence.sources.push(IpIntelligenceSource {
        provider: "IPinfo".to_string(),
        kind: if value.get("geo").is_some() {
            "geolocation_asn".to_string()
        } else {
            "country_asn".to_string()
        },
        url: None,
        retrieved_at: now(),
    });
    includes_privacy
}

fn apply_ipinfo_privacy(intelligence: &mut IpIntelligence, value: &Value) {
    intelligence.vpn = detection(value, "vpn");
    intelligence.proxy = detection(value, "proxy");
    intelligence.tor = detection(value, "tor");
    intelligence.relay = detection(value, "relay");
    intelligence.is_hosting = bool_field(value, "hosting").or(intelligence.is_hosting);
    intelligence.privacy_service = string_field(value, "service");
    intelligence.sources.push(IpIntelligenceSource {
        provider: "IPinfo".to_string(),
        kind: "privacy".to_string(),
        url: None,
        retrieved_at: now(),
    });
}

fn detection(value: &Value, key: &str) -> DetectionStatus {
    match value.get(key).and_then(Value::as_bool) {
        Some(true) => DetectionStatus::Detected,
        Some(false) => DetectionStatus::NotDetected,
        None => DetectionStatus::Unknown,
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn bool_field(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

fn pointer_string(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn pointer_number_string(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_f64)
        .map(|number| {
            let mut rendered = number.to_string();
            if rendered == "-0" {
                rendered = "0".to_string();
            }
            rendered
        })
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn classifies_non_public_address_ranges_without_network_lookups() {
        assert_eq!(ip_scope(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), "private");
        assert_eq!(
            ip_scope(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
            "shared"
        );
        assert_eq!(
            ip_scope(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            "documentation"
        );
        assert_eq!(
            ip_scope(&IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))),
            "benchmarking"
        );
        assert_eq!(
            ip_scope(&IpAddr::V6("fc00::1".parse::<Ipv6Addr>().unwrap())),
            "private"
        );
        assert_eq!(
            ip_scope(&IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())),
            "documentation"
        );
        assert_eq!(ip_scope(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), "public");
    }

    #[test]
    fn selects_the_most_specific_safe_iana_rdap_service() {
        let bootstrap = RdapBootstrap {
            services: vec![
                (
                    vec!["0.0.0.0/0".to_string()],
                    vec!["https://rdap.arin.net/registry/".to_string()],
                ),
                (
                    vec!["159.0.0.0/8".to_string()],
                    vec!["https://rdap.apnic.net/".to_string()],
                ),
            ],
        };
        let selected = select_rdap_base("159.26.122.10".parse().unwrap(), &bootstrap).unwrap();
        assert_eq!(selected.as_str(), "https://rdap.apnic.net/");
    }

    #[test]
    fn rejects_untrusted_or_insecure_rdap_services() {
        assert!(validated_rdap_base("http://rdap.arin.net/registry/").is_none());
        assert!(validated_rdap_base("https://evil.example/rdap/").is_none());
        assert!(validated_rdap_base("https://user@rdap.arin.net/").is_none());
    }

    #[test]
    fn parses_registry_owner_and_referral_without_person_contact_data() {
        let value = json!({
            "handle": "NET-159-26-96-0-1",
            "name": "RIPE",
            "startAddress": "159.26.96.0",
            "endAddress": "159.26.127.255",
            "port43": "whois.ripe.net",
            "links": [{
                "rel": "self",
                "type": "application/rdap+json",
                "href": "https://untrusted.example/ip/159.26.122.10"
            }],
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "RIPE Network Coordination Centre"],
                        ["kind", {}, "text", "org"]
                    ]]
                },
                {
                    "roles": ["technical"],
                    "vcardArray": ["vcard", [
                        ["fn", {}, "text", "Named Person"],
                        ["kind", {}, "text", "individual"]
                    ]]
                }
            ]
        });
        let url = Url::parse("https://rdap.arin.net/registry/ip/159.26.122.10").unwrap();
        let parsed = parse_rdap(&value, &url);
        assert_eq!(
            parsed.network_owner.as_deref(),
            Some("RIPE Network Coordination Centre")
        );
        assert_eq!(parsed.rir.as_deref(), Some("ARIN"));
        assert_eq!(
            parsed.rdap_url.as_deref(),
            Some("https://rdap.arin.net/registry/ip/159.26.122.10")
        );
        assert_eq!(
            parsed.referral_base.unwrap().as_str(),
            "https://rdap.db.ripe.net/"
        );
    }

    #[test]
    fn parses_ipinfo_core_and_privacy_as_tristate_evidence() {
        let mut intelligence = IpIntelligence::default();
        let includes_privacy = apply_ipinfo(
            &mut intelligence,
            &json!({
                "hostname": "example.net",
                "geo": {
                    "city": "Montevideo",
                    "region": "Montevideo",
                    "country": "Uruguay",
                    "country_code": "UY",
                    "continent": "South America",
                    "continent_code": "SA",
                    "latitude": -34.9,
                    "longitude": -56.2,
                    "timezone": "America/Montevideo"
                },
                "as": {
                    "asn": "AS6057",
                    "name": "ANTEL",
                    "domain": "antel.com.uy",
                    "type": "isp"
                },
                "is_anonymous": false,
                "is_hosting": false
            }),
        );
        assert!(!includes_privacy);
        apply_ipinfo_privacy(
            &mut intelligence,
            &json!({
                "vpn": true,
                "proxy": false,
                "tor": false,
                "hosting": true,
                "service": "Example VPN"
            }),
        );
        assert_eq!(intelligence.country_code.as_deref(), Some("UY"));
        assert_eq!(intelligence.asn.as_deref(), Some("AS6057"));
        assert_eq!(intelligence.vpn, DetectionStatus::Detected);
        assert_eq!(intelligence.proxy, DetectionStatus::NotDetected);
        assert_eq!(intelligence.relay, DetectionStatus::Unknown);
        assert_eq!(intelligence.is_hosting, Some(true));
    }

    #[test]
    fn embedded_ipinfo_privacy_is_applied_once() {
        let mut intelligence = IpIntelligence::default();
        let includes_privacy = apply_ipinfo(
            &mut intelligence,
            &json!({
                "as": {"asn": "AS64500"},
                "privacy": {
                    "vpn": false,
                    "proxy": true,
                    "tor": false,
                    "relay": false
                }
            }),
        );

        assert!(includes_privacy);
        assert_eq!(intelligence.vpn, DetectionStatus::NotDetected);
        assert_eq!(intelligence.proxy, DetectionStatus::Detected);
        assert_eq!(
            intelligence
                .sources
                .iter()
                .filter(|source| source.kind == "privacy")
                .count(),
            1
        );
    }

    #[test]
    fn lite_ipinfo_response_still_adds_country_and_asn() {
        let mut intelligence = IpIntelligence::default();
        let includes_privacy = apply_ipinfo(
            &mut intelligence,
            &json!({
                "asn": "AS16509",
                "as_name": "Amazon.com, Inc.",
                "as_domain": "amazon.com",
                "country_code": "US",
                "country": "United States",
                "continent_code": "NA",
                "continent": "North America"
            }),
        );
        assert!(!includes_privacy);
        assert_eq!(intelligence.asn.as_deref(), Some("AS16509"));
        assert_eq!(intelligence.country.as_deref(), Some("United States"));
        assert_eq!(intelligence.vpn, DetectionStatus::Unknown);
    }
}
