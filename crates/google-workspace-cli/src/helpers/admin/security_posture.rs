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
use crate::output::sanitize_for_terminal;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};

pub(super) const GOOGLE_USER_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.user.readonly";
pub(super) const GOOGLE_ROLE_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly";

#[derive(Debug)]
pub(super) struct ReadOnlyRequest {
    pub source: String,
    pub method: reqwest::Method,
    pub url: String,
    pub query: Vec<(String, String)>,
    pub item_key: &'static str,
}

pub(super) fn google_posture_requests() -> Vec<ReadOnlyRequest> {
    vec![
        ReadOnlyRequest {
            source: "google.users".to_string(),
            method: reqwest::Method::GET,
            url: "https://admin.googleapis.com/admin/directory/v1/users".to_string(),
            query: vec![
                ("customer".to_string(), "my_customer".to_string()),
                ("maxResults".to_string(), "500".to_string()),
                ("orderBy".to_string(), "email".to_string()),
                ("projection".to_string(), "full".to_string()),
                (
                    "fields".to_string(),
                    "nextPageToken,users(id,primaryEmail,suspended,archived,isEnrolledIn2Sv,isEnforcedIn2Sv,lastLoginTime)"
                        .to_string(),
                ),
            ],
            item_key: "users",
        },
        ReadOnlyRequest {
            source: "google.roles".to_string(),
            method: reqwest::Method::GET,
            url: "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roles"
                .to_string(),
            query: vec![
                ("maxResults".to_string(), "100".to_string()),
                (
                    "fields".to_string(),
                    "nextPageToken,items(roleId,roleName,isSuperAdminRole,isSystemRole)"
                        .to_string(),
                ),
            ],
            item_key: "items",
        },
        ReadOnlyRequest {
            source: "google.roleAssignments".to_string(),
            method: reqwest::Method::GET,
            url: "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roleassignments"
                .to_string(),
            query: vec![
                ("maxResults".to_string(), "100".to_string()),
                (
                    "fields".to_string(),
                    "nextPageToken,items(roleAssignmentId,roleId,assignedTo,scopeType,orgUnitId)"
                        .to_string(),
                ),
            ],
            item_key: "items",
        },
    ]
}

pub(super) fn microsoft_graph_requests(start_time: &str) -> Vec<ReadOnlyRequest> {
    let graph = "https://graph.microsoft.com/v1.0";
    vec![
        ReadOnlyRequest {
            source: "microsoft.users".to_string(),
            method: reqwest::Method::GET,
            url: format!("{graph}/users"),
            query: vec![(
                "$select".to_string(),
                "id,userPrincipalName,mail,accountEnabled,userType,createdDateTime".to_string(),
            )],
            item_key: "value",
        },
        ReadOnlyRequest {
            source: "microsoft.authenticationMethods".to_string(),
            method: reqwest::Method::GET,
            url: format!("{graph}/reports/authenticationMethods/userRegistrationDetails"),
            query: vec![(
                "$select".to_string(),
                "id,userPrincipalName,isMfaRegistered,isMfaCapable,isPasswordlessCapable,methodsRegistered"
                    .to_string(),
            )],
            item_key: "value",
        },
        ReadOnlyRequest {
            source: "microsoft.roleAssignments".to_string(),
            method: reqwest::Method::GET,
            url: format!("{graph}/roleManagement/directory/roleAssignments"),
            query: vec![(
                "$select".to_string(),
                "id,principalId,roleDefinitionId".to_string(),
            )],
            item_key: "value",
        },
        ReadOnlyRequest {
            source: "microsoft.conditionalAccess".to_string(),
            method: reqwest::Method::GET,
            url: format!("{graph}/identity/conditionalAccess/policies"),
            query: vec![
                (
                    "$select".to_string(),
                    "id,displayName,state,conditions,grantControls,sessionControls".to_string(),
                ),
            ],
            item_key: "value",
        },
        ReadOnlyRequest {
            source: "microsoft.signIns".to_string(),
            method: reqwest::Method::GET,
            url: format!("{graph}/auditLogs/signIns"),
            query: vec![
                ("$filter".to_string(), format!("createdDateTime ge {start_time}")),
                (
                    "$select".to_string(),
                    "id,createdDateTime,userId,userPrincipalName,appId,appDisplayName,ipAddress,clientAppUsed,conditionalAccessStatus,riskDetail,riskLevelDuringSignIn,riskState,status"
                        .to_string(),
                ),
            ],
            item_key: "value",
        },
        ReadOnlyRequest {
            source: "microsoft.directoryAudits".to_string(),
            method: reqwest::Method::GET,
            url: format!("{graph}/auditLogs/directoryAudits"),
            query: vec![
                ("$filter".to_string(), format!("activityDateTime ge {start_time}")),
                (
                    "$select".to_string(),
                    "id,activityDateTime,activityDisplayName,category,initiatedBy,result,targetResources"
                        .to_string(),
                ),
            ],
            item_key: "value",
        },
        ReadOnlyRequest {
            source: "microsoft.defenderAlerts".to_string(),
            method: reqwest::Method::GET,
            url: format!("{graph}/security/alerts_v2"),
            query: vec![
                ("$filter".to_string(), format!("createdDateTime ge {start_time}")),
                (
                    "$select".to_string(),
                    "id,createdDateTime,lastUpdateDateTime,title,severity,status,serviceSource,category,classification,determination"
                        .to_string(),
                ),
            ],
            item_key: "value",
        },
        ReadOnlyRequest {
            source: "microsoft.defenderIncidents".to_string(),
            method: reqwest::Method::GET,
            url: format!("{graph}/security/incidents"),
            query: vec![
                ("$filter".to_string(), format!("createdDateTime ge {start_time}")),
                (
                    "$select".to_string(),
                    "id,createdDateTime,lastUpdateDateTime,displayName,severity,status,classification,determination"
                        .to_string(),
                ),
            ],
            item_key: "value",
        },
        ReadOnlyRequest {
            source: "microsoft.secureScore".to_string(),
            method: reqwest::Method::GET,
            url: format!("{graph}/security/secureScores"),
            query: vec![("$top".to_string(), "1".to_string())],
            item_key: "value",
        },
    ]
}

fn bounded_provider_error_code(status: reqwest::StatusCode, body: &Value, prefix: &str) -> String {
    let provider_code = body
        .pointer("/error/code")
        .and_then(Value::as_str)
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 64
                && code
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        });
    match provider_code {
        Some(code) => format!("{prefix}_{}_{}", status.as_u16(), code),
        None => format!("{prefix}_{}", status.as_u16()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum PostureSeverity {
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(super) enum ContextualVerdict {
    Alert,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(super) enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(super) enum Urgency {
    Immediate,
    Today,
    Review,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct HumanAnalysis {
    pub conclusion: String,
    pub escalation_reason: String,
    pub plausible_impact: String,
    pub evidence_for: Vec<String>,
    pub counter_evidence: Vec<String>,
    pub uncertainty: String,
    pub recommended_action: String,
    pub urgency: Urgency,
    pub confidence: Confidence,
}

impl HumanAnalysis {
    #[cfg(test)]
    fn is_complete(&self) -> bool {
        !self.conclusion.is_empty()
            && !self.escalation_reason.is_empty()
            && !self.plausible_impact.is_empty()
            && !self.evidence_for.is_empty()
            && !self.uncertainty.is_empty()
            && !self.recommended_action.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PostureFinding {
    pub finding_id: String,
    pub control_id: &'static str,
    pub provider: &'static str,
    pub severity: PostureSeverity,
    pub contextual_verdict: ContextualVerdict,
    pub title: String,
    pub subject: String,
    pub summary: String,
    pub evidence: BTreeMap<String, String>,
    pub analysis: HumanAnalysis,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct IdentityRecord {
    pub provider: &'static str,
    pub provider_id: String,
    pub primary_email: String,
    pub normalized_email: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_enrolled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_capable: Option<bool>,
    pub privileged: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sign_in_at: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct GoogleSignalContext {
    pub event_id: String,
    pub actor: String,
    pub rule: String,
    pub event_time: Option<String>,
}

impl IdentityRecord {
    fn google(
        id: &str,
        email: &str,
        enabled: bool,
        mfa_enrolled: Option<bool>,
        privileged: bool,
    ) -> Self {
        Self {
            provider: "googleWorkspace",
            provider_id: id.to_string(),
            primary_email: email.to_string(),
            normalized_email: normalize_email(email),
            enabled,
            mfa_enrolled,
            mfa_capable: mfa_enrolled,
            privileged,
            last_sign_in_at: None,
        }
    }

    fn microsoft(
        id: &str,
        email: &str,
        enabled: bool,
        mfa_enrolled: Option<bool>,
        mfa_capable: Option<bool>,
        privileged: bool,
    ) -> Self {
        Self {
            provider: "microsoft365",
            provider_id: id.to_string(),
            primary_email: email.to_string(),
            normalized_email: normalize_email(email),
            enabled,
            mfa_enrolled,
            mfa_capable,
            privileged,
            last_sign_in_at: None,
        }
    }
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PostureAnalysisResult {
    pub identities: Vec<IdentityRecord>,
    pub findings: Vec<PostureFinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum CoverageStatus {
    Available,
    Unavailable,
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CoverageEntry {
    pub source: String,
    pub status: CoverageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub assurance: bool,
}

impl CoverageEntry {
    pub(super) fn available(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            status: CoverageStatus::Available,
            error_code: None,
            assurance: true,
        }
    }

    pub(super) fn unavailable(source: impl Into<String>, error_code: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            status: CoverageStatus::Unavailable,
            error_code: Some(error_code.into()),
            assurance: false,
        }
    }

    pub(super) fn disabled(source: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            status: CoverageStatus::Disabled,
            error_code: None,
            assurance: false,
        }
    }

    #[cfg(test)]
    fn is_assurance(&self) -> bool {
        self.assurance
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SecureScoreSnapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_date_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_user_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub licensed_user_count: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SecurityPostureReport {
    pub schema_version: &'static str,
    pub generated_at: String,
    pub coverage_complete: bool,
    pub coverage: Vec<CoverageEntry>,
    pub identity_count: usize,
    pub identity_posture: Vec<PostureFinding>,
    pub control_posture: Vec<PostureFinding>,
    pub cross_cloud_correlations: Vec<PostureFinding>,
    pub signal_findings: Vec<PostureFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub microsoft_secure_score: Option<SecureScoreSnapshot>,
}

fn secure_score_snapshot(values: &[Value]) -> Option<SecureScoreSnapshot> {
    let value = values.first()?;
    let current_score = value.get("currentScore").and_then(Value::as_f64);
    let max_score = value.get("maxScore").and_then(Value::as_f64);
    let percentage = match (current_score, max_score) {
        (Some(current), Some(maximum)) if maximum > 0.0 => {
            Some((current / maximum * 10_000.0).round() / 100.0)
        }
        _ => None,
    };
    Some(SecureScoreSnapshot {
        created_date_time: string_field(value, "createdDateTime").map(str::to_string),
        current_score,
        max_score,
        percentage,
        active_user_count: value.get("activeUserCount").and_then(Value::as_u64),
        licensed_user_count: value.get("licensedUserCount").and_then(Value::as_u64),
    })
}

fn graph_next_link(value: &Value) -> Option<String> {
    value
        .get("@odata.nextLink")
        .and_then(Value::as_str)
        .map(str::to_string)
}

async fn fetch_google_posture_request(
    client: &reqwest::Client,
    request: &ReadOnlyRequest,
    token: &str,
) -> Result<Vec<Value>, GwsError> {
    if request.method != reqwest::Method::GET {
        return Err(GwsError::Validation(
            "Security posture request rejected: only GET is allowed".to_string(),
        ));
    }
    let mut page_token: Option<String> = None;
    let mut items = Vec::new();
    for _ in 0..100 {
        let mut query = request.query.clone();
        if let Some(token) = &page_token {
            query.push(("pageToken".to_string(), token.clone()));
        }
        let response = client
            .get(&request.url)
            .query(&query)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|error| {
                GwsError::Other(anyhow::anyhow!(
                    "Google posture request failed for {}: {}",
                    request.source,
                    sanitize_for_terminal(&error.to_string())
                ))
            })?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let parsed_body = serde_json::from_str::<Value>(&body).unwrap_or(Value::Null);
            let error_code = bounded_provider_error_code(status, &parsed_body, "google_http");
            return Err(GwsError::Api {
                code: status.as_u16(),
                message: format!(
                    "Google posture source {} failed ({error_code})",
                    request.source
                ),
                reason: error_code,
                enable_url: None,
            });
        }
        let value = response.json::<Value>().await.map_err(|error| {
            GwsError::Other(anyhow::anyhow!(
                "Google posture response for {} was not valid JSON: {}",
                request.source,
                sanitize_for_terminal(&error.to_string())
            ))
        })?;
        items.extend(
            value
                .get(request.item_key)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
        page_token = value
            .get("nextPageToken")
            .and_then(Value::as_str)
            .map(str::to_string);
        if page_token.is_none() {
            return Ok(items);
        }
    }
    Err(GwsError::Validation(format!(
        "Google posture source {} exceeded the 100-page safety limit",
        request.source
    )))
}

async fn fetch_microsoft_graph_request(
    client: &reqwest::Client,
    request: &ReadOnlyRequest,
    token: &str,
) -> Result<Vec<Value>, String> {
    if request.method != reqwest::Method::GET {
        return Err("non_read_only_request_rejected".to_string());
    }
    let mut next_url = Some(request.url.clone());
    let mut first_page = true;
    let mut items = Vec::new();
    for _ in 0..100 {
        let Some(url) = next_url.take() else {
            return Ok(items);
        };
        let parsed = reqwest::Url::parse(&url).map_err(|_| "invalid_next_link".to_string())?;
        if parsed.scheme() != "https"
            || parsed.host_str() != Some("graph.microsoft.com")
            || !parsed.path().starts_with("/v1.0/")
        {
            return Err("unsafe_next_link_rejected".to_string());
        }
        let mut builder = client.get(parsed).bearer_auth(token);
        if first_page {
            builder = builder.query(&request.query);
            first_page = false;
        }
        let response = builder
            .send()
            .await
            .map_err(|_| "request_failed".to_string())?;
        let status = response.status();
        let value = response
            .json::<Value>()
            .await
            .map_err(|_| format!("http_{}_invalid_json", status.as_u16()))?;
        if !status.is_success() {
            return Err(bounded_provider_error_code(status, &value, "http"));
        }
        items.extend(
            value
                .get(request.item_key)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
        );
        next_url = graph_next_link(&value);
        if next_url.is_none() {
            return Ok(items);
        }
    }
    Err("page_limit_exceeded".to_string())
}

pub(super) async fn collect_security_posture(
    client: &reqwest::Client,
    google_token: &str,
    microsoft_token: Option<&str>,
    google_signals: &[GoogleSignalContext],
    now: DateTime<Utc>,
    inactive_days: i64,
    start_time: &str,
) -> Result<SecurityPostureReport, GwsError> {
    let mut coverage = Vec::new();
    let mut google_sections = BTreeMap::<String, Vec<Value>>::new();
    for request in google_posture_requests() {
        let values = fetch_google_posture_request(client, &request, google_token).await?;
        coverage.push(CoverageEntry::available(request.source.clone()));
        google_sections.insert(request.source, values);
    }
    let google_result = analyze_google_posture(
        google_sections
            .get("google.users")
            .map(Vec::as_slice)
            .unwrap_or_default(),
        google_sections
            .get("google.roles")
            .map(Vec::as_slice)
            .unwrap_or_default(),
        google_sections
            .get("google.roleAssignments")
            .map(Vec::as_slice)
            .unwrap_or_default(),
        now,
        inactive_days,
    );

    let mut microsoft_sections = BTreeMap::<String, Vec<Value>>::new();
    let microsoft_requests = microsoft_graph_requests(start_time);
    if let Some(token) = microsoft_token {
        for request in microsoft_requests {
            match fetch_microsoft_graph_request(client, &request, token).await {
                Ok(values) => {
                    coverage.push(CoverageEntry::available(request.source.clone()));
                    microsoft_sections.insert(request.source, values);
                }
                Err(code) => coverage.push(CoverageEntry::unavailable(request.source, code)),
            }
        }
    } else {
        coverage.extend(
            microsoft_requests
                .into_iter()
                .map(|request| CoverageEntry::disabled(request.source)),
        );
    }

    let microsoft_result = analyze_microsoft_posture(
        microsoft_sections
            .get("microsoft.users")
            .map(Vec::as_slice)
            .unwrap_or_default(),
        microsoft_sections
            .get("microsoft.authenticationMethods")
            .map(Vec::as_slice)
            .unwrap_or_default(),
        microsoft_sections
            .get("microsoft.roleAssignments")
            .map(Vec::as_slice)
            .unwrap_or_default(),
        microsoft_sections
            .get("microsoft.conditionalAccess")
            .map(Vec::as_slice)
            .unwrap_or_default(),
    );
    let mut cross_cloud_correlations =
        correlate_identities(&google_result.identities, &microsoft_result.identities);
    let signal_findings = analyze_microsoft_signals(
        microsoft_sections
            .get("microsoft.signIns")
            .map(Vec::as_slice)
            .unwrap_or_default(),
        microsoft_sections
            .get("microsoft.directoryAudits")
            .map(Vec::as_slice)
            .unwrap_or_default(),
        microsoft_sections
            .get("microsoft.defenderAlerts")
            .map(Vec::as_slice)
            .unwrap_or_default(),
        microsoft_sections
            .get("microsoft.defenderIncidents")
            .map(Vec::as_slice)
            .unwrap_or_default(),
    );
    cross_cloud_correlations.extend(correlate_cross_cloud_signals(
        google_signals,
        &signal_findings,
    ));
    cross_cloud_correlations.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    let microsoft_secure_score = microsoft_sections
        .get("microsoft.secureScore")
        .and_then(|values| secure_score_snapshot(values));
    let identity_count = google_result.identities.len() + microsoft_result.identities.len();
    let mut identity_posture = google_result.findings;
    let (mut control_posture, microsoft_identity_posture): (Vec<_>, Vec<_>) = microsoft_result
        .findings
        .into_iter()
        .partition(|finding| finding.control_id.starts_with("MSFT.CA."));
    identity_posture.extend(microsoft_identity_posture);
    identity_posture.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    control_posture.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    let coverage_complete = coverage
        .iter()
        .all(|entry| entry.status != CoverageStatus::Unavailable);

    Ok(SecurityPostureReport {
        schema_version: "security_intelligence_v1",
        generated_at: now.to_rfc3339(),
        coverage_complete,
        coverage,
        identity_count,
        identity_posture,
        control_posture,
        cross_cloud_correlations,
        signal_findings,
        microsoft_secure_score,
    })
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn normalized_email_for_correlation(email: &str) -> Option<String> {
    let normalized = normalize_email(email);
    let (local_part, domain) = normalized.split_once('@')?;
    (!local_part.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && !normalized
            .chars()
            .any(|character| character.is_whitespace() || character.is_control()))
    .then_some(normalized)
}

fn string_field<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn bool_field(value: &Value, name: &str) -> Option<bool> {
    value.get(name).and_then(Value::as_bool)
}

fn finding_id(control_id: &str, provider: &str, subject: &str) -> String {
    format!("{control_id}:{provider}:{}", normalize_email(subject))
}

// Keeping construction in one place ensures every actionable finding carries
// the same identity, verdict, evidence, and analysis contract.
#[allow(clippy::too_many_arguments)]
fn finding(
    control_id: &'static str,
    provider: &'static str,
    severity: PostureSeverity,
    subject: &str,
    title: impl Into<String>,
    summary: impl Into<String>,
    evidence: BTreeMap<String, String>,
    analysis: HumanAnalysis,
) -> PostureFinding {
    PostureFinding {
        finding_id: finding_id(control_id, provider, subject),
        control_id,
        provider,
        severity,
        contextual_verdict: ContextualVerdict::Alert,
        title: title.into(),
        subject: subject.to_string(),
        summary: summary.into(),
        evidence,
        analysis,
    }
}

pub(super) fn analyze_google_posture(
    users: &[Value],
    roles: &[Value],
    assignments: &[Value],
    now: DateTime<Utc>,
    inactive_days: i64,
) -> PostureAnalysisResult {
    let role_names = roles
        .iter()
        .filter_map(|role| {
            Some((
                string_field(role, "roleId")?.to_string(),
                string_field(role, "roleName")
                    .unwrap_or("administrator role")
                    .to_string(),
            ))
        })
        .collect::<HashMap<_, _>>();
    let privileged_users = assignments
        .iter()
        .filter_map(|assignment| {
            let user = string_field(assignment, "assignedTo")?;
            let role_id = string_field(assignment, "roleId")?;
            role_names.contains_key(role_id).then(|| user.to_string())
        })
        .collect::<HashSet<_>>();

    let mut result = PostureAnalysisResult::default();
    for user in users {
        let Some(id) = string_field(user, "id") else {
            continue;
        };
        let Some(email) = string_field(user, "primaryEmail") else {
            continue;
        };
        let enabled = !bool_field(user, "suspended").unwrap_or(false)
            && !bool_field(user, "archived").unwrap_or(false);
        let enrolled = bool_field(user, "isEnrolledIn2Sv");
        let enforced = bool_field(user, "isEnforcedIn2Sv");
        let privileged = privileged_users.contains(id);
        let last_sign_in_at = string_field(user, "lastLoginTime").map(str::to_string);
        let mut identity = IdentityRecord::google(id, email, enabled, enrolled, privileged);
        identity.last_sign_in_at = last_sign_in_at.clone();
        result.identities.push(identity);

        if enabled && enrolled == Some(false) {
            let (control_id, severity, title, action, urgency) = if privileged {
                (
                    "GOOGLE.IDENTITY.ADMIN_WITHOUT_2SV",
                    PostureSeverity::Critical,
                    "Administrador activo sin 2-Step Verification",
                    "Confirmar hoy la identidad y función del administrador; exigir enrolamiento y enforcement de 2SV mediante una decisión humana antes de mantener el privilegio.",
                    Urgency::Immediate,
                )
            } else {
                (
                    "GOOGLE.IDENTITY.USER_WITHOUT_2SV",
                    PostureSeverity::High,
                    "Usuario activo sin 2-Step Verification",
                    "Validar si la cuenta requiere acceso interactivo y completar el enrolamiento de 2SV; si existe una excepción, documentar propietario, motivo y vencimiento.",
                    Urgency::Today,
                )
            };
            let mut evidence = BTreeMap::from([
                ("isEnrolledIn2Sv".to_string(), "false".to_string()),
                (
                    "isEnforcedIn2Sv".to_string(),
                    enforced.unwrap_or(false).to_string(),
                ),
                ("privileged".to_string(), privileged.to_string()),
            ]);
            if let Some(last_login) = &last_sign_in_at {
                evidence.insert("lastLoginTime".to_string(), last_login.clone());
            }
            result.findings.push(finding(
                control_id,
                "googleWorkspace",
                severity,
                email,
                title,
                "La cuenta está habilitada y Google informa que no está enrolada en 2SV; una contraseña comprometida podría bastar para acceder.",
                evidence,
                HumanAnalysis {
                    conclusion: format!("Google Workspace informa una cuenta {} activa sin enrolamiento en 2SV.", if privileged { "administrativa" } else { "de usuario" }),
                    escalation_reason: if privileged { "La cuenta conserva privilegios administrativos y carece de un segundo factor registrado." } else { "La cuenta puede iniciar sesión y carece de un segundo factor registrado." }.to_string(),
                    plausible_impact: "Un acceso no autorizado podría afectar correo, Drive y otros datos permitidos a la cuenta; el alcance exacto depende de sus permisos efectivos.".to_string(),
                    evidence_for: vec!["Estado de cuenta habilitado.".to_string(), "isEnrolledIn2Sv=false informado por Directory API.".to_string()],
                    counter_evidence: enforced.filter(|value| *value).map(|_| vec!["La política informa enforcement de 2SV, aunque la cuenta aún no figura enrolada.".to_string()]).unwrap_or_default(),
                    uncertainty: "No se validó con el usuario si la cuenta es interactiva ni si existe una excepción temporal aprobada.".to_string(),
                    recommended_action: action.to_string(),
                    urgency,
                    confidence: Confidence::High,
                },
            ));
        }

        if enabled {
            if let Some(last_login) = last_sign_in_at
                .as_deref()
                .and_then(|timestamp| DateTime::parse_from_rfc3339(timestamp).ok())
                .map(|timestamp| timestamp.with_timezone(&Utc))
            {
                if now - last_login >= Duration::days(inactive_days) {
                    let days = (now - last_login).num_days();
                    result.findings.push(finding(
                        "GOOGLE.IDENTITY.STALE_ACTIVE_ACCOUNT",
                        "googleWorkspace",
                        PostureSeverity::High,
                        email,
                        "Cuenta activa sin uso reciente",
                        format!("La cuenta sigue habilitada y no registra inicio de sesión desde hace {days} días."),
                        BTreeMap::from([
                            ("lastLoginTime".to_string(), last_login.to_rfc3339()),
                            ("inactiveDays".to_string(), days.to_string()),
                        ]),
                        HumanAnalysis {
                            conclusion: format!("Cuenta de Google habilitada sin inicios de sesión observados durante {days} días."),
                            escalation_reason: format!("La inactividad supera el umbral configurado de {inactive_days} días mientras el acceso permanece habilitado."),
                            plausible_impact: "Una cuenta abandonada podría conservar acceso innecesario y tener menor probabilidad de que su uso indebido sea advertido por el titular.".to_string(),
                            evidence_for: vec![format!("lastLoginTime está {days} días detrás de la fecha del reporte."), "La cuenta no está suspendida ni archivada.".to_string()],
                            counter_evidence: Vec::new(),
                            uncertainty: "La telemetría no demuestra que la persona haya dejado la organización ni que la cuenta carezca de un uso no interactivo autorizado.".to_string(),
                            recommended_action: "Confirmar propietario, relación laboral y necesidad vigente; cerrar si existe una justificación documentada o escalar una decisión humana de suspensión si la cuenta ya no es necesaria.".to_string(),
                            urgency: Urgency::Review,
                            confidence: Confidence::Medium,
                        },
                    ));
                }
            }
        }
    }
    result
}

pub(super) fn analyze_microsoft_posture(
    users: &[Value],
    registrations: &[Value],
    assignments: &[Value],
    policies: &[Value],
) -> PostureAnalysisResult {
    let registrations_by_id = registrations
        .iter()
        .filter_map(|registration| string_field(registration, "id").map(|id| (id, registration)))
        .collect::<HashMap<_, _>>();
    let privileged_ids = assignments
        .iter()
        .filter_map(|assignment| string_field(assignment, "principalId").map(str::to_string))
        .collect::<HashSet<_>>();
    let user_by_id = users
        .iter()
        .filter_map(|user| string_field(user, "id").map(|id| (id, user)))
        .collect::<HashMap<_, _>>();
    let mut result = PostureAnalysisResult::default();

    for user in users {
        let Some(id) = string_field(user, "id") else {
            continue;
        };
        let Some(email) =
            string_field(user, "userPrincipalName").or_else(|| string_field(user, "mail"))
        else {
            continue;
        };
        let enabled = bool_field(user, "accountEnabled").unwrap_or(false);
        let registration = registrations_by_id.get(id).copied();
        let enrolled = registration.and_then(|value| bool_field(value, "isMfaRegistered"));
        let capable = registration.and_then(|value| bool_field(value, "isMfaCapable"));
        let privileged = privileged_ids.contains(id);
        result.identities.push(IdentityRecord::microsoft(
            id, email, enabled, enrolled, capable, privileged,
        ));

        let mfa_gap = if privileged {
            if capable == Some(false) {
                Some((
                    "MSFT.IDENTITY.ADMIN_NOT_MFA_CAPABLE",
                    PostureSeverity::Critical,
                    "Administrador de Microsoft 365 sin capacidad MFA",
                    "La cuenta privilegiada no figura como capaz de realizar MFA según userRegistrationDetails.",
                    "Microsoft informa una cuenta privilegiada habilitada sin capacidad MFA.",
                    "La cuenta tiene una asignación de rol y no es MFA-capable según el reporte de métodos de autenticación.",
                    Urgency::Immediate,
                ))
            } else if enrolled == Some(false) {
                Some((
                    "MSFT.IDENTITY.ADMIN_NOT_MFA_REGISTERED",
                    PostureSeverity::Critical,
                    "Administrador de Microsoft 365 sin MFA registrado",
                    "La cuenta privilegiada está habilitada y no tiene MFA registrado, aunque Microsoft la informa como MFA-capable.",
                    "Microsoft 365 informa una cuenta privilegiada habilitada sin MFA registrado.",
                    "La cuenta conserva una asignación de rol y todavía no registra un método MFA.",
                    Urgency::Immediate,
                ))
            } else {
                None
            }
        } else if enrolled == Some(false) {
            Some((
                "MSFT.IDENTITY.USER_NOT_MFA_REGISTERED",
                PostureSeverity::High,
                "Usuario de Microsoft 365 sin MFA registrado",
                "Microsoft informa que la cuenta habilitada no tiene MFA registrado; la protección efectiva puede depender de Conditional Access y otros controles no sustituyen el registro del factor.",
                "Microsoft 365 informa una cuenta de usuario habilitada sin MFA registrado.",
                "La cuenta está habilitada y no registra un método MFA.",
                Urgency::Today,
            ))
        } else {
            None
        };

        if enabled {
            let Some((
                control_id,
                severity,
                title,
                summary,
                conclusion,
                escalation_reason,
                urgency,
            )) = mfa_gap
            else {
                continue;
            };
            let mut evidence = BTreeMap::from([
                (
                    "isMfaRegistered".to_string(),
                    enrolled
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                ),
                ("privileged".to_string(), privileged.to_string()),
            ]);
            if let Some(value) = capable {
                evidence.insert("isMfaCapable".to_string(), value.to_string());
            }
            let mut evidence_for = vec!["accountEnabled=true.".to_string()];
            if let Some(value) = enrolled {
                evidence_for.push(format!(
                    "isMfaRegistered={value} en userRegistrationDetails."
                ));
            }
            if let Some(value) = capable {
                evidence_for.push(format!("isMfaCapable={value} en userRegistrationDetails."));
            }
            result.findings.push(finding(
                control_id,
                "microsoft365",
                severity,
                email,
                title,
                summary,
                evidence,
                HumanAnalysis {
                    conclusion: conclusion.to_string(),
                    escalation_reason: escalation_reason.to_string(),
                    plausible_impact: "Una credencial comprometida podría permitir acceso a recursos de Microsoft 365 según las políticas efectivamente aplicadas a la cuenta.".to_string(),
                    evidence_for,
                    counter_evidence: Vec::new(),
                    uncertainty: "No se ejecutó Conditional Access What If ni se confirmó una excepción aprobada para esta identidad.".to_string(),
                    recommended_action: "Validar el propósito y privilegio de la cuenta, comprobar la política de Conditional Access aplicable y completar MFA; si no se reconoce o el privilegio es innecesario, escalar una decisión humana de contención o retiro del rol.".to_string(),
                    urgency,
                    confidence: if registration.is_some() { Confidence::High } else { Confidence::Low },
                },
            ));
        }
    }

    let enabled_mfa_policies = policies
        .iter()
        .filter(|policy| string_field(policy, "state") == Some("enabled"))
        .filter(|policy| {
            let has_mfa_control = policy
                .pointer("/grantControls/builtInControls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|control| control.as_str() == Some("mfa"));
            let has_authentication_strength = policy
                .pointer("/grantControls/authenticationStrength/id")
                .and_then(Value::as_str)
                .is_some_and(|id| !id.is_empty());
            has_mfa_control || has_authentication_strength
        })
        .collect::<Vec<_>>();

    if !policies.is_empty() && enabled_mfa_policies.is_empty() {
        result.findings.push(finding(
            "MSFT.CA.NO_ENABLED_MFA_POLICY",
            "microsoft365",
            PostureSeverity::Critical,
            "tenant",
            "No se observó una política MFA habilitada",
            "La colección devolvió políticas de Conditional Access, pero ninguna habilitada exige el control MFA.",
            BTreeMap::from([("policiesObserved".to_string(), policies.len().to_string())]),
            HumanAnalysis {
                conclusion: "No se observó una política habilitada de Conditional Access que exija MFA.".to_string(),
                escalation_reason: "Existen políticas legibles, pero ninguna combina state=enabled con el grant control mfa.".to_string(),
                plausible_impact: "Las identidades podrían depender de controles menos fuertes o de configuraciones externas a Conditional Access; no se demuestra que todas estén desprotegidas.".to_string(),
                evidence_for: vec![format!("Se analizaron {} políticas de Conditional Access.", policies.len())],
                counter_evidence: Vec::new(),
                uncertainty: "No se evaluó What If por usuario ni Authentication Strength, por lo que puede existir una política equivalente que requiera análisis adicional.".to_string(),
                recommended_action: "Validar en Conditional Access qué política protege usuarios y administradores, ejecutar What If sobre identidades representativas y documentar la cobertura; escalar un cambio sólo si se confirma el gap.".to_string(),
                urgency: Urgency::Immediate,
                confidence: Confidence::Medium,
            },
        ));
    }

    for policy in enabled_mfa_policies {
        let policy_id = string_field(policy, "id").unwrap_or("unknown-policy");
        let policy_name =
            string_field(policy, "displayName").unwrap_or("Conditional Access policy");
        let excluded = policy
            .pointer("/conditions/users/excludeUsers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str);
        for user_id in excluded {
            let Some(user) = user_by_id.get(user_id) else {
                continue;
            };
            if bool_field(user, "accountEnabled") != Some(true) {
                continue;
            }
            let email = string_field(user, "userPrincipalName")
                .or_else(|| string_field(user, "mail"))
                .unwrap_or(user_id);
            result.findings.push(finding(
                "MSFT.CA.USER_EXCLUDED_FROM_MFA",
                "microsoft365",
                PostureSeverity::High,
                email,
                "Usuario activo excluido de política MFA",
                format!("La política habilitada '{policy_name}' exige MFA pero excluye explícitamente a esta cuenta."),
                BTreeMap::from([
                    ("policyId".to_string(), policy_id.to_string()),
                    ("policyName".to_string(), policy_name.to_string()),
                    ("accountEnabled".to_string(), "true".to_string()),
                ]),
                HumanAnalysis {
                    conclusion: format!("Una cuenta activa está excluida de la política MFA habilitada '{policy_name}'."),
                    escalation_reason: "La exclusión explícita evita que esta política exija MFA a la identidad.".to_string(),
                    plausible_impact: "La cuenta podría autenticarse sin el nivel de protección esperado si ninguna otra política aplicable compensa la exclusión.".to_string(),
                    evidence_for: vec!["La cuenta está habilitada.".to_string(), format!("Su ID aparece en excludeUsers de la política {policy_id}." )],
                    counter_evidence: Vec::new(),
                    uncertainty: "No se ejecutó What If y otra política podría exigir MFA; la exclusión no demuestra por sí sola un bypass efectivo.".to_string(),
                    recommended_action: "Ejecutar Conditional Access What If para esta identidad y aplicación objetivo, validar propietario y vencimiento de la excepción, y retirar o acotar la exclusión sólo mediante una decisión humana si no está justificada.".to_string(),
                    urgency: Urgency::Today,
                    confidence: Confidence::Medium,
                },
            ));
        }
    }
    result
}

pub(super) fn correlate_identities(
    google: &[IdentityRecord],
    microsoft: &[IdentityRecord],
) -> Vec<PostureFinding> {
    let microsoft_by_email = microsoft
        .iter()
        .filter_map(|identity| {
            normalized_email_for_correlation(&identity.primary_email).map(|email| (email, identity))
        })
        .collect::<HashMap<_, _>>();
    let mut findings = Vec::new();
    for google_identity in google {
        let Some(normalized_email) =
            normalized_email_for_correlation(&google_identity.primary_email)
        else {
            continue;
        };
        let Some(microsoft_identity) = microsoft_by_email.get(&normalized_email) else {
            continue;
        };
        if google_identity.enabled != microsoft_identity.enabled {
            let subject = &normalized_email;
            findings.push(finding(
                "CROSS.IDENTITY.ACTIVE_STATE_MISMATCH",
                "crossCloud",
                PostureSeverity::High,
                subject,
                "Estado de cuenta inconsistente entre nubes",
                format!("La misma identidad está {} en Google Workspace y {} en Microsoft 365.", if google_identity.enabled { "habilitada" } else { "deshabilitada" }, if microsoft_identity.enabled { "habilitada" } else { "deshabilitada" }),
                BTreeMap::from([
                    ("googleEnabled".to_string(), google_identity.enabled.to_string()),
                    ("microsoftEnabled".to_string(), microsoft_identity.enabled.to_string()),
                ]),
                HumanAnalysis {
                    conclusion: "La identidad correlacionada por email tiene estados activos diferentes entre Google Workspace y Microsoft 365.".to_string(),
                    escalation_reason: "Un sistema mantiene acceso habilitado mientras el otro lo informa deshabilitado.".to_string(),
                    plausible_impact: "Un proceso de baja o suspensión incompleto podría dejar acceso residual en una de las plataformas.".to_string(),
                    evidence_for: vec![format!("Google enabled={}.", google_identity.enabled), format!("Microsoft enabled={}.", microsoft_identity.enabled)],
                    counter_evidence: Vec::new(),
                    uncertainty: "La correlación usa el email normalizado; debe confirmarse el sistema de identidad autoritativo y que ambas cuentas representen a la misma persona.".to_string(),
                    recommended_action: "Confirmar identidad y estado esperado en el sistema autoritativo de RR.HH./IAM; si la baja o suspensión es válida, escalar la deshabilitación humana de la cuenta residual, y si no, corregir el sistema que quedó desactualizado.".to_string(),
                    urgency: Urgency::Today,
                    confidence: Confidence::Medium,
                },
            ));
        }

        let privilege_present = google_identity.privileged || microsoft_identity.privileged;
        let protection_gap = google_identity.mfa_enrolled == Some(false)
            || microsoft_identity.mfa_capable == Some(false);
        if privilege_present && protection_gap {
            let subject = &normalized_email;
            findings.push(finding(
                "CROSS.IDENTITY.PRIVILEGE_PROTECTION_GAP",
                "crossCloud",
                PostureSeverity::Critical,
                subject,
                "Identidad privilegiada con protección desigual",
                "La identidad tiene privilegios en al menos una nube y una señal explícita de MFA ausente o no-capable en otra.",
                BTreeMap::from([
                    ("googlePrivileged".to_string(), google_identity.privileged.to_string()),
                    ("googleMfaEnrolled".to_string(), google_identity.mfa_enrolled.map(|value| value.to_string()).unwrap_or_else(|| "unknown".to_string())),
                    ("microsoftPrivileged".to_string(), microsoft_identity.privileged.to_string()),
                    ("microsoftMfaCapable".to_string(), microsoft_identity.mfa_capable.map(|value| value.to_string()).unwrap_or_else(|| "unknown".to_string())),
                ]),
                HumanAnalysis {
                    conclusion: "Una identidad correlacionada conserva privilegios y presenta una brecha explícita de MFA entre plataformas.".to_string(),
                    escalation_reason: "El privilegio amplifica el impacto potencial y al menos un proveedor informa protección MFA ausente o no-capable.".to_string(),
                    plausible_impact: "El uso indebido de la identidad podría alcanzar funciones administrativas o datos sensibles según sus roles efectivos.".to_string(),
                    evidence_for: vec!["Existe una asignación privilegiada en al menos una plataforma.".to_string(), "Un estado MFA explícito es false.".to_string()],
                    counter_evidence: Vec::new(),
                    uncertainty: "No se verificó la política efectiva por sesión ni si ambos privilegios son permanentes o elegibles mediante PIM.".to_string(),
                    recommended_action: "Validar roles efectivos y métodos MFA en ambas plataformas, retirar privilegios innecesarios y completar protección fuerte mediante decisiones humanas; escalar contención si la identidad o el acceso no son reconocidos.".to_string(),
                    urgency: Urgency::Immediate,
                    confidence: Confidence::High,
                },
            ));
        }
    }
    findings
}

pub(super) fn analyze_microsoft_signals(
    sign_ins: &[Value],
    directory_audits: &[Value],
    defender_alerts: &[Value],
    defender_incidents: &[Value],
) -> Vec<PostureFinding> {
    let mut findings = Vec::new();

    for sign_in in sign_ins {
        let risk_level = string_field(sign_in, "riskLevelDuringSignIn").unwrap_or("unknown");
        let risk_state = string_field(sign_in, "riskState").unwrap_or("unknown");
        let is_risky = matches!(risk_level, "high" | "medium")
            || matches!(risk_state, "atRisk" | "confirmedCompromised");
        if !is_risky {
            continue;
        }
        let id = string_field(sign_in, "id").unwrap_or("unknown-sign-in");
        let subject = string_field(sign_in, "userPrincipalName").unwrap_or(id);
        let app = string_field(sign_in, "appDisplayName").unwrap_or("Microsoft 365 application");
        let conditional_access =
            string_field(sign_in, "conditionalAccessStatus").unwrap_or("unknown");
        let time = string_field(sign_in, "createdDateTime").unwrap_or("unknown");
        let severity = if risk_level == "high" || risk_state == "confirmedCompromised" {
            PostureSeverity::Critical
        } else {
            PostureSeverity::High
        };
        let urgency = if severity == PostureSeverity::Critical {
            Urgency::Immediate
        } else {
            Urgency::Today
        };
        findings.push(finding(
            "MSFT.SIGNAL.RISKY_SIGN_IN",
            "microsoft365",
            severity,
            subject,
            "Inicio de sesión con riesgo en Microsoft 365",
            format!("Microsoft calificó el inicio de sesión hacia {app} con riesgo {risk_level}, estado {risk_state} y Conditional Access {conditional_access}."),
            BTreeMap::from([
                ("signInId".to_string(), id.to_string()),
                ("createdDateTime".to_string(), time.to_string()),
                ("appDisplayName".to_string(), app.to_string()),
                ("riskLevelDuringSignIn".to_string(), risk_level.to_string()),
                ("riskState".to_string(), risk_state.to_string()),
                ("conditionalAccessStatus".to_string(), conditional_access.to_string()),
            ]),
            HumanAnalysis {
                conclusion: format!("Microsoft Entra registró un inicio de sesión de riesgo {risk_level} para una cuenta de la organización."),
                escalation_reason: format!("La evaluación de riesgo es {risk_level} y el estado es {risk_state}; no se reduce por ubicación o red."),
                plausible_impact: "Si el acceso fue exitoso y no reconocido, la sesión podría permitir acciones sobre recursos de Microsoft 365 autorizados a la cuenta.".to_string(),
                evidence_for: vec![format!("Evento {id} a las {time}."), format!("Aplicación {app}; Conditional Access={conditional_access}." )],
                counter_evidence: if conditional_access == "failure" { vec!["Conditional Access informó failure, lo que puede indicar bloqueo; debe confirmarse el resultado efectivo del acceso.".to_string()] } else { Vec::new() },
                uncertainty: "La señal no confirma por sí sola compromiso, éxito de la sesión ni reconocimiento del acceso por el usuario.".to_string(),
                recommended_action: "Validar con el usuario el acceso y el método de desafío, confirmar el resultado de la sesión y revisar sign-ins, tokens y cambios administrativos correlacionados; escalar contención humana sólo si el acceso no se reconoce o hubo sesión efectiva.".to_string(),
                urgency,
                confidence: Confidence::Medium,
            },
        ));
    }

    for audit in directory_audits {
        let category = string_field(audit, "category").unwrap_or("unknown");
        if !matches!(
            category,
            "RoleManagement" | "Policy" | "ApplicationManagement" | "UserManagement"
        ) {
            continue;
        }
        let result = string_field(audit, "result").unwrap_or("unknown");
        if result != "success" {
            continue;
        }
        let id = string_field(audit, "id").unwrap_or("unknown-directory-audit");
        let activity = string_field(audit, "activityDisplayName").unwrap_or("directory change");
        let time = string_field(audit, "activityDateTime").unwrap_or("unknown");
        let critical = matches!(category, "RoleManagement" | "Policy");
        findings.push(finding(
            "MSFT.SIGNAL.DIRECTORY_CHANGE",
            "microsoft365",
            if critical { PostureSeverity::Critical } else { PostureSeverity::High },
            id,
            "Cambio sensible en Microsoft Entra",
            format!("Microsoft registró el cambio exitoso '{activity}' en la categoría {category}."),
            BTreeMap::from([
                ("auditId".to_string(), id.to_string()),
                ("activityDateTime".to_string(), time.to_string()),
                ("activityDisplayName".to_string(), activity.to_string()),
                ("category".to_string(), category.to_string()),
                ("result".to_string(), result.to_string()),
            ]),
            HumanAnalysis {
                conclusion: format!("Se ejecutó con éxito un cambio de directorio de tipo {category}: {activity}."),
                escalation_reason: "El cambio afecta privilegios, políticas, aplicaciones o identidades y requiere atribución a una operación autorizada.".to_string(),
                plausible_impact: "Un cambio no autorizado podría ampliar acceso, debilitar políticas o modificar el control de una identidad o aplicación.".to_string(),
                evidence_for: vec![format!("Directory audit {id} a las {time} con result=success.")],
                counter_evidence: Vec::new(),
                uncertainty: "Esta vista no confirma el ticket, motivo de negocio ni autorización humana del cambio.".to_string(),
                recommended_action: "Validar el iniciador, cambio exacto, ventana y ticket o motivo de negocio en Entra audit logs; escalar inmediatamente una decisión humana de contención si no está autorizado.".to_string(),
                urgency: if critical { Urgency::Immediate } else { Urgency::Today },
                confidence: Confidence::High,
            },
        ));
    }

    for alert in defender_alerts {
        let severity_text = string_field(alert, "severity").unwrap_or("unknown");
        let severity = match severity_text {
            "critical" => PostureSeverity::Critical,
            "high" => PostureSeverity::High,
            _ => continue,
        };
        let id = string_field(alert, "id").unwrap_or("unknown-defender-alert");
        let title = string_field(alert, "title").unwrap_or("Defender alert");
        let source = string_field(alert, "serviceSource").unwrap_or("Microsoft Defender");
        let status = string_field(alert, "status").unwrap_or("unknown");
        let time = string_field(alert, "createdDateTime").unwrap_or("unknown");
        findings.push(finding(
            "MSFT.DEFENDER.HIGH_SEVERITY_ALERT",
            "microsoft365",
            severity,
            id,
            "Alerta de alta severidad en Microsoft Defender",
            format!("{source} emitió la alerta '{title}' con severidad {severity_text} y estado {status}."),
            BTreeMap::from([
                ("alertId".to_string(), id.to_string()),
                ("createdDateTime".to_string(), time.to_string()),
                ("title".to_string(), title.to_string()),
                ("severity".to_string(), severity_text.to_string()),
                ("status".to_string(), status.to_string()),
                ("serviceSource".to_string(), source.to_string()),
            ]),
            HumanAnalysis {
                conclusion: format!("Microsoft Defender emitió una alerta {severity_text}: {title}."),
                escalation_reason: "La severidad del proveedor alcanza el piso de escalamiento y la alerta todavía requiere validación humana.".to_string(),
                plausible_impact: "El activo o identidad asociado podría estar afectado según la evidencia detallada disponible en Defender; esta colección no demuestra compromiso por sí sola.".to_string(),
                evidence_for: vec![format!("Alerta {id} creada a las {time}, estado {status}, fuente {source}." )],
                counter_evidence: Vec::new(),
                uncertainty: "No se copiaron entidades, contenido ni evidencia sensible de Defender; el analista debe abrir la alerta para determinar alcance y validez.".to_string(),
                recommended_action: "Abrir la alerta en Microsoft Defender, validar entidades, evidencia y línea de tiempo, correlacionar con Entra sign-ins y cambios; cerrar sólo si existe una explicación verificable o escalar contención humana si se confirma actividad no autorizada.".to_string(),
                urgency: if severity == PostureSeverity::Critical { Urgency::Immediate } else { Urgency::Today },
                confidence: Confidence::Medium,
            },
        ));
    }

    for incident in defender_incidents {
        let severity_text = string_field(incident, "severity").unwrap_or("unknown");
        let severity = match severity_text {
            "critical" => PostureSeverity::Critical,
            "high" => PostureSeverity::High,
            _ => continue,
        };
        let id = string_field(incident, "id").unwrap_or("unknown-defender-incident");
        let title = string_field(incident, "displayName").unwrap_or("Defender incident");
        let status = string_field(incident, "status").unwrap_or("unknown");
        let time = string_field(incident, "createdDateTime").unwrap_or("unknown");
        findings.push(finding(
            "MSFT.DEFENDER.HIGH_SEVERITY_INCIDENT",
            "microsoft365",
            severity,
            id,
            "Incidente de alta severidad en Microsoft Defender",
            format!("Microsoft Defender agrupó el incidente '{title}' con severidad {severity_text} y estado {status}."),
            BTreeMap::from([
                ("incidentId".to_string(), id.to_string()),
                ("createdDateTime".to_string(), time.to_string()),
                ("displayName".to_string(), title.to_string()),
                ("severity".to_string(), severity_text.to_string()),
                ("status".to_string(), status.to_string()),
            ]),
            HumanAnalysis {
                conclusion: format!("Microsoft Defender informa un incidente {severity_text}: {title}."),
                escalation_reason: "El incidente agrupa señales de alta severidad y exige revisar alcance y entidades relacionadas.".to_string(),
                plausible_impact: "Podría existir actividad coordinada sobre identidades, correo, endpoints o aplicaciones; el impacto debe confirmarse en Defender.".to_string(),
                evidence_for: vec![format!("Incidente {id} creado a las {time}, estado {status}." )],
                counter_evidence: Vec::new(),
                uncertainty: "El resumen no contiene las alertas y entidades del incidente, por lo que no permite confirmar compromiso o impacto.".to_string(),
                recommended_action: "Abrir el incidente en Microsoft Defender, priorizar alertas y entidades, correlacionar la línea de tiempo con Entra y decidir contención humana según evidencia confirmada.".to_string(),
                urgency: if severity == PostureSeverity::Critical { Urgency::Immediate } else { Urgency::Today },
                confidence: Confidence::Medium,
            },
        ));
    }

    findings
}

pub(super) fn correlate_cross_cloud_signals(
    google_signals: &[GoogleSignalContext],
    microsoft_signals: &[PostureFinding],
) -> Vec<PostureFinding> {
    let risky_google_rules = HashSet::from([
        "google_suspicious_login",
        "suspicious_session_cookie",
        "password_leak",
        "account_hijacked",
        "suspicious_successful_login",
    ]);
    let mut findings = Vec::new();
    for google in google_signals
        .iter()
        .filter(|signal| risky_google_rules.contains(signal.rule.as_str()))
    {
        let Some(normalized_actor) = normalized_email_for_correlation(&google.actor) else {
            continue;
        };
        for microsoft in microsoft_signals.iter().filter(|signal| {
            signal.control_id == "MSFT.SIGNAL.RISKY_SIGN_IN"
                && normalized_email_for_correlation(&signal.subject).as_deref()
                    == Some(normalized_actor.as_str())
        }) {
            let microsoft_id = microsoft
                .evidence
                .get("signInId")
                .map(String::as_str)
                .unwrap_or("unknown");
            findings.push(finding(
                "CROSS.SIGNAL.MULTITENANT_SUSPICIOUS_LOGIN",
                "crossCloud",
                PostureSeverity::Critical,
                &normalized_actor,
                "Señales de acceso riesgoso en ambas nubes",
                "Google Workspace y Microsoft Entra produjeron señales de acceso riesgoso para la misma identidad dentro de la ventana observada.",
                BTreeMap::from([
                    ("googleEventId".to_string(), google.event_id.clone()),
                    ("googleRule".to_string(), google.rule.clone()),
                    ("microsoftSignInId".to_string(), microsoft_id.to_string()),
                ]),
                HumanAnalysis {
                    conclusion: "La misma identidad presenta una señal de acceso sospechoso en Google Workspace y otra de riesgo en Microsoft Entra dentro de la ventana.".to_string(),
                    escalation_reason: "La coincidencia exacta por email entre dos proveedores independientes eleva la probabilidad de un problema de identidad que atraviesa plataformas.".to_string(),
                    plausible_impact: "Si alguno de los accesos fue exitoso y no reconocido, podrían estar en riesgo los recursos autorizados a la cuenta en ambas nubes.".to_string(),
                    evidence_for: vec![
                        format!("Google: regla {} en evento {}{}.", google.rule, google.event_id, google.event_time.as_deref().map(|time| format!(" a las {time}")).unwrap_or_default()),
                        format!("Microsoft: risky sign-in {microsoft_id}."),
                    ],
                    counter_evidence: Vec::new(),
                    uncertainty: "La correlación no confirma que ambos accesos hayan sido exitosos, provengan del mismo dispositivo o sean desconocidos para el usuario.".to_string(),
                    recommended_action: "Contactar al usuario por un canal confiable, validar ambos accesos y desafíos, revisar sesiones/tokens y cambios correlacionados en Google y Entra, y escalar una decisión humana de contención si alguno no se reconoce.".to_string(),
                    urgency: Urgency::Immediate,
                    confidence: Confidence::High,
                },
            ));
        }
    }
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    findings.dedup_by(|left, right| left.finding_id == right.finding_id);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    #[test]
    fn google_admin_without_2sv_is_an_actionable_finding() {
        let users = json!([{
            "id": "google-1",
            "primaryEmail": "Admin@Example.com",
            "suspended": false,
            "isEnrolledIn2Sv": false,
            "isEnforcedIn2Sv": false,
            "lastLoginTime": "2026-07-31T12:00:00Z"
        }]);
        let roles =
            json!([{"roleId": "role-1", "roleName": "Super Admin", "isSuperAdminRole": true}]);
        let assignments = json!([{"roleAssignmentId": "assignment-1", "roleId": "role-1", "assignedTo": "google-1"}]);

        let result = analyze_google_posture(
            users.as_array().unwrap(),
            roles.as_array().unwrap(),
            assignments.as_array().unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 1, 12, 0, 0).unwrap(),
            90,
        );

        let finding = result
            .findings
            .iter()
            .find(|finding| finding.control_id == "GOOGLE.IDENTITY.ADMIN_WITHOUT_2SV")
            .expect("admin without 2SV must be actionable");
        assert_eq!(finding.severity, PostureSeverity::Critical);
        assert_eq!(finding.contextual_verdict, ContextualVerdict::Alert);
        assert!(finding.analysis.is_complete());
        assert_eq!(result.identities[0].normalized_email, "admin@example.com");
    }

    #[test]
    fn microsoft_privileged_user_without_mfa_capability_is_actionable() {
        let users = json!([{
            "id": "ms-1",
            "userPrincipalName": "admin@example.com",
            "accountEnabled": true
        }]);
        let registrations = json!([{
            "id": "ms-1",
            "userPrincipalName": "admin@example.com",
            "isMfaRegistered": false,
            "isMfaCapable": false,
            "isPasswordlessCapable": false,
            "methodsRegistered": []
        }]);
        let assignments = json!([{
            "id": "assignment-1",
            "principalId": "ms-1",
            "roleDefinition": {"id": "role-1", "displayName": "Global Administrator"}
        }]);

        let result = analyze_microsoft_posture(
            users.as_array().unwrap(),
            registrations.as_array().unwrap(),
            assignments.as_array().unwrap(),
            &[],
        );

        let finding = result
            .findings
            .iter()
            .find(|finding| finding.control_id == "MSFT.IDENTITY.ADMIN_NOT_MFA_CAPABLE")
            .expect("privileged account without MFA capability must be actionable");
        assert_eq!(finding.severity, PostureSeverity::Critical);
        assert!(finding.analysis.recommended_action.contains("MFA"));
    }

    #[test]
    fn microsoft_privileged_user_without_mfa_capability_is_detected_when_registered() {
        let users = json!([{
            "id": "ms-capability-gap",
            "userPrincipalName": "capability-gap@example.com",
            "accountEnabled": true
        }]);
        let registrations = json!([{
            "id": "ms-capability-gap",
            "userPrincipalName": "capability-gap@example.com",
            "isMfaRegistered": true,
            "isMfaCapable": false
        }]);
        let assignments = json!([{
            "id": "assignment-capability-gap",
            "principalId": "ms-capability-gap"
        }]);

        let result = analyze_microsoft_posture(
            users.as_array().unwrap(),
            registrations.as_array().unwrap(),
            assignments.as_array().unwrap(),
            &[],
        );

        assert!(result
            .findings
            .iter()
            .any(|finding| finding.control_id == "MSFT.IDENTITY.ADMIN_NOT_MFA_CAPABLE"));
    }

    #[test]
    fn microsoft_privileged_user_without_registered_mfa_has_an_accurate_control() {
        let users = json!([{
            "id": "ms-registration-gap",
            "userPrincipalName": "registration-gap@example.com",
            "accountEnabled": true
        }]);
        let registrations = json!([{
            "id": "ms-registration-gap",
            "userPrincipalName": "registration-gap@example.com",
            "isMfaRegistered": false,
            "isMfaCapable": true
        }]);
        let assignments = json!([{
            "id": "assignment-registration-gap",
            "principalId": "ms-registration-gap"
        }]);

        let result = analyze_microsoft_posture(
            users.as_array().unwrap(),
            registrations.as_array().unwrap(),
            assignments.as_array().unwrap(),
            &[],
        );

        let finding = result
            .findings
            .iter()
            .find(|finding| finding.control_id == "MSFT.IDENTITY.ADMIN_NOT_MFA_REGISTERED")
            .expect("missing MFA registration needs an accurate privileged control");
        assert_eq!(
            finding.evidence.get("isMfaCapable").map(String::as_str),
            Some("true")
        );
        assert!(!finding
            .analysis
            .escalation_reason
            .contains("no es MFA-capable"));
    }

    #[test]
    fn conditional_access_exclusion_is_reported_for_active_user() {
        let users = json!([{
            "id": "ms-2",
            "userPrincipalName": "user@example.com",
            "accountEnabled": true
        }]);
        let policies = json!([{
            "id": "policy-1",
            "displayName": "Require MFA",
            "state": "enabled",
            "conditions": {"users": {"excludeUsers": ["ms-2"]}},
            "grantControls": {"builtInControls": ["mfa"]}
        }]);

        let result = analyze_microsoft_posture(
            users.as_array().unwrap(),
            &[],
            &[],
            policies.as_array().unwrap(),
        );

        assert!(result
            .findings
            .iter()
            .any(|finding| finding.control_id == "MSFT.CA.USER_EXCLUDED_FROM_MFA"));
    }

    #[test]
    fn conditional_access_authentication_strength_counts_as_strong_authentication() {
        let policies = json!([{
            "id": "policy-strength",
            "displayName": "Require phishing-resistant authentication",
            "state": "enabled",
            "conditions": {"users": {"includeUsers": ["All"]}},
            "grantControls": {
                "builtInControls": [],
                "authenticationStrength": {
                    "id": "00000000-0000-0000-0000-000000000003"
                }
            }
        }]);

        let result = analyze_microsoft_posture(&[], &[], &[], policies.as_array().unwrap());

        assert!(!result
            .findings
            .iter()
            .any(|finding| finding.control_id == "MSFT.CA.NO_ENABLED_MFA_POLICY"));
    }

    #[test]
    fn cross_cloud_active_state_mismatch_is_never_silently_safe() {
        let google = IdentityRecord::google("g-1", "person@example.com", false, Some(true), false);
        let microsoft = IdentityRecord::microsoft(
            "m-1",
            "person@example.com",
            true,
            Some(true),
            Some(true),
            false,
        );

        let findings = correlate_identities(&[google], &[microsoft]);

        let mismatch = findings
            .iter()
            .find(|finding| finding.control_id == "CROSS.IDENTITY.ACTIVE_STATE_MISMATCH")
            .expect("state mismatch must remain visible");
        assert_eq!(mismatch.contextual_verdict, ContextualVerdict::Alert);
        assert!(mismatch
            .analysis
            .uncertainty
            .contains("sistema de identidad"));
    }

    #[test]
    fn cross_cloud_identity_correlation_requires_an_exact_normalized_email() {
        let google = IdentityRecord::google("g-1", "identity-unknown", false, Some(true), false);
        let microsoft = IdentityRecord::microsoft(
            "m-1",
            "identity-unknown",
            true,
            Some(true),
            Some(true),
            false,
        );

        assert!(correlate_identities(&[google], &[microsoft]).is_empty());
    }

    #[test]
    fn disabled_source_is_explicitly_not_assured() {
        let coverage = CoverageEntry::disabled("microsoft.secureScore");

        assert_eq!(coverage.status, CoverageStatus::Disabled);
        assert_eq!(coverage.error_code, None);
        assert!(!coverage.is_assurance());
    }

    #[test]
    fn unavailable_source_is_explicit_coverage_not_a_clean_result() {
        let coverage =
            CoverageEntry::unavailable("microsoft.signIns", "license_or_permission_required");

        assert_eq!(coverage.status, CoverageStatus::Unavailable);
        assert_eq!(
            coverage.error_code.as_deref(),
            Some("license_or_permission_required")
        );
        assert!(!coverage.is_assurance());
    }

    #[test]
    fn collector_contract_covers_google_and_microsoft_security_sources() {
        let google_sources = google_posture_requests()
            .into_iter()
            .map(|request| request.source)
            .collect::<Vec<_>>();
        assert_eq!(
            google_sources,
            ["google.users", "google.roles", "google.roleAssignments"]
        );
        let google = google_posture_requests();
        assert!(google.iter().all(|request| {
            request.method == reqwest::Method::GET
                && request
                    .url
                    .starts_with("https://admin.googleapis.com/admin/directory/v1/")
        }));
        assert!(google
            .iter()
            .all(|request| request.query.iter().any(|(name, _)| name == "fields")));

        let microsoft = microsoft_graph_requests("2026-08-01T00:00:00Z");
        let microsoft_sources = microsoft
            .iter()
            .map(|request| request.source.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            microsoft_sources,
            [
                "microsoft.users",
                "microsoft.authenticationMethods",
                "microsoft.roleAssignments",
                "microsoft.conditionalAccess",
                "microsoft.signIns",
                "microsoft.directoryAudits",
                "microsoft.defenderAlerts",
                "microsoft.defenderIncidents",
                "microsoft.secureScore",
            ]
        );
        assert!(microsoft.iter().all(|request| {
            request.method == reqwest::Method::GET
                && request.url.starts_with("https://graph.microsoft.com/v1.0/")
        }));
    }

    #[test]
    fn role_assignments_query_requests_only_fields_consumed_by_analyzer() {
        let request = microsoft_graph_requests("2026-08-01T00:00:00Z")
            .into_iter()
            .find(|request| request.source == "microsoft.roleAssignments")
            .expect("roleAssignments request must be present");

        assert_eq!(request.method, reqwest::Method::GET);
        assert_eq!(
            request.url,
            "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
        );
        assert_eq!(
            request.query,
            vec![(
                "$select".to_string(),
                "id,principalId,roleDefinitionId".to_string()
            )]
        );
    }

    #[test]
    fn graph_error_codes_are_bounded_and_do_not_expose_provider_body() {
        let body = json!({
            "error": {
                "code": "Authorization_RequestDenied",
                "message": "sensitive tenant detail"
            }
        });

        assert_eq!(
            bounded_provider_error_code(reqwest::StatusCode::FORBIDDEN, &body, "http"),
            "http_403_Authorization_RequestDenied"
        );
        assert!(
            !bounded_provider_error_code(reqwest::StatusCode::FORBIDDEN, &body, "http")
                .contains("sensitive")
        );
    }

    #[test]
    fn graph_next_link_present_is_not_silently_dropped_before_validation() {
        let candidate = "https://evil.example/v1.0/users?page=2";
        assert_eq!(
            graph_next_link(&json!({"@odata.nextLink": candidate})).as_deref(),
            Some(candidate)
        );
    }

    #[test]
    fn google_error_codes_are_bounded_and_do_not_copy_provider_body() {
        let body = json!({
            "error": {
                "code": "forbidden",
                "message": "tenant-specific user detail"
            }
        });

        let error_code =
            bounded_provider_error_code(reqwest::StatusCode::FORBIDDEN, &body, "google_http");
        assert_eq!(error_code, "google_http_403_forbidden");
        assert!(!error_code.contains("tenant-specific"));
    }

    #[test]
    fn partial_microsoft_registration_remains_unknown_without_a_false_finding() {
        let users = json!([{
            "id": "ms-partial",
            "userPrincipalName": "partial@example.com",
            "accountEnabled": true
        }]);

        let result = analyze_microsoft_posture(users.as_array().unwrap(), &[], &[], &[]);
        let identity = result.identities.first().expect("user should be retained");

        assert_eq!(identity.mfa_enrolled, None);
        assert_eq!(identity.mfa_capable, None);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn risky_microsoft_sign_in_has_human_operational_analysis() {
        let sign_ins = json!([{
            "id": "signin-1",
            "createdDateTime": "2026-08-01T11:30:00Z",
            "userPrincipalName": "person@example.com",
            "appDisplayName": "Microsoft 365",
            "riskLevelDuringSignIn": "high",
            "riskState": "atRisk",
            "conditionalAccessStatus": "failure",
            "status": {"errorCode": 53003}
        }]);

        let findings = analyze_microsoft_signals(sign_ins.as_array().unwrap(), &[], &[], &[]);

        let finding = findings
            .iter()
            .find(|finding| finding.control_id == "MSFT.SIGNAL.RISKY_SIGN_IN")
            .expect("high-risk sign-in should be actionable");
        assert!(finding.analysis.is_complete());
        assert!(finding.summary.contains("high"));
        assert_eq!(finding.analysis.urgency, Urgency::Immediate);
    }

    #[test]
    fn high_defender_alert_is_preserved_as_actionable_signal() {
        let alerts = json!([{
            "id": "alert-1",
            "createdDateTime": "2026-08-01T11:45:00Z",
            "title": "Suspicious inbox rule",
            "severity": "high",
            "status": "new",
            "serviceSource": "microsoftDefenderForOffice365",
            "category": "Persistence"
        }]);

        let findings = analyze_microsoft_signals(&[], &[], alerts.as_array().unwrap(), &[]);

        let finding = findings
            .iter()
            .find(|finding| finding.control_id == "MSFT.DEFENDER.HIGH_SEVERITY_ALERT")
            .expect("Defender high alert should be actionable");
        assert_eq!(finding.severity, PostureSeverity::High);
        assert!(finding.analysis.recommended_action.contains("Defender"));
    }

    #[test]
    fn risky_signals_for_same_identity_across_clouds_are_correlated() {
        let google = vec![GoogleSignalContext {
            event_id: "login:g-1:suspicious_login:0".to_string(),
            actor: "person@example.com".to_string(),
            rule: "google_suspicious_login".to_string(),
            event_time: Some("2026-08-01T11:20:00Z".to_string()),
        }];
        let microsoft = analyze_microsoft_signals(
            json!([{
                "id": "signin-2",
                "createdDateTime": "2026-08-01T11:25:00Z",
                "userPrincipalName": "person@example.com",
                "riskLevelDuringSignIn": "high",
                "riskState": "atRisk"
            }])
            .as_array()
            .unwrap(),
            &[],
            &[],
            &[],
        );

        let correlations = correlate_cross_cloud_signals(&google, &microsoft);

        let finding = correlations
            .iter()
            .find(|finding| finding.control_id == "CROSS.SIGNAL.MULTITENANT_SUSPICIOUS_LOGIN")
            .expect("same-identity risky signals should correlate");
        assert_eq!(finding.severity, PostureSeverity::Critical);
        assert!(finding.analysis.evidence_for.len() >= 2);
        assert!(finding.analysis.is_complete());
    }

    #[test]
    fn cross_cloud_signal_correlation_requires_an_exact_normalized_email() {
        let google = vec![GoogleSignalContext {
            event_id: "login:g-1:suspicious_login:0".to_string(),
            actor: "signin-unknown".to_string(),
            rule: "google_suspicious_login".to_string(),
            event_time: None,
        }];
        let microsoft = analyze_microsoft_signals(
            json!([{
                "id": "signin-unknown",
                "createdDateTime": "2026-08-01T11:25:00Z",
                "riskLevelDuringSignIn": "high",
                "riskState": "atRisk"
            }])
            .as_array()
            .unwrap(),
            &[],
            &[],
            &[],
        );

        assert!(correlate_cross_cloud_signals(&google, &microsoft).is_empty());
    }
}
