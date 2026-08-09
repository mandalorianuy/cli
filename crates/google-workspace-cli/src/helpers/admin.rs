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

use super::Helper;
use crate::auth;
use crate::error::GwsError;
use crate::output::sanitize_for_terminal;
use chrono::{Duration, SecondsFormat, Utc};
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;

mod ip_intelligence;
mod microsoft_graph_auth;
mod monitor_contract;
mod monitor_correlation;
mod monitor_cutover;
mod monitor_program;
mod provenance;
mod security_posture;

pub struct AdminHelper;

const ADMIN_REPORTS_AUDIT_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.reports.audit.readonly";
const DIRECTORY_USER_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.user.readonly";
const DIRECTORY_GROUP_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.group.readonly";
const DIRECTORY_ORGUNIT_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly";
const DIRECTORY_ROLE_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly";
const DIRECTORY_DOMAIN_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.domain.readonly";
const DIRECTORY_CHROMEOS_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly";
const DIRECTORY_MOBILE_READONLY_SCOPE: &str =
    "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly";
const MAX_CORRELATION_INPUT_BYTES: u64 = 1_048_576;

struct ObserverRequest {
    application_name: &'static str,
    method: reqwest::Method,
    url: String,
    scope: &'static str,
    query: Vec<(String, String)>,
}

struct InventoryRequest {
    label: &'static str,
    method: reqwest::Method,
    url: &'static str,
    scope: &'static str,
    query: Vec<(&'static str, &'static str)>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    High,
    Critical,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct Finding {
    event_id: String,
    event_time: Option<String>,
    source: String,
    event_name: String,
    severity: Severity,
    rule: &'static str,
    reason: &'static str,
    actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance: Option<provenance::ProvenanceV1>,
    ip_address: Option<String>,
    occurrences: usize,
    evidence: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    visibility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    originating_app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_intelligence: Option<ip_intelligence::IpIntelligence>,
}

#[derive(Debug)]
struct SecurityObserverConfig {
    trusted_domains: HashSet<String>,
    consumer_domains: HashSet<String>,
    bulk_download_threshold: usize,
    bulk_api_access_threshold: usize,
    bulk_delete_threshold: usize,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecurityTelemetry {
    drive_document_types: BTreeMap<String, usize>,
    drive_visibilities: BTreeMap<String, usize>,
    originating_app_ids: BTreeMap<String, usize>,
    external_target_domains: BTreeMap<String, usize>,
    matched_dlp_detectors: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Recommendation {
    recommendation_id: &'static str,
    priority: &'static str,
    category: &'static str,
    title: &'static str,
    rationale: String,
    evidence_count: usize,
    status: &'static str,
}

#[derive(Clone, Debug)]
struct ActivityMetadata {
    source: String,
    qualifier: String,
    event_time: Option<String>,
}

impl ActivityMetadata {
    fn from_activity(activity: &Value) -> Self {
        Self {
            source: activity
                .pointer("/id/applicationName")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            qualifier: activity
                .pointer("/id/uniqueQualifier")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            event_time: activity
                .pointer("/id/time")
                .and_then(Value::as_str)
                .map(str::to_string),
        }
    }

    fn event_id(&self, event_name: &str, event_index: usize) -> String {
        format!(
            "{}:{}:{}:{}",
            self.source, self.qualifier, event_name, event_index
        )
    }

    fn burst_event_id(&self) -> String {
        format!("{}:{}:repeated_login_failures", self.source, self.qualifier)
    }

    fn is_later_than(&self, other: &Self) -> bool {
        self.event_time.as_deref().unwrap_or_default()
            > other.event_time.as_deref().unwrap_or_default()
    }
}

struct FailedLoginBurst {
    count: usize,
    ip_address: Option<String>,
    latest: ActivityMetadata,
}

struct DriveBurst {
    document_ids: HashSet<String>,
    ip_address: Option<String>,
    originating_app_id: Option<String>,
    latest: ActivityMetadata,
}

fn event_bool_parameter(event: &Value, name: &str) -> bool {
    event
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|parameter| parameter.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|parameter| parameter.get("boolValue"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn event_string_parameter(event: &Value, name: &str) -> Option<String> {
    event
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|parameter| parameter.get("name").and_then(Value::as_str) == Some(name))
        .and_then(|parameter| parameter.get("value"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn event_string_values(event: &Value, name: &str) -> Vec<String> {
    let Some(parameter) = event
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|parameter| parameter.get("name").and_then(Value::as_str) == Some(name))
    else {
        return Vec::new();
    };

    let mut values = Vec::new();
    if let Some(value) = parameter.get("value").and_then(Value::as_str) {
        values.push(value.to_string());
    }
    if let Some(multi_values) = parameter.get("multiValue").and_then(Value::as_array) {
        values.extend(
            multi_values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string),
        );
    }
    values
}

fn event_nested_parameter_values(
    event: &Value,
    parameter_name: &str,
    nested_name: &str,
) -> Vec<String> {
    event
        .get("parameters")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|parameter| parameter.get("name").and_then(Value::as_str) == Some(parameter_name))
        .and_then(|parameter| parameter.get("multiMessageValue"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|message| message.get("parameter").and_then(Value::as_array))
        .flatten()
        .filter(|parameter| parameter.get("name").and_then(Value::as_str) == Some(nested_name))
        .filter_map(|parameter| parameter.get("value").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn domain_from_target(target: &str) -> Option<String> {
    let normalized = target.trim().trim_start_matches('@').to_ascii_lowercase();
    let domain = normalized
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or(&normalized);
    validate_domain(domain).ok()
}

fn validate_domain(value: &str) -> Result<String, String> {
    let normalized = value.trim().trim_start_matches('@').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 || !normalized.contains('.') {
        return Err("domain must be a dotted DNS name no longer than 253 characters".to_string());
    }
    if !normalized.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err("domain contains an invalid DNS label".to_string());
    }
    Ok(normalized)
}

fn is_public_visibility(value: Option<&str>) -> bool {
    matches!(value, Some("people_with_link" | "public_on_the_web"))
}

fn is_access_grant(value: Option<&str>) -> bool {
    !matches!(value, None | Some("none"))
}

fn increment(map: &mut BTreeMap<String, usize>, key: Option<String>) {
    if let Some(key) = key.filter(|value| !value.is_empty()) {
        *map.entry(key).or_default() += 1;
    }
}

fn finding_from_event(
    metadata: &ActivityMetadata,
    event_name: &str,
    event_index: usize,
    event: &Value,
    severity: Severity,
    rule: &'static str,
    principal: (String, Option<String>),
) -> Finding {
    let (actor, ip_address) = principal;
    let mut evidence = BTreeMap::new();
    for name in [
        "affected_email_address",
        "api_method",
        "api_name",
        "app_name",
        "client_id",
        "client_type",
        "data_source",
        "doc_type",
        "is_suspicious",
        "login_challenge_method",
        "login_type",
        "matched_trigger",
        "new_value",
        "old_value",
        "originating_app_id",
        "owner",
        "resource_type",
        "rule_name",
        "rule_type",
        "scan_type",
        "scope",
        "severity",
        "target",
        "target_domain",
        "target_user",
        "visibility",
        "visibility_change",
    ] {
        let values = event_string_values(event, name)
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if !values.is_empty() {
            evidence.insert(name.to_string(), values.join(", "));
        } else if event_bool_parameter(event, name) {
            evidence.insert(name.to_string(), "true".to_string());
        }
    }
    let matched_detectors =
        event_nested_parameter_values(event, "matched_detectors", "display_name");
    if !matched_detectors.is_empty() {
        evidence.insert(
            "matched_detectors".to_string(),
            matched_detectors.join(", "),
        );
    }

    Finding {
        event_id: metadata.event_id(event_name, event_index),
        event_time: metadata.event_time.clone(),
        source: metadata.source.clone(),
        event_name: event_name.to_string(),
        severity,
        rule,
        reason: reason_for_rule(rule),
        actor: actor.clone(),
        provenance: Some(google_finding_provenance(
            event,
            &actor,
            metadata.event_time.as_deref(),
        )),
        ip_address,
        occurrences: 1,
        evidence,
        target: event_string_parameter(event, "target_user")
            .or_else(|| event_string_parameter(event, "target"))
            .or_else(|| event_string_parameter(event, "target_domain")),
        resource_id: event_string_parameter(event, "doc_id")
            .or_else(|| event_string_parameter(event, "resource_id")),
        resource_type: event_string_parameter(event, "doc_type")
            .or_else(|| event_string_parameter(event, "resource_type")),
        visibility: event_string_parameter(event, "visibility").or_else(|| {
            event_string_parameter(event, "new_value").filter(|value| {
                matches!(
                    value.as_str(),
                    "people_with_link"
                        | "people_within_domain_with_link"
                        | "private"
                        | "public_in_the_domain"
                        | "public_on_the_web"
                )
            })
        }),
        originating_app_id: event_string_parameter(event, "originating_app_id"),
        ip_intelligence: None,
    }
}

fn google_finding_provenance(
    event: &Value,
    actor: &str,
    event_time: Option<&str>,
) -> provenance::ProvenanceV1 {
    if provenance::validated_email(actor).is_some() {
        return provenance::ProvenanceV1::google_actor(actor, event_time);
    }
    if event_string_parameter(event, "resource_owner_email").is_some() {
        return provenance::ProvenanceV1::google_resource_owner(event_time);
    }
    provenance::ProvenanceV1::google_unknown(event_time)
}

fn reason_for_rule(rule: &str) -> &'static str {
    match rule {
        "google_suspicious_login" => "Google explicitly detected and blocked a suspicious login.",
        "suspicious_less_secure_app" => {
            "Google detected a suspicious login from a less secure application."
        }
        "suspicious_programmatic_login" => {
            "Google detected suspicious programmatic authentication."
        }
        "suspicious_session_cookie" => {
            "Google signed the user out after detecting a suspicious session cookie."
        }
        "password_leak" => "Google disabled the account after detecting a leaked password.",
        "account_hijacked" => "Google disabled the account after detecting possible hijacking.",
        "government_backed_attack_warning" => {
            "Google warned that the account may be targeted by a government-backed attacker."
        }
        "google_ransomware_sync_pause" => {
            "Google paused Drive sync after detecting potential ransomware behavior."
        }
        "suspicious_successful_login" => {
            "Google marked a successful login as suspicious due to unusual characteristics."
        }
        "two_step_verification_disabled" => "Two-step verification was disabled for the account.",
        "passkey_removed" => "A passkey was removed from the account.",
        "recovery_email_changed" => "The account recovery email was changed.",
        "recovery_phone_changed" => "The account recovery phone was changed.",
        "admin_role_assigned" => "An administrator role was assigned.",
        "domain_wide_delegation_authorized" => {
            "A client was authorized for domain-wide delegation."
        }
        "context_aware_access_changed" => "Context-Aware Access assignments were changed.",
        "oauth_application_authorized" => {
            "A user authorized an OAuth application; app, client, and scopes require review."
        }
        "drive_public_link_enabled" => {
            "Drive link visibility changed to anyone with the link or public on the web."
        }
        "drive_shared_with_consumer_account" => {
            "A Drive item was shared with an account on a consumer email domain."
        }
        "drive_shared_outside_trusted_domains" => {
            "A Drive item was shared outside the configured trusted domains."
        }
        "drive_external_ownership_transfer" => {
            "Ownership of a Drive item was transferred outside the configured trusted domains."
        }
        "drive_emailed_to_consumer_account" => {
            "A Drive item was emailed as an attachment to a consumer account."
        }
        "drive_emailed_outside_trusted_domains" => {
            "A Drive item was emailed as an attachment outside trusted domains."
        }
        "dlp_content_match" => "An existing Workspace DLP rule matched content.",
        "dlp_rule_triggered" => "An existing Workspace DLP rule was triggered.",
        "dlp_user_warned" => "A user received a DLP warning while sending content.",
        "repeated_login_failures" => {
            "The account reached the failed-login threshold during the observation window."
        }
        "bulk_drive_download" => {
            "The actor downloaded at least the configured number of unique Drive items."
        }
        "bulk_drive_api_access" => {
            "The actor or application accessed at least the configured number of unique Drive items."
        }
        "bulk_drive_delete" => {
            "The actor deleted or trashed at least the configured number of unique Drive items."
        }
        _ => "The observed event matched a configured security rule.",
    }
}

fn activities_from_response(response: &Value) -> (Vec<Value>, Option<String>) {
    let activities = response
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let next_page = response
        .get("nextPageToken")
        .and_then(Value::as_str)
        .map(str::to_string);
    (activities, next_page)
}

fn analyze_activities(
    activities: &[Value],
    config: &SecurityObserverConfig,
) -> (Vec<Finding>, SecurityTelemetry) {
    let mut findings = Vec::new();
    let mut failed_logins: HashMap<String, FailedLoginBurst> = HashMap::new();
    let mut download_bursts: HashMap<String, DriveBurst> = HashMap::new();
    let mut api_access_bursts: HashMap<String, DriveBurst> = HashMap::new();
    let mut delete_bursts: HashMap<String, DriveBurst> = HashMap::new();
    let mut telemetry = SecurityTelemetry::default();

    for activity in activities {
        let metadata = ActivityMetadata::from_activity(activity);
        let actor = activity
            .pointer("/actor/email")
            .and_then(Value::as_str)
            .unwrap_or("(unknown)")
            .to_string();
        let ip_address = activity
            .get("ipAddress")
            .and_then(Value::as_str)
            .map(str::to_string);

        for (event_index, event) in activity
            .get("events")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let Some(event_name) = event.get("name").and_then(Value::as_str) else {
                continue;
            };
            let effective_actor = actor.clone();
            let doc_id = event_string_parameter(event, "doc_id")
                .or_else(|| event_string_parameter(event, "resource_id"))
                .unwrap_or_else(|| metadata.event_id(event_name, event_index));
            let originating_app_id = event_string_parameter(event, "originating_app_id");

            if metadata.source == "drive" {
                increment(
                    &mut telemetry.drive_document_types,
                    event_string_parameter(event, "doc_type"),
                );
                increment(
                    &mut telemetry.drive_visibilities,
                    event_string_parameter(event, "visibility"),
                );
                increment(
                    &mut telemetry.originating_app_ids,
                    originating_app_id.clone(),
                );
            }
            if metadata.source == "rules" {
                for detector in
                    event_nested_parameter_values(event, "matched_detectors", "display_name")
                {
                    increment(&mut telemetry.matched_dlp_detectors, Some(detector));
                }
            }

            let target = event_string_parameter(event, "target_user")
                .or_else(|| event_string_parameter(event, "target"));
            let target_domain = target.as_deref().and_then(domain_from_target).or_else(|| {
                event_string_parameter(event, "target_domain")
                    .and_then(|value| domain_from_target(&value))
            });
            let target_is_consumer = target_domain
                .as_ref()
                .is_some_and(|domain| config.consumer_domains.contains(domain));
            let target_is_untrusted = target_domain
                .as_ref()
                .is_some_and(|domain| !config.trusted_domains.contains(domain));
            let became_external =
                event_string_parameter(event, "visibility_change").as_deref() == Some("external");
            let permission_value = event_string_parameter(event, "new_value");
            let permission_granted = is_access_grant(permission_value.as_deref());
            let untrusted_external_change = target_domain
                .as_ref()
                .map(|_| target_is_untrusted)
                .unwrap_or(became_external);
            if metadata.source == "drive" && permission_granted && target_is_untrusted {
                increment(
                    &mut telemetry.external_target_domains,
                    target_domain.clone(),
                );
            }

            if event_name == "login_failure" {
                let entry = failed_logins
                    .entry(effective_actor.clone())
                    .or_insert_with(|| FailedLoginBurst {
                        count: 0,
                        ip_address: ip_address.clone(),
                        latest: metadata.clone(),
                    });
                entry.count += 1;
                if metadata.is_later_than(&entry.latest) {
                    entry.latest = metadata.clone();
                    entry.ip_address = ip_address.clone();
                }
                continue;
            }

            let burst_key = format!(
                "{}\u{1f}{}\u{1f}{}",
                effective_actor,
                ip_address.as_deref().unwrap_or(""),
                originating_app_id.as_deref().unwrap_or("")
            );
            let burst_map = match event_name {
                "download" | "download_forms_response" => Some(&mut download_bursts),
                "access_item_content" | "prefetch_item_content" | "sync_item_content" => {
                    Some(&mut api_access_bursts)
                }
                "delete" | "trash" | "delete_revision" => Some(&mut delete_bursts),
                _ => None,
            };
            if let Some(bursts) = burst_map {
                let entry = bursts.entry(burst_key).or_insert_with(|| DriveBurst {
                    document_ids: HashSet::new(),
                    ip_address: ip_address.clone(),
                    originating_app_id: originating_app_id.clone(),
                    latest: metadata.clone(),
                });
                entry.document_ids.insert(doc_id);
                if metadata.is_later_than(&entry.latest) {
                    entry.latest = metadata.clone();
                    entry.ip_address = ip_address.clone();
                    entry.originating_app_id = originating_app_id.clone();
                }
            }

            let critical_rule = match event_name {
                "suspicious_login" => Some("google_suspicious_login"),
                "suspicious_login_less_secure_app" => Some("suspicious_less_secure_app"),
                "suspicious_programmatic_login" => Some("suspicious_programmatic_login"),
                "user_signed_out_due_to_suspicious_session_cookie" => {
                    Some("suspicious_session_cookie")
                }
                "account_disabled_password_leak" => Some("password_leak"),
                "account_disabled_hijacked" => Some("account_hijacked"),
                "gov_attack_warning" => Some("government_backed_attack_warning"),
                "pause_sync_client" => Some("google_ransomware_sync_pause"),
                "ASSIGN_ROLE" => Some("admin_role_assigned"),
                "AUTHORIZE_API_CLIENT_ACCESS" => Some("domain_wide_delegation_authorized"),
                "change_document_visibility"
                    if is_public_visibility(
                        event_string_parameter(event, "new_value").as_deref(),
                    ) =>
                {
                    Some("drive_public_link_enabled")
                }
                "change_user_access"
                    if permission_value.as_deref() == Some("owner")
                        && untrusted_external_change =>
                {
                    Some("drive_external_ownership_transfer")
                }
                _ => None,
            };

            if let Some(rule) = critical_rule {
                findings.push(finding_from_event(
                    &metadata,
                    event_name,
                    event_index,
                    event,
                    Severity::Critical,
                    rule,
                    (effective_actor, ip_address.clone()),
                ));
                continue;
            }

            let high_rule = match event_name {
                "login_success" if event_bool_parameter(event, "is_suspicious") => {
                    Some("suspicious_successful_login")
                }
                "2sv_disable" => Some("two_step_verification_disabled"),
                "passkey_removed" => Some("passkey_removed"),
                "recovery_email_edit" => Some("recovery_email_changed"),
                "recovery_phone_edit" => Some("recovery_phone_changed"),
                "CHANGE_CAA_APP_ASSIGNMENTS" => Some("context_aware_access_changed"),
                "authorize" => Some("oauth_application_authorized"),
                "change_user_access" if permission_granted && target_is_consumer => {
                    Some("drive_shared_with_consumer_account")
                }
                "change_user_access" if permission_granted && untrusted_external_change => {
                    Some("drive_shared_outside_trusted_domains")
                }
                "email_as_attachment" if target_is_consumer => {
                    Some("drive_emailed_to_consumer_account")
                }
                "email_as_attachment" if target_is_untrusted => {
                    Some("drive_emailed_outside_trusted_domains")
                }
                "content_matched" | "rule_match"
                    if event_string_parameter(event, "rule_type").as_deref() == Some("DLP")
                        || event_name == "content_matched" =>
                {
                    Some("dlp_content_match")
                }
                "rule_trigger"
                    if event_string_parameter(event, "rule_type").as_deref() == Some("DLP") =>
                {
                    Some("dlp_rule_triggered")
                }
                "message_send_warned" => Some("dlp_user_warned"),
                _ => None,
            };

            if let Some(rule) = high_rule {
                findings.push(finding_from_event(
                    &metadata,
                    event_name,
                    event_index,
                    event,
                    Severity::High,
                    rule,
                    (effective_actor, ip_address.clone()),
                ));
            }
        }
    }

    findings.extend(
        failed_logins
            .into_iter()
            .filter(|(_, burst)| burst.count >= 5)
            .map(|(actor, burst)| {
                let provenance = provenance::ProvenanceV1::google_actor(
                    &actor,
                    burst.latest.event_time.as_deref(),
                );
                Finding {
                    event_id: burst.latest.burst_event_id(),
                    event_time: burst.latest.event_time,
                    source: burst.latest.source,
                    event_name: "login_failure_aggregate".to_string(),
                    severity: Severity::High,
                    rule: "repeated_login_failures",
                    reason: reason_for_rule("repeated_login_failures"),
                    actor,
                    provenance: Some(provenance),
                    ip_address: burst.ip_address,
                    occurrences: burst.count,
                    evidence: BTreeMap::from([(
                        "failed_login_count".to_string(),
                        burst.count.to_string(),
                    )]),
                    target: None,
                    resource_id: None,
                    resource_type: None,
                    visibility: None,
                    originating_app_id: None,
                    ip_intelligence: None,
                }
            }),
    );

    findings.extend(drive_burst_findings(
        download_bursts,
        config.bulk_download_threshold,
        "bulk_drive_download",
    ));
    findings.extend(drive_burst_findings(
        api_access_bursts,
        config.bulk_api_access_threshold,
        "bulk_drive_api_access",
    ));
    findings.extend(drive_burst_findings(
        delete_bursts,
        config.bulk_delete_threshold,
        "bulk_drive_delete",
    ));
    findings.sort_by(|left, right| {
        left.event_time
            .cmp(&right.event_time)
            .then_with(|| left.rule.cmp(right.rule))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    (findings, telemetry)
}

fn drive_burst_findings(
    bursts: HashMap<String, DriveBurst>,
    threshold: usize,
    rule: &'static str,
) -> Vec<Finding> {
    bursts
        .into_iter()
        .filter(|(_, burst)| burst.document_ids.len() >= threshold)
        .map(|(key, burst)| {
            let actor = key
                .split('\u{1f}')
                .next()
                .unwrap_or("(unknown)")
                .to_string();
            let provenance =
                provenance::ProvenanceV1::google_actor(&actor, burst.latest.event_time.as_deref());
            Finding {
                event_id: format!("{}:{}:{rule}", burst.latest.source, burst.latest.qualifier),
                event_time: burst.latest.event_time,
                source: burst.latest.source,
                event_name: "drive_activity_aggregate".to_string(),
                severity: Severity::High,
                rule,
                reason: reason_for_rule(rule),
                actor,
                provenance: Some(provenance),
                ip_address: burst.ip_address,
                occurrences: burst.document_ids.len(),
                evidence: BTreeMap::from([(
                    "unique_resource_count".to_string(),
                    burst.document_ids.len().to_string(),
                )]),
                target: None,
                resource_id: None,
                resource_type: None,
                visibility: None,
                originating_app_id: burst.originating_app_id,
                ip_intelligence: None,
            }
        })
        .collect()
}

fn build_recommendations(
    findings: &[Finding],
    telemetry: &SecurityTelemetry,
) -> Vec<Recommendation> {
    let count_rule = |rule: &str| {
        findings
            .iter()
            .filter(|finding| finding.rule == rule)
            .count()
    };
    let mut recommendations = vec![
        Recommendation {
            recommendation_id: "dlp-audit-sensitive-data-types",
            priority: "medium",
            category: "dlp",
            title: "Baseline sensitive data with audit-only DLP detectors",
            rationale: "Start with audit-only predefined detectors for financial identifiers, government IDs, tax IDs, credentials, email addresses, and phone numbers; tune confidence and match counts before enforcement.".to_string(),
            evidence_count: telemetry.matched_dlp_detectors.values().sum(),
            status: "proposed",
        },
        Recommendation {
            recommendation_id: "drive-label-classification-taxonomy",
            priority: "medium",
            category: "classification",
            title: "Define a Drive classification label taxonomy",
            rationale: "Use a small taxonomy such as Public, Internal, Confidential, and Restricted so later DLP and sharing rules can combine content matches with business context.".to_string(),
            evidence_count: telemetry.drive_document_types.values().sum(),
            status: "proposed",
        },
    ];

    let public_links = count_rule("drive_public_link_enabled");
    if public_links > 0 {
        recommendations.push(Recommendation {
            recommendation_id: "drive-public-link-governance",
            priority: "critical",
            category: "sharing",
            title: "Restrict public link sharing",
            rationale: "Review public-link findings, identify legitimate publishing workflows, then limit public links by OU/group and use exceptions instead of a domain-wide allowance.".to_string(),
            evidence_count: public_links,
            status: "proposed",
        });
    }

    let consumer_shares = count_rule("drive_shared_with_consumer_account")
        + count_rule("drive_emailed_to_consumer_account");
    if consumer_shares > 0 {
        recommendations.push(Recommendation {
            recommendation_id: "consumer-account-sharing-policy",
            priority: "high",
            category: "sharing",
            title: "Govern sharing to consumer accounts",
            rationale: "Review whether consumer-account recipients are approved business exceptions; use trusted-domain allowlists and audit-only DLP rules before blocking.".to_string(),
            evidence_count: consumer_shares,
            status: "proposed",
        });
    }

    let bulk_downloads = count_rule("bulk_drive_download");
    if bulk_downloads > 0 {
        recommendations.push(Recommendation {
            recommendation_id: "bulk-download-controls",
            priority: "high",
            category: "behavior",
            title: "Protect sensitive files from bulk download",
            rationale: "Baseline expected export and migration tooling, then apply labels, download/copy restrictions, and alert thresholds to sensitive repositories.".to_string(),
            evidence_count: bulk_downloads,
            status: "proposed",
        });
    }

    let bulk_api_access = count_rule("bulk_drive_api_access");
    if bulk_api_access > 0 {
        recommendations.push(Recommendation {
            recommendation_id: "drive-api-tooling-baseline",
            priority: "high",
            category: "tooling",
            title: "Baseline and allowlist high-volume Drive tooling",
            rationale: "Map originating Google Cloud project IDs to approved tools, owners, expected volumes, and change windows; investigate high-volume access outside that baseline.".to_string(),
            evidence_count: bulk_api_access,
            status: "proposed",
        });
    }

    let dlp_matches = count_rule("dlp_content_match") + count_rule("dlp_rule_triggered");
    if dlp_matches > 0 {
        recommendations.push(Recommendation {
            recommendation_id: "dlp-match-tuning",
            priority: "high",
            category: "dlp",
            title: "Review and tune existing DLP detector matches",
            rationale: "Use matched detector counts to measure precision, document false positives, and promote only stable audit rules to warn or block.".to_string(),
            evidence_count: dlp_matches,
            status: "proposed",
        });
    }

    let externally_visible_observations = telemetry
        .drive_visibilities
        .get("shared_externally")
        .copied()
        .unwrap_or_default();
    if externally_visible_observations > 0 {
        recommendations.push(Recommendation {
            recommendation_id: "drive-external-sharing-inventory",
            priority: "high",
            category: "sharing",
            title: "Build a current inventory of externally visible Drive resources",
            rationale: "Use unique resource IDs and current ACL state to separate approved collaboration from stale or excessive exposure before introducing restrictions. Telemetry counts audit observations, not unique files.".to_string(),
            evidence_count: externally_visible_observations,
            status: "proposed",
        });
    }

    let public_link_observations = telemetry
        .drive_visibilities
        .get("people_with_link")
        .copied()
        .unwrap_or_default()
        + telemetry
            .drive_visibilities
            .get("public_on_the_web")
            .copied()
            .unwrap_or_default();
    if public_link_observations > 0 {
        recommendations.push(Recommendation {
            recommendation_id: "drive-public-link-inventory",
            priority: "high",
            category: "sharing",
            title: "Review active resources observed with public-link visibility",
            rationale: "Confirm business purpose and ownership for public-link resources, then restrict public links by OU or group with documented exceptions. Telemetry counts audit observations, not unique files.".to_string(),
            evidence_count: public_link_observations,
            status: "proposed",
        });
    }

    recommendations
}

fn filter_findings(findings: Vec<Finding>, min_severity: &str) -> Vec<Finding> {
    if min_severity == "critical" {
        findings
            .into_iter()
            .filter(|finding| finding.severity == Severity::Critical)
            .collect()
    } else {
        findings
    }
}

fn build_security_observer_cmd() -> Command {
    Command::new("+security-observer")
        .about("[Helper] Detect suspicious Workspace activity without modifying the domain")
        .arg(
            Arg::new("lookback-minutes")
                .long("lookback-minutes")
                .value_parser(value_parser!(u64).range(1..=10_080))
                .default_value("15")
                .value_name("MINUTES"),
        )
        .arg(
            Arg::new("max-results")
                .long("max-results")
                .value_parser(value_parser!(u32).range(1..=1_000))
                .default_value("100")
                .value_name("COUNT"),
        )
        .arg(
            Arg::new("min-severity")
                .long("min-severity")
                .value_parser(["high", "critical"])
                .default_value("high")
                .value_name("LEVEL"),
        )
        .arg(
            Arg::new("internal-domain")
                .long("internal-domain")
                .action(ArgAction::Append)
                .value_parser(validate_domain)
                .value_name("DOMAIN")
                .help("Internal Workspace domain; repeat for aliases"),
        )
        .arg(
            Arg::new("trusted-domain")
                .long("trusted-domain")
                .action(ArgAction::Append)
                .value_parser(validate_domain)
                .value_name("DOMAIN")
                .help("Approved external sharing domain; repeat as needed"),
        )
        .arg(
            Arg::new("consumer-domain")
                .long("consumer-domain")
                .action(ArgAction::Append)
                .value_parser(validate_domain)
                .value_name("DOMAIN")
                .help("Additional consumer email domain to flag"),
        )
        .arg(
            Arg::new("bulk-download-threshold")
                .long("bulk-download-threshold")
                .value_parser(value_parser!(u32).range(5..=1_000))
                .default_value("25")
                .value_name("UNIQUE_FILES"),
        )
        .arg(
            Arg::new("bulk-api-access-threshold")
                .long("bulk-api-access-threshold")
                .value_parser(value_parser!(u32).range(5..=1_000))
                .default_value("100")
                .value_name("UNIQUE_FILES"),
        )
        .arg(
            Arg::new("bulk-delete-threshold")
                .long("bulk-delete-threshold")
                .value_parser(value_parser!(u32).range(5..=1_000))
                .default_value("50")
                .value_name("UNIQUE_FILES"),
        )
        .arg(
            Arg::new("ip-intelligence")
                .long("ip-intelligence")
                .action(ArgAction::SetTrue)
                .help(
                    "Enrich finding IPs with authoritative RDAP registration data and optional IPinfo context",
                ),
        )
        .arg(
            Arg::new("include-posture")
                .long("include-posture")
                .action(ArgAction::SetTrue)
                .help("Include read-only Google identity and administrator posture"),
        )
        .arg(
            Arg::new("microsoft-graph")
                .long("microsoft-graph")
                .requires("include-posture")
                .action(ArgAction::SetTrue)
                .help(
                    "Include Microsoft 365 posture and signals using MICROSOFT_GRAPH_ACCESS_TOKEN; certificate auth uses MICROSOFT_GRAPH_TENANT_ID, MICROSOFT_GRAPH_CLIENT_ID, MICROSOFT_GRAPH_CERTIFICATE_FILE, and MICROSOFT_GRAPH_PRIVATE_KEY_FILE, or a mode-0600 microsoft_graph.json file in GOOGLE_WORKSPACE_CLI_CONFIG_DIR",
                ),
        )
        .arg(
            Arg::new("inactive-days")
                .long("inactive-days")
                .requires("include-posture")
                .value_parser(value_parser!(u32).range(30..=730))
                .default_value_if("include-posture", "true", "90")
                .value_name("DAYS")
                .help("Flag enabled Google accounts without a recent login after this many days"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_parser(["json", "table", "yaml", "csv"])
                .default_value("json")
                .value_name("FORMAT"),
        )
        .after_help(
            "READ-ONLY GUARANTEE:\n  Uses only Google Admin and optional Microsoft Graph GET requests.\n  Never suspends users, revokes tokens, changes 2SV, modifies devices, or changes policies.",
        )
}

fn build_security_monitor_plan_cmd() -> Command {
    Command::new("+security-monitor-plan")
        .about("[Helper] Compile a Security Intelligence Monitor cutover bundle without external effects")
        .arg(
            Arg::new("input")
                .long("input")
                .required(true)
                .value_name("FILE")
                .help("Read-only observer report containing monitorIntegration"),
        )
        .arg(
            Arg::new("existing")
                .long("existing")
                .required(true)
                .value_name("FILE")
                .help("Local monitor target snapshot with schemaVersion, records, and optional revision/hash guards"),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .action(ArgAction::SetTrue)
                .help("Required: emit a local bundle only; never write a Sheet or send email"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_parser(["json", "yaml"])
                .default_value("json")
                .value_name("FORMAT"),
        )
        .after_help(
            "NO-EFFECT GUARANTEE:\n  Reads only the two local JSON files.\n  The command never calls Google Sheets, Gmail, Microsoft Graph, or any writer.\n  A schema or coverage gate failure is represented as blocked in the bundle.\n  The notification phase is always suppressed until a separately authorized writer completes readback.",
        )
}

fn build_security_monitor_correlate_cmd() -> Command {
    Command::new("+security-monitor-correlate")
        .about("[Helper] Correlate an existing security observer report without external effects")
        .arg(
            Arg::new("input")
                .long("input")
                .required(true)
                .value_name("FILE")
                .help("Local read-only security observer report JSON"),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .required(true)
                .action(ArgAction::SetTrue)
                .help("Required: emit only a bounded local correlation view"),
        )
        .arg(
            Arg::new("window-minutes")
                .long("window-minutes")
                .value_parser(value_parser!(u64).range(1..=1_440))
                .default_value("30")
                .value_name("MINUTES")
                .help("Maximum event-time distance allowed for a correlation"),
        )
        .arg(
            Arg::new("max-correlations")
                .long("max-correlations")
                .value_parser(value_parser!(u32).range(1..=100))
                .default_value("50")
                .value_name("COUNT")
                .help("Maximum deterministic correlation records to emit"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_parser(["json", "yaml"])
                .default_value("json")
                .value_name("FORMAT"),
        )
        .after_help(
            "NO-EFFECT GUARANTEE:\n  Reads one bounded local JSON file only.\n  Never calls Google Admin, Microsoft Graph, Sheets, Gmail, a writer, or a notifier.\n  Missing, disabled, unavailable, contradictory, stale, or overflowing evidence remains fail-closed and requires human review.",
        )
}

fn build_security_monitor_program_cmd() -> Command {
    Command::new("+security-monitor-program")
        .about("[Helper] Compile and simulate a local Security Intelligence Monitor execution program")
        .arg(
            Arg::new("bundle")
                .long("bundle")
                .required(true)
                .value_name("FILE")
                .help("T3b cutover bundle JSON; it is never sent to an external service"),
        )
        .arg(
            Arg::new("target")
                .long("target")
                .required(true)
                .value_name("FILE")
                .help("Pinned local target snapshot JSON"),
        )
        .arg(
            Arg::new("policy")
                .long("policy")
                .required(true)
                .value_name("FILE")
                .help("Explicit local writer policy JSON; presence is not human approval"),
        )
        .arg(
            Arg::new("simulate")
                .long("simulate")
                .required(true)
                .action(ArgAction::SetTrue)
                .help("Required: run only the deterministic local receipt simulator"),
        )
        .arg(
            Arg::new("failure-phase")
                .long("failure-phase")
                .value_name("PHASE")
                .value_parser(parse_security_monitor_failure_phase)
                .help("Optional local simulation fault; it cannot enable external writes"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_parser(["json", "yaml"])
                .default_value("json")
                .value_name("FORMAT"),
        )
        .after_help(
            "NO-EFFECT GUARANTEE:\n  Reads only the three local JSON files.\n  Compiles typed requests and receipts; it never calls Sheets, Gmail, Google Admin, Microsoft Graph, or any writer.\n  All simulations keep externalWritesAllowed=false, liveApplyAvailable=false, and notification=suppress.",
        )
}

fn parse_security_monitor_failure_phase(value: &str) -> Result<String, String> {
    if monitor_program::failure_phase_names().contains(&value) {
        Ok(value.to_string())
    } else {
        Err(format!("unknown failure phase '{value}'"))
    }
}

fn security_observer_config(matches: &ArgMatches) -> SecurityObserverConfig {
    let mut trusted_domains: HashSet<String> = matches
        .get_many::<String>("internal-domain")
        .into_iter()
        .flatten()
        .chain(
            matches
                .get_many::<String>("trusted-domain")
                .into_iter()
                .flatten(),
        )
        .cloned()
        .collect();
    trusted_domains.shrink_to_fit();

    let mut consumer_domains: HashSet<String> = [
        "gmail.com",
        "googlemail.com",
        "hotmail.com",
        "outlook.com",
        "live.com",
        "yahoo.com",
        "icloud.com",
        "proton.me",
        "protonmail.com",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    consumer_domains.extend(
        matches
            .get_many::<String>("consumer-domain")
            .into_iter()
            .flatten()
            .cloned(),
    );

    SecurityObserverConfig {
        trusted_domains,
        consumer_domains,
        bulk_download_threshold: matches
            .get_one::<u32>("bulk-download-threshold")
            .copied()
            .unwrap_or(25) as usize,
        bulk_api_access_threshold: matches
            .get_one::<u32>("bulk-api-access-threshold")
            .copied()
            .unwrap_or(100) as usize,
        bulk_delete_threshold: matches
            .get_one::<u32>("bulk-delete-threshold")
            .copied()
            .unwrap_or(50) as usize,
    }
}

fn build_admin_observer_cmd() -> Command {
    Command::new("+admin-observer")
        .about("[Helper] Inventory Workspace administration without modifying the domain")
        .arg(
            Arg::new("include-devices")
                .long("include-devices")
                .action(ArgAction::SetTrue)
                .help("Include basic ChromeOS and mobile device inventory"),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_parser(["json", "table", "yaml", "csv"])
                .default_value("json")
                .value_name("FORMAT"),
        )
        .after_help(
            "READ-ONLY GUARANTEE:\n  Uses only Admin Directory API GET requests with readonly scopes.\n  Never creates, updates, suspends, deletes, or signs out users.",
        )
}

fn security_observer_requests(start_time: &str, max_results: u32) -> Vec<ObserverRequest> {
    ["login", "admin", "token", "drive", "rules"]
        .into_iter()
        .map(|application_name| ObserverRequest {
            application_name,
            method: reqwest::Method::GET,
            url: format!(
                "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{application_name}"
            ),
            scope: ADMIN_REPORTS_AUDIT_READONLY_SCOPE,
            query: vec![
                ("startTime".to_string(), start_time.to_string()),
                ("maxResults".to_string(), max_results.to_string()),
            ],
        })
        .collect()
}

fn admin_observer_requests(include_devices: bool) -> Vec<InventoryRequest> {
    let mut requests = vec![
        InventoryRequest {
            label: "users",
            method: reqwest::Method::GET,
            url: "https://admin.googleapis.com/admin/directory/v1/users",
            scope: DIRECTORY_USER_READONLY_SCOPE,
            query: vec![
                ("customer", "my_customer"),
                ("maxResults", "500"),
                ("orderBy", "email"),
                ("projection", "basic"),
            ],
        },
        InventoryRequest {
            label: "groups",
            method: reqwest::Method::GET,
            url: "https://admin.googleapis.com/admin/directory/v1/groups",
            scope: DIRECTORY_GROUP_READONLY_SCOPE,
            query: vec![("customer", "my_customer"), ("maxResults", "200")],
        },
        InventoryRequest {
            label: "organizationalUnits",
            method: reqwest::Method::GET,
            url: "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/orgunits",
            scope: DIRECTORY_ORGUNIT_READONLY_SCOPE,
            query: vec![("type", "all")],
        },
        InventoryRequest {
            label: "roles",
            method: reqwest::Method::GET,
            url: "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roles",
            scope: DIRECTORY_ROLE_READONLY_SCOPE,
            query: vec![("maxResults", "100")],
        },
        InventoryRequest {
            label: "roleAssignments",
            method: reqwest::Method::GET,
            url: "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roleassignments",
            scope: DIRECTORY_ROLE_READONLY_SCOPE,
            query: vec![("maxResults", "100")],
        },
        InventoryRequest {
            label: "domains",
            method: reqwest::Method::GET,
            url: "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/domains",
            scope: DIRECTORY_DOMAIN_READONLY_SCOPE,
            query: Vec::new(),
        },
    ];

    if include_devices {
        requests.extend([
            InventoryRequest {
                label: "chromeOsDevices",
                method: reqwest::Method::GET,
                url: "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/devices/chromeos",
                scope: DIRECTORY_CHROMEOS_READONLY_SCOPE,
                query: vec![("maxResults", "100"), ("projection", "BASIC")],
            },
            InventoryRequest {
                label: "mobileDevices",
                method: reqwest::Method::GET,
                url: "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/devices/mobile",
                scope: DIRECTORY_MOBILE_READONLY_SCOPE,
                query: vec![("maxResults", "100"), ("projection", "BASIC")],
            },
        ]);
    }

    requests
}

async fn fetch_observer_request(
    client: &reqwest::Client,
    request: &ObserverRequest,
    token: &str,
) -> Result<Vec<Value>, GwsError> {
    if request.method != reqwest::Method::GET {
        return Err(GwsError::Validation(
            "Observer request rejected: only GET is allowed".to_string(),
        ));
    }

    let response = client
        .get(&request.url)
        .query(&request.query)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| {
            GwsError::Other(anyhow::anyhow!(
                "Admin observer request failed: {}",
                sanitize_for_terminal(&error.to_string())
            ))
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(GwsError::Api {
            code: status.as_u16(),
            message: sanitize_for_terminal(&body),
            reason: "admin_observer_request_failed".to_string(),
            enable_url: None,
        });
    }

    let value = response.json::<Value>().await.map_err(|error| {
        GwsError::Other(anyhow::anyhow!(
            "Admin observer response was not valid JSON: {}",
            sanitize_for_terminal(&error.to_string())
        ))
    })?;
    Ok(activities_from_response(&value).0)
}

async fn fetch_inventory_request(
    client: &reqwest::Client,
    request: &InventoryRequest,
    token: &str,
) -> Result<Value, GwsError> {
    if request.method != reqwest::Method::GET {
        return Err(GwsError::Validation(
            "Admin inventory request rejected: only GET is allowed".to_string(),
        ));
    }

    let response = client
        .get(request.url)
        .query(&request.query)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| {
            GwsError::Other(anyhow::anyhow!(
                "Admin inventory request failed: {}",
                sanitize_for_terminal(&error.to_string())
            ))
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(GwsError::Api {
            code: status.as_u16(),
            message: sanitize_for_terminal(&body),
            reason: "admin_inventory_request_failed".to_string(),
            enable_url: None,
        });
    }

    response.json::<Value>().await.map_err(|error| {
        GwsError::Other(anyhow::anyhow!(
            "Admin inventory response was not valid JSON: {}",
            sanitize_for_terminal(&error.to_string())
        ))
    })
}

async fn handle_admin_observer(matches: &ArgMatches) -> Result<(), GwsError> {
    let include_devices = matches.get_flag("include-devices");
    let output_format = matches
        .get_one::<String>("format")
        .map(String::as_str)
        .unwrap_or("json");
    let requests = admin_observer_requests(include_devices);
    let mut scopes: Vec<&str> = requests.iter().map(|request| request.scope).collect();
    scopes.sort_unstable();
    scopes.dedup();

    let token = auth::get_token(&scopes)
        .await
        .map_err(|error| GwsError::Auth(format!("Authentication failed: {error:#}")))?;
    let client = crate::client::build_client()?;
    let mut inventory = serde_json::Map::new();
    for request in &requests {
        let value = fetch_inventory_request(&client, request, &token).await?;
        inventory.insert(request.label.to_string(), value);
    }

    let report = json!({
        "mode": "read-only",
        "generatedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        "includeDevices": include_devices,
        "sections": inventory,
    });
    let format = crate::formatter::OutputFormat::parse(output_format)
        .map_err(|unknown| GwsError::Validation(format!("Unknown output format '{unknown}'")))?;
    println!("{}", crate::formatter::format_value(&report, &format));
    Ok(())
}

async fn handle_security_observer(matches: &ArgMatches) -> Result<(), GwsError> {
    let lookback_minutes = matches
        .get_one::<u64>("lookback-minutes")
        .copied()
        .unwrap_or(15);
    let max_results = matches
        .get_one::<u32>("max-results")
        .copied()
        .unwrap_or(100);
    let min_severity = matches
        .get_one::<String>("min-severity")
        .map(String::as_str)
        .unwrap_or("high");
    let output_format = matches
        .get_one::<String>("format")
        .map(String::as_str)
        .unwrap_or("json");
    let include_posture = matches.get_flag("include-posture");
    let include_microsoft = matches.get_flag("microsoft-graph");
    let inactive_days = matches
        .get_one::<u32>("inactive-days")
        .copied()
        .unwrap_or(90) as i64;
    let config = security_observer_config(matches);

    let end_time = Utc::now();
    let start_time = end_time - Duration::minutes(lookback_minutes as i64);
    let start_rfc3339 = start_time.to_rfc3339_opts(SecondsFormat::Secs, true);
    let end_rfc3339 = end_time.to_rfc3339_opts(SecondsFormat::Secs, true);
    let requests = security_observer_requests(&start_rfc3339, max_results);
    let client = crate::client::build_client()?;
    let microsoft_token = if include_microsoft {
        Some(microsoft_graph_auth::resolve_access_token(&client).await?)
    } else {
        None
    };
    let mut scopes: Vec<&str> = requests.iter().map(|request| request.scope).collect();
    if include_posture {
        scopes.extend([
            security_posture::GOOGLE_USER_SCOPE,
            security_posture::GOOGLE_ROLE_SCOPE,
        ]);
    }
    scopes.sort_unstable();
    scopes.dedup();
    let token = auth::get_token(&scopes)
        .await
        .map_err(|error| GwsError::Auth(format!("Authentication failed: {error:#}")))?;

    let mut activities = Vec::new();
    for request in &requests {
        activities.extend(fetch_observer_request(&client, request, &token).await?);
    }

    let activity_count = activities.len();
    let (findings, telemetry) = analyze_activities(&activities, &config);
    let mut findings = filter_findings(findings, min_severity);
    let ip_intelligence = if matches.get_flag("ip-intelligence") {
        let ipinfo_token = std::env::var(ip_intelligence::IPINFO_TOKEN_ENV).ok();
        let addresses = findings
            .iter()
            .filter_map(|finding| finding.ip_address.clone())
            .collect::<Vec<_>>();
        let (entries, summary) =
            ip_intelligence::enrich_ip_addresses(&client, addresses, ipinfo_token.as_deref()).await;
        for finding in &mut findings {
            finding.ip_intelligence = finding
                .ip_address
                .as_ref()
                .and_then(|address| entries.get(address))
                .cloned();
        }
        summary
    } else {
        ip_intelligence::IpIntelligenceSummary::disabled()
    };
    let recommendations = build_recommendations(&findings, &telemetry);
    let security_posture = if include_posture {
        let google_signal_contexts = findings
            .iter()
            .map(|finding| security_posture::GoogleSignalContext {
                event_id: finding.event_id.clone(),
                actor: finding.actor.clone(),
                rule: finding.rule.to_string(),
                event_time: finding.event_time.clone(),
                provenance: finding.provenance.unwrap_or_else(|| {
                    provenance::ProvenanceV1::google_unknown(finding.event_time.as_deref())
                }),
            })
            .collect::<Vec<_>>();
        Some(
            security_posture::collect_security_posture(
                &client,
                &token,
                microsoft_token.as_ref().map(|token| token.as_str()),
                &google_signal_contexts,
                end_time,
                inactive_days,
                &start_rfc3339,
            )
            .await?,
        )
    } else {
        None
    };
    let mut report = json!({
        "mode": "read-only",
        "window": {
            "startTime": start_rfc3339,
            "endTime": end_rfc3339,
            "lookbackMinutes": lookback_minutes,
        },
        "sources": requests
            .iter()
            .map(|request| request.application_name)
            .collect::<Vec<_>>(),
        "activitiesAnalyzed": activity_count,
        "findingCount": findings.len(),
        "findings": findings,
        "ipIntelligence": ip_intelligence,
        "telemetry": telemetry,
        "recommendationCount": recommendations.len(),
        "recommendations": recommendations,
    });
    if let Some(posture) = security_posture {
        insert_security_posture(&mut report, posture)?;
    }
    let format = crate::formatter::OutputFormat::parse(output_format)
        .map_err(|unknown| GwsError::Validation(format!("Unknown output format '{unknown}'")))?;
    println!("{}", crate::formatter::format_value(&report, &format));
    Ok(())
}

fn insert_security_posture(
    report: &mut Value,
    posture: security_posture::SecurityPostureReport,
) -> Result<(), GwsError> {
    let monitor_integration = monitor_contract::build_monitor_integration(&posture);
    let report_object = report
        .as_object_mut()
        .expect("security observer report is an object");
    report_object.insert(
        "securityPosture".to_string(),
        serde_json::to_value(posture).map_err(|error| {
            GwsError::Other(anyhow::anyhow!(
                "Could not serialize security posture report: {error}"
            ))
        })?,
    );
    report_object.insert(
        "monitorIntegration".to_string(),
        serde_json::to_value(monitor_integration).map_err(|error| {
            GwsError::Other(anyhow::anyhow!(
                "Could not serialize monitor integration contract: {error}"
            ))
        })?,
    );
    Ok(())
}

fn read_monitor_plan_json(path: &str, flag_name: &str) -> Result<Value, GwsError> {
    let safe_path = crate::validate::validate_safe_file_path(path, flag_name)?;
    let contents = std::fs::read_to_string(&safe_path).map_err(|error| {
        GwsError::Validation(format!(
            "Could not read monitor plan input: {}",
            sanitize_for_terminal(&error.to_string())
        ))
    })?;
    serde_json::from_str(&contents).map_err(|error| {
        GwsError::Validation(format!(
            "Monitor plan input is not valid JSON: {}",
            sanitize_for_terminal(&error.to_string())
        ))
    })
}

fn read_security_monitor_correlation_json(path: &str) -> Result<Value, GwsError> {
    let safe_path = crate::validate::validate_safe_file_path(path, "--input")?;
    let metadata = std::fs::metadata(&safe_path).map_err(|error| {
        GwsError::Validation(format!(
            "Could not inspect correlation input: {}",
            sanitize_for_terminal(&error.to_string())
        ))
    })?;
    if metadata.len() > MAX_CORRELATION_INPUT_BYTES {
        return Err(GwsError::Validation(format!(
            "Correlation input exceeds the {MAX_CORRELATION_INPUT_BYTES}-byte safety bound"
        )));
    }
    let contents = std::fs::read_to_string(&safe_path).map_err(|error| {
        GwsError::Validation(format!(
            "Could not read correlation input: {}",
            sanitize_for_terminal(&error.to_string())
        ))
    })?;
    if contents.len() as u64 > MAX_CORRELATION_INPUT_BYTES {
        return Err(GwsError::Validation(format!(
            "Correlation input exceeds the {MAX_CORRELATION_INPUT_BYTES}-byte safety bound"
        )));
    }
    serde_json::from_str(&contents).map_err(|error| {
        GwsError::Validation(format!(
            "Correlation input is not valid JSON: {}",
            sanitize_for_terminal(&error.to_string())
        ))
    })
}

fn handle_security_monitor_plan(matches: &ArgMatches) -> Result<(), GwsError> {
    if !matches.get_flag("dry-run") {
        return Err(GwsError::Validation(
            "+security-monitor-plan requires --dry-run; external cutover is not implemented"
                .to_string(),
        ));
    }
    let input_path = matches
        .get_one::<String>("input")
        .expect("input is required by clap");
    let existing_path = matches
        .get_one::<String>("existing")
        .expect("existing is required by clap");
    let input = read_monitor_plan_json(input_path, "--input")?;
    let existing = read_monitor_plan_json(existing_path, "--existing")?;
    let bundle = monitor_cutover::build_cutover_bundle(&input, &existing).map_err(|error| {
        GwsError::Validation(format!("Monitor cutover bundle rejected: {error}"))
    })?;
    let value = serde_json::to_value(bundle).map_err(|error| {
        GwsError::Other(anyhow::anyhow!(
            "Could not serialize monitor cutover bundle: {error}"
        ))
    })?;
    let output_format = matches
        .get_one::<String>("format")
        .map(String::as_str)
        .unwrap_or("json");
    let format = crate::formatter::OutputFormat::parse(output_format)
        .map_err(|unknown| GwsError::Validation(format!("Unknown output format '{unknown}'")))?;
    println!("{}", crate::formatter::format_value(&value, &format));
    Ok(())
}

fn handle_security_monitor_correlate(matches: &ArgMatches) -> Result<(), GwsError> {
    if !matches.get_flag("dry-run") {
        return Err(GwsError::Validation(
            "+security-monitor-correlate requires --dry-run; external correlation is not implemented"
                .to_string(),
        ));
    }
    let input_path = matches
        .get_one::<String>("input")
        .expect("input is required by clap");
    let window_minutes = matches
        .get_one::<u64>("window-minutes")
        .copied()
        .unwrap_or(30);
    let max_correlations = matches
        .get_one::<u32>("max-correlations")
        .copied()
        .unwrap_or(50) as usize;
    let input = read_security_monitor_correlation_json(input_path)?;
    let output = monitor_correlation::correlate_report(&input, window_minutes, max_correlations)
        .map_err(|error| GwsError::Validation(format!("Security correlation rejected: {error}")))?;
    let output_format = matches
        .get_one::<String>("format")
        .map(String::as_str)
        .unwrap_or("json");
    let format = crate::formatter::OutputFormat::parse(output_format)
        .map_err(|unknown| GwsError::Validation(format!("Unknown output format '{unknown}'")))?;
    println!("{}", crate::formatter::format_value(&output, &format));
    Ok(())
}

fn handle_security_monitor_program(matches: &ArgMatches) -> Result<(), GwsError> {
    if !matches.get_flag("simulate") {
        return Err(GwsError::Validation(
            "+security-monitor-program requires --simulate; external execution is not implemented"
                .to_string(),
        ));
    }
    let bundle_path = matches
        .get_one::<String>("bundle")
        .expect("bundle is required by clap");
    let target_path = matches
        .get_one::<String>("target")
        .expect("target is required by clap");
    let policy_path = matches
        .get_one::<String>("policy")
        .expect("policy is required by clap");
    let bundle = read_monitor_plan_json(bundle_path, "--bundle")?;
    let target = read_monitor_plan_json(target_path, "--target")?;
    let policy = read_monitor_plan_json(policy_path, "--policy")?;
    let program =
        monitor_program::compile_execution_program(&bundle, &target, &policy).map_err(|error| {
            GwsError::Validation(format!("Monitor execution program rejected: {error}"))
        })?;
    let failure_phase = matches
        .get_one::<String>("failure-phase")
        .map(String::as_str);
    let simulation =
        monitor_program::simulate_execution_program(&program, failure_phase).map_err(|error| {
            GwsError::Validation(format!("Monitor execution simulation rejected: {error}"))
        })?;
    let replay = if failure_phase.is_none() {
        Some(
            monitor_program::replay_execution_program(&program, &simulation).map_err(|error| {
                GwsError::Validation(format!("Monitor execution replay rejected: {error}"))
            })?,
        )
    } else {
        None
    };
    let output = json!({
        "program": program,
        "simulation": simulation,
        "replay": replay,
        "externalWritesAllowed": false,
        "liveApplyAvailable": false,
        "notificationEffective": "suppress",
        "humanAuthorizationRequired": true,
    });
    let output_format = matches
        .get_one::<String>("format")
        .map(String::as_str)
        .unwrap_or("json");
    let format = crate::formatter::OutputFormat::parse(output_format)
        .map_err(|unknown| GwsError::Validation(format!("Unknown output format '{unknown}'")))?;
    println!("{}", crate::formatter::format_value(&output, &format));
    Ok(())
}

impl Helper for AdminHelper {
    fn inject_commands(
        &self,
        mut cmd: Command,
        _doc: &crate::discovery::RestDescription,
    ) -> Command {
        cmd = cmd.subcommand(build_admin_observer_cmd());
        cmd = cmd.subcommand(build_security_observer_cmd());
        cmd = cmd.subcommand(build_security_monitor_plan_cmd());
        cmd = cmd.subcommand(build_security_monitor_correlate_cmd());
        cmd = cmd.subcommand(build_security_monitor_program_cmd());
        cmd
    }

    fn handle<'a>(
        &'a self,
        _doc: &'a crate::discovery::RestDescription,
        matches: &'a ArgMatches,
        _sanitize_config: &'a crate::helpers::modelarmor::SanitizeConfig,
    ) -> Pin<Box<dyn Future<Output = Result<bool, GwsError>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(observer_matches) = matches.subcommand_matches("+admin-observer") {
                handle_admin_observer(observer_matches).await?;
                return Ok(true);
            }
            if let Some(observer_matches) = matches.subcommand_matches("+security-observer") {
                handle_security_observer(observer_matches).await?;
                return Ok(true);
            }
            if let Some(plan_matches) = matches.subcommand_matches("+security-monitor-plan") {
                handle_security_monitor_plan(plan_matches)?;
                return Ok(true);
            }
            if let Some(correlation_matches) =
                matches.subcommand_matches("+security-monitor-correlate")
            {
                handle_security_monitor_correlate(correlation_matches)?;
                return Ok(true);
            }
            if let Some(program_matches) = matches.subcommand_matches("+security-monitor-program") {
                handle_security_monitor_program(program_matches)?;
                return Ok(true);
            }
            Ok(false)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn posture_report_adds_versioned_monitor_integration_contract() {
        let posture = security_posture::SecurityPostureReport {
            schema_version: "security_intelligence_v1",
            generated_at: "2026-08-05T12:00:00Z".to_string(),
            coverage_complete: true,
            coverage: Vec::new(),
            identity_count: 0,
            identity_posture: Vec::new(),
            control_posture: Vec::new(),
            cross_cloud_correlations: Vec::new(),
            signal_findings: Vec::new(),
            microsoft_secure_score: None,
        };
        let mut report = json!({"mode": "read-only"});

        insert_security_posture(&mut report, posture).expect("posture should serialize");

        assert!(report
            .pointer("/monitorIntegration/security_intelligence_monitor_v1")
            .is_some());
    }

    fn test_config() -> SecurityObserverConfig {
        SecurityObserverConfig {
            trusted_domains: HashSet::from(["wearenexa.com".to_string()]),
            consumer_domains: HashSet::from(["gmail.com".to_string(), "outlook.com".to_string()]),
            bulk_download_threshold: 5,
            bulk_api_access_threshold: 5,
            bulk_delete_threshold: 5,
        }
    }

    fn test_analyze(activities: &[Value]) -> Vec<Finding> {
        analyze_activities(activities, &test_config()).0
    }

    #[test]
    fn injects_admin_and_security_observer_commands() {
        let helper = AdminHelper;
        let cmd = helper.inject_commands(
            Command::new("admin"),
            &crate::discovery::RestDescription::default(),
        );
        let names: Vec<_> = cmd.get_subcommands().map(Command::get_name).collect();

        assert!(names.contains(&"+admin-observer"));
        assert!(names.contains(&"+security-observer"));
        assert!(names.contains(&"+security-monitor-plan"));
        assert!(names.contains(&"+security-monitor-correlate"));
        assert!(names.contains(&"+security-monitor-program"));
    }

    #[test]
    fn microsoft_graph_help_names_durable_certificate_configuration() {
        let help = build_security_observer_cmd().render_help().to_string();

        for variable in [
            "MICROSOFT_GRAPH_TENANT_ID",
            "MICROSOFT_GRAPH_CLIENT_ID",
            "MICROSOFT_GRAPH_CERTIFICATE_FILE",
            "MICROSOFT_GRAPH_PRIVATE_KEY_FILE",
        ] {
            assert!(
                help.contains(variable),
                "Microsoft certificate configuration should document {variable}"
            );
        }
    }

    #[test]
    fn security_monitor_correlation_command_is_local_and_bounded() {
        let matches = build_security_monitor_correlate_cmd()
            .try_get_matches_from([
                "+security-monitor-correlate",
                "--input",
                "evidence/report.json",
                "--dry-run",
                "--window-minutes",
                "60",
                "--max-correlations",
                "25",
            ])
            .expect("bounded local correlation arguments should parse");

        assert!(matches.get_flag("dry-run"));
        assert_eq!(matches.get_one::<u64>("window-minutes"), Some(&60));
        assert_eq!(matches.get_one::<u32>("max-correlations"), Some(&25));
        assert!(build_security_monitor_correlate_cmd()
            .try_get_matches_from([
                "+security-monitor-correlate",
                "--input",
                "evidence/report.json",
            ])
            .is_err());
        assert!(build_security_monitor_correlate_cmd()
            .try_get_matches_from([
                "+security-monitor-correlate",
                "--input",
                "evidence/report.json",
                "--dry-run",
                "--window-minutes",
                "0",
            ])
            .is_err());
        assert!(build_security_monitor_correlate_cmd()
            .try_get_matches_from([
                "+security-monitor-correlate",
                "--input",
                "evidence/report.json",
                "--dry-run",
                "--max-correlations",
                "101",
            ])
            .is_err());
    }

    #[test]
    fn security_monitor_plan_command_is_explicitly_dry_run() {
        let matches = build_security_monitor_plan_cmd()
            .try_get_matches_from([
                "+security-monitor-plan",
                "--input",
                "evidence/report.json",
                "--existing",
                "evidence/monitor-target.json",
                "--dry-run",
            ])
            .expect("monitor plan arguments should parse");

        assert!(matches.get_flag("dry-run"));
        assert_eq!(
            matches.get_one::<String>("input").map(String::as_str),
            Some("evidence/report.json")
        );
        assert_eq!(
            matches.get_one::<String>("existing").map(String::as_str),
            Some("evidence/monitor-target.json")
        );
    }

    #[test]
    fn security_monitor_plan_rejects_implicit_external_execution() {
        let matches = build_security_monitor_plan_cmd()
            .try_get_matches_from([
                "+security-monitor-plan",
                "--input",
                "evidence/report.json",
                "--existing",
                "evidence/monitor-target.json",
            ])
            .expect("arguments should parse before the explicit dry-run gate");

        let error = handle_security_monitor_plan(&matches)
            .expect_err("live execution must not be available");
        assert!(error.to_string().contains("requires --dry-run"));
    }

    #[test]
    fn security_monitor_program_requires_explicit_local_simulation() {
        let matches = build_security_monitor_program_cmd()
            .try_get_matches_from([
                "+security-monitor-program",
                "--bundle",
                "evidence/bundle.json",
                "--target",
                "evidence/target.json",
                "--policy",
                "evidence/policy.json",
                "--simulate",
                "--failure-phase",
                "findings_writes",
            ])
            .expect("program arguments should parse");

        assert!(matches.get_flag("simulate"));
        assert_eq!(
            matches
                .get_one::<String>("failure-phase")
                .map(String::as_str),
            Some("findings_writes")
        );
    }

    #[test]
    fn suspicious_login_is_a_critical_finding() {
        let activities = vec![json!({
            "id": {
                "time": "2026-07-23T18:00:00.000Z",
                "applicationName": "login",
                "uniqueQualifier": "event-1"
            },
            "actor": {"email": "user@wearenexa.com"},
            "ipAddress": "203.0.113.10",
            "events": [{
                "type": "account_warning",
                "name": "suspicious_login",
                "parameters": [{
                    "name": "affected_email_address",
                    "value": "user@wearenexa.com"
                }]
            }]
        })];

        let findings = test_analyze(&activities);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].rule, "google_suspicious_login");
        assert_eq!(findings[0].actor, "user@wearenexa.com");
        assert_eq!(findings[0].ip_address.as_deref(), Some("203.0.113.10"));
        assert_eq!(findings[0].event_id, "login:event-1:suspicious_login:0");
        assert_eq!(
            findings[0].event_time.as_deref(),
            Some("2026-07-23T18:00:00.000Z")
        );
        assert_eq!(findings[0].source, "login");
        assert_eq!(findings[0].occurrences, 1);
    }

    #[test]
    fn google_compromise_signals_are_all_critical() {
        let event_names = [
            "suspicious_login",
            "suspicious_login_less_secure_app",
            "suspicious_programmatic_login",
            "user_signed_out_due_to_suspicious_session_cookie",
            "account_disabled_password_leak",
            "account_disabled_hijacked",
        ];
        let activities: Vec<_> = event_names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                json!({
                    "id": {"applicationName": "login", "uniqueQualifier": index.to_string()},
                    "actor": {"email": "user@wearenexa.com"},
                    "events": [{"name": name}]
                })
            })
            .collect();

        let findings = test_analyze(&activities);

        assert_eq!(findings.len(), event_names.len());
        assert!(findings
            .iter()
            .all(|finding| finding.severity == Severity::Critical));
    }

    #[test]
    fn suspicious_success_and_identity_weakening_are_high_severity() {
        let activities = vec![
            json!({
                "actor": {"email": "user@wearenexa.com"},
                "events": [{
                    "name": "login_success",
                    "parameters": [{"name": "is_suspicious", "boolValue": true}]
                }]
            }),
            json!({
                "actor": {"email": "user@wearenexa.com"},
                "events": [{"name": "2sv_disable"}]
            }),
            json!({
                "actor": {"email": "user@wearenexa.com"},
                "events": [{"name": "passkey_removed"}]
            }),
            json!({
                "actor": {"email": "user@wearenexa.com"},
                "events": [{"name": "recovery_email_edit"}]
            }),
            json!({
                "actor": {"email": "admin@wearenexa.com"},
                "events": [{"name": "CHANGE_CAA_APP_ASSIGNMENTS"}]
            }),
        ];

        let findings = test_analyze(&activities);

        assert_eq!(findings.len(), activities.len());
        assert!(findings
            .iter()
            .all(|finding| finding.severity == Severity::High));
    }

    #[test]
    fn ordinary_successful_login_is_not_a_finding() {
        let activities = vec![json!({
            "actor": {"email": "user@wearenexa.com"},
            "events": [{
                "name": "login_success",
                "parameters": [{"name": "is_suspicious", "boolValue": false}]
            }]
        })];

        assert!(test_analyze(&activities).is_empty());
    }

    #[test]
    fn five_failed_logins_for_one_actor_raise_one_high_finding() {
        let activities: Vec<_> = (0..5)
            .map(|index| {
                json!({
                    "id": {
                        "time": format!("2026-07-23T18:00:0{index}.000Z"),
                        "applicationName": "login",
                        "uniqueQualifier": index.to_string()
                    },
                    "actor": {"email": "user@wearenexa.com"},
                    "ipAddress": "203.0.113.20",
                    "events": [{"name": "login_failure"}]
                })
            })
            .collect();

        let findings = test_analyze(&activities);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].rule, "repeated_login_failures");
        assert_eq!(findings[0].actor, "user@wearenexa.com");
        assert_eq!(findings[0].event_id, "login:4:repeated_login_failures");
        assert_eq!(findings[0].occurrences, 5);
    }

    #[test]
    fn security_observer_command_has_bounded_read_only_controls() {
        let matches = build_security_observer_cmd()
            .try_get_matches_from(["+security-observer"])
            .expect("defaults should parse");

        assert_eq!(
            matches.get_one::<u64>("lookback-minutes").copied(),
            Some(15)
        );
        assert_eq!(matches.get_one::<u32>("max-results").copied(), Some(100));
        assert_eq!(
            matches
                .get_one::<String>("min-severity")
                .map(String::as_str),
            Some("high")
        );
        assert!(!matches.get_flag("ip-intelligence"));
        assert!(build_security_observer_cmd()
            .try_get_matches_from(["+security-observer", "--ip-intelligence"])
            .expect("IP intelligence should be opt-in")
            .get_flag("ip-intelligence"));
        assert!(build_security_observer_cmd()
            .try_get_matches_from(["+security-observer", "--lookback-minutes", "0"])
            .is_err());
        assert!(build_security_observer_cmd()
            .try_get_matches_from(["+security-observer", "--min-severity", "urgent"])
            .is_err());
    }

    #[test]
    fn security_observer_accepts_opt_in_posture_and_microsoft_sources() {
        let matches = build_security_observer_cmd()
            .try_get_matches_from([
                "+security-observer",
                "--include-posture",
                "--microsoft-graph",
                "--inactive-days",
                "120",
            ])
            .expect("posture flags should be accepted");

        assert!(matches.get_flag("include-posture"));
        assert!(matches.get_flag("microsoft-graph"));
        assert_eq!(matches.get_one::<u32>("inactive-days"), Some(&120));
    }

    #[test]
    fn security_observer_keeps_posture_flags_opt_in() {
        assert!(build_security_observer_cmd()
            .try_get_matches_from(["+security-observer", "--microsoft-graph"])
            .is_err());
        assert!(build_security_observer_cmd()
            .try_get_matches_from(["+security-observer", "--inactive-days", "90"])
            .is_err());
    }

    #[test]
    fn security_observer_plan_contains_only_reports_get_requests() {
        let requests = security_observer_requests("2026-07-23T18:00:00Z", 100);

        assert_eq!(requests.len(), 5);
        assert_eq!(
            requests
                .iter()
                .map(|request| request.application_name)
                .collect::<Vec<_>>(),
            ["login", "admin", "token", "drive", "rules"]
        );
        assert!(requests
            .iter()
            .all(|request| request.method == reqwest::Method::GET));
        assert!(requests.iter().all(|request| request.url.starts_with(
            "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/"
        )));
        assert!(requests
            .iter()
            .all(|request| request.scope == ADMIN_REPORTS_AUDIT_READONLY_SCOPE));
    }

    #[test]
    fn finding_serializes_as_stable_machine_readable_json() {
        let finding = Finding {
            event_id: "login:event-30:account_disabled_password_leak:0".to_string(),
            event_time: Some("2026-07-23T18:00:00.000Z".to_string()),
            source: "login".to_string(),
            event_name: "account_disabled_password_leak".to_string(),
            severity: Severity::Critical,
            rule: "password_leak",
            reason: reason_for_rule("password_leak"),
            actor: "user@wearenexa.com".to_string(),
            provenance: None,
            ip_address: Some("203.0.113.30".to_string()),
            occurrences: 1,
            evidence: BTreeMap::new(),
            target: None,
            resource_id: None,
            resource_type: None,
            visibility: None,
            originating_app_id: None,
            ip_intelligence: None,
        };

        let value = serde_json::to_value(finding).expect("finding should serialize");

        assert_eq!(value["severity"], "critical");
        assert_eq!(
            value["eventId"],
            "login:event-30:account_disabled_password_leak:0"
        );
        assert_eq!(value["eventTime"], "2026-07-23T18:00:00.000Z");
        assert_eq!(value["source"], "login");
        assert_eq!(value["rule"], "password_leak");
        assert_eq!(value["actor"], "user@wearenexa.com");
        assert_eq!(value["ipAddress"], "203.0.113.30");
        assert_eq!(value["occurrences"], 1);
        assert!(value.get("ipIntelligence").is_none());
    }

    #[test]
    fn google_explicit_actor_has_versioned_provenance() {
        let findings = test_analyze(&[json!({
            "id": {
                "applicationName": "login",
                "uniqueQualifier": "google-actor",
                "time": "2026-08-02T12:01:00Z"
            },
            "actor": {"email": "Admin@Example.com"},
            "events": [{"name": "suspicious_login"}]
        })]);
        let value = serde_json::to_value(&findings[0]).expect("finding should serialize");

        assert_eq!(
            value["provenance"],
            json!({
                "contractVersion": "security_intelligence_provenance_v1",
                "actorRole": "humanUser",
                "actorSource": "googleActor",
                "temporalBasis": "providerEventTime"
            })
        );
    }

    #[test]
    fn google_resource_owner_without_actor_is_not_promoted_to_actor() {
        let findings = test_analyze(&[json!({
            "id": {
                "applicationName": "rules",
                "uniqueQualifier": "resource-owner",
                "time": "2026-08-02T12:02:00Z"
            },
            "events": [{
                "name": "content_matched",
                "parameters": [
                    {"name": "rule_type", "value": "DLP"},
                    {"name": "resource_owner_email", "value": "owner@wearenexa.com"},
                    {"name": "resource_id", "value": "resource-1"}
                ]
            }]
        })]);
        let value = serde_json::to_value(&findings[0]).expect("finding should serialize");

        assert_eq!(value["actor"], "(unknown)");
        assert_eq!(
            value["provenance"],
            json!({
                "contractVersion": "security_intelligence_provenance_v1",
                "actorRole": "resourceOwner",
                "actorSource": "googleResourceOwner",
                "temporalBasis": "providerEventTime"
            })
        );
        assert!(!serde_json::to_string(&value)
            .expect("finding should serialize")
            .contains("owner@wearenexa.com"));
    }

    #[test]
    fn omits_empty_event_parameter_values_from_finding_evidence() {
        let findings = test_analyze(&[json!({
            "id": {
                "applicationName": "rules",
                "uniqueQualifier": "synthetic-empty-evidence",
                "time": "2026-08-02T12:01:00Z"
            },
            "actor": {"email": "first@example.com"},
            "events": [{
                "name": "message_send_warned",
                "parameters": [
                    {"name": "severity", "value": ""},
                    {"name": "resource_id", "value": "message-<synthetic@example.invalid>"}
                ]
            }]
        })]);

        assert_eq!(findings.len(), 1);
        assert!(!findings[0].evidence.contains_key("severity"));
    }

    #[test]
    fn extracts_activity_items_and_next_page_token() {
        let response = json!({
            "items": [
                {"id": {"uniqueQualifier": "one"}},
                {"id": {"uniqueQualifier": "two"}}
            ],
            "nextPageToken": "next-token"
        });

        let (activities, next_page) = activities_from_response(&response);

        assert_eq!(activities.len(), 2);
        assert_eq!(next_page.as_deref(), Some("next-token"));
    }

    #[test]
    fn critical_filter_excludes_high_findings() {
        let findings = vec![
            Finding {
                event_id: "login:event-high:2sv_disable:0".to_string(),
                event_time: None,
                source: "login".to_string(),
                event_name: "2sv_disable".to_string(),
                severity: Severity::High,
                rule: "two_step_verification_disabled",
                reason: reason_for_rule("two_step_verification_disabled"),
                actor: "user@wearenexa.com".to_string(),
                provenance: None,
                ip_address: None,
                occurrences: 1,
                evidence: BTreeMap::new(),
                target: None,
                resource_id: None,
                resource_type: None,
                visibility: None,
                originating_app_id: None,
                ip_intelligence: None,
            },
            Finding {
                event_id: "login:event-critical:account_disabled_password_leak:0".to_string(),
                event_time: None,
                source: "login".to_string(),
                event_name: "account_disabled_password_leak".to_string(),
                severity: Severity::Critical,
                rule: "password_leak",
                reason: reason_for_rule("password_leak"),
                actor: "user@wearenexa.com".to_string(),
                provenance: None,
                ip_address: None,
                occurrences: 1,
                evidence: BTreeMap::new(),
                target: None,
                resource_id: None,
                resource_type: None,
                visibility: None,
                originating_app_id: None,
                ip_intelligence: None,
            },
        ];

        let filtered = filter_findings(findings, "critical");

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].severity, Severity::Critical);
    }

    #[test]
    fn admin_observer_plan_is_get_only_and_uses_readonly_scopes() {
        let requests = admin_observer_requests(false);

        assert_eq!(
            requests
                .iter()
                .map(|request| request.label)
                .collect::<Vec<_>>(),
            [
                "users",
                "groups",
                "organizationalUnits",
                "roles",
                "roleAssignments",
                "domains"
            ]
        );
        assert!(requests
            .iter()
            .all(|request| request.method == reqwest::Method::GET));
        assert!(requests
            .iter()
            .all(|request| request.scope.ends_with(".readonly")));
        assert_eq!(admin_observer_requests(true).len(), requests.len() + 2);
    }

    #[test]
    fn role_inventory_respects_directory_api_page_limit() {
        let requests = admin_observer_requests(false);

        for label in ["roles", "roleAssignments"] {
            let request = requests
                .iter()
                .find(|request| request.label == label)
                .expect("role request should exist");
            assert_eq!(
                request
                    .query
                    .iter()
                    .find(|(name, _)| *name == "maxResults")
                    .map(|(_, value)| *value),
                Some("100")
            );
        }
    }

    #[test]
    fn admin_observer_devices_are_opt_in() {
        let defaults = build_admin_observer_cmd()
            .try_get_matches_from(["+admin-observer"])
            .expect("defaults should parse");
        assert!(!defaults.get_flag("include-devices"));

        let with_devices = build_admin_observer_cmd()
            .try_get_matches_from(["+admin-observer", "--include-devices"])
            .expect("device flag should parse");
        assert!(with_devices.get_flag("include-devices"));
    }

    #[test]
    fn privilege_and_domain_wide_delegation_changes_are_critical() {
        let activities = vec![
            json!({
                "actor": {"email": "admin@wearenexa.com"},
                "events": [{"name": "ASSIGN_ROLE"}]
            }),
            json!({
                "actor": {"email": "admin@wearenexa.com"},
                "events": [{"name": "AUTHORIZE_API_CLIENT_ACCESS"}]
            }),
        ];

        let findings = test_analyze(&activities);

        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .all(|finding| finding.severity == Severity::Critical));
        assert_eq!(findings[0].rule, "admin_role_assigned");
        assert_eq!(findings[1].rule, "domain_wide_delegation_authorized");
    }

    #[test]
    fn oauth_authorization_is_high_severity() {
        let activities = vec![json!({
            "actor": {"email": "user@wearenexa.com"},
            "events": [{
                "name": "authorize",
                "parameters": [
                    {"name": "app_name", "value": "Unfamiliar App"},
                    {"name": "scope", "value": "https://www.googleapis.com/auth/drive"}
                ]
            }]
        })];

        let findings = test_analyze(&activities);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].rule, "oauth_application_authorized");
        assert_eq!(findings[0].event_name, "authorize");
        assert_eq!(
            findings[0].evidence.get("app_name").map(String::as_str),
            Some("Unfamiliar App")
        );
        assert!(findings[0].reason.contains("client"));
    }

    #[test]
    fn public_link_and_external_ownership_are_critical() {
        let activities = vec![
            json!({
                "id": {"applicationName": "drive", "uniqueQualifier": "public-link"},
                "actor": {"email": "user@wearenexa.com"},
                "events": [{
                    "name": "change_document_visibility",
                    "parameters": [
                        {"name": "doc_id", "value": "doc-public"},
                        {"name": "doc_type", "value": "spreadsheet"},
                        {"name": "new_value", "value": "people_with_link"}
                    ]
                }]
            }),
            json!({
                "id": {"applicationName": "drive", "uniqueQualifier": "owner-transfer"},
                "actor": {"email": "user@wearenexa.com"},
                "events": [{
                    "name": "change_user_access",
                    "parameters": [
                        {"name": "doc_id", "value": "doc-owned"},
                        {"name": "target_user", "value": "personal@gmail.com"},
                        {"name": "new_value", "value": "owner"},
                        {"name": "visibility_change", "value": "external"}
                    ]
                }]
            }),
        ];

        let findings = test_analyze(&activities);

        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .all(|finding| finding.severity == Severity::Critical));
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "drive_public_link_enabled"));
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "drive_external_ownership_transfer"));
    }

    #[test]
    fn consumer_share_is_high_and_trusted_external_share_is_not_flagged() {
        let activities = vec![
            json!({
                "id": {"applicationName": "drive", "uniqueQualifier": "consumer"},
                "actor": {"email": "user@wearenexa.com"},
                "events": [{
                    "name": "change_user_access",
                    "parameters": [
                        {"name": "target_user", "value": "person@gmail.com"},
                        {"name": "new_value", "value": "can_view"},
                        {"name": "visibility_change", "value": "external"}
                    ]
                }]
            }),
            json!({
                "id": {"applicationName": "drive", "uniqueQualifier": "partner"},
                "actor": {"email": "user@wearenexa.com"},
                "events": [{
                    "name": "change_user_access",
                    "parameters": [
                        {"name": "target_user", "value": "partner@approved.example"},
                        {"name": "new_value", "value": "can_view"},
                        {"name": "visibility_change", "value": "external"}
                    ]
                }]
            }),
        ];
        let mut config = test_config();
        config
            .trusted_domains
            .insert("approved.example".to_string());

        let findings = analyze_activities(&activities, &config).0;

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "drive_shared_with_consumer_account");
        assert_eq!(findings[0].target.as_deref(), Some("person@gmail.com"));
    }

    #[test]
    fn bulk_download_counts_unique_documents() {
        let activities: Vec<_> = (0..5)
            .map(|index| {
                json!({
                    "id": {
                        "time": format!("2026-07-23T18:00:0{index}.000Z"),
                        "applicationName": "drive",
                        "uniqueQualifier": index.to_string()
                    },
                    "actor": {"email": "user@wearenexa.com"},
                    "ipAddress": "203.0.113.40",
                    "events": [{
                        "name": "download",
                        "parameters": [
                            {"name": "doc_id", "value": format!("doc-{index}")},
                            {"name": "originating_app_id", "value": "cloud-project-1"}
                        ]
                    }]
                })
            })
            .collect();

        let findings = test_analyze(&activities);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "bulk_drive_download");
        assert_eq!(findings[0].occurrences, 5);
        assert_eq!(
            findings[0].originating_app_id.as_deref(),
            Some("cloud-project-1")
        );
        assert_eq!(
            findings[0]
                .evidence
                .get("unique_resource_count")
                .map(String::as_str),
            Some("5")
        );
    }

    #[test]
    fn dlp_match_exposes_detector_evidence_without_resource_title() {
        let activities = vec![json!({
            "id": {"applicationName": "rules", "uniqueQualifier": "dlp-1"},
            "events": [{
                "name": "content_matched",
                "parameters": [
                    {"name": "rule_type", "value": "DLP"},
                    {"name": "rule_name", "value": "Financial data audit"},
                    {"name": "resource_owner_email", "value": "owner@wearenexa.com"},
                    {"name": "resource_id", "value": "resource-1"},
                    {"name": "resource_title", "value": "Sensitive title must not be retained"},
                    {"name": "matched_detectors", "multiMessageValue": [{
                        "parameter": [
                            {"name": "detector_id", "value": "detector-1"},
                            {"name": "display_name", "value": "Credit card number"}
                        ]
                    }]}
                ]
            }]
        })];

        let (findings, telemetry) = analyze_activities(&activities, &test_config());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "dlp_content_match");
        assert_eq!(findings[0].actor, "(unknown)");
        assert_eq!(
            findings[0]
                .evidence
                .get("matched_detectors")
                .map(String::as_str),
            Some("Credit card number")
        );
        assert!(!findings[0].evidence.contains_key("resource_title"));
        assert_eq!(
            telemetry
                .matched_dlp_detectors
                .get("Credit card number")
                .copied(),
            Some(1)
        );
    }

    #[test]
    fn resource_context_does_not_substitute_for_a_missing_actor() {
        let activities = vec![json!({
            "id": {"applicationName": "admin", "uniqueQualifier": "context-only-1"},
            "events": [{
                "name": "message_send_warned",
                "parameters": [
                    {"name": "resource_owner_email", "value": "owner@wearenexa.com"},
                    {"name": "target_user", "value": "recipient@example.net"},
                    {"name": "affected_email_address", "value": "affected@example.net"}
                ]
            }]
        })];

        let findings = test_analyze(&activities);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].actor, "(unknown)");
        assert_eq!(findings[0].target.as_deref(), Some("recipient@example.net"));
    }

    #[test]
    fn domain_flags_are_normalized_and_reject_unsafe_values() {
        assert_eq!(
            validate_domain("@WeAreNexa.COM").as_deref(),
            Ok("wearenexa.com")
        );
        for invalid in ["wearenexa", "-bad.example", "bad..example", "bad/example"] {
            assert!(validate_domain(invalid).is_err(), "{invalid} should fail");
        }

        assert!(build_security_observer_cmd()
            .try_get_matches_from([
                "+security-observer",
                "--internal-domain",
                "wearenexa.com",
                "--trusted-domain",
                "partner.example",
            ])
            .is_ok());
        assert!(build_security_observer_cmd()
            .try_get_matches_from([
                "+security-observer",
                "--internal-domain",
                "bad/../../domain",
            ])
            .is_err());
    }

    #[test]
    fn visibility_telemetry_creates_inventory_recommendations_without_claiming_unique_files() {
        let telemetry = SecurityTelemetry {
            drive_visibilities: BTreeMap::from([
                ("shared_externally".to_string(), 12),
                ("people_with_link".to_string(), 3),
            ]),
            ..SecurityTelemetry::default()
        };

        let recommendations = build_recommendations(&[], &telemetry);
        let external = recommendations
            .iter()
            .find(|recommendation| {
                recommendation.recommendation_id == "drive-external-sharing-inventory"
            })
            .expect("external inventory recommendation should exist");
        let public = recommendations
            .iter()
            .find(|recommendation| {
                recommendation.recommendation_id == "drive-public-link-inventory"
            })
            .expect("public link recommendation should exist");

        assert_eq!(external.evidence_count, 12);
        assert_eq!(public.evidence_count, 3);
        assert!(external.rationale.contains("not unique files"));
        assert!(public.rationale.contains("not unique files"));
    }
}
