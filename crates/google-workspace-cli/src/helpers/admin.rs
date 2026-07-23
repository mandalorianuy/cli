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
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

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
    severity: Severity,
    rule: &'static str,
    actor: String,
    ip_address: Option<String>,
    occurrences: usize,
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

fn analyze_activities(activities: &[Value]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut failed_logins: HashMap<String, FailedLoginBurst> = HashMap::new();

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
            if event_name == "login_failure" {
                let entry =
                    failed_logins
                        .entry(actor.clone())
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
            let critical_rule = match event_name {
                "suspicious_login" => Some("google_suspicious_login"),
                "suspicious_login_less_secure_app" => Some("suspicious_less_secure_app"),
                "suspicious_programmatic_login" => Some("suspicious_programmatic_login"),
                "user_signed_out_due_to_suspicious_session_cookie" => {
                    Some("suspicious_session_cookie")
                }
                "account_disabled_password_leak" => Some("password_leak"),
                "account_disabled_hijacked" => Some("account_hijacked"),
                "ASSIGN_ROLE" => Some("admin_role_assigned"),
                "AUTHORIZE_API_CLIENT_ACCESS" => Some("domain_wide_delegation_authorized"),
                _ => None,
            };

            if let Some(rule) = critical_rule {
                findings.push(Finding {
                    event_id: metadata.event_id(event_name, event_index),
                    event_time: metadata.event_time.clone(),
                    source: metadata.source.clone(),
                    severity: Severity::Critical,
                    rule,
                    actor: actor.clone(),
                    ip_address: ip_address.clone(),
                    occurrences: 1,
                });
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
                _ => None,
            };

            if let Some(rule) = high_rule {
                findings.push(Finding {
                    event_id: metadata.event_id(event_name, event_index),
                    event_time: metadata.event_time.clone(),
                    source: metadata.source.clone(),
                    severity: Severity::High,
                    rule,
                    actor: actor.clone(),
                    ip_address: ip_address.clone(),
                    occurrences: 1,
                });
            }
        }
    }

    findings.extend(
        failed_logins
            .into_iter()
            .filter(|(_, burst)| burst.count >= 5)
            .map(|(actor, burst)| Finding {
                event_id: burst.latest.burst_event_id(),
                event_time: burst.latest.event_time,
                source: burst.latest.source,
                severity: Severity::High,
                rule: "repeated_login_failures",
                actor,
                ip_address: burst.ip_address,
                occurrences: burst.count,
            }),
    );

    findings
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
            Arg::new("format")
                .long("format")
                .value_parser(["json", "table", "yaml", "csv"])
                .default_value("json")
                .value_name("FORMAT"),
        )
        .after_help(
            "READ-ONLY GUARANTEE:\n  Uses only Admin Reports API GET requests.\n  Never suspends users, revokes tokens, changes 2SV, or modifies devices.",
        )
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
    ["login", "admin", "token"]
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

    let end_time = Utc::now();
    let start_time = end_time - Duration::minutes(lookback_minutes as i64);
    let start_rfc3339 = start_time.to_rfc3339_opts(SecondsFormat::Secs, true);
    let end_rfc3339 = end_time.to_rfc3339_opts(SecondsFormat::Secs, true);
    let requests = security_observer_requests(&start_rfc3339, max_results);
    let scopes: Vec<&str> = requests.iter().map(|request| request.scope).collect();
    let token = auth::get_token(&scopes)
        .await
        .map_err(|error| GwsError::Auth(format!("Authentication failed: {error:#}")))?;
    let client = crate::client::build_client()?;

    let mut activities = Vec::new();
    for request in &requests {
        activities.extend(fetch_observer_request(&client, request, &token).await?);
    }

    let activity_count = activities.len();
    let findings = filter_findings(analyze_activities(&activities), min_severity);
    let report = json!({
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
    });
    let format = crate::formatter::OutputFormat::parse(output_format)
        .map_err(|unknown| GwsError::Validation(format!("Unknown output format '{unknown}'")))?;
    println!("{}", crate::formatter::format_value(&report, &format));
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
            Ok(false)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

        let findings = analyze_activities(&activities);

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

        let findings = analyze_activities(&activities);

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

        let findings = analyze_activities(&activities);

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

        assert!(analyze_activities(&activities).is_empty());
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

        let findings = analyze_activities(&activities);

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
        assert!(build_security_observer_cmd()
            .try_get_matches_from(["+security-observer", "--lookback-minutes", "0"])
            .is_err());
        assert!(build_security_observer_cmd()
            .try_get_matches_from(["+security-observer", "--min-severity", "urgent"])
            .is_err());
    }

    #[test]
    fn security_observer_plan_contains_only_reports_get_requests() {
        let requests = security_observer_requests("2026-07-23T18:00:00Z", 100);

        assert_eq!(requests.len(), 3);
        assert_eq!(
            requests
                .iter()
                .map(|request| request.application_name)
                .collect::<Vec<_>>(),
            ["login", "admin", "token"]
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
            severity: Severity::Critical,
            rule: "password_leak",
            actor: "user@wearenexa.com".to_string(),
            ip_address: Some("203.0.113.30".to_string()),
            occurrences: 1,
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
                severity: Severity::High,
                rule: "two_step_verification_disabled",
                actor: "user@wearenexa.com".to_string(),
                ip_address: None,
                occurrences: 1,
            },
            Finding {
                event_id: "login:event-critical:account_disabled_password_leak:0".to_string(),
                event_time: None,
                source: "login".to_string(),
                severity: Severity::Critical,
                rule: "password_leak",
                actor: "user@wearenexa.com".to_string(),
                ip_address: None,
                occurrences: 1,
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

        let findings = analyze_activities(&activities);

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

        let findings = analyze_activities(&activities);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].rule, "oauth_application_authorized");
    }
}
