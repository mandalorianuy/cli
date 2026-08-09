use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use uuid::Uuid;

use super::provenance::{
    validated_email, ActorRole, ActorSource, ProvenanceV1, TemporalBasis,
    PROVENANCE_CONTRACT_VERSION,
};

pub(super) const CORRELATION_CONTRACT_VERSION: &str =
    "security_intelligence_monitor_correlation_v1";

const REQUIRED_SOURCES: [&str; 5] = ["login", "admin", "token", "drive", "rules"];
const POSTURE_COVERAGE_SOURCES: [&str; 12] = [
    "google.users",
    "google.roles",
    "google.roleAssignments",
    "microsoft.users",
    "microsoft.authenticationMethods",
    "microsoft.roleAssignments",
    "microsoft.conditionalAccess",
    "microsoft.signIns",
    "microsoft.directoryAudits",
    "microsoft.defenderAlerts",
    "microsoft.defenderIncidents",
    "microsoft.secureScore",
];
const MAX_FINDINGS: usize = 1_000;
const MAX_SIGNALS_PER_CORRELATION: usize = 32;
const MAX_COUNTER_EVIDENCE: usize = 16;
const MAX_TEXT_LENGTH: usize = 512;

const RAW_RULES: &[&str] = &[
    "google_suspicious_login",
    "suspicious_less_secure_app",
    "suspicious_programmatic_login",
    "suspicious_session_cookie",
    "password_leak",
    "account_hijacked",
    "government_backed_attack_warning",
    "google_ransomware_sync_pause",
    "suspicious_successful_login",
    "two_step_verification_disabled",
    "passkey_removed",
    "recovery_email_changed",
    "recovery_phone_changed",
    "admin_role_assigned",
    "domain_wide_delegation_authorized",
    "context_aware_access_changed",
    "oauth_application_authorized",
    "drive_public_link_enabled",
    "drive_shared_with_consumer_account",
    "drive_shared_outside_trusted_domains",
    "drive_external_ownership_transfer",
    "drive_emailed_to_consumer_account",
    "drive_emailed_outside_trusted_domains",
    "dlp_content_match",
    "dlp_rule_triggered",
    "dlp_user_warned",
    "repeated_login_failures",
    "bulk_drive_download",
    "bulk_drive_api_access",
    "bulk_drive_delete",
];

const RAW_EVIDENCE_KEYS: &[&str] = &[
    "affected_email_address",
    "api_method",
    "api_name",
    "app_name",
    "client_id",
    "client_type",
    "data_source",
    "doc_id",
    "doc_type",
    "failed_login_count",
    "is_suspicious",
    "login_challenge_method",
    "login_type",
    "matched_detectors",
    "matched_trigger",
    "new_value",
    "old_value",
    "originating_app_id",
    "owner",
    "resource_id",
    "resource_type",
    "rule_name",
    "rule_type",
    "scan_type",
    "scope",
    "severity",
    "target",
    "target_domain",
    "target_user",
    "unique_resource_count",
    "visibility",
    "visibility_change",
];

const POSTURE_EVIDENCE_KEYS: &[&str] = &[
    "accountEnabled",
    "activityDateTime",
    "activityDisplayName",
    "alertId",
    "appDisplayName",
    "category",
    "conditionalAccessStatus",
    "createdDateTime",
    "displayName",
    "googleEnabled",
    "googleEventId",
    "googleMfaEnrolled",
    "googlePrivileged",
    "googleRule",
    "inactiveDays",
    "incidentId",
    "isEnrolledIn2Sv",
    "isMfaCapable",
    "isMfaRegistered",
    "lastLoginTime",
    "microsoftEnabled",
    "microsoftMfaCapable",
    "microsoftPrivileged",
    "microsoftSignInId",
    "policiesObserved",
    "policyId",
    "policyName",
    "privileged",
    "result",
    "riskLevelDuringSignIn",
    "riskState",
    "serviceSource",
    "severity",
    "signInId",
    "status",
    "title",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CorrelationError(String);

impl CorrelationError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for CorrelationError {}

#[derive(Clone, Debug)]
struct CorrelationWindow {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct Signal {
    event_id: String,
    source: String,
    event_time: Option<DateTime<Utc>>,
    actor: Option<String>,
    provenance: Option<ProvenanceV1>,
    resource_id: Option<String>,
    client_id: Option<String>,
    target: Option<String>,
    rule: String,
    severity: Severity,
    evidence: BTreeMap<String, String>,
    counter_evidence: usize,
    ip_context: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
enum Severity {
    High,
    Critical,
}

impl Severity {
    fn parse(value: &str, path: &str) -> Result<Self, CorrelationError> {
        match value {
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(CorrelationError::new(format!(
                "{path} has an unsupported severity"
            ))),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PostureState {
    present: bool,
    assured: bool,
    signals: Vec<Signal>,
}

pub(super) fn correlate_report(
    input: &Value,
    window_minutes: u64,
    max_correlations: usize,
) -> Result<Value, CorrelationError> {
    if !(1..=1_440).contains(&window_minutes) {
        return Err(CorrelationError::new(
            "correlation window must be between 1 and 1440 minutes",
        ));
    }
    if !(1..=100).contains(&max_correlations) {
        return Err(CorrelationError::new(
            "max correlations must be between 1 and 100",
        ));
    }

    let input_object = input
        .as_object()
        .ok_or_else(|| CorrelationError::new("correlation input must be a JSON object"))?;
    require_string(input_object, "mode").and_then(|mode| {
        if mode == "read-only" {
            Ok(())
        } else {
            Err(CorrelationError::new(
                "correlation input mode must be read-only",
            ))
        }
    })?;

    let input_window = parse_input_window(input_object)?;
    let declared_sources = parse_declared_sources(input_object)?;
    let declared_source_set: BTreeSet<_> = declared_sources.iter().map(String::as_str).collect();
    let mut missing_data = BTreeSet::new();
    for source in REQUIRED_SOURCES {
        if !declared_source_set.contains(source) {
            missing_data.insert(format!("source:{source}:not_declared"));
        }
    }

    let findings = input_object
        .get("findings")
        .and_then(Value::as_array)
        .ok_or_else(|| CorrelationError::new("correlation input findings must be an array"))?;
    if findings.len() > MAX_FINDINGS {
        return Err(CorrelationError::new(format!(
            "correlation input exceeds the {MAX_FINDINGS} finding limit"
        )));
    }
    let finding_count = input_object
        .get("findingCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| CorrelationError::new("correlation input findingCount is required"))?;
    if finding_count != findings.len() as u64 {
        return Err(CorrelationError::new(
            "correlation input findingCount does not match findings",
        ));
    }

    let mut signals = Vec::with_capacity(findings.len());
    let mut seen_event_ids: BTreeMap<String, String> = BTreeMap::new();
    for (index, finding) in findings.iter().enumerate() {
        let signal = parse_raw_signal(
            finding,
            index,
            &input_window,
            &declared_source_set,
            &mut missing_data,
        )?;
        let canonical = signal_fingerprint_key(&signal).to_string();
        if let Some(previous) = seen_event_ids.insert(signal.event_id.clone(), canonical.clone()) {
            if previous != canonical {
                return Err(CorrelationError::new(format!(
                    "ambiguous duplicate eventId '{}'",
                    signal.event_id
                )));
            }
            continue;
        }
        signals.push(signal);
    }

    let posture = parse_posture_state(input_object, &input_window, &mut missing_data)?;
    signals.extend(posture.signals.iter().cloned());
    let mut unique_signals = Vec::with_capacity(signals.len());
    let mut all_signal_ids: BTreeMap<String, String> = BTreeMap::new();
    for signal in signals {
        let canonical = signal_fingerprint_key(&signal).to_string();
        if let Some(previous) = all_signal_ids.insert(signal.event_id.clone(), canonical.clone()) {
            if previous != canonical {
                return Err(CorrelationError::new(format!(
                    "ambiguous duplicate signal id '{}'",
                    signal.event_id
                )));
            }
            continue;
        }
        unique_signals.push(signal);
    }
    signals = unique_signals;
    signals.sort_by(|left, right| left.event_id.cmp(&right.event_id));

    let mut global_contradictions = BTreeSet::new();
    let mut overflow = BTreeSet::new();
    let mut candidates = Vec::new();
    for (dimension, groups) in build_indexes(&signals) {
        for (key, indexes) in groups {
            let unique_sources: BTreeSet<_> = indexes
                .iter()
                .map(|index| signals[*index].source.as_str())
                .collect();
            if unique_sources.len() < 2 {
                continue;
            }
            if indexes.len() > MAX_SIGNALS_PER_CORRELATION {
                overflow.insert(format!("{dimension}:signal_group_overflow"));
                continue;
            }
            let mut selected = indexes;
            selected.sort_by(|left, right| signal_order(&signals[*left], &signals[*right]));
            if selected
                .iter()
                .any(|index| signals[*index].event_time.is_none())
            {
                missing_data.insert(format!("{dimension}:eventTime_missing"));
                continue;
            }
            let start = signals[selected[0]].event_time.expect("checked above");
            let end = signals[*selected.last().expect("selected is not empty")]
                .event_time
                .expect("checked above");
            if end.signed_duration_since(start) > Duration::minutes(window_minutes as i64) {
                missing_data.insert(format!("{dimension}:outside_correlation_window"));
                continue;
            }
            let contradictions = contradiction_labels(&selected, &signals);
            global_contradictions.extend(contradictions.iter().cloned());
            candidates.push((dimension.clone(), key, selected, contradictions));
        }
    }

    let mut correlations = candidates
        .into_iter()
        .map(|(dimension, key, selected, contradictions)| {
            build_correlation(
                &dimension,
                &key,
                &selected,
                &signals,
                &contradictions,
                &posture,
            )
        })
        .collect::<Vec<_>>();
    correlations.sort_by(|left, right| {
        left["correlationId"]
            .as_str()
            .cmp(&right["correlationId"].as_str())
    });
    if correlations.len() > max_correlations {
        overflow.insert(format!(
            "correlation_count_exceeds_limit:{max_correlations}"
        ));
        correlations.truncate(max_correlations);
    }

    let required_coverage_complete = REQUIRED_SOURCES
        .iter()
        .all(|source| declared_source_set.contains(source));
    let coverage_complete = required_coverage_complete && posture.present && posture.assured;
    let status = if !overflow.is_empty() {
        "overflow"
    } else if !global_contradictions.is_empty() {
        "contradictory"
    } else if !required_coverage_complete || !missing_data.is_empty() || !coverage_complete {
        "incomplete"
    } else if correlations.is_empty() {
        "no_correlations"
    } else {
        "correlated"
    };
    let fail_closed = status != "correlated";

    let coverage = build_coverage(
        &declared_source_set,
        posture.present,
        posture.assured,
        required_coverage_complete,
    );
    let missing_data = missing_data.into_iter().collect::<Vec<_>>();
    let contradictions = global_contradictions.into_iter().collect::<Vec<_>>();
    let overflow = overflow.into_iter().collect::<Vec<_>>();
    let input_fingerprint = sha256_json(&json!({
        "window": {
            "startTime": canonical_time(input_window.start),
            "endTime": canonical_time(input_window.end),
        },
        "windowMinutes": window_minutes,
        "signals": signals.iter().map(signal_fingerprint_key).collect::<Vec<_>>(),
        "postureAssured": posture.assured,
    }))?;

    let mut output = json!({
        "artifact": CORRELATION_CONTRACT_VERSION,
        "contractVersion": CORRELATION_CONTRACT_VERSION,
        "mode": "read-only-local",
        "dryRun": true,
        "status": status,
        "coverageComplete": coverage_complete,
        "requiredCoverageComplete": required_coverage_complete,
        "failClosed": fail_closed,
        "window": {
            "startTime": canonical_time(input_window.start),
            "endTime": canonical_time(input_window.end),
            "windowMinutes": window_minutes,
        },
        "inputFingerprint": input_fingerprint,
        "coverage": coverage,
        "correlations": correlations,
        "missingData": missing_data,
        "contradictions": contradictions,
        "overflow": overflow,
        "humanReview": {
            "status": "proposed",
            "reviewedBy": "",
            "disposition": "",
            "notes": ""
        },
        "nextAction": "human_review_only"
    });
    let fingerprint = sha256_json(&output)?;
    output["fingerprint"] = Value::String(fingerprint);
    Ok(output)
}

fn parse_input_window(input: &Map<String, Value>) -> Result<CorrelationWindow, CorrelationError> {
    let window = input
        .get("window")
        .and_then(Value::as_object)
        .ok_or_else(|| CorrelationError::new("correlation input window is required"))?;
    let start = parse_timestamp(require_string(window, "startTime")?, "window.startTime")?;
    let end = parse_timestamp(require_string(window, "endTime")?, "window.endTime")?;
    if end < start {
        return Err(CorrelationError::new(
            "correlation input window endTime precedes startTime",
        ));
    }
    let declared_minutes = window
        .get("lookbackMinutes")
        .and_then(Value::as_u64)
        .ok_or_else(|| CorrelationError::new("correlation input lookbackMinutes is required"))?;
    let actual_minutes = end.signed_duration_since(start).num_minutes();
    if actual_minutes < 0 || declared_minutes != actual_minutes as u64 {
        return Err(CorrelationError::new(
            "correlation input window duration does not match lookbackMinutes",
        ));
    }
    if actual_minutes > 10_080 {
        return Err(CorrelationError::new(
            "correlation input window exceeds the seven-day safety bound",
        ));
    }
    Ok(CorrelationWindow { start, end })
}

fn parse_declared_sources(input: &Map<String, Value>) -> Result<Vec<String>, CorrelationError> {
    let values = input
        .get("sources")
        .and_then(Value::as_array)
        .ok_or_else(|| CorrelationError::new("correlation input sources must be an array"))?;
    let mut sources = BTreeSet::new();
    for value in values {
        let source = value
            .as_str()
            .ok_or_else(|| CorrelationError::new("correlation input source must be a string"))?;
        if !REQUIRED_SOURCES.contains(&source) {
            return Err(CorrelationError::new(format!(
                "correlation input source '{source}' is not allowlisted"
            )));
        }
        if !sources.insert(source.to_string()) {
            return Err(CorrelationError::new(format!(
                "correlation input source '{source}' is duplicated"
            )));
        }
    }
    Ok(sources.into_iter().collect())
}

fn parse_raw_signal(
    value: &Value,
    index: usize,
    input_window: &CorrelationWindow,
    declared_sources: &BTreeSet<&str>,
    missing_data: &mut BTreeSet<String>,
) -> Result<Signal, CorrelationError> {
    let object = value
        .as_object()
        .ok_or_else(|| CorrelationError::new(format!("finding[{index}] must be a JSON object")))?;
    let path = format!("finding[{index}]");
    let event_id = bounded_string(
        require_string(object, "eventId")?,
        &format!("{path}.eventId"),
    )?;
    let source = bounded_string(require_string(object, "source")?, &format!("{path}.source"))?;
    if !REQUIRED_SOURCES.contains(&source.as_str()) {
        return Err(CorrelationError::new(format!(
            "{path}.source is not allowlisted"
        )));
    }
    if !declared_sources.contains(source.as_str()) {
        missing_data.insert(format!("source:{source}:finding_not_declared"));
    }
    let rule = bounded_string(require_string(object, "rule")?, &format!("{path}.rule"))?;
    if !RAW_RULES.contains(&rule.as_str()) {
        return Err(CorrelationError::new(format!(
            "{path}.rule is not allowlisted"
        )));
    }
    let severity = Severity::parse(
        require_string(object, "severity")?,
        &format!("{path}.severity"),
    )?;
    let mut evidence = parse_evidence(
        object.get("evidence"),
        RAW_EVIDENCE_KEYS,
        &format!("{path}.evidence"),
    )?;
    let provenance = parse_provenance(object.get("provenance"), &path, missing_data)?;
    let actor = parse_signal_actor(object, &path, provenance, missing_data)?;
    let event_time = parse_signal_event_time(
        object.get("eventTime"),
        &format!("{path}.eventTime"),
        provenance,
        &event_id,
        missing_data,
    )?;
    let event_time = retain_signal_in_input_window(
        event_time,
        input_window,
        &event_id,
        provenance,
        missing_data,
    );

    let resource_id = first_consistent_value(
        "resourceId",
        object.get("resourceId").and_then(Value::as_str),
        evidence
            .get("resource_id")
            .map(String::as_str)
            .or_else(|| evidence.get("doc_id").map(String::as_str)),
        &path,
    )?;
    let client_id = first_consistent_value(
        "clientId",
        object.get("originatingAppId").and_then(Value::as_str),
        evidence
            .get("client_id")
            .map(String::as_str)
            .or_else(|| evidence.get("originating_app_id").map(String::as_str)),
        &path,
    )?;
    let target = first_consistent_value(
        "target",
        object.get("target").and_then(Value::as_str),
        evidence
            .get("target_user")
            .map(String::as_str)
            .or_else(|| evidence.get("target").map(String::as_str))
            .or_else(|| evidence.get("target_domain").map(String::as_str)),
        &path,
    )?;
    let visibility = first_consistent_value(
        "visibility",
        object.get("visibility").and_then(Value::as_str),
        evidence.get("visibility").map(String::as_str),
        &path,
    )?;
    if let Some(value) = &visibility {
        evidence.insert("visibility".to_string(), value.clone());
    }
    if let Some(value) = &resource_id {
        evidence.insert("resourceId".to_string(), value.clone());
    }
    if let Some(value) = &client_id {
        evidence.insert("clientId".to_string(), value.clone());
    }
    if let Some(value) = &target {
        evidence.insert("target".to_string(), value.clone());
    }

    let ip_context = parse_ip_context(object.get("ipIntelligence"), &path, missing_data)?;
    if ip_context {
        evidence.insert("ipContext".to_string(), "observed".to_string());
    }

    Ok(Signal {
        event_id,
        source,
        event_time,
        actor,
        provenance,
        resource_id,
        client_id,
        target,
        rule,
        severity,
        evidence,
        counter_evidence: 0,
        ip_context,
    })
}

fn parse_posture_state(
    input: &Map<String, Value>,
    input_window: &CorrelationWindow,
    missing_data: &mut BTreeSet<String>,
) -> Result<PostureState, CorrelationError> {
    let Some(monitor) = input.get("monitorIntegration") else {
        if let Some(posture) = input.get("securityPosture") {
            return parse_security_posture(posture, input_window, missing_data);
        }
        missing_data.insert("posture:disabled_or_not_available".to_string());
        return Ok(PostureState::default());
    };
    let monitor = monitor
        .get("security_intelligence_monitor_v1")
        .and_then(Value::as_object)
        .ok_or_else(|| CorrelationError::new("monitorIntegration envelope is malformed"))?;
    if require_string(monitor, "contractVersion")? != "security_intelligence_monitor_v1" {
        return Err(CorrelationError::new(
            "monitorIntegration contractVersion is unsupported",
        ));
    }
    let status = require_string(monitor, "status")?;
    let coverage_complete = monitor
        .get("coverageComplete")
        .and_then(Value::as_bool)
        .ok_or_else(|| CorrelationError::new("monitorIntegration coverageComplete is required"))?;
    let fail_closed = monitor
        .get("failClosed")
        .and_then(Value::as_bool)
        .ok_or_else(|| CorrelationError::new("monitorIntegration failClosed is required"))?;
    let coverage_assured = parse_posture_coverage(monitor.get("coverage"))?;
    let assured = status == "complete" && coverage_complete && !fail_closed && coverage_assured;
    if !assured {
        missing_data.insert("posture:coverage_not_assured".to_string());
    }
    let values = monitor
        .get("findings")
        .and_then(Value::as_array)
        .ok_or_else(|| CorrelationError::new("monitorIntegration findings must be an array"))?;
    if values.len() > MAX_FINDINGS {
        return Err(CorrelationError::new(
            "monitorIntegration findings exceed the safety bound",
        ));
    }
    let signals = values
        .iter()
        .enumerate()
        .map(|(index, value)| parse_posture_signal(value, index, input_window, missing_data))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PostureState {
        present: true,
        assured,
        signals,
    })
}

fn parse_security_posture(
    value: &Value,
    input_window: &CorrelationWindow,
    missing_data: &mut BTreeSet<String>,
) -> Result<PostureState, CorrelationError> {
    let posture = value
        .as_object()
        .ok_or_else(|| CorrelationError::new("securityPosture must be an object"))?;
    if require_string(posture, "schemaVersion")? != "security_intelligence_v1" {
        return Err(CorrelationError::new(
            "securityPosture schemaVersion is unsupported",
        ));
    }
    let coverage_complete = posture
        .get("coverageComplete")
        .and_then(Value::as_bool)
        .ok_or_else(|| CorrelationError::new("securityPosture coverageComplete is required"))?;
    let coverage_assured = parse_posture_coverage(posture.get("coverage"))?;
    let assured = coverage_complete && coverage_assured;
    if !assured {
        missing_data.insert("posture:coverage_not_assured".to_string());
    }
    let mut signals = Vec::new();
    for field in [
        "identityPosture",
        "controlPosture",
        "crossCloudCorrelations",
        "signalFindings",
    ] {
        let values = posture
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CorrelationError::new(format!("securityPosture.{field} must be an array"))
            })?;
        if signals.len() + values.len() > MAX_FINDINGS {
            return Err(CorrelationError::new(
                "securityPosture findings exceed the safety bound",
            ));
        }
        for (index, finding) in values.iter().enumerate() {
            signals.push(parse_security_posture_signal(
                finding,
                field,
                index,
                input_window,
                missing_data,
            )?);
        }
    }
    Ok(PostureState {
        present: true,
        assured,
        signals,
    })
}

fn parse_posture_coverage(value: Option<&Value>) -> Result<bool, CorrelationError> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| CorrelationError::new("posture coverage must be an array"))?;
    if values.is_empty() {
        return Ok(false);
    }
    let mut assured = true;
    let mut seen_sources = BTreeSet::new();
    for entry in values {
        let object = entry
            .as_object()
            .ok_or_else(|| CorrelationError::new("posture coverage entry must be an object"))?;
        let source = require_string(object, "source")?;
        if !POSTURE_COVERAGE_SOURCES.contains(&source) {
            return Err(CorrelationError::new(
                "posture coverage source is not allowlisted",
            ));
        }
        if !seen_sources.insert(source) {
            return Err(CorrelationError::new(
                "posture coverage source is duplicated",
            ));
        }
        let status = require_string(object, "status")?;
        if !matches!(status, "available" | "unavailable" | "disabled") {
            return Err(CorrelationError::new(
                "posture coverage status is not allowlisted",
            ));
        }
        let entry_assured = object
            .get("assured")
            .or_else(|| object.get("assurance"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        assured &= status == "available" && entry_assured;
    }
    assured &= POSTURE_COVERAGE_SOURCES
        .iter()
        .all(|source| seen_sources.contains(source));
    Ok(assured)
}

fn parse_provenance(
    value: Option<&Value>,
    path: &str,
    missing_data: &mut BTreeSet<String>,
) -> Result<Option<ProvenanceV1>, CorrelationError> {
    let Some(value) = value else {
        missing_data.insert(format!("{path}.provenance:missing"));
        return Ok(None);
    };
    if value.is_null() {
        missing_data.insert(format!("{path}.provenance:missing"));
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| CorrelationError::new(format!("{path}.provenance must be an object")))?;
    if require_string(object, "contractVersion")? != PROVENANCE_CONTRACT_VERSION {
        return Err(CorrelationError::new(format!(
            "{path}.provenance.contractVersion is unsupported"
        )));
    }
    let actor_role = parse_actor_role(
        require_string(object, "actorRole")?,
        &format!("{path}.provenance.actorRole"),
    )?;
    let actor_source = parse_actor_source(
        require_string(object, "actorSource")?,
        &format!("{path}.provenance.actorSource"),
    )?;
    let temporal_basis = parse_temporal_basis(
        require_string(object, "temporalBasis")?,
        &format!("{path}.provenance.temporalBasis"),
    )?;
    Ok(Some(ProvenanceV1::new(
        actor_role,
        actor_source,
        temporal_basis,
    )))
}

fn parse_actor_role(value: &str, path: &str) -> Result<ActorRole, CorrelationError> {
    match value {
        "humanUser" => Ok(ActorRole::HumanUser),
        "application" => Ok(ActorRole::Application),
        "system" => Ok(ActorRole::System),
        "resourceOwner" => Ok(ActorRole::ResourceOwner),
        "target" => Ok(ActorRole::Target),
        "affectedUser" => Ok(ActorRole::AffectedUser),
        "subject" => Ok(ActorRole::Subject),
        "unknown" => Ok(ActorRole::Unknown),
        _ => Err(CorrelationError::new(format!("{path} is not allowlisted"))),
    }
}

fn parse_actor_source(value: &str, path: &str) -> Result<ActorSource, CorrelationError> {
    match value {
        "googleActor" => Ok(ActorSource::GoogleActor),
        "googleResourceOwner" => Ok(ActorSource::GoogleResourceOwner),
        "googlePostureSubject" => Ok(ActorSource::GooglePostureSubject),
        "microsoftInitiatedByUser" => Ok(ActorSource::MicrosoftInitiatedByUser),
        "microsoftInitiatedByApp" => Ok(ActorSource::MicrosoftInitiatedByApp),
        "microsoftInitiatedBySystem" => Ok(ActorSource::MicrosoftInitiatedBySystem),
        "microsoftInitiatedByOpaqueId" => Ok(ActorSource::MicrosoftInitiatedByOpaqueId),
        "microsoftSignInUser" => Ok(ActorSource::MicrosoftSignInUser),
        "microsoftDefender" => Ok(ActorSource::MicrosoftDefender),
        "crossCloudSubject" => Ok(ActorSource::CrossCloudSubject),
        "providerSubject" => Ok(ActorSource::ProviderSubject),
        "unknown" => Ok(ActorSource::Unknown),
        _ => Err(CorrelationError::new(format!("{path} is not allowlisted"))),
    }
}

fn parse_temporal_basis(value: &str, path: &str) -> Result<TemporalBasis, CorrelationError> {
    match value {
        "providerEventTime" => Ok(TemporalBasis::ProviderEventTime),
        "snapshotObservedAt" => Ok(TemporalBasis::SnapshotObservedAt),
        "snapshotGeneratedAt" => Ok(TemporalBasis::SnapshotGeneratedAt),
        "stateLastLoginTime" => Ok(TemporalBasis::StateLastLoginTime),
        "unknown" => Ok(TemporalBasis::Unknown),
        _ => Err(CorrelationError::new(format!("{path} is not allowlisted"))),
    }
}

fn parse_signal_actor(
    object: &Map<String, Value>,
    path: &str,
    provenance: Option<ProvenanceV1>,
    missing_data: &mut BTreeSet<String>,
) -> Result<Option<String>, CorrelationError> {
    let actor = optional_string(object, "actor", &format!("{path}.actor"))?;
    if provenance.is_some_and(ProvenanceV1::actor_correlation_eligible) {
        return match actor.as_deref().and_then(validated_email) {
            Some(actor) => Ok(Some(actor)),
            None => {
                missing_data.insert(format!("{path}.actor:ambiguous_or_missing"));
                Ok(None)
            }
        };
    }
    if actor.is_some() {
        missing_data.insert(format!("{path}.actor:not_eligible"));
    }
    Ok(None)
}

fn parse_signal_event_time(
    value: Option<&Value>,
    path: &str,
    provenance: Option<ProvenanceV1>,
    event_id: &str,
    missing_data: &mut BTreeSet<String>,
) -> Result<Option<DateTime<Utc>>, CorrelationError> {
    let event_time = parse_optional_time(value, path, missing_data)?;
    if !provenance.is_some_and(ProvenanceV1::temporal_correlation_eligible) {
        missing_data.insert(format!("{event_id}:causal_time_unavailable"));
        return Ok(None);
    }
    Ok(event_time)
}

fn retain_signal_in_input_window(
    value: Option<DateTime<Utc>>,
    input_window: &CorrelationWindow,
    event_id: &str,
    provenance: Option<ProvenanceV1>,
    missing_data: &mut BTreeSet<String>,
) -> Option<DateTime<Utc>> {
    if !provenance.is_some_and(ProvenanceV1::temporal_correlation_eligible) {
        return None;
    }
    retain_in_input_window(value, input_window, event_id, missing_data)
}

fn parse_posture_signal(
    value: &Value,
    index: usize,
    input_window: &CorrelationWindow,
    missing_data: &mut BTreeSet<String>,
) -> Result<Signal, CorrelationError> {
    let object = value.as_object().ok_or_else(|| {
        CorrelationError::new(format!("posture finding[{index}] must be an object"))
    })?;
    let path = format!("posture.finding[{index}]");
    let event_id = bounded_string(
        require_string(object, "eventId")?,
        &format!("{path}.eventId"),
    )?;
    let rule = bounded_string(
        object
            .get("rule")
            .or_else(|| object.get("controlId"))
            .and_then(Value::as_str)
            .ok_or_else(|| CorrelationError::new(format!("{path}.rule is required")))?,
        &format!("{path}.rule"),
    )?;
    validate_posture_token(&rule, &format!("{path}.rule"))?;
    let source_detail =
        bounded_string(require_string(object, "source")?, &format!("{path}.source"))?;
    validate_posture_source(&source_detail, &format!("{path}.source"))?;
    let provenance = parse_provenance(object.get("provenance"), &path, missing_data)?;
    let actor = parse_signal_actor(object, &path, provenance, missing_data)?;
    let event_time = parse_signal_event_time(
        object.get("eventTime"),
        &format!("{path}.eventTime"),
        provenance,
        &event_id,
        missing_data,
    )?;
    let event_time = retain_signal_in_input_window(
        event_time,
        input_window,
        &event_id,
        provenance,
        missing_data,
    );
    let evidence = parse_evidence(
        object.get("evidence"),
        POSTURE_EVIDENCE_KEYS,
        &format!("{path}.evidence"),
    )?;
    let counter_evidence = parse_counter_evidence(object.get("narrative"), &path)?;
    let ip_context = false;
    Ok(Signal {
        event_id,
        source: "posture".to_string(),
        event_time,
        actor,
        provenance,
        resource_id: None,
        client_id: None,
        target: None,
        rule,
        severity: Severity::parse(
            require_string(object, "rawSeverity")?,
            &format!("{path}.rawSeverity"),
        )?,
        evidence,
        counter_evidence,
        ip_context,
    })
}

fn parse_security_posture_signal(
    value: &Value,
    field: &str,
    index: usize,
    input_window: &CorrelationWindow,
    missing_data: &mut BTreeSet<String>,
) -> Result<Signal, CorrelationError> {
    let object = value.as_object().ok_or_else(|| {
        CorrelationError::new(format!(
            "securityPosture.{field}[{index}] must be an object"
        ))
    })?;
    let path = format!("securityPosture.{field}[{index}]");
    let event_id = bounded_string(
        require_string(object, "findingId")?,
        &format!("{path}.findingId"),
    )?;
    let rule = bounded_string(
        require_string(object, "controlId")?,
        &format!("{path}.controlId"),
    )?;
    validate_posture_token(&rule, &format!("{path}.controlId"))?;
    bounded_string(
        require_string(object, "subject")?,
        &format!("{path}.subject"),
    )?;
    let provenance = parse_provenance(object.get("provenance"), &path, missing_data)?;
    let actor = parse_signal_actor(object, &path, provenance, missing_data)?;
    let evidence = parse_evidence(
        object.get("evidence"),
        POSTURE_EVIDENCE_KEYS,
        &format!("{path}.evidence"),
    )?;
    let event_time_value = provenance.and_then(|value| {
        value
            .temporal_correlation_eligible()
            .then(|| {
                ["createdDateTime", "activityDateTime"]
                    .iter()
                    .find_map(|key| {
                        evidence
                            .get(*key)
                            .and_then(|value| parse_timestamp(value, key).ok())
                    })
            })
            .flatten()
    });
    if event_time_value.is_none() {
        missing_data.insert(format!("{path}.eventTime:missing"));
    }
    if !provenance.is_some_and(ProvenanceV1::temporal_correlation_eligible) {
        missing_data.insert(format!("{event_id}:causal_time_unavailable"));
    }
    let event_time = retain_signal_in_input_window(
        event_time_value,
        input_window,
        &event_id,
        provenance,
        missing_data,
    );
    let counter_evidence = object
        .get("analysis")
        .and_then(Value::as_object)
        .map(|analysis| parse_counter_evidence_value(analysis.get("counterEvidence"), &path))
        .transpose()?
        .unwrap_or(0);
    Ok(Signal {
        event_id,
        source: "posture".to_string(),
        event_time,
        actor,
        provenance,
        resource_id: None,
        client_id: None,
        target: None,
        rule,
        severity: Severity::parse(
            require_string(object, "severity")?,
            &format!("{path}.severity"),
        )?,
        evidence,
        counter_evidence,
        ip_context: false,
    })
}

fn build_indexes(signals: &[Signal]) -> BTreeMap<String, BTreeMap<String, Vec<usize>>> {
    let mut indexes: BTreeMap<String, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
    for (index, signal) in signals.iter().enumerate() {
        if !signal
            .provenance
            .is_some_and(ProvenanceV1::temporal_correlation_eligible)
        {
            continue;
        }
        let actor = signal
            .provenance
            .filter(|provenance| provenance.actor_correlation_eligible())
            .and(signal.actor.as_ref());
        for (dimension, value) in [
            ("actor", actor),
            ("resourceId", signal.resource_id.as_ref()),
            ("oauthClient", signal.client_id.as_ref()),
            ("target", signal.target.as_ref()),
            ("rule", Some(&signal.rule)),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                indexes
                    .entry(dimension.to_string())
                    .or_default()
                    .entry(value.clone())
                    .or_default()
                    .push(index);
            }
        }
    }
    indexes
}

fn signal_order(left: &Signal, right: &Signal) -> std::cmp::Ordering {
    left.event_time
        .cmp(&right.event_time)
        .then_with(|| left.event_id.cmp(&right.event_id))
}

fn build_correlation(
    dimension: &str,
    key: &str,
    selected: &[usize],
    signals: &[Signal],
    contradictions: &[String],
    posture: &PostureState,
) -> Value {
    let event_ids = selected
        .iter()
        .map(|index| signals[*index].event_id.clone())
        .collect::<Vec<_>>();
    let id_key = format!(
        "{CORRELATION_CONTRACT_VERSION}|{dimension}|{}",
        event_ids.join("|")
    );
    let correlation_id = format!(
        "corrv1-{}",
        Uuid::new_v5(&Uuid::NAMESPACE_URL, id_key.as_bytes())
    );
    let sources = selected
        .iter()
        .map(|index| signals[*index].source.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let rules = selected
        .iter()
        .map(|index| signals[*index].rule.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let resource_ids = selected
        .iter()
        .filter_map(|index| signals[*index].resource_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let client_ids = selected
        .iter()
        .filter_map(|index| signals[*index].client_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let targets = selected
        .iter()
        .filter_map(|index| signals[*index].target.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let event_times = selected
        .iter()
        .filter_map(|index| signals[*index].event_time.map(canonical_time))
        .collect::<Vec<_>>();
    let actor = unique_value(selected, signals, |signal| signal.actor.clone());
    let critical = selected
        .iter()
        .any(|index| signals[*index].severity == Severity::Critical);
    let counter_evidence_count: usize = selected
        .iter()
        .map(|index| signals[*index].counter_evidence)
        .sum();
    let ip_context_count = selected
        .iter()
        .filter(|index| signals[**index].ip_context)
        .count();
    let benign_context = counter_evidence_count > 0
        || selected.iter().any(|index| {
            signals[*index]
                .evidence
                .get("conditionalAccessStatus")
                .is_some_and(|value| matches!(value.as_str(), "failure" | "blocked" | "denied"))
        });
    let contextual_verdict = if !contradictions.is_empty() {
        "CONTRADICTORY"
    } else if benign_context {
        "BENIGN_CONTEXT_REVIEW"
    } else {
        "CORRELATED_ALERT"
    };
    let start_time = event_times.first().cloned().unwrap_or_default();
    let end_time = event_times.last().cloned().unwrap_or_default();
    let matched_value = bounded_output_value(key);
    let mut evidence = BTreeMap::new();
    evidence.insert("matchType".to_string(), dimension.to_string());
    evidence.insert("matchedValue".to_string(), matched_value.clone());
    evidence.insert("sourceSet".to_string(), sources.join(","));
    evidence.insert("rules".to_string(), bounded_output_value(&rules.join(",")));
    if !resource_ids.is_empty() {
        evidence.insert(
            "resourceIds".to_string(),
            bounded_output_value(&resource_ids.join(",")),
        );
    }
    if !client_ids.is_empty() {
        evidence.insert(
            "oauthClientIds".to_string(),
            bounded_output_value(&client_ids.join(",")),
        );
    }
    if !targets.is_empty() {
        evidence.insert(
            "targets".to_string(),
            bounded_output_value(&targets.join(",")),
        );
    }
    evidence.insert(
        "eventTimes".to_string(),
        bounded_output_value(&event_times.join(",")),
    );
    evidence.insert(
        "counterEvidenceCount".to_string(),
        counter_evidence_count.to_string(),
    );
    evidence.insert(
        "ipContext".to_string(),
        if ip_context_count == 0 {
            "none".to_string()
        } else {
            "observed".to_string()
        },
    );

    let mut assertions = vec![json!({
        "kind": "HECHO",
        "text": format!("Se observaron {} señales de {} en la misma clave exacta dentro de la ventana temporal.", selected.len(), sources.join(", "))
    })];
    let inference = if !contradictions.is_empty() {
        "Los valores contradictorios impiden una conclusión única; la correlación conserva ambos estados para revisión humana."
    } else if benign_context {
        "La contraevidencia explícita puede explicar o bloquear parte de la señal; no demuestra seguridad ni cierre."
    } else if ip_context_count > 0 {
        "La coincidencia temporal sugiere una relación operativa; el contexto IP ayuda a revisar, pero no prueba seguridad."
    } else {
        "La coincidencia exacta y temporal sugiere una relación operativa; no prueba compromiso, éxito ni autorización."
    };
    assertions.push(json!({"kind":"INFERENCIA","text": inference}));
    let missing_text = if posture.present && posture.assured {
        "No se confirmó éxito, reconocimiento del usuario, autoridad humana ni impacto efectivo."
    } else {
        "Falta postura/cross-cloud completa y no se confirmó éxito, reconocimiento del usuario, autoridad humana ni impacto efectivo."
    };
    assertions.push(json!({"kind":"DATO FALTANTE","text": missing_text}));

    let quick_view = bounded_output_value(&format!(
        "{}: {} señales de {} para {} ({}–{}); revisión humana requerida.",
        dimension,
        selected.len(),
        sources.join("/"),
        actor.as_deref().unwrap_or("clave no atribuida"),
        start_time,
        end_time,
    ));
    json!({
        "correlationId": correlation_id,
        "matchedBy": dimension,
        "matchedValue": matched_value,
        "actor": actor,
        "signalIds": event_ids,
        "sources": sources,
        "eventCount": selected.len(),
        "startTime": start_time,
        "endTime": end_time,
        "rawSeverity": if critical { "critical" } else { "high" },
        "contextualVerdict": contextual_verdict,
        "confidence": if contradictions.is_empty() && sources.len() >= 3 { "medium" } else { "low" },
        "quickView": quick_view,
        "evidence": evidence,
        "assertions": assertions,
        "contradictions": contradictions,
    })
}

fn contradiction_labels(selected: &[usize], signals: &[Signal]) -> Vec<String> {
    let mut values: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for index in selected {
        for key in [
            "visibility",
            "conditionalAccessStatus",
            "accountEnabled",
            "result",
        ] {
            if let Some(value) = signals[*index].evidence.get(key) {
                values
                    .entry(key)
                    .or_default()
                    .insert(value.to_ascii_lowercase());
            }
        }
    }
    values
        .into_iter()
        .filter(|(key, values)| {
            values.len() > 1
                && match *key {
                    "visibility" => {
                        values.contains("private")
                            && values.iter().any(|value| {
                                matches!(value.as_str(), "people_with_link" | "public_on_the_web")
                            })
                    }
                    "conditionalAccessStatus" => {
                        values.contains("failure") && values.contains("success")
                    }
                    "accountEnabled" => values.contains("true") && values.contains("false"),
                    "result" => values.contains("success") && values.contains("failure"),
                    _ => false,
                }
        })
        .map(|(key, values)| format!("{key}:{}", values.into_iter().collect::<Vec<_>>().join("|")))
        .collect()
}

fn unique_value<F>(selected: &[usize], signals: &[Signal], getter: F) -> Option<String>
where
    F: Fn(&Signal) -> Option<String>,
{
    let values = selected
        .iter()
        .filter_map(|index| getter(&signals[*index]))
        .collect::<BTreeSet<_>>();
    (values.len() == 1).then(|| values.into_iter().next().expect("one value exists"))
}

fn build_coverage(
    declared_sources: &BTreeSet<&str>,
    posture_present: bool,
    posture_assured: bool,
    required_coverage_complete: bool,
) -> Vec<Value> {
    let mut coverage = REQUIRED_SOURCES
        .iter()
        .map(|source| {
            if declared_sources.contains(source) {
                json!({"source": source, "status":"available", "requested":true, "required":true, "assured":true})
            } else {
                json!({"source": source, "status":"unavailable", "requested":true, "required":true, "assured":false, "errorCode":"source_not_declared"})
            }
        })
        .collect::<Vec<_>>();
    coverage.push(if !posture_present {
        json!({"source":"posture", "status":"disabled", "requested":false, "required":false, "assured":false})
    } else if posture_assured && required_coverage_complete {
        json!({"source":"posture", "status":"available", "requested":true, "required":false, "assured":true})
    } else {
        json!({"source":"posture", "status":"unavailable", "requested":true, "required":false, "assured":false, "errorCode":"posture_coverage_not_assured"})
    });
    coverage
}

fn parse_evidence(
    value: Option<&Value>,
    allowed_keys: &[&str],
    path: &str,
) -> Result<BTreeMap<String, String>, CorrelationError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| CorrelationError::new(format!("{path} must be an object")))?;
    let mut evidence = BTreeMap::new();
    for (key, value) in object {
        if !allowed_keys.contains(&key.as_str()) {
            return Err(CorrelationError::new(format!(
                "{path}.{key} is not in the evidence allowlist"
            )));
        }
        let value = value
            .as_str()
            .ok_or_else(|| CorrelationError::new(format!("{path}.{key} must be a string")))?;
        let value_path = format!("{path}.{key}");
        let value = if key == "activityDisplayName" {
            bounded_activity_display_name(value, &value_path)?
        } else {
            bounded_string(value, &value_path)?
        };
        evidence.insert(key.clone(), value);
    }
    Ok(evidence)
}

fn parse_counter_evidence(
    narrative: Option<&Value>,
    path: &str,
) -> Result<usize, CorrelationError> {
    let Some(narrative) = narrative else {
        return Ok(0);
    };
    let object = narrative
        .as_object()
        .ok_or_else(|| CorrelationError::new(format!("{path}.narrative must be an object")))?;
    parse_counter_evidence_value(object.get("counterEvidence"), path)
}

fn parse_counter_evidence_value(
    value: Option<&Value>,
    path: &str,
) -> Result<usize, CorrelationError> {
    let Some(values) = value else {
        return Ok(0);
    };
    let values = values
        .as_array()
        .ok_or_else(|| CorrelationError::new(format!("{path}.counterEvidence must be an array")))?;
    if values.len() > MAX_COUNTER_EVIDENCE {
        return Err(CorrelationError::new(
            "counterEvidence exceeds the safety bound",
        ));
    }
    for (index, value) in values.iter().enumerate() {
        let text = value.as_str().ok_or_else(|| {
            CorrelationError::new(format!("{path}.counterEvidence[{index}] must be a string"))
        })?;
        bounded_string(text, &format!("{path}.counterEvidence[{index}]"))?;
    }
    Ok(values.len())
}

fn parse_ip_context(
    value: Option<&Value>,
    path: &str,
    missing_data: &mut BTreeSet<String>,
) -> Result<bool, CorrelationError> {
    let Some(value) = value else {
        return Ok(false);
    };
    let object = value
        .as_object()
        .ok_or_else(|| CorrelationError::new(format!("{path}.ipIntelligence must be an object")))?;
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CorrelationError::new(format!("{path}.ipIntelligence.status is required"))
        })?;
    if !matches!(status, "complete" | "partial" | "unavailable" | "local") {
        missing_data.insert(format!("{path}.ipIntelligence:unknown_status"));
        return Ok(false);
    }
    Ok(true)
}

fn parse_optional_time(
    value: Option<&Value>,
    path: &str,
    missing_data: &mut BTreeSet<String>,
) -> Result<Option<DateTime<Utc>>, CorrelationError> {
    let Some(value) = value else {
        missing_data.insert(format!("{path}:missing"));
        return Ok(None);
    };
    if value.is_null() {
        missing_data.insert(format!("{path}:missing"));
        return Ok(None);
    }
    let value = value
        .as_str()
        .ok_or_else(|| CorrelationError::new(format!("{path} must be a string or null")))?;
    match parse_timestamp(value, path) {
        Ok(timestamp) => Ok(Some(timestamp)),
        Err(_) => {
            missing_data.insert(format!("{path}:invalid"));
            Ok(None)
        }
    }
}

fn retain_in_input_window(
    value: Option<DateTime<Utc>>,
    input_window: &CorrelationWindow,
    event_id: &str,
    missing_data: &mut BTreeSet<String>,
) -> Option<DateTime<Utc>> {
    value.filter(|timestamp| {
        let inside = *timestamp >= input_window.start && *timestamp <= input_window.end;
        if !inside {
            missing_data.insert(format!("{event_id}:stale_event_time"));
        }
        inside
    })
}

fn first_consistent_value(
    name: &str,
    first: Option<&str>,
    second: Option<&str>,
    path: &str,
) -> Result<Option<String>, CorrelationError> {
    let first = first
        .map(|value| safe_match_value(value, &format!("{path}.{name}"), name == "resourceId"))
        .transpose()?;
    let second = second
        .map(|value| safe_match_value(value, &format!("{path}.{name}"), name == "resourceId"))
        .transpose()?;
    if first.is_some() && second.is_some() && first != second {
        return Err(CorrelationError::new(format!(
            "{path}.{name} has ambiguous conflicting identifiers"
        )));
    }
    Ok(first.or(second))
}

fn safe_match_value(
    value: &str,
    path: &str,
    allow_rfc_message_id_delimiters: bool,
) -> Result<String, CorrelationError> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 254 || normalized.chars().any(char::is_control) {
        return Err(CorrelationError::new(format!(
            "{path} is empty, unsafe, or too long"
        )));
    }
    if normalized.chars().any(char::is_whitespace) {
        return Err(CorrelationError::new(format!("{path} contains whitespace")));
    }
    if !normalized.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || "-_.:@/+=".contains(character)
            || (allow_rfc_message_id_delimiters && "<>".contains(character))
    }) {
        return Err(CorrelationError::new(format!(
            "{path} contains an unsafe identifier character"
        )));
    }
    Ok(normalized)
}

fn validate_posture_source(value: &str, path: &str) -> Result<(), CorrelationError> {
    if value == "cross-cloud.correlator"
        || value.starts_with("google.")
        || value.starts_with("microsoft.")
    {
        Ok(())
    } else {
        Err(CorrelationError::new(format!(
            "{path} is not an allowlisted posture source"
        )))
    }
}

fn validate_posture_token(value: &str, path: &str) -> Result<(), CorrelationError> {
    if value.is_empty()
        || value.len() > 160
        || value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || !character.is_ascii()
        })
    {
        Err(CorrelationError::new(format!(
            "{path} is not a safe posture identifier"
        )))
    } else {
        Ok(())
    }
}

fn require_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, CorrelationError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| CorrelationError::new(format!("{key} must be a string")))
}

fn optional_string(
    object: &Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<Option<String>, CorrelationError> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(bounded_string(
        value
            .as_str()
            .ok_or_else(|| CorrelationError::new(format!("{path} must be a string or null")))?,
        path,
    )?))
}

fn bounded_string(value: &str, path: &str) -> Result<String, CorrelationError> {
    bounded_string_with_marker_policy(value, path, true)
}

fn bounded_activity_display_name(value: &str, path: &str) -> Result<String, CorrelationError> {
    bounded_string_with_marker_policy(value, path, false)
}

fn bounded_string_with_marker_policy(
    value: &str,
    path: &str,
    reject_literal_secret_marker: bool,
) -> Result<String, CorrelationError> {
    if value.is_empty()
        || value.chars().count() > MAX_TEXT_LENGTH
        || value.chars().any(char::is_control)
    {
        return Err(CorrelationError::new(format!(
            "{path} is empty, unsafe, or exceeds the bounded text limit"
        )));
    }
    if [
        "bearer ",
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "secret-token",
    ]
    .iter()
    .any(|marker| value.to_ascii_lowercase().contains(marker))
        || (reject_literal_secret_marker && value.to_ascii_lowercase().contains("secret"))
    {
        return Err(CorrelationError::new(format!(
            "{path} contains a sensitive marker"
        )));
    }
    Ok(value.to_string())
}

fn parse_timestamp(value: &str, path: &str) -> Result<DateTime<Utc>, CorrelationError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| CorrelationError::new(format!("{path} is not RFC3339")))
}

fn canonical_time(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn signal_fingerprint_key(signal: &Signal) -> Value {
    json!({
        "eventId": signal.event_id,
        "source": signal.source,
        "eventTime": signal.event_time.map(canonical_time),
        "actor": signal.actor,
        "provenance": signal.provenance,
        "resourceId": signal.resource_id,
        "clientId": signal.client_id,
        "target": signal.target,
        "rule": signal.rule,
        "severity": signal.severity.as_str(),
        "evidence": signal.evidence,
        "counterEvidence": signal.counter_evidence,
        "ipContext": signal.ip_context,
    })
}

fn sha256_json(value: &Value) -> Result<String, CorrelationError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CorrelationError::new(format!("could not fingerprint JSON: {error}")))?;
    let digest = Sha256::digest(bytes);
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("sha256:{hex}"))
}

fn bounded_output_value(value: &str) -> String {
    value.chars().take(300).collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    fn finding(
        event_id: &str,
        event_time: Option<&str>,
        source: &str,
        rule: &str,
        actor: &str,
        extra: serde_json::Value,
    ) -> serde_json::Value {
        let mut value = json!({
            "eventId": event_id,
            "eventTime": event_time,
            "source": source,
            "eventName": rule,
            "severity": "high",
            "rule": rule,
            "actor": actor,
            "provenance": explicit_google_provenance(),
            "occurrences": 1,
            "evidence": {}
        });
        let object = value.as_object_mut().expect("finding object");
        for (key, item) in extra.as_object().expect("extra object") {
            object.insert(key.clone(), item.clone());
        }
        value
    }

    fn explicit_google_provenance() -> serde_json::Value {
        json!({
            "contractVersion": "security_intelligence_provenance_v1",
            "actorRole": "humanUser",
            "actorSource": "googleActor",
            "temporalBasis": "providerEventTime"
        })
    }

    fn input(findings: Vec<serde_json::Value>) -> serde_json::Value {
        json!({
            "mode": "read-only",
            "window": {
                "startTime": "2026-08-02T12:00:00Z",
                "endTime": "2026-08-02T12:30:00Z",
                "lookbackMinutes": 30
            },
            "sources": ["login", "admin", "token", "drive", "rules"],
            "findingCount": findings.len(),
            "findings": findings
        })
    }

    fn two_source_findings(actor: &str, prefix: &str, start_minute: u32) -> Vec<serde_json::Value> {
        let mut findings = vec![
            finding(
                &format!("{prefix}-login"),
                Some(&format!("2026-08-02T12:{start_minute:02}:00Z")),
                "login",
                "google_suspicious_login",
                actor,
                json!({}),
            ),
            finding(
                &format!("{prefix}-drive"),
                Some(&format!("2026-08-02T12:{:02}:00Z", start_minute + 1)),
                "drive",
                "drive_public_link_enabled",
                actor,
                json!({"resourceId": format!("resource-{prefix}")}),
            ),
        ];
        for finding in &mut findings {
            finding
                .as_object_mut()
                .expect("finding object")
                .insert("provenance".to_string(), explicit_google_provenance());
        }
        findings
    }

    #[test]
    fn historical_v1_input_without_provenance_is_accepted_but_not_correlated() {
        let mut findings = two_source_findings("user@example.com", "legacy", 1);
        for finding in &mut findings {
            finding
                .as_object_mut()
                .expect("finding object")
                .remove("provenance");
        }
        let report = input(findings);

        let output = super::correlate_report(&report, 30, 50).expect("input remains readable");

        assert!(output["correlations"].as_array().unwrap().is_empty());
        assert!(output["failClosed"].as_bool().unwrap());
        assert!(output["missingData"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "finding[0].provenance:missing"));
    }

    #[test]
    fn snapshot_observed_and_generated_times_never_become_causal_event_time() {
        let mut findings = two_source_findings("user@example.com", "snapshot", 1);
        for finding in &mut findings {
            let object = finding.as_object_mut().expect("finding object");
            object.insert(
                "provenance".to_string(),
                json!({
                    "contractVersion": "security_intelligence_provenance_v1",
                    "actorRole": "humanUser",
                    "actorSource": "googleActor",
                    "temporalBasis": "snapshotObservedAt"
                }),
            );
            object.insert("observedAt".to_string(), json!("2026-08-02T12:00:00Z"));
            object.insert("generatedAt".to_string(), json!("2026-08-02T12:00:01Z"));
        }
        let report = input(findings);

        let output = super::correlate_report(&report, 30, 50).expect("input remains readable");

        assert!(output["correlations"].as_array().unwrap().is_empty());
        assert!(output["missingData"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "snapshot-login:causal_time_unavailable"));
    }

    #[test]
    fn historical_security_posture_without_provenance_is_readable_but_not_causal() {
        let mut report = input(Vec::new());
        report["securityPosture"] = json!({
            "schemaVersion": "security_intelligence_v1",
            "generatedAt": "2026-08-02T12:00:01Z",
            "coverageComplete": false,
            "coverage": [{
                "source": "google.users",
                "status": "available",
                "requested": true,
                "required": true,
                "assured": true
            }],
            "identityPosture": [{
                "findingId": "legacy-posture-1",
                "controlId": "GOOGLE.IDENTITY.STALE_ACTIVE_ACCOUNT",
                "provider": "googleWorkspace",
                "severity": "high",
                "contextualVerdict": "ALERT",
                "title": "Cuenta activa sin uso reciente",
                "subject": "person@example.com",
                "summary": "La cuenta permanece habilitada.",
                "evidence": {"lastLoginTime": "2026-07-20T12:00:00Z"},
                "analysis": {}
            }],
            "controlPosture": [],
            "crossCloudCorrelations": [],
            "signalFindings": []
        });

        let output = super::correlate_report(&report, 30, 50).expect("legacy input is readable");

        assert!(output["correlations"].as_array().unwrap().is_empty());
        assert!(output["missingData"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| { item == "securityPosture.identityPosture[0].provenance:missing" }));
        assert!(output["missingData"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| { item == "legacy-posture-1:causal_time_unavailable" }));
    }

    #[test]
    fn correlates_exact_actor_across_google_sources_with_bounded_assertions() {
        let input = json!({
            "mode": "read-only",
            "window": {
                "startTime": "2026-08-02T12:00:00Z",
                "endTime": "2026-08-02T12:30:00Z",
                "lookbackMinutes": 30
            },
            "sources": ["login", "admin", "token", "drive", "rules"],
            "findingCount": 5,
            "findings": [
                {"eventId":"login-1","eventTime":"2026-08-02T12:01:00Z","source":"login","eventName":"suspicious_login","severity":"critical","rule":"google_suspicious_login","actor":"User@Example.com","provenance": explicit_google_provenance(),"occurrences":1,"evidence":{}},
                {"eventId":"admin-1","eventTime":"2026-08-02T12:04:00Z","source":"admin","eventName":"ASSIGN_ROLE","severity":"critical","rule":"admin_role_assigned","actor":"user@example.com","provenance": explicit_google_provenance(),"occurrences":1,"evidence":{}},
                {"eventId":"token-1","eventTime":"2026-08-02T12:07:00Z","source":"token","eventName":"authorize","severity":"high","rule":"oauth_application_authorized","actor":"user@example.com","provenance": explicit_google_provenance(),"occurrences":1,"evidence":{"client_id":"client-1"}},
                {"eventId":"drive-1","eventTime":"2026-08-02T12:10:00Z","source":"drive","eventName":"change_user_access","severity":"high","rule":"drive_shared_outside_trusted_domains","actor":"user@example.com","provenance": explicit_google_provenance(),"resourceId":"file-1","target":"outside@example.net","occurrences":1,"evidence":{"doc_id":"file-1","target_user":"outside@example.net"}},
                {"eventId":"rules-1","eventTime":"2026-08-02T12:13:00Z","source":"rules","eventName":"rule_trigger","severity":"high","rule":"dlp_rule_triggered","actor":"user@example.com","provenance": explicit_google_provenance(),"occurrences":1,"evidence":{"rule_name":"sensitive-data"}}
            ]
        });

        let output = super::correlate_report(&input, 30, 50).expect("correlation should succeed");
        let actor = output["correlations"]
            .as_array()
            .and_then(|items| items.iter().find(|item| item["matchedBy"] == "actor"))
            .expect("actor correlation should be present");

        assert_eq!(actor["actor"], "user@example.com");
        assert_eq!(actor["eventCount"], 5);
        assert_eq!(actor["sources"].as_array().map(Vec::len), Some(5));
        assert!(actor["quickView"].as_str().unwrap().chars().count() <= 300);
        let kinds: Vec<_> = actor["assertions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item["kind"].as_str())
            .collect();
        assert!(kinds.contains(&"HECHO"));
        assert!(kinds.contains(&"INFERENCIA"));
        assert!(kinds.contains(&"DATO FALTANTE"));
        assert!(output["failClosed"].as_bool().unwrap());
    }

    #[test]
    fn explicit_counter_evidence_is_benign_context_not_a_clean_result() {
        let mut report = input(vec![
            finding(
                "login-1",
                Some("2026-08-02T12:01:00Z"),
                "login",
                "google_suspicious_login",
                "user@example.com",
                json!({}),
            ),
            finding(
                "drive-1",
                Some("2026-08-02T12:03:00Z"),
                "drive",
                "drive_public_link_enabled",
                "user@example.com",
                json!({"resourceId":"file-1"}),
            ),
        ]);
        report["monitorIntegration"] = json!({
            "security_intelligence_monitor_v1": {
                "contractVersion": "security_intelligence_monitor_v1",
                "status": "complete",
                "coverageComplete": true,
                "requiredCoverageComplete": true,
                "failClosed": false,
                "coverage": [{"source":"microsoft.signIns","status":"available","requested":true,"required":true,"assured":true}],
                "findings": [{
                    "eventId":"posture-1",
                    "controlId":"MSFT.SIGNAL.DIRECTORY_CHANGE",
                    "rule":"MSFT.SIGNAL.DIRECTORY_CHANGE",
                    "provider":"microsoft365",
                    "source":"microsoft.signIns",
                    "sourceKind":"microsoft365",
                    "eventTime":"2026-08-02T12:02:00Z",
                    "rawSeverity":"high",
                    "contextualVerdict":"ALERT",
                    "confidence":"medium",
                    "urgency":"today",
                    "actor":"user@example.com",
                    "provenance": {
                        "contractVersion":"security_intelligence_provenance_v1",
                        "actorRole":"humanUser",
                        "actorSource":"microsoftInitiatedByUser",
                        "temporalBasis":"providerEventTime"
                    },
                    "quickView":"risky sign-in",
                    "whyFlagged":"review",
                    "evidence":{"conditionalAccessStatus":"failure"},
                    "assertions":[],
                    "narrative":{"conclusion":"risk","whyItMatters":"review","observedEvidence":[],"counterEvidence":["Conditional Access informó failure."],"whatWeDoNotKnow":"success unknown","whatToDoNow":"review","urgency":"today"},
                    "links":[]
                }]
            }
        });

        let output = super::correlate_report(&report, 30, 50).expect("correlation should succeed");
        let posture = output["correlations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["matchedBy"] == "actor" && item["eventCount"] == 3)
            .expect("actor correlation should include posture");

        assert_eq!(posture["contextualVerdict"], "BENIGN_CONTEXT_REVIEW");
        assert!(posture["assertions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["kind"] == "INFERENCIA"
                && item["text"]
                    .as_str()
                    .unwrap()
                    .contains("no demuestra seguridad")));
        assert_ne!(output["status"], "clean");
    }

    #[test]
    fn already_available_cross_cloud_signal_is_context_only_and_not_an_actor() {
        let mut report = input(vec![
            finding(
                "login-1",
                Some("2026-08-02T12:01:00Z"),
                "login",
                "google_suspicious_login",
                "user@example.com",
                json!({}),
            ),
            finding(
                "drive-1",
                Some("2026-08-02T12:03:00Z"),
                "drive",
                "drive_public_link_enabled",
                "user@example.com",
                json!({"resourceId":"file-1"}),
            ),
        ]);
        report["monitorIntegration"] = json!({
            "security_intelligence_monitor_v1": {
                "contractVersion": "security_intelligence_monitor_v1",
                "status": "incomplete",
                "coverageComplete": false,
                "requiredCoverageComplete": false,
                "failClosed": true,
                "coverage": [{"source":"microsoft.signIns","status":"unavailable","requested":true,"required":true,"assured":false}],
                "findings": [{
                    "eventId":"cross-1",
                    "controlId":"CROSS.SIGNAL.MULTITENANT_SUSPICIOUS_LOGIN",
                    "rule":"CROSS.SIGNAL.MULTITENANT_SUSPICIOUS_LOGIN",
                    "provider":"crossCloud",
                    "source":"cross-cloud.correlator",
                    "sourceKind":"crossCloud",
                    "eventTime":"2026-08-02T12:02:00Z",
                    "rawSeverity":"critical",
                    "contextualVerdict":"ALERT",
                    "confidence":"high",
                    "urgency":"immediate",
                    "actor":"user@example.com",
                    "provenance": {
                        "contractVersion":"security_intelligence_provenance_v1",
                        "actorRole":"affectedUser",
                        "actorSource":"crossCloudSubject",
                        "temporalBasis":"snapshotGeneratedAt"
                    },
                    "quickView":"cross-cloud signal",
                    "whyFlagged":"review",
                    "evidence":{"googleEventId":"login-1","googleRule":"google_suspicious_login","microsoftSignInId":"sign-in-1"},
                    "assertions":[],
                    "narrative":{"conclusion":"risk","whyItMatters":"review","observedEvidence":[],"counterEvidence":[],"whatWeDoNotKnow":"scope unknown","whatToDoNow":"review","urgency":"immediate"},
                    "links":[]
                }]
            }
        });

        let output =
            super::correlate_report(&report, 30, 50).expect("local posture should be readable");
        assert!(!output["correlations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item["matchedBy"] == "actor"
                    && item["eventCount"] == 3
                    && item["sources"]
                        .as_array()
                        .is_some_and(|sources| sources.iter().any(|source| source == "posture"))
            }));
        assert!(output["failClosed"].as_bool().unwrap());
        assert_eq!(output["coverage"][5]["status"], "unavailable");
    }

    #[test]
    fn exact_oauth_client_and_target_keys_join_distinct_google_sources() {
        let report = input(vec![
            finding(
                "token-1",
                Some("2026-08-02T12:01:00Z"),
                "token",
                "oauth_application_authorized",
                "user@example.com",
                json!({
                    "evidence": {
                        "client_id": "client-1",
                        "target_user": "outside@example.net"
                    }
                }),
            ),
            finding(
                "drive-1",
                Some("2026-08-02T12:02:00Z"),
                "drive",
                "drive_shared_outside_trusted_domains",
                "other@example.com",
                json!({
                    "originatingAppId": "client-1",
                    "target": "outside@example.net",
                    "resourceId": "file-1"
                }),
            ),
            finding(
                "rules-1",
                Some("2026-08-02T12:03:00Z"),
                "rules",
                "dlp_rule_triggered",
                "other@example.com",
                json!({"target_user":"outside@example.net"}),
            ),
        ]);

        let output = super::correlate_report(&report, 30, 50).expect("exact keys should correlate");
        let correlations = output["correlations"].as_array().unwrap();
        assert!(correlations
            .iter()
            .any(|item| item["matchedBy"] == "oauthClient" && item["matchedValue"] == "client-1"));
        assert!(correlations.iter().any(|item| {
            item["matchedBy"] == "target" && item["matchedValue"] == "outside@example.net"
        }));
    }

    #[test]
    fn conflicting_resource_context_is_preserved_as_contradictory() {
        let report = input(vec![
            finding(
                "drive-1",
                Some("2026-08-02T12:01:00Z"),
                "drive",
                "drive_public_link_enabled",
                "user@example.com",
                json!({"resourceId":"file-1","visibility":"private"}),
            ),
            finding(
                "rules-1",
                Some("2026-08-02T12:02:00Z"),
                "rules",
                "dlp_rule_triggered",
                "user@example.com",
                json!({"resourceId":"file-1","visibility":"public_on_the_web"}),
            ),
        ]);

        let output = super::correlate_report(&report, 30, 50).expect("correlation should succeed");
        let resource = output["correlations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["matchedBy"] == "resourceId")
            .expect("resource correlation should be present");

        assert_eq!(resource["contextualVerdict"], "CONTRADICTORY");
        assert!(output["failClosed"].as_bool().unwrap());
        assert!(!output["contradictions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn accepts_rfc_message_id_resource_identifiers_without_relaxing_path_controls() {
        let resource_id = "message-<synthetic@example.invalid>";
        let report = input(vec![
            finding(
                "rules-1",
                Some("2026-08-02T12:01:00Z"),
                "rules",
                "dlp_user_warned",
                "first@example.com",
                json!({"resourceId": resource_id}),
            ),
            finding(
                "drive-1",
                Some("2026-08-02T12:02:00Z"),
                "drive",
                "drive_public_link_enabled",
                "second@example.com",
                json!({"resourceId": resource_id}),
            ),
        ]);

        let output = super::correlate_report(&report, 30, 50)
            .expect("provider resource identifier should be accepted");
        assert!(output["correlations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["matchedBy"] == "resourceId"));

        for invalid_resource_id in [
            "message?<synthetic@example.invalid>",
            "message#<synthetic@example.invalid>",
            "message-\n<synthetic@example.invalid>",
        ] {
            let invalid_report = input(vec![finding(
                "rules-invalid",
                Some("2026-08-02T12:01:00Z"),
                "rules",
                "dlp_user_warned",
                "first@example.com",
                json!({"resourceId": invalid_resource_id}),
            )]);
            let error = super::correlate_report(&invalid_report, 30, 50)
                .expect_err("path and control characters must remain rejected");
            assert!(error.to_string().contains("resourceId"));
        }

        let invalid_target_report = input(vec![finding(
            "rules-invalid-target",
            Some("2026-08-02T12:01:00Z"),
            "rules",
            "dlp_user_warned",
            "first@example.com",
            json!({"target": "recipient<synthetic@example.invalid>"}),
        )]);
        let error = super::correlate_report(&invalid_target_report, 30, 50)
            .expect_err("message-id delimiters must remain rejected for non-resource fields");
        assert!(error.to_string().contains("target"));
    }

    #[test]
    fn treats_activity_display_name_as_metadata_not_a_secret_body() {
        let mut report = input(Vec::new());
        report["monitorIntegration"] = json!({
            "security_intelligence_monitor_v1": {
                "contractVersion": "security_intelligence_monitor_v1",
                "status": "incomplete",
                "coverageComplete": false,
                "requiredCoverageComplete": false,
                "failClosed": true,
                "coverage": [{"source":"google.users","status":"available","requested":true,"required":true,"assured":true}],
                "findings": [{
                    "eventId":"posture-synthetic-1",
                    "controlId":"MSFT.SIGNAL.DIRECTORY_CHANGE",
                    "rule":"MSFT.SIGNAL.DIRECTORY_CHANGE",
                    "provider":"microsoft365",
                    "source":"microsoft.directoryAudits",
                    "sourceKind":"microsoft365",
                    "eventTime":"2026-08-02T12:02:00Z",
                    "rawSeverity":"high",
                    "contextualVerdict":"ALERT",
                    "confidence":"medium",
                    "urgency":"today",
                    "actor":"user@example.com",
                    "quickView":"synthetic directory activity",
                    "whyFlagged":"review",
                    "evidence":{"activityDisplayName":"Synthetic secret metadata label"},
                    "assertions":[],
                    "narrative":{"conclusion":"review","whyItMatters":"review","observedEvidence":[],"counterEvidence":[],"whatWeDoNotKnow":"scope unknown","whatToDoNow":"review","urgency":"today"},
                    "links":[]
                }]
            }
        });

        let output = super::correlate_report(&report, 30, 50)
            .expect("allowlisted activity metadata should be readable");
        assert_eq!(output["status"], "incomplete");

        let mut blocked = report;
        blocked["monitorIntegration"]["security_intelligence_monitor_v1"]["findings"][0]
            ["evidence"]["activityDisplayName"] = json!("Synthetic secret-token marker");
        let error = super::correlate_report(&blocked, 30, 50)
            .expect_err("credential-shaped markers must remain rejected");
        assert!(error.to_string().contains("sensitive marker"));
    }

    #[test]
    fn missing_source_and_identifiers_never_become_clean() {
        let mut report = input(vec![finding(
            "login-1",
            None,
            "login",
            "google_suspicious_login",
            "(unknown)",
            json!({}),
        )]);
        report["sources"] = json!(["login", "admin", "token", "drive"]);

        let output = super::correlate_report(&report, 30, 50).expect("missing data is reportable");

        assert_eq!(output["status"], "incomplete");
        assert!(output["failClosed"].as_bool().unwrap());
        let missing = output["missingData"].as_array().unwrap();
        assert!(missing
            .iter()
            .any(|item| item.as_str().unwrap().contains("rules")));
        assert!(missing
            .iter()
            .any(|item| item.as_str().unwrap().contains("eventTime")));
    }

    #[test]
    fn unknown_evidence_key_is_rejected_by_the_allowlist() {
        let report = input(vec![finding(
            "login-1",
            Some("2026-08-02T12:01:00Z"),
            "login",
            "google_suspicious_login",
            "user@example.com",
            json!({"evidence":{"private_payload":"must not pass"}}),
        )]);

        let error = super::correlate_report(&report, 30, 50)
            .expect_err("unknown evidence must fail closed");
        assert!(error.to_string().contains("allowlist"));
    }

    #[test]
    fn existing_observer_aggregate_evidence_remains_compatible() {
        let report = input(vec![finding(
            "login-aggregate",
            Some("2026-08-02T12:01:00Z"),
            "login",
            "repeated_login_failures",
            "user@example.com",
            json!({
                "evidence": {
                    "failed_login_count": "5",
                    "matched_trigger": "login_failure",
                    "unique_resource_count": "25"
                }
            }),
        )]);

        let output = super::correlate_report(&report, 30, 50)
            .expect("known observer evidence should remain compatible");
        assert_eq!(output["status"], "incomplete");
        assert!(output["failClosed"].as_bool().unwrap());
    }

    #[test]
    fn duplicate_event_id_with_conflicting_identity_is_rejected() {
        let report = input(vec![
            finding(
                "duplicate",
                Some("2026-08-02T12:01:00Z"),
                "login",
                "google_suspicious_login",
                "one@example.com",
                json!({}),
            ),
            finding(
                "duplicate",
                Some("2026-08-02T12:02:00Z"),
                "admin",
                "admin_role_assigned",
                "two@example.com",
                json!({}),
            ),
        ]);

        let error =
            super::correlate_report(&report, 30, 50).expect_err("ambiguous IDs must fail closed");
        assert!(error.to_string().contains("duplicate eventId"));
    }

    #[test]
    fn correlation_ids_and_fingerprint_are_order_independent() {
        let mut findings = two_source_findings("user@example.com", "one", 1);
        findings.extend(two_source_findings("other@example.com", "two", 5));
        let first = input(findings.clone());
        findings.reverse();
        let mut second = input(findings);
        second["sources"] = json!(["rules", "drive", "token", "admin", "login"]);

        let first_output = super::correlate_report(&first, 30, 50).expect("first report");
        let second_output = super::correlate_report(&second, 30, 50).expect("second report");

        assert_eq!(first_output["fingerprint"], second_output["fingerprint"]);
        assert_eq!(first_output["correlations"], second_output["correlations"]);
    }

    #[test]
    fn time_window_excludes_distant_signals_and_records_the_gap() {
        let report = input(vec![
            finding(
                "login-1",
                Some("2026-08-02T12:01:00Z"),
                "login",
                "google_suspicious_login",
                "user@example.com",
                json!({}),
            ),
            finding(
                "drive-1",
                Some("2026-08-02T12:25:00Z"),
                "drive",
                "drive_public_link_enabled",
                "user@example.com",
                json!({"resourceId":"file-1"}),
            ),
        ]);

        let output = super::correlate_report(&report, 10, 50).expect("correlation should succeed");

        assert!(!output["correlations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["matchedBy"] == "actor"));
        assert!(output["missingData"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item
                .as_str()
                .unwrap()
                .contains("outside_correlation_window")));
    }

    #[test]
    fn correlation_limit_overflow_is_explicitly_fail_closed() {
        let mut findings = Vec::new();
        for index in 0..3 {
            findings.extend(two_source_findings(
                &format!("user{index}@example.com"),
                &format!("actor{index}"),
                index * 2 + 1,
            ));
        }
        let report = input(findings);

        let output =
            super::correlate_report(&report, 30, 1).expect("overflow should be reportable");

        assert_eq!(output["status"], "overflow");
        assert!(output["failClosed"].as_bool().unwrap());
        assert!(output["overflow"].as_array().unwrap().len() >= 1);
        assert!(output["correlations"].as_array().unwrap().len() <= 1);
    }

    #[test]
    fn ip_context_is_not_converted_into_a_safety_conclusion() {
        let report = input(vec![
            finding(
                "login-1",
                Some("2026-08-02T12:01:00Z"),
                "login",
                "google_suspicious_login",
                "user@example.com",
                json!({"ipIntelligence":{"status":"complete","vpn":"not_detected"}}),
            ),
            finding(
                "drive-1",
                Some("2026-08-02T12:02:00Z"),
                "drive",
                "drive_public_link_enabled",
                "user@example.com",
                json!({"resourceId":"file-1"}),
            ),
        ]);

        let output = super::correlate_report(&report, 30, 50).expect("correlation should succeed");
        let actor = output["correlations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["matchedBy"] == "actor")
            .expect("actor correlation should be present");

        assert_eq!(actor["evidence"]["ipContext"], "observed");
        assert_ne!(actor["contextualVerdict"], "BENIGN_CONTEXT_REVIEW");
        assert!(actor["assertions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["text"]
                .as_str()
                .unwrap()
                .contains("no prueba seguridad")));
    }
}
