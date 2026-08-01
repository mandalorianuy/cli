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

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use uuid::Uuid;

pub(super) const CUTOVER_PLAN_VERSION: &str = "security_intelligence_monitor_cutover_v1";
pub(super) const TARGET_SCHEMA_VERSION: u64 = 7;
const CONTRACT_VERSION: &str = "security_intelligence_monitor_v1";

const ALLOWED_SOURCE_LINKS: &[(&str, &str)] = &[
    (
        "Google Admin security",
        "https://admin.google.com/ac/security",
    ),
    ("Microsoft Entra overview", "https://entra.microsoft.com/"),
    (
        "Microsoft Defender portal",
        "https://security.microsoft.com/",
    ),
];

const ALLOWED_EVIDENCE_KEYS: &[&str] = &[
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

const HUMAN_FIELDS: &[&str] = &[
    "assignee",
    "comment",
    "comments",
    "decision",
    "decisionAt",
    "disposition",
    "humanDisposition",
    "humanStatus",
    "notes",
    "owner",
    "resolution",
    "reviewedAt",
    "reviewer",
    "status",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CutoverError(String);

impl CutoverError {
    fn invalid(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CutoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CutoverError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum SyncAction {
    Create,
    Update,
    Noop,
    Suppress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum NotifierAction {
    Emit,
    Suppress,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CutoverGate {
    schema_compatible: bool,
    coverage_complete: bool,
    required_coverage_complete: bool,
    fail_closed: bool,
    authorization_required: bool,
    blocked_reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncOperation {
    action: SyncAction,
    key: String,
    eligible: bool,
    reason: String,
    record: BTreeMap<String, Value>,
    patch: BTreeMap<String, Value>,
    preserved_human_fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct EmailOperation {
    action: NotifierAction,
    candidate_action: NotifierAction,
    eligible: bool,
    reason: String,
    payload: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MonitorSyncPlan {
    plan_version: &'static str,
    mode: &'static str,
    contract_version: &'static str,
    target_schema_version: u64,
    observed_target_schema_version: u64,
    status: &'static str,
    coverage_status: String,
    coverage: Vec<RawCoverage>,
    external_writes_allowed: bool,
    email_allowed: bool,
    gate: CutoverGate,
    blocked_reasons: Vec<String>,
    findings: Vec<SyncOperation>,
    investigations: Vec<SyncOperation>,
    recommendations: Vec<SyncOperation>,
    email: EmailOperation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RawCoverage {
    source: String,
    source_kind: String,
    status: String,
    requested: bool,
    required: bool,
    assured: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RawAssertion {
    kind: String,
    text: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RawLink {
    label: String,
    url: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RawNarrative {
    conclusion: String,
    why_it_matters: String,
    observed_evidence: Vec<String>,
    counter_evidence: Vec<String>,
    what_we_do_not_know: String,
    what_to_do_now: String,
    urgency: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RawFinding {
    event_id: String,
    control_id: String,
    rule: String,
    provider: String,
    source: String,
    source_kind: String,
    observed_at: String,
    #[serde(default)]
    event_time: Option<String>,
    raw_severity: String,
    contextual_verdict: String,
    confidence: String,
    urgency: String,
    #[serde(default)]
    actor: Option<String>,
    quick_view: String,
    why_flagged: String,
    evidence: BTreeMap<String, String>,
    assertions: Vec<RawAssertion>,
    narrative: RawNarrative,
    links: Vec<RawLink>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RawRecommendation {
    recommendation_id: String,
    finding_event_ids: Vec<String>,
    control_id: String,
    source_kind: String,
    category: String,
    priority: String,
    title: String,
    rationale: String,
    evidence: Vec<RawAssertion>,
    urgency: String,
    status: String,
    links: Vec<RawLink>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RawEmailBlock {
    event_id: String,
    control_id: String,
    conclusion: String,
    why_it_matters: String,
    evidence_observed: Vec<String>,
    counter_evidence: Vec<String>,
    what_we_do_not_know: String,
    what_to_do_now: String,
    urgency: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RawEmail {
    format_version: String,
    subject: String,
    coverage_notice: String,
    blocks: Vec<RawEmailBlock>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct RawContract {
    contract_version: String,
    generated_at: String,
    status: String,
    coverage_complete: bool,
    required_coverage_complete: bool,
    fail_closed: bool,
    coverage: Vec<RawCoverage>,
    findings: Vec<RawFinding>,
    recommendations: Vec<RawRecommendation>,
    email: RawEmail,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct ExistingTarget {
    schema_version: u64,
    #[serde(default)]
    findings: Vec<BTreeMap<String, Value>>,
    #[serde(default)]
    investigations: Vec<BTreeMap<String, Value>>,
    #[serde(default)]
    recommendations: Vec<BTreeMap<String, Value>>,
}

#[derive(Clone, Debug)]
struct PlannedRecord {
    key: String,
    record: BTreeMap<String, Value>,
}

pub(super) fn build_sync_plan(
    input: &Value,
    target: &Value,
) -> Result<MonitorSyncPlan, CutoverError> {
    if input.get("mode").and_then(Value::as_str) != Some("read-only") {
        return Err(CutoverError::invalid(
            "monitor input mode must be read-only",
        ));
    }

    let contract_value = input
        .pointer("/monitorIntegration/security_intelligence_monitor_v1")
        .ok_or_else(|| CutoverError::invalid("missing security intelligence monitor contract"))?;
    let contract: RawContract = serde_json::from_value(contract_value.clone()).map_err(|_| {
        CutoverError::invalid("invalid security intelligence monitor contract shape")
    })?;
    let existing: ExistingTarget = serde_json::from_value(target.clone())
        .map_err(|_| CutoverError::invalid("invalid monitor target state shape"))?;

    validate_contract(&contract)?;
    let findings = normalize_findings(contract.findings.clone())?;
    let recommendations = normalize_recommendations(contract.recommendations.clone())?;
    validate_recommendation_references(&findings, &recommendations)?;
    let email_contract = canonicalize_email(contract.email.clone());
    validate_email(&email_contract, &findings)?;
    let email_payload = serde_json::to_value(&email_contract)
        .map_err(|_| CutoverError::invalid("could not serialize email payload"))?;
    let mut coverage = contract.coverage.clone();
    coverage.sort_by(|left, right| left.source.cmp(&right.source));

    let existing_findings = index_existing(existing.findings, "eventId", "finding")?;
    let existing_investigations =
        index_existing(existing.investigations, "investigationId", "investigation")?;
    let existing_recommendations = index_existing(
        existing.recommendations,
        "recommendationId",
        "recommendation",
    )?;

    let schema_compatible = existing.schema_version == TARGET_SCHEMA_VERSION;
    let mut blocked_reasons = Vec::new();
    if !schema_compatible {
        blocked_reasons.push("target_schema_version_unsupported".to_string());
    }
    if !contract.coverage_complete {
        blocked_reasons.push("coverage_incomplete".to_string());
    }
    if !contract.required_coverage_complete {
        blocked_reasons.push("required_coverage_incomplete".to_string());
    }
    if contract.fail_closed {
        blocked_reasons.push("contract_fail_closed".to_string());
    }
    blocked_reasons.sort();

    let gate_open = schema_compatible
        && contract.coverage_complete
        && contract.required_coverage_complete
        && !contract.fail_closed;
    let gate = CutoverGate {
        schema_compatible,
        coverage_complete: contract.coverage_complete,
        required_coverage_complete: contract.required_coverage_complete,
        fail_closed: contract.fail_closed,
        authorization_required: true,
        blocked_reasons: blocked_reasons.clone(),
    };

    let planned_findings = findings
        .iter()
        .map(|finding| PlannedRecord {
            key: finding.event_id.clone(),
            record: finding_record(finding),
        })
        .collect::<Vec<_>>();
    let planned_investigations = findings
        .iter()
        .map(|finding| PlannedRecord {
            key: investigation_id(&finding.event_id),
            record: investigation_record(finding, &contract),
        })
        .collect::<Vec<_>>();
    let planned_recommendations = recommendations
        .iter()
        .map(|recommendation| PlannedRecord {
            key: recommendation.recommendation_id.clone(),
            record: recommendation_record(recommendation),
        })
        .collect::<Vec<_>>();

    let email = EmailOperation {
        action: NotifierAction::Suppress,
        candidate_action: if gate_open {
            NotifierAction::Emit
        } else {
            NotifierAction::Suppress
        },
        eligible: gate_open,
        reason: if gate_open {
            "external_notification_disabled_in_dry_run".to_string()
        } else {
            "notification_blocked_by_cutover_gate".to_string()
        },
        payload: email_payload,
    };

    Ok(MonitorSyncPlan {
        plan_version: CUTOVER_PLAN_VERSION,
        mode: "dry-run",
        contract_version: CONTRACT_VERSION,
        target_schema_version: TARGET_SCHEMA_VERSION,
        observed_target_schema_version: existing.schema_version,
        status: if gate_open {
            "eligible_pending_authorization"
        } else {
            "blocked"
        },
        coverage_status: contract.status.clone(),
        coverage,
        external_writes_allowed: false,
        email_allowed: false,
        gate,
        blocked_reasons,
        findings: plan_records(&planned_findings, &existing_findings, gate_open)?,
        investigations: plan_records(&planned_investigations, &existing_investigations, gate_open)?,
        recommendations: plan_records(
            &planned_recommendations,
            &existing_recommendations,
            gate_open,
        )?,
        email,
    })
}

fn validate_contract(contract: &RawContract) -> Result<(), CutoverError> {
    if contract.contract_version != CONTRACT_VERSION {
        return Err(CutoverError::invalid(
            "unsupported monitor contract version",
        ));
    }
    validate_text("generatedAt", &contract.generated_at, 64)?;
    validate_timestamp("generatedAt", &contract.generated_at)?;
    if !matches!(
        contract.status.as_str(),
        "complete" | "degraded" | "incomplete"
    ) {
        return Err(CutoverError::invalid("invalid monitor contract status"));
    }
    validate_coverage(contract)?;

    for finding in &contract.findings {
        validate_finding(finding)?;
    }
    for recommendation in &contract.recommendations {
        validate_recommendation(recommendation)?;
    }
    Ok(())
}

fn validate_coverage(contract: &RawContract) -> Result<(), CutoverError> {
    let mut sources = BTreeSet::new();
    for entry in &contract.coverage {
        if !sources.insert(entry.source.clone()) {
            return Err(CutoverError::invalid("duplicate coverage source"));
        }
        let expected_kind = source_kind_for_coverage(&entry.source)
            .ok_or_else(|| CutoverError::invalid("unknown source in monitor coverage"))?;
        if entry.source_kind != expected_kind {
            return Err(CutoverError::invalid("coverage source kind mismatch"));
        }
        let (requested, required, assured) = match entry.status.as_str() {
            "available" => (true, true, true),
            "unavailable" => (true, true, false),
            "disabled" => (false, false, false),
            _ => return Err(CutoverError::invalid("invalid coverage status")),
        };
        if (entry.requested, entry.required, entry.assured) != (requested, required, assured) {
            return Err(CutoverError::invalid(
                "coverage assurance flags are inconsistent",
            ));
        }
        if let Some(error_code) = &entry.error_code {
            validate_error_code(error_code)?;
        }
    }

    let coverage_complete = !contract.coverage.is_empty()
        && contract
            .coverage
            .iter()
            .all(|entry| entry.status == "available" && entry.assured);
    let required_coverage_complete = !contract.coverage.is_empty()
        && contract
            .coverage
            .iter()
            .all(|entry| !entry.required || (entry.status == "available" && entry.assured));
    if contract.coverage_complete != coverage_complete
        || contract.required_coverage_complete != required_coverage_complete
        || contract.fail_closed == required_coverage_complete
    {
        return Err(CutoverError::invalid(
            "coverage aggregate flags are inconsistent",
        ));
    }
    let expected_status = if contract.fail_closed {
        "incomplete"
    } else if coverage_complete {
        "complete"
    } else {
        "degraded"
    };
    if contract.status != expected_status {
        return Err(CutoverError::invalid(
            "coverage status aggregate is inconsistent",
        ));
    }
    Ok(())
}

fn validate_finding(finding: &RawFinding) -> Result<(), CutoverError> {
    validate_key(&finding.event_id, "simv1-event-", "eventId")?;
    validate_text("controlId", &finding.control_id, 160)?;
    validate_text("rule", &finding.rule, 160)?;
    validate_provider_source(&finding.provider, &finding.source, &finding.source_kind)?;
    validate_text("observedAt", &finding.observed_at, 64)?;
    validate_timestamp("observedAt", &finding.observed_at)?;
    if let Some(event_time) = &finding.event_time {
        validate_text("eventTime", event_time, 64)?;
        validate_timestamp("eventTime", event_time)?;
    }
    if !matches!(finding.raw_severity.as_str(), "high" | "critical") {
        return Err(CutoverError::invalid("invalid rawSeverity"));
    }
    if finding.contextual_verdict != "ALERT" {
        return Err(CutoverError::invalid("invalid contextualVerdict"));
    }
    if !matches!(finding.confidence.as_str(), "high" | "medium" | "low") {
        return Err(CutoverError::invalid("invalid confidence"));
    }
    if !matches!(finding.urgency.as_str(), "immediate" | "today" | "review") {
        return Err(CutoverError::invalid("invalid urgency"));
    }
    if let Some(actor) = &finding.actor {
        if !valid_email(actor) {
            return Err(CutoverError::invalid("invalid minimized actor"));
        }
    }
    validate_text("quickView", &finding.quick_view, 300)?;
    validate_text("whyFlagged", &finding.why_flagged, 1_200)?;
    for (key, value) in &finding.evidence {
        if !ALLOWED_EVIDENCE_KEYS.contains(&key.as_str()) {
            return Err(CutoverError::invalid("evidence key is not allowlisted"));
        }
        validate_text("evidence", value, 240)?;
    }
    for assertion in &finding.assertions {
        validate_assertion(assertion)?;
    }
    for required_kind in ["HECHO", "INFERENCIA", "DATO FALTANTE"] {
        if !finding
            .assertions
            .iter()
            .any(|assertion| assertion.kind == required_kind)
        {
            return Err(CutoverError::invalid(
                "finding assertions must include facts, inferences, and missing data",
            ));
        }
    }
    validate_narrative(&finding.narrative)?;
    validate_links(&finding.links)?;
    Ok(())
}

fn validate_recommendation(recommendation: &RawRecommendation) -> Result<(), CutoverError> {
    validate_key(
        &recommendation.recommendation_id,
        "simv1-recommendation-",
        "recommendationId",
    )?;
    if recommendation.finding_event_ids.is_empty() {
        return Err(CutoverError::invalid(
            "recommendation must reference a finding",
        ));
    }
    for event_id in &recommendation.finding_event_ids {
        validate_key(event_id, "simv1-event-", "findingEventIds")?;
    }
    validate_text("controlId", &recommendation.control_id, 160)?;
    if !matches!(
        recommendation.source_kind.as_str(),
        "googleWorkspace" | "microsoft365" | "crossCloud"
    ) {
        return Err(CutoverError::invalid(
            "unknown source kind in recommendation",
        ));
    }
    validate_text("category", &recommendation.category, 64)?;
    validate_text("priority", &recommendation.priority, 32)?;
    validate_text("title", &recommendation.title, 300)?;
    validate_text("rationale", &recommendation.rationale, 1_200)?;
    if !matches!(
        recommendation.urgency.as_str(),
        "immediate" | "today" | "review"
    ) {
        return Err(CutoverError::invalid("invalid recommendation urgency"));
    }
    if recommendation.status != "proposed" {
        return Err(CutoverError::invalid(
            "observer recommendation status must remain proposed",
        ));
    }
    for assertion in &recommendation.evidence {
        validate_assertion(assertion)?;
    }
    if recommendation.evidence.is_empty()
        || recommendation
            .evidence
            .iter()
            .any(|assertion| assertion.kind != "HECHO")
    {
        return Err(CutoverError::invalid(
            "recommendation evidence must contain observations classified as facts",
        ));
    }
    validate_links(&recommendation.links)?;
    Ok(())
}

fn validate_email(email: &RawEmail, findings: &[RawFinding]) -> Result<(), CutoverError> {
    if email.format_version != CONTRACT_VERSION {
        return Err(CutoverError::invalid("invalid email format version"));
    }
    validate_text("email.subject", &email.subject, 300)?;
    validate_text("email.coverageNotice", &email.coverage_notice, 1_200)?;
    let finding_by_id = findings
        .iter()
        .map(|finding| (finding.event_id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let mut email_ids = BTreeSet::new();
    for block in &email.blocks {
        if !email_ids.insert(block.event_id.clone()) {
            return Err(CutoverError::invalid("duplicate email finding block"));
        }
        let finding = finding_by_id
            .get(block.event_id.as_str())
            .ok_or_else(|| CutoverError::invalid("email block references unknown finding"))?;
        if block.control_id != finding.control_id
            || block.conclusion != finding.narrative.conclusion
            || block.why_it_matters != finding.narrative.why_it_matters
            || block.evidence_observed != finding.narrative.observed_evidence
            || block.counter_evidence != finding.narrative.counter_evidence
            || block.what_we_do_not_know != finding.narrative.what_we_do_not_know
            || block.what_to_do_now != finding.narrative.what_to_do_now
            || block.urgency != finding.narrative.urgency
        {
            return Err(CutoverError::invalid(
                "email block does not match finding narrative",
            ));
        }
        validate_text("email.block.conclusion", &block.conclusion, 1_200)?;
        validate_text("email.block.whyItMatters", &block.why_it_matters, 1_200)?;
        for evidence in block
            .evidence_observed
            .iter()
            .chain(block.counter_evidence.iter())
        {
            validate_text("email.block.evidence", evidence, 600)?;
        }
        validate_text(
            "email.block.whatWeDoNotKnow",
            &block.what_we_do_not_know,
            1_200,
        )?;
        validate_text("email.block.whatToDoNow", &block.what_to_do_now, 1_200)?;
    }
    if email_ids.len() != findings.len()
        || findings
            .iter()
            .any(|finding| !email_ids.contains(&finding.event_id))
    {
        return Err(CutoverError::invalid(
            "email blocks do not cover the normalized findings",
        ));
    }
    Ok(())
}

fn validate_narrative(narrative: &RawNarrative) -> Result<(), CutoverError> {
    validate_text("narrative.conclusion", &narrative.conclusion, 1_200)?;
    validate_text("narrative.whyItMatters", &narrative.why_it_matters, 1_200)?;
    for evidence in narrative
        .observed_evidence
        .iter()
        .chain(narrative.counter_evidence.iter())
    {
        validate_text("narrative.evidence", evidence, 600)?;
    }
    validate_text(
        "narrative.whatWeDoNotKnow",
        &narrative.what_we_do_not_know,
        1_200,
    )?;
    validate_text("narrative.whatToDoNow", &narrative.what_to_do_now, 1_200)?;
    if !matches!(narrative.urgency.as_str(), "immediate" | "today" | "review") {
        return Err(CutoverError::invalid("invalid narrative urgency"));
    }
    Ok(())
}

fn validate_assertion(assertion: &RawAssertion) -> Result<(), CutoverError> {
    if !matches!(
        assertion.kind.as_str(),
        "HECHO" | "INFERENCIA" | "DATO FALTANTE"
    ) {
        return Err(CutoverError::invalid("invalid assertion kind"));
    }
    validate_text("assertion.text", &assertion.text, 600)
}

fn validate_links(links: &[RawLink]) -> Result<(), CutoverError> {
    let mut seen = BTreeSet::new();
    for link in links {
        if !ALLOWED_SOURCE_LINKS
            .iter()
            .any(|(label, url)| *label == link.label && *url == link.url)
        {
            return Err(CutoverError::invalid(
                "non-allowlisted URL in monitor contract",
            ));
        }
        if !seen.insert((link.label.as_str(), link.url.as_str())) {
            return Err(CutoverError::invalid("duplicate monitor link"));
        }
    }
    Ok(())
}

fn validate_provider_source(
    provider: &str,
    source: &str,
    source_kind: &str,
) -> Result<(), CutoverError> {
    let expected = match provider {
        "googleWorkspace" => ("google.admin.directory", "googleWorkspace"),
        "microsoft365" => ("microsoft.graph", "microsoft365"),
        "crossCloud" => ("cross-cloud.correlator", "crossCloud"),
        _ => return Err(CutoverError::invalid("unknown provider in monitor finding")),
    };
    if (source, source_kind) != expected {
        return Err(CutoverError::invalid("provider source mapping mismatch"));
    }
    Ok(())
}

fn source_kind_for_coverage(source: &str) -> Option<&'static str> {
    match source {
        "google.users" | "google.roles" | "google.roleAssignments" => Some("googleWorkspace"),
        "microsoft.users"
        | "microsoft.authenticationMethods"
        | "microsoft.roleAssignments"
        | "microsoft.conditionalAccess"
        | "microsoft.signIns"
        | "microsoft.directoryAudits"
        | "microsoft.defenderAlerts"
        | "microsoft.defenderIncidents"
        | "microsoft.secureScore" => Some("microsoft365"),
        _ => None,
    }
}

fn normalize_findings(findings: Vec<RawFinding>) -> Result<Vec<RawFinding>, CutoverError> {
    let mut by_id = BTreeMap::new();
    for finding in findings.into_iter().map(canonicalize_finding) {
        match by_id.get(&finding.event_id) {
            Some(existing) if existing != &finding => {
                return Err(CutoverError::invalid(
                    "conflicting duplicate finding eventId",
                ));
            }
            Some(_) => {}
            None => {
                by_id.insert(finding.event_id.clone(), finding);
            }
        }
    }
    Ok(by_id.into_values().collect())
}

fn normalize_recommendations(
    recommendations: Vec<RawRecommendation>,
) -> Result<Vec<RawRecommendation>, CutoverError> {
    let mut by_id = BTreeMap::new();
    for recommendation in recommendations.into_iter().map(canonicalize_recommendation) {
        if let Some(existing) = by_id.get_mut(&recommendation.recommendation_id) {
            merge_recommendation(existing, recommendation)?;
        } else {
            by_id.insert(recommendation.recommendation_id.clone(), recommendation);
        }
    }
    Ok(by_id.into_values().collect())
}

fn canonicalize_finding(mut finding: RawFinding) -> RawFinding {
    finding.assertions.sort_by(|left, right| {
        assertion_rank(&left.kind)
            .cmp(&assertion_rank(&right.kind))
            .then_with(|| left.text.cmp(&right.text))
    });
    finding
        .links
        .sort_by(|left, right| (&left.label, &left.url).cmp(&(&right.label, &right.url)));
    finding
}

fn canonicalize_recommendation(mut recommendation: RawRecommendation) -> RawRecommendation {
    recommendation.finding_event_ids.sort();
    recommendation
        .evidence
        .sort_by(|left, right| (&left.kind, &left.text).cmp(&(&right.kind, &right.text)));
    recommendation
        .links
        .sort_by(|left, right| (&left.label, &left.url).cmp(&(&right.label, &right.url)));
    recommendation
}

fn canonicalize_email(mut email: RawEmail) -> RawEmail {
    email
        .blocks
        .sort_by(|left, right| left.event_id.cmp(&right.event_id));
    email
}

fn assertion_rank(kind: &str) -> u8 {
    match kind {
        "HECHO" => 0,
        "INFERENCIA" => 1,
        "DATO FALTANTE" => 2,
        _ => 3,
    }
}

fn validate_recommendation_references(
    findings: &[RawFinding],
    recommendations: &[RawRecommendation],
) -> Result<(), CutoverError> {
    let finding_ids = findings
        .iter()
        .map(|finding| finding.event_id.as_str())
        .collect::<BTreeSet<_>>();
    for recommendation in recommendations {
        if recommendation
            .finding_event_ids
            .iter()
            .any(|event_id| !finding_ids.contains(event_id.as_str()))
        {
            return Err(CutoverError::invalid(
                "recommendation references an unknown finding eventId",
            ));
        }
    }
    Ok(())
}

fn merge_recommendation(
    existing: &mut RawRecommendation,
    incoming: RawRecommendation,
) -> Result<(), CutoverError> {
    if existing.control_id != incoming.control_id
        || existing.source_kind != incoming.source_kind
        || existing.category != incoming.category
        || existing.priority != incoming.priority
        || existing.title != incoming.title
        || existing.rationale != incoming.rationale
        || existing.urgency != incoming.urgency
        || existing.status != incoming.status
    {
        return Err(CutoverError::invalid(
            "conflicting duplicate recommendationId",
        ));
    }
    let finding_ids = existing
        .finding_event_ids
        .iter()
        .cloned()
        .chain(incoming.finding_event_ids)
        .collect::<BTreeSet<_>>();
    existing.finding_event_ids = finding_ids.into_iter().collect();

    let observations = existing
        .evidence
        .iter()
        .map(|item| (item.kind.clone(), item.text.clone()))
        .chain(
            incoming
                .evidence
                .iter()
                .map(|item| (item.kind.clone(), item.text.clone())),
        )
        .collect::<BTreeSet<_>>();
    existing.evidence = observations
        .into_iter()
        .map(|(kind, text)| RawAssertion { kind, text })
        .collect();

    let links = existing
        .links
        .iter()
        .map(|link| (link.label.clone(), link.url.clone()))
        .chain(
            incoming
                .links
                .into_iter()
                .map(|link| (link.label, link.url)),
        )
        .collect::<BTreeSet<_>>();
    existing.links = links
        .into_iter()
        .map(|(label, url)| RawLink { label, url })
        .collect();
    Ok(())
}

fn index_existing(
    records: Vec<BTreeMap<String, Value>>,
    key_field: &str,
    collection: &str,
) -> Result<BTreeMap<String, BTreeMap<String, Value>>, CutoverError> {
    let mut indexed = BTreeMap::new();
    for record in records {
        let key = record
            .get(key_field)
            .and_then(Value::as_str)
            .ok_or_else(|| CutoverError::invalid(format!("{collection} target row has no key")))?;
        let prefix = match key_field {
            "eventId" => "simv1-event-",
            "investigationId" => "simv1-investigation-",
            "recommendationId" => "simv1-recommendation-",
            _ => return Err(CutoverError::invalid("unsupported target key field")),
        };
        validate_key(key, prefix, key_field)?;
        if indexed.insert(key.to_string(), record).is_some() {
            return Err(CutoverError::invalid(format!(
                "duplicate {collection} target key"
            )));
        }
    }
    Ok(indexed)
}

fn plan_records(
    planned: &[PlannedRecord],
    existing: &BTreeMap<String, BTreeMap<String, Value>>,
    gate_open: bool,
) -> Result<Vec<SyncOperation>, CutoverError> {
    let incoming_keys = planned
        .iter()
        .map(|record| record.key.as_str())
        .collect::<BTreeSet<_>>();
    let mut operations = Vec::new();

    for planned_record in planned {
        let current = existing.get(&planned_record.key);
        let preserved = current
            .map(preserved_human_fields)
            .transpose()?
            .unwrap_or_default();
        let has_human_disposition = current.map(has_human_disposition).unwrap_or(false);
        let (action, eligible, reason, patch) = if has_human_disposition {
            (
                SyncAction::Suppress,
                false,
                "human_disposition_preserved".to_string(),
                BTreeMap::new(),
            )
        } else if current.is_none() {
            (
                SyncAction::Create,
                gate_open,
                "new_exact_key".to_string(),
                BTreeMap::new(),
            )
        } else if machine_projection_matches(
            current.expect("checked above"),
            &planned_record.record,
        ) {
            (
                SyncAction::Noop,
                true,
                "machine_projection_unchanged".to_string(),
                BTreeMap::new(),
            )
        } else {
            (
                SyncAction::Update,
                gate_open,
                "machine_projection_changed_human_fields_preserved".to_string(),
                machine_patch(current.expect("checked above"), &planned_record.record),
            )
        };
        operations.push(SyncOperation {
            action,
            key: planned_record.key.clone(),
            eligible,
            reason,
            record: planned_record.record.clone(),
            patch,
            preserved_human_fields: preserved,
        });
    }

    for (key, record) in existing {
        if incoming_keys.contains(key.as_str()) {
            continue;
        }
        operations.push(SyncOperation {
            action: SyncAction::Suppress,
            key: key.clone(),
            eligible: false,
            reason: if gate_open {
                "not_in_current_observation".to_string()
            } else {
                "stale_row_suppression_blocked_by_cutover_gate".to_string()
            },
            record: BTreeMap::new(),
            patch: BTreeMap::new(),
            preserved_human_fields: preserved_human_fields(record)?,
        });
    }
    operations.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(operations)
}

fn machine_projection_matches(
    current: &BTreeMap<String, Value>,
    planned: &BTreeMap<String, Value>,
) -> bool {
    planned
        .iter()
        .all(|(key, value)| HUMAN_FIELDS.contains(&key.as_str()) || current.get(key) == Some(value))
}

fn machine_patch(
    current: &BTreeMap<String, Value>,
    planned: &BTreeMap<String, Value>,
) -> BTreeMap<String, Value> {
    planned
        .iter()
        .filter(|(key, value)| {
            !HUMAN_FIELDS.contains(&key.as_str()) && current.get(*key) != Some(*value)
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn preserved_human_fields(
    record: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>, CutoverError> {
    let mut preserved = BTreeMap::new();
    for field in HUMAN_FIELDS {
        if let Some(value) = record.get(*field) {
            validate_preserved_value(value)?;
            preserved.insert((*field).to_string(), value.clone());
        }
    }
    Ok(preserved)
}

fn validate_preserved_value(value: &Value) -> Result<(), CutoverError> {
    match value {
        Value::String(text) => validate_text("existing human field", text, 4_000),
        Value::Array(items) => items.iter().try_for_each(validate_preserved_value),
        Value::Object(fields) => fields.values().try_for_each(validate_preserved_value),
        _ => Ok(()),
    }
}

fn has_human_disposition(record: &BTreeMap<String, Value>) -> bool {
    [
        "disposition",
        "humanDisposition",
        "humanStatus",
        "decision",
        "resolution",
        "status",
    ]
    .iter()
    .filter_map(|key| record.get(*key).and_then(Value::as_str))
    .map(|value| value.to_ascii_lowercase())
    .any(|value| {
        matches!(
            value.as_str(),
            "accepted" | "rejected" | "implemented" | "closed" | "covered"
        )
    })
}

fn finding_record(finding: &RawFinding) -> BTreeMap<String, Value> {
    let mut record = BTreeMap::new();
    record.insert("actor".to_string(), optional_string(&finding.actor));
    record.insert(
        "assertionsFact".to_string(),
        assertion_values(finding, "HECHO"),
    );
    record.insert(
        "assertionsInference".to_string(),
        assertion_values(finding, "INFERENCIA"),
    );
    record.insert(
        "assertionsMissingData".to_string(),
        assertion_values(finding, "DATO FALTANTE"),
    );
    record.insert(
        "confidence".to_string(),
        Value::String(finding.confidence.clone()),
    );
    record.insert(
        "contextualVerdict".to_string(),
        Value::String(finding.contextual_verdict.clone()),
    );
    record.insert(
        "contractVersion".to_string(),
        Value::String(CONTRACT_VERSION.to_string()),
    );
    record.insert(
        "controlId".to_string(),
        Value::String(finding.control_id.clone()),
    );
    record.insert(
        "eventId".to_string(),
        Value::String(finding.event_id.clone()),
    );
    record.insert(
        "eventTime".to_string(),
        optional_string(&finding.event_time),
    );
    record.insert("evidence".to_string(), json_value(&finding.evidence));
    record.insert("links".to_string(), links_value(&finding.links));
    record.insert(
        "narrativeConclusion".to_string(),
        Value::String(finding.narrative.conclusion.clone()),
    );
    record.insert(
        "narrativeCounterEvidence".to_string(),
        string_values(&finding.narrative.counter_evidence),
    );
    record.insert(
        "narrativeObservedEvidence".to_string(),
        string_values(&finding.narrative.observed_evidence),
    );
    record.insert(
        "narrativeUrgency".to_string(),
        Value::String(finding.narrative.urgency.clone()),
    );
    record.insert(
        "narrativeWhatToDoNow".to_string(),
        Value::String(finding.narrative.what_to_do_now.clone()),
    );
    record.insert(
        "narrativeWhatWeDoNotKnow".to_string(),
        Value::String(finding.narrative.what_we_do_not_know.clone()),
    );
    record.insert(
        "narrativeWhyItMatters".to_string(),
        Value::String(finding.narrative.why_it_matters.clone()),
    );
    record.insert(
        "provider".to_string(),
        Value::String(finding.provider.clone()),
    );
    record.insert(
        "quickView".to_string(),
        Value::String(finding.quick_view.clone()),
    );
    record.insert(
        "rawSeverity".to_string(),
        Value::String(finding.raw_severity.clone()),
    );
    record.insert("rule".to_string(), Value::String(finding.rule.clone()));
    record.insert("source".to_string(), Value::String(finding.source.clone()));
    record.insert(
        "sourceKind".to_string(),
        Value::String(finding.source_kind.clone()),
    );
    record.insert("status".to_string(), Value::String("open".to_string()));
    record.insert(
        "urgency".to_string(),
        Value::String(finding.urgency.clone()),
    );
    record.insert(
        "whyFlagged".to_string(),
        Value::String(finding.why_flagged.clone()),
    );
    record.insert(
        "observedAt".to_string(),
        Value::String(finding.observed_at.clone()),
    );
    record
}

fn investigation_record(finding: &RawFinding, contract: &RawContract) -> BTreeMap<String, Value> {
    let mut record = BTreeMap::new();
    record.insert(
        "investigationId".to_string(),
        Value::String(investigation_id(&finding.event_id)),
    );
    record.insert(
        "findingEventId".to_string(),
        Value::String(finding.event_id.clone()),
    );
    record.insert(
        "controlId".to_string(),
        Value::String(finding.control_id.clone()),
    );
    record.insert(
        "provider".to_string(),
        Value::String(finding.provider.clone()),
    );
    record.insert("source".to_string(), Value::String(finding.source.clone()));
    record.insert(
        "sourceKind".to_string(),
        Value::String(finding.source_kind.clone()),
    );
    record.insert(
        "observedAt".to_string(),
        Value::String(finding.observed_at.clone()),
    );
    record.insert(
        "eventTime".to_string(),
        optional_string(&finding.event_time),
    );
    record.insert(
        "conclusion".to_string(),
        Value::String(finding.narrative.conclusion.clone()),
    );
    record.insert(
        "whyItMatters".to_string(),
        Value::String(finding.narrative.why_it_matters.clone()),
    );
    record.insert(
        "evidence".to_string(),
        json_value(&finding.narrative.observed_evidence),
    );
    record.insert(
        "counterEvidence".to_string(),
        json_value(&finding.narrative.counter_evidence),
    );
    record.insert(
        "whatWeDoNotKnow".to_string(),
        Value::String(finding.narrative.what_we_do_not_know.clone()),
    );
    record.insert(
        "whatToDoNow".to_string(),
        Value::String(finding.narrative.what_to_do_now.clone()),
    );
    record.insert(
        "urgency".to_string(),
        Value::String(finding.urgency.clone()),
    );
    record.insert(
        "coverageStatus".to_string(),
        Value::String(contract.status.clone()),
    );
    record.insert("failClosed".to_string(), Value::Bool(contract.fail_closed));
    record.insert("status".to_string(), Value::String("proposed".to_string()));
    record.insert(
        "contractVersion".to_string(),
        Value::String(CONTRACT_VERSION.to_string()),
    );
    record
}

fn recommendation_record(recommendation: &RawRecommendation) -> BTreeMap<String, Value> {
    let mut record = BTreeMap::new();
    record.insert(
        "recommendationId".to_string(),
        Value::String(recommendation.recommendation_id.clone()),
    );
    record.insert(
        "findingEventIds".to_string(),
        json_value(&recommendation.finding_event_ids),
    );
    record.insert(
        "controlId".to_string(),
        Value::String(recommendation.control_id.clone()),
    );
    record.insert(
        "category".to_string(),
        Value::String(recommendation.category.clone()),
    );
    record.insert(
        "priority".to_string(),
        Value::String(recommendation.priority.clone()),
    );
    record.insert(
        "title".to_string(),
        Value::String(recommendation.title.clone()),
    );
    record.insert(
        "rationale".to_string(),
        Value::String(recommendation.rationale.clone()),
    );
    record.insert("evidence".to_string(), json_value(&recommendation.evidence));
    record.insert(
        "sourceKind".to_string(),
        Value::String(recommendation.source_kind.clone()),
    );
    record.insert("links".to_string(), links_value(&recommendation.links));
    record.insert(
        "status".to_string(),
        Value::String(recommendation.status.clone()),
    );
    record.insert(
        "urgency".to_string(),
        Value::String(recommendation.urgency.clone()),
    );
    record.insert(
        "contractVersion".to_string(),
        Value::String(CONTRACT_VERSION.to_string()),
    );
    record
}

fn investigation_id(event_id: &str) -> String {
    let uuid = Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("{CUTOVER_PLAN_VERSION}|{event_id}").as_bytes(),
    );
    format!("simv1-investigation-{uuid}")
}

fn assertion_values(finding: &RawFinding, kind: &str) -> Value {
    Value::Array(
        finding
            .assertions
            .iter()
            .filter(|assertion| assertion.kind == kind)
            .map(|assertion| Value::String(assertion.text.clone()))
            .collect(),
    )
}

fn string_values(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn optional_string(value: &Option<String>) -> Value {
    value
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null)
}

fn json_value<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("validated monitor value should serialize")
}

fn links_value(links: &[RawLink]) -> Value {
    Value::Array(
        links
            .iter()
            .map(|link| {
                let mut value = BTreeMap::new();
                value.insert("label", link.label.clone());
                value.insert("url", link.url.clone());
                json_value(&value)
            })
            .collect(),
    )
}

fn validate_key(value: &str, prefix: &str, field: &str) -> Result<(), CutoverError> {
    let suffix = value.strip_prefix(prefix).ok_or_else(|| {
        CutoverError::invalid(format!("{field} is not a valid exact monitor key"))
    })?;
    if Uuid::parse_str(suffix).is_err() {
        return Err(CutoverError::invalid(format!(
            "{field} is not a valid exact monitor key"
        )));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str, max_chars: usize) -> Result<(), CutoverError> {
    if value.trim().is_empty() || value.chars().count() > max_chars {
        return Err(CutoverError::invalid(format!(
            "invalid or oversized {field}"
        )));
    }
    if value.chars().any(|character| character.is_control()) {
        return Err(CutoverError::invalid(format!(
            "{field} contains control characters"
        )));
    }
    let trimmed = value.trim_start();
    if trimmed.starts_with(['=', '+', '-', '@']) {
        return Err(CutoverError::invalid(format!(
            "unsafe formula-like value in {field}"
        )));
    }
    let lower = value.to_ascii_lowercase();
    if lower.contains("https://") || lower.contains("http://") {
        return Err(CutoverError::invalid(format!(
            "untrusted URL-like value in {field}"
        )));
    }
    Ok(())
}

fn validate_timestamp(field: &str, value: &str) -> Result<(), CutoverError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|_| ())
        .map_err(|_| CutoverError::invalid(format!("invalid {field} timestamp")))
}

fn validate_error_code(value: &str) -> Result<(), CutoverError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
    {
        return Err(CutoverError::invalid("invalid coverage error code"));
    }
    Ok(())
}

fn valid_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && value.len() <= 254
        && value.matches('@').count() == 1
        && value
            .chars()
            .all(|character| !character.is_whitespace() && !character.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EVENT_ID: &str = "simv1-event-00000000-0000-0000-0000-000000000001";
    const SECOND_EVENT_ID: &str = "simv1-event-00000000-0000-0000-0000-000000000002";
    const RECOMMENDATION_ID: &str = "simv1-recommendation-00000000-0000-0000-0000-000000000001";

    fn finding(event_id: &str) -> Value {
        json!({
            "eventId": event_id,
            "controlId": "GOOGLE.IDENTITY.ADMIN_WITHOUT_2SV",
            "rule": "GOOGLE.IDENTITY.ADMIN_WITHOUT_2SV",
            "provider": "googleWorkspace",
            "source": "google.admin.directory",
            "sourceKind": "googleWorkspace",
            "observedAt": "2026-08-01T15:00:00Z",
            "eventTime": "2026-08-01T14:59:00Z",
            "rawSeverity": "critical",
            "contextualVerdict": "ALERT",
            "confidence": "high",
            "urgency": "immediate",
            "actor": "admin@example.com",
            "quickView": "Administrador activo sin 2SV: Google informa una cuenta habilitada.",
            "whyFlagged": "La fuente googleWorkspace informó el control GOOGLE.IDENTITY.ADMIN_WITHOUT_2SV.",
            "evidence": {
                "isEnrolledIn2Sv": "false",
                "privileged": "true"
            },
            "assertions": [
                {"kind": "HECHO", "text": "Se observó isEnrolledIn2Sv=false."},
                {"kind": "INFERENCIA", "text": "La cuenta requiere revisión."},
                {"kind": "DATO FALTANTE", "text": "No se validó una excepción aprobada."}
            ],
            "narrative": {
                "conclusion": "Google informa una cuenta administrativa activa sin 2SV.",
                "whyItMatters": "La cuenta conserva privilegios administrativos.",
                "observedEvidence": ["Se observó isEnrolledIn2Sv=false."],
                "counterEvidence": ["No hay evidencia de compromiso."],
                "whatWeDoNotKnow": "No se validó una excepción temporal aprobada.",
                "whatToDoNow": "Confirmar la identidad y exigir enrolamiento de 2SV mediante una decisión humana.",
                "urgency": "immediate"
            },
            "links": [
                {"label": "Google Admin security", "url": "https://admin.google.com/ac/security"}
            ]
        })
    }

    fn recommendation(finding_event_ids: Vec<&str>) -> Value {
        json!({
            "recommendationId": RECOMMENDATION_ID,
            "findingEventIds": finding_event_ids,
            "controlId": "GOOGLE.IDENTITY.ADMIN_WITHOUT_2SV",
            "sourceKind": "googleWorkspace",
            "category": "identity",
            "priority": "critical",
            "title": "Revisar y decidir sobre GOOGLE.IDENTITY.ADMIN_WITHOUT_2SV",
            "rationale": "Confirmar la identidad y exigir enrolamiento de 2SV mediante una decisión humana.",
            "evidence": [
                {"kind": "HECHO", "text": "Observación asociada al evento simv1-event-00000000-0000-0000-0000-000000000001."}
            ],
            "urgency": "immediate",
            "status": "proposed",
            "links": [
                {"label": "Google Admin security", "url": "https://admin.google.com/ac/security"}
            ]
        })
    }

    fn email_block(event_id: &str) -> Value {
        json!({
            "eventId": event_id,
            "controlId": "GOOGLE.IDENTITY.ADMIN_WITHOUT_2SV",
            "conclusion": "Google informa una cuenta administrativa activa sin 2SV.",
            "whyItMatters": "La cuenta conserva privilegios administrativos.",
            "evidenceObserved": ["Se observó isEnrolledIn2Sv=false."],
            "counterEvidence": ["No hay evidencia de compromiso."],
            "whatWeDoNotKnow": "No se validó una excepción temporal aprobada.",
            "whatToDoNow": "Confirmar la identidad y exigir enrolamiento de 2SV mediante una decisión humana.",
            "urgency": "immediate"
        })
    }

    fn report(findings: Vec<Value>, recommendations: Vec<Value>) -> Value {
        json!({
            "mode": "read-only",
            "monitorIntegration": {
                "security_intelligence_monitor_v1": {
                    "contractVersion": "security_intelligence_monitor_v1",
                    "generatedAt": "2026-08-01T15:00:00Z",
                    "status": "complete",
                    "coverageComplete": true,
                    "requiredCoverageComplete": true,
                    "failClosed": false,
                    "coverage": [{
                        "source": "google.users",
                        "sourceKind": "googleWorkspace",
                        "status": "available",
                        "requested": true,
                        "required": true,
                        "assured": true
                    }],
                    "findings": findings,
                    "recommendations": recommendations,
                    "email": {
                        "formatVersion": "security_intelligence_monitor_v1",
                        "subject": "Revisión de seguridad: hallazgos accionables de postura",
                        "coverageNotice": "Las fuentes solicitadas están disponibles para esta observación.",
                        "blocks": [email_block(EVENT_ID)]
                    }
                }
            }
        })
    }

    fn empty_target(schema_version: u64) -> Value {
        json!({
            "schemaVersion": schema_version,
            "findings": [],
            "investigations": [],
            "recommendations": []
        })
    }

    fn plan_value(report: Value, target: Value) -> Value {
        serde_json::to_value(build_sync_plan(&report, &target).expect("plan should build"))
            .expect("plan should serialize")
    }

    fn first_operation<'a>(plan: &'a Value, collection: &str) -> &'a Value {
        plan.get(collection)
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .expect("operation should exist")
    }

    #[test]
    fn creates_deterministic_findings_investigations_recommendations_and_dry_email_plan() {
        let report = report(
            vec![finding(EVENT_ID)],
            vec![recommendation(vec![EVENT_ID])],
        );
        let plan = plan_value(report.clone(), empty_target(7));
        let second = plan_value(report, empty_target(7));

        assert_eq!(plan, second);
        assert_eq!(
            plan["planVersion"],
            "security_intelligence_monitor_cutover_v1"
        );
        assert_eq!(plan["mode"], "dry-run");
        assert_eq!(plan["coverageStatus"], "complete");
        assert_eq!(plan["coverage"][0]["source"], "google.users");
        assert_eq!(plan["externalWritesAllowed"], false);
        assert_eq!(plan["findings"][0]["action"], "create");
        assert_eq!(plan["findings"][0]["key"], EVENT_ID);
        assert_eq!(plan["investigations"][0]["action"], "create");
        assert_eq!(
            plan["investigations"][0]["record"]["findingEventId"],
            EVENT_ID
        );
        assert_eq!(plan["recommendations"][0]["action"], "create");
        assert_eq!(plan["recommendations"][0]["key"], RECOMMENDATION_ID);
        assert_eq!(plan["email"]["action"], "suppress");
        assert_eq!(plan["email"]["eligible"], true);
        assert_eq!(
            plan["email"]["payload"]["formatVersion"],
            "security_intelligence_monitor_v1"
        );
    }

    #[test]
    fn deduplicates_input_and_merges_recommendations_by_exact_id() {
        let mut second = finding(SECOND_EVENT_ID);
        second["actor"] = json!(null);
        let mut merged = recommendation(vec![EVENT_ID]);
        merged["findingEventIds"] = json!([EVENT_ID, SECOND_EVENT_ID]);
        merged["evidence"] = json!([
            {"kind": "HECHO", "text": "Observación adicional del segundo finding."}
        ]);
        let mut input = report(
            vec![finding(EVENT_ID), finding(EVENT_ID), second],
            vec![
                recommendation(vec![EVENT_ID]),
                recommendation(vec![EVENT_ID]),
                merged,
            ],
        );
        input["monitorIntegration"]["security_intelligence_monitor_v1"]["email"]["blocks"]
            .as_array_mut()
            .expect("email blocks should be an array")
            .push(email_block(SECOND_EVENT_ID));

        let plan = plan_value(input, empty_target(7));
        assert_eq!(plan["findings"].as_array().expect("findings").len(), 2);
        assert_eq!(
            plan["recommendations"]
                .as_array()
                .expect("recommendations")
                .len(),
            1
        );
        assert_eq!(
            plan["recommendations"][0]["record"]["findingEventIds"],
            json!([EVENT_ID, SECOND_EVENT_ID])
        );
    }

    #[test]
    fn canonicalizes_input_order_for_stable_json() {
        let mut first = report(
            vec![finding(EVENT_ID), finding(SECOND_EVENT_ID)],
            vec![recommendation(vec![EVENT_ID, SECOND_EVENT_ID])],
        );
        first["monitorIntegration"]["security_intelligence_monitor_v1"]["email"]["blocks"]
            .as_array_mut()
            .expect("email blocks should be an array")
            .push(email_block(SECOND_EVENT_ID));
        let mut second = first.clone();
        second["monitorIntegration"]["security_intelligence_monitor_v1"]["findings"]
            .as_array_mut()
            .expect("findings should be an array")
            .reverse();
        second["monitorIntegration"]["security_intelligence_monitor_v1"]["email"]["blocks"]
            .as_array_mut()
            .expect("email blocks should be an array")
            .reverse();

        assert_eq!(
            plan_value(first, empty_target(7)),
            plan_value(second, empty_target(7))
        );
    }

    #[test]
    fn updates_only_machine_fields_and_preserves_human_fields_and_disposition() {
        let input = report(
            vec![finding(EVENT_ID)],
            vec![recommendation(vec![EVENT_ID])],
        );
        let initial = plan_value(input.clone(), empty_target(7));
        let mut existing_finding = initial["findings"][0]["record"].clone();
        existing_finding["quickView"] = json!("old machine projection");
        existing_finding["disposition"] = json!("accepted");
        existing_finding["notes"] = json!("Nota humana que debe sobrevivir");
        existing_finding["owner"] = json!("analyst@example.com");
        let target = json!({
            "schemaVersion": 7,
            "findings": [existing_finding],
            "investigations": [],
            "recommendations": []
        });

        let plan = plan_value(input, target);
        let operation = first_operation(&plan, "findings");
        assert_eq!(operation["action"], "suppress");
        assert_eq!(operation["reason"], "human_disposition_preserved");
        assert_eq!(operation["preservedHumanFields"]["disposition"], "accepted");
        assert_eq!(
            operation["preservedHumanFields"]["notes"],
            "Nota humana que debe sobrevivir"
        );
        assert_eq!(
            operation["preservedHumanFields"]["owner"],
            "analyst@example.com"
        );
        assert!(operation["patch"].as_object().expect("patch").is_empty());
    }

    #[test]
    fn represents_noop_update_and_suppress_without_losing_stale_target_rows() {
        let input = report(
            vec![finding(EVENT_ID)],
            vec![recommendation(vec![EVENT_ID])],
        );
        let initial = plan_value(input.clone(), empty_target(7));
        let mut existing_finding = initial["findings"][0]["record"].clone();
        existing_finding["notes"] = json!("conservar");
        existing_finding["disposition"] = json!("open");
        let stale = json!({"eventId": "simv1-event-00000000-0000-0000-0000-000000000099", "notes": "stale"});
        let target = json!({
            "schemaVersion": 7,
            "findings": [existing_finding, stale],
            "investigations": [],
            "recommendations": []
        });

        let plan = plan_value(input, target);
        let findings = plan["findings"].as_array().expect("findings");
        assert!(findings.iter().any(|item| item["action"] == "noop"));
        assert!(findings.iter().any(|item| item["action"] == "suppress"));
        assert!(findings
            .iter()
            .any(|item| item["reason"] == "not_in_current_observation"));
    }

    #[test]
    fn blocks_writes_and_email_for_partial_required_coverage() {
        let mut input = report(
            vec![finding(EVENT_ID)],
            vec![recommendation(vec![EVENT_ID])],
        );
        let contract = &mut input["monitorIntegration"]["security_intelligence_monitor_v1"];
        contract["status"] = json!("incomplete");
        contract["coverageComplete"] = json!(false);
        contract["requiredCoverageComplete"] = json!(false);
        contract["failClosed"] = json!(true);
        contract["coverage"][0]["status"] = json!("unavailable");
        contract["coverage"][0]["assured"] = json!(false);
        contract["coverage"][0]["errorCode"] = json!("http_403_permission");

        let plan = plan_value(input, empty_target(7));
        assert_eq!(plan["status"], "blocked");
        assert_eq!(plan["gate"]["requiredCoverageComplete"], false);
        assert_eq!(plan["externalWritesAllowed"], false);
        assert_eq!(plan["email"]["action"], "suppress");
        assert_eq!(plan["email"]["eligible"], false);
        assert!(plan["blockedReasons"]
            .as_array()
            .expect("blocked reasons")
            .iter()
            .any(|reason| reason == "required_coverage_incomplete"));
    }

    #[test]
    fn schema_version_six_is_an_explicit_cutover_gate() {
        let input = report(
            vec![finding(EVENT_ID)],
            vec![recommendation(vec![EVENT_ID])],
        );
        let plan = plan_value(input, empty_target(6));

        assert_eq!(plan["status"], "blocked");
        assert_eq!(plan["gate"]["schemaCompatible"], false);
        assert_eq!(plan["externalWritesAllowed"], false);
        assert!(plan["blockedReasons"]
            .as_array()
            .expect("blocked reasons")
            .iter()
            .any(|reason| reason == "target_schema_version_unsupported"));
    }

    #[test]
    fn rejects_unknown_sources_formula_injection_and_arbitrary_urls() {
        let mut unknown = report(
            vec![finding(EVENT_ID)],
            vec![recommendation(vec![EVENT_ID])],
        );
        unknown["monitorIntegration"]["security_intelligence_monitor_v1"]["coverage"][0]
            ["source"] = json!("unknown");
        unknown["monitorIntegration"]["security_intelligence_monitor_v1"]["coverage"][0]
            ["sourceKind"] = json!("unknown");
        assert!(build_sync_plan(&unknown, &empty_target(7))
            .expect_err("unknown source must fail closed")
            .to_string()
            .contains("unknown source"));

        let mut formula = report(
            vec![finding(EVENT_ID)],
            vec![recommendation(vec![EVENT_ID])],
        );
        formula["monitorIntegration"]["security_intelligence_monitor_v1"]["findings"][0]
            ["quickView"] = json!("=HYPERLINK(\"https://evil.example\",\"open\")");
        assert!(build_sync_plan(&formula, &empty_target(7))
            .expect_err("formula input must fail closed")
            .to_string()
            .contains("unsafe formula"));

        let mut url = report(
            vec![finding(EVENT_ID)],
            vec![recommendation(vec![EVENT_ID])],
        );
        url["monitorIntegration"]["security_intelligence_monitor_v1"]["findings"][0]["links"][0]
            ["url"] = json!("https://evil.example/redirect");
        assert!(build_sync_plan(&url, &empty_target(7))
            .expect_err("arbitrary URL must fail closed")
            .to_string()
            .contains("non-allowlisted URL"));

        let unknown_recommendation = report(
            vec![finding(EVENT_ID)],
            vec![recommendation(vec![SECOND_EVENT_ID])],
        );
        assert!(build_sync_plan(&unknown_recommendation, &empty_target(7))
            .expect_err("unknown recommendation reference must fail closed")
            .to_string()
            .contains("unknown finding eventId"));
    }

    #[test]
    fn rejects_duplicate_existing_keys_before_any_sync_plan_is_eligible() {
        let input = report(
            vec![finding(EVENT_ID)],
            vec![recommendation(vec![EVENT_ID])],
        );
        let mut target = empty_target(7);
        target["findings"] = json!([
            {"eventId": EVENT_ID},
            {"eventId": EVENT_ID}
        ]);

        assert!(build_sync_plan(&input, &target)
            .expect_err("duplicate target keys must fail closed")
            .to_string()
            .contains("duplicate finding target key"));
    }

    #[test]
    fn rejects_quick_view_over_300_characters_and_accepts_empty_noop_contract() {
        let mut oversized = report(
            vec![finding(EVENT_ID)],
            vec![recommendation(vec![EVENT_ID])],
        );
        oversized["monitorIntegration"]["security_intelligence_monitor_v1"]["findings"][0]
            ["quickView"] = json!("x".repeat(301));
        assert!(build_sync_plan(&oversized, &empty_target(7))
            .expect_err("quick view must be bounded")
            .to_string()
            .contains("quickView"));

        let empty = report(Vec::new(), Vec::new());
        let mut empty_contract = empty.clone();
        empty_contract["monitorIntegration"]["security_intelligence_monitor_v1"]["email"]
            ["blocks"] = json!([]);
        let plan = plan_value(empty_contract, empty_target(7));
        assert!(plan["findings"].as_array().expect("findings").is_empty());
        assert!(plan["investigations"]
            .as_array()
            .expect("investigations")
            .is_empty());
        assert!(plan["recommendations"]
            .as_array()
            .expect("recommendations")
            .is_empty());
        assert_eq!(plan["email"]["action"], "suppress");
    }
}
