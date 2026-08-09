use super::provenance::{validated_email, ProvenanceV1};
use super::security_posture::{
    Confidence, ContextualVerdict, CoverageStatus, PostureFinding, PostureSeverity,
    SecurityPostureReport, Urgency,
};
use serde::Serialize;
use std::collections::BTreeMap;
use uuid::Uuid;

pub(super) const MONITOR_CONTRACT_VERSION: &str = "security_intelligence_monitor_v1";
pub(super) const POSTURE_FINDING_SCHEMA: &str = "posture_finding_v1";
pub(super) const POSTURE_CASE_SCHEMA: &str = "posture_case_v1";
pub(super) const POSTURE_RECOMMENDATION_SCHEMA: &str = "posture_recommendation_v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum SourceKind {
    GoogleWorkspace,
    Microsoft365,
    CrossCloud,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum MonitorCoverageStatus {
    Available,
    Unavailable,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum AssertionKind {
    #[serde(rename = "HECHO")]
    Fact,
    #[serde(rename = "INFERENCIA")]
    Inference,
    #[serde(rename = "DATO FALTANTE")]
    MissingData,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct MonitorAssertion {
    kind: AssertionKind,
    text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct MonitorLink {
    label: &'static str,
    url: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StaticSourceLink {
    source_kind: SourceKind,
    label: &'static str,
    url: &'static str,
}

pub(super) const ALLOWED_SOURCE_LINKS: &[StaticSourceLink] = &[
    StaticSourceLink {
        source_kind: SourceKind::GoogleWorkspace,
        label: "Google Admin security",
        url: "https://admin.google.com/ac/security",
    },
    StaticSourceLink {
        source_kind: SourceKind::Microsoft365,
        label: "Microsoft Entra overview",
        url: "https://entra.microsoft.com/",
    },
    StaticSourceLink {
        source_kind: SourceKind::Microsoft365,
        label: "Microsoft Defender portal",
        url: "https://security.microsoft.com/",
    },
    StaticSourceLink {
        source_kind: SourceKind::CrossCloud,
        label: "Google Admin security",
        url: "https://admin.google.com/ac/security",
    },
    StaticSourceLink {
        source_kind: SourceKind::CrossCloud,
        label: "Microsoft Entra overview",
        url: "https://entra.microsoft.com/",
    },
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct MonitorCoverage {
    source: &'static str,
    source_kind: SourceKind,
    status: MonitorCoverageStatus,
    requested: bool,
    required: bool,
    assured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct MonitorNarrative {
    conclusion: String,
    why_it_matters: String,
    observed_evidence: Vec<String>,
    counter_evidence: Vec<String>,
    what_we_do_not_know: String,
    what_to_do_now: String,
    urgency: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MonitorFinding {
    finding_id: String,
    control_id: String,
    rule: String,
    provider: &'static str,
    source: &'static str,
    source_kind: SourceKind,
    observed_at: String,
    provenance: ProvenanceV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_time: Option<String>,
    raw_severity: String,
    contextual_verdict: String,
    confidence: String,
    urgency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    quick_view: String,
    why_flagged: String,
    evidence: BTreeMap<String, String>,
    assertions: Vec<MonitorAssertion>,
    narrative: MonitorNarrative,
    links: Vec<MonitorLink>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct MonitorObservation {
    kind: AssertionKind,
    text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct MonitorRecommendation {
    recommendation_id: String,
    finding_ids: Vec<String>,
    control_id: String,
    source_kind: SourceKind,
    category: &'static str,
    priority: String,
    title: String,
    rationale: String,
    evidence: Vec<MonitorObservation>,
    urgency: String,
    status: &'static str,
    links: Vec<MonitorLink>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct MonitorEmailBlock {
    finding_id: String,
    control_id: String,
    conclusion: String,
    why_it_matters: String,
    evidence_observed: Vec<String>,
    counter_evidence: Vec<String>,
    what_we_do_not_know: String,
    what_to_do_now: String,
    urgency: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct MonitorEmailPayload {
    format_version: &'static str,
    subject: String,
    coverage_notice: String,
    blocks: Vec<MonitorEmailBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct MonitorLifecycleSchemas {
    finding: &'static str,
    #[serde(rename = "case")]
    case_schema: &'static str,
    recommendation: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SecurityIntelligenceMonitorV1 {
    contract_version: &'static str,
    lifecycle_schemas: MonitorLifecycleSchemas,
    generated_at: String,
    status: &'static str,
    coverage_complete: bool,
    required_coverage_complete: bool,
    fail_closed: bool,
    coverage: Vec<MonitorCoverage>,
    findings: Vec<MonitorFinding>,
    recommendations: Vec<MonitorRecommendation>,
    email: MonitorEmailPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct MonitorIntegration {
    #[serde(rename = "security_intelligence_monitor_v1")]
    security_intelligence_monitor_v1: SecurityIntelligenceMonitorV1,
}

pub(super) fn build_monitor_integration(report: &SecurityPostureReport) -> MonitorIntegration {
    let mut findings = report
        .identity_posture
        .iter()
        .chain(report.control_posture.iter())
        .chain(report.cross_cloud_correlations.iter())
        .chain(report.signal_findings.iter())
        .filter_map(|finding| normalize_finding(finding, &report.generated_at))
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    findings.dedup_by(|left, right| left.finding_id == right.finding_id);

    let coverage = report
        .coverage
        .iter()
        .map(normalize_coverage)
        .collect::<Vec<_>>();
    let coverage_complete = !coverage.is_empty()
        && coverage
            .iter()
            .all(|entry| entry.status == MonitorCoverageStatus::Available && entry.assured);
    let required_coverage_complete = !coverage.is_empty()
        && coverage.iter().all(|entry| {
            !entry.required || (entry.status == MonitorCoverageStatus::Available && entry.assured)
        });
    let fail_closed = !required_coverage_complete;
    let recommendations = build_recommendations(&findings);
    let email = build_email_payload(&coverage, &findings, coverage_complete, fail_closed);

    MonitorIntegration {
        security_intelligence_monitor_v1: SecurityIntelligenceMonitorV1 {
            contract_version: MONITOR_CONTRACT_VERSION,
            lifecycle_schemas: MonitorLifecycleSchemas {
                finding: POSTURE_FINDING_SCHEMA,
                case_schema: POSTURE_CASE_SCHEMA,
                recommendation: POSTURE_RECOMMENDATION_SCHEMA,
            },
            generated_at: bounded_text(&report.generated_at, 64),
            status: if fail_closed {
                "incomplete"
            } else if coverage_complete {
                "complete"
            } else {
                "degraded"
            },
            coverage_complete,
            required_coverage_complete,
            fail_closed,
            coverage,
            findings,
            recommendations,
            email,
        },
    }
}

fn normalize_finding(finding: &PostureFinding, observed_at: &str) -> Option<MonitorFinding> {
    if finding.control_id.trim().is_empty()
        || finding.title.trim().is_empty()
        || finding.summary.trim().is_empty()
        || finding.analysis.recommended_action.trim().is_empty()
    {
        return None;
    }

    let (provider, source, source_kind) = source_for_provider(finding.provider);
    let control_id = finding.control_id.to_string();
    let finding_id = stable_id(
        "finding",
        &[
            finding.control_id,
            finding.provider,
            &normalized_subject(&finding.subject),
        ],
    );
    let raw_severity = posture_severity(finding.severity).to_string();
    let contextual_verdict = contextual_verdict(finding.contextual_verdict).to_string();
    let confidence = confidence(finding.analysis.confidence).to_string();
    let urgency = urgency(finding.analysis.urgency).to_string();
    let evidence = allowlisted_evidence(&finding.evidence);
    let observed_evidence = if evidence.is_empty() {
        finding
            .analysis
            .evidence_for
            .iter()
            .map(|value| bounded_text(value, 400))
            .collect()
    } else {
        evidence
            .iter()
            .map(|(key, value)| format!("Se observó {key}={value}."))
            .collect()
    };
    let counter_evidence = finding
        .analysis
        .counter_evidence
        .iter()
        .map(|value| bounded_text(value, 400))
        .collect::<Vec<_>>();
    let what_we_do_not_know = bounded_text(&finding.analysis.uncertainty, 600);
    let what_to_do_now = bounded_text(&finding.analysis.recommended_action, 600);
    let conclusion = bounded_text(&finding.analysis.conclusion, 600);
    let why_it_matters = bounded_text(&finding.analysis.plausible_impact, 600);
    let why_flagged = format!(
        "La fuente {} informó el control {}; la observación resumida es: {}",
        provider,
        control_id,
        bounded_text(&finding.summary, 360)
    );
    let quick_view = bounded_text(
        &format!("{}: {}", finding.title.trim(), finding.summary.trim()),
        300,
    );
    let assertions = assertions(
        &evidence,
        &finding.analysis.escalation_reason,
        &why_it_matters,
        &what_we_do_not_know,
    );
    let event_time = finding
        .provenance
        .temporal_correlation_eligible()
        .then(|| event_time(&evidence))
        .flatten();
    let actor = finding
        .provenance
        .actor_correlation_eligible()
        .then_some(finding.actor.as_deref())
        .flatten()
        .and_then(validated_email);
    let links = links_for_source_kind(source_kind);

    Some(MonitorFinding {
        finding_id,
        control_id: control_id.clone(),
        rule: control_id,
        provider,
        source,
        source_kind,
        observed_at: bounded_text(observed_at, 64),
        provenance: finding.provenance,
        event_time,
        raw_severity,
        contextual_verdict,
        confidence,
        urgency: urgency.clone(),
        actor,
        quick_view,
        why_flagged,
        evidence,
        assertions,
        narrative: MonitorNarrative {
            conclusion,
            why_it_matters,
            observed_evidence,
            counter_evidence,
            what_we_do_not_know,
            what_to_do_now,
            urgency,
        },
        links,
    })
}

fn normalize_coverage(entry: &super::security_posture::CoverageEntry) -> MonitorCoverage {
    let (source, source_kind, known_source) = source_for_coverage(&entry.source);
    let mut status = match entry.status {
        CoverageStatus::Available => MonitorCoverageStatus::Available,
        CoverageStatus::Unavailable => MonitorCoverageStatus::Unavailable,
        CoverageStatus::Disabled => MonitorCoverageStatus::Disabled,
    };
    if !known_source && status == MonitorCoverageStatus::Available {
        status = MonitorCoverageStatus::Unavailable;
    }
    let requested = status != MonitorCoverageStatus::Disabled;
    let required = requested;
    let error_code = (!known_source)
        .then(|| "unknown_source".to_string())
        .or_else(|| entry.error_code.as_deref().and_then(bounded_error_code))
        .or_else(|| {
            (status == MonitorCoverageStatus::Unavailable).then(|| "source_unavailable".to_string())
        });

    MonitorCoverage {
        source,
        source_kind,
        status,
        requested,
        required,
        assured: status == MonitorCoverageStatus::Available && entry.assurance,
        error_code,
    }
}

fn build_recommendations(findings: &[MonitorFinding]) -> Vec<MonitorRecommendation> {
    let mut recommendations = findings
        .iter()
        .map(|finding| MonitorRecommendation {
            recommendation_id: stable_id("recommendation", &[&finding.finding_id]),
            finding_ids: vec![finding.finding_id.clone()],
            control_id: finding.control_id.clone(),
            source_kind: finding.source_kind,
            category: recommendation_category(&finding.control_id),
            priority: finding.raw_severity.clone(),
            title: format!("Revisar y decidir sobre {}", finding.control_id),
            rationale: finding.narrative.what_to_do_now.clone(),
            evidence: vec![MonitorObservation {
                kind: AssertionKind::Fact,
                text: format!(
                    "Observación asociada al hallazgo de postura {}: {}",
                    finding.finding_id, finding.why_flagged
                ),
            }],
            urgency: finding.urgency.clone(),
            status: "proposed",
            links: finding.links.clone(),
        })
        .collect::<Vec<_>>();
    recommendations.sort_by(|left, right| left.recommendation_id.cmp(&right.recommendation_id));
    recommendations
}

fn build_email_payload(
    coverage: &[MonitorCoverage],
    findings: &[MonitorFinding],
    coverage_complete: bool,
    fail_closed: bool,
) -> MonitorEmailPayload {
    let coverage_notice = coverage_notice(coverage, coverage_complete, fail_closed);
    let mut blocks = findings
        .iter()
        .map(|finding| MonitorEmailBlock {
            finding_id: finding.finding_id.clone(),
            control_id: finding.control_id.clone(),
            conclusion: finding.narrative.conclusion.clone(),
            why_it_matters: finding.narrative.why_it_matters.clone(),
            evidence_observed: finding.narrative.observed_evidence.clone(),
            counter_evidence: finding.narrative.counter_evidence.clone(),
            what_we_do_not_know: finding.narrative.what_we_do_not_know.clone(),
            what_to_do_now: finding.narrative.what_to_do_now.clone(),
            urgency: finding.narrative.urgency.clone(),
        })
        .collect::<Vec<_>>();
    blocks.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));

    let subject = if fail_closed {
        "Revisión de seguridad: cobertura incompleta (fail-closed)".to_string()
    } else if !coverage_complete {
        "Revisión de seguridad: cobertura limitada (fuentes deshabilitadas)".to_string()
    } else if blocks.is_empty() {
        "Revisión de seguridad: sin hallazgos accionables observados".to_string()
    } else {
        "Revisión de seguridad: hallazgos accionables de postura".to_string()
    };

    MonitorEmailPayload {
        format_version: MONITOR_CONTRACT_VERSION,
        subject,
        coverage_notice,
        blocks,
    }
}

fn coverage_notice(
    coverage: &[MonitorCoverage],
    coverage_complete: bool,
    fail_closed: bool,
) -> String {
    if coverage_complete {
        return "Las fuentes solicitadas están disponibles para esta observación; la ausencia de un hallazgo sólo describe la ventana observada.".to_string();
    }

    let unavailable = coverage
        .iter()
        .filter(|entry| entry.status == MonitorCoverageStatus::Unavailable)
        .map(|entry| entry.source)
        .collect::<Vec<_>>();
    let disabled = coverage
        .iter()
        .filter(|entry| entry.status == MonitorCoverageStatus::Disabled)
        .map(|entry| entry.source)
        .collect::<Vec<_>>();
    let mut details = Vec::new();
    if !unavailable.is_empty() {
        details.push(format!(
            "fuentes no disponibles: {}",
            unavailable.join(", ")
        ));
    }
    if !disabled.is_empty() {
        details.push(format!("fuentes deshabilitadas: {}", disabled.join(", ")));
    }
    let label = if fail_closed {
        "Cobertura incompleta y fail-closed"
    } else {
        "Cobertura limitada"
    };
    format!(
        "{label} ({}). La ausencia de hallazgos no debe interpretarse como normalidad.",
        details.join("; ")
    )
}

fn assertions(
    evidence: &BTreeMap<String, String>,
    escalation_reason: &str,
    plausible_impact: &str,
    uncertainty: &str,
) -> Vec<MonitorAssertion> {
    let mut assertions = evidence
        .iter()
        .map(|(key, value)| MonitorAssertion {
            kind: AssertionKind::Fact,
            text: format!("Se observó {key}={value}."),
        })
        .collect::<Vec<_>>();
    if assertions.is_empty() {
        assertions.push(MonitorAssertion {
            kind: AssertionKind::Fact,
            text: "Se observó un finding accionable emitido por una fuente de postura.".to_string(),
        });
    }
    assertions.push(MonitorAssertion {
        kind: AssertionKind::Inference,
        text: bounded_text(escalation_reason, 500),
    });
    assertions.push(MonitorAssertion {
        kind: AssertionKind::Inference,
        text: bounded_text(plausible_impact, 500),
    });
    assertions.push(MonitorAssertion {
        kind: AssertionKind::MissingData,
        text: bounded_text(uncertainty, 500),
    });
    assertions
}

fn source_for_provider(provider: &str) -> (&'static str, &'static str, SourceKind) {
    match provider {
        "googleWorkspace" => (
            "googleWorkspace",
            "google.admin.directory",
            SourceKind::GoogleWorkspace,
        ),
        "microsoft365" => ("microsoft365", "microsoft.graph", SourceKind::Microsoft365),
        "crossCloud" => (
            "crossCloud",
            "cross-cloud.correlator",
            SourceKind::CrossCloud,
        ),
        _ => ("unknown", "unknown", SourceKind::Unknown),
    }
}

fn source_for_coverage(source: &str) -> (&'static str, SourceKind, bool) {
    if source.starts_with("google.") {
        let (safe_source, known) = known_coverage_source(source, "google.unknown");
        (safe_source, SourceKind::GoogleWorkspace, known)
    } else if source.starts_with("microsoft.") {
        let (safe_source, known) = known_coverage_source(source, "microsoft.unknown");
        (safe_source, SourceKind::Microsoft365, known)
    } else {
        ("unknown", SourceKind::Unknown, false)
    }
}

fn known_coverage_source(source: &str, fallback: &'static str) -> (&'static str, bool) {
    let safe_source = match source {
        "google.users" => "google.users",
        "google.roles" => "google.roles",
        "google.roleAssignments" => "google.roleAssignments",
        "microsoft.users" => "microsoft.users",
        "microsoft.authenticationMethods" => "microsoft.authenticationMethods",
        "microsoft.roleAssignments" => "microsoft.roleAssignments",
        "microsoft.conditionalAccess" => "microsoft.conditionalAccess",
        "microsoft.signIns" => "microsoft.signIns",
        "microsoft.directoryAudits" => "microsoft.directoryAudits",
        "microsoft.defenderAlerts" => "microsoft.defenderAlerts",
        "microsoft.defenderIncidents" => "microsoft.defenderIncidents",
        "microsoft.secureScore" => "microsoft.secureScore",
        _ => fallback,
    };
    (safe_source, safe_source == source)
}

fn links_for_source_kind(source_kind: SourceKind) -> Vec<MonitorLink> {
    ALLOWED_SOURCE_LINKS
        .iter()
        .filter(|link| link.source_kind == source_kind)
        .map(|link| MonitorLink {
            label: link.label,
            url: link.url,
        })
        .collect()
}

fn allowlisted_evidence(evidence: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    const ALLOWED_KEYS: &[&str] = &[
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

    evidence
        .iter()
        .filter(|(key, _)| ALLOWED_KEYS.contains(&key.as_str()))
        .filter_map(|(key, value)| safe_evidence_value(value).map(|value| (key.clone(), value)))
        .collect()
}

fn safe_evidence_value(value: &str) -> Option<String> {
    if contains_sensitive_marker(value) {
        return None;
    }
    let normalized = bounded_text(value, 240);
    Some(normalized)
}

fn event_time(evidence: &BTreeMap<String, String>) -> Option<String> {
    ["createdDateTime", "activityDateTime"]
        .iter()
        .filter_map(|key| evidence.get(*key))
        .find(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok())
        .cloned()
}

fn normalized_subject(subject: &str) -> String {
    bounded_text(&subject.trim().to_ascii_lowercase(), 160)
}

fn stable_id(kind: &str, components: &[&str]) -> String {
    let canonical = format!("{MONITOR_CONTRACT_VERSION}|{kind}|{}", components.join("|"));
    format!(
        "simv1-{}-{}",
        kind,
        Uuid::new_v5(&Uuid::NAMESPACE_URL, canonical.as_bytes())
    )
}

fn posture_severity(severity: PostureSeverity) -> &'static str {
    match severity {
        PostureSeverity::High => "high",
        PostureSeverity::Critical => "critical",
    }
}

fn contextual_verdict(verdict: ContextualVerdict) -> &'static str {
    match verdict {
        ContextualVerdict::Alert => "ALERT",
    }
}

fn confidence(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

fn urgency(urgency: Urgency) -> &'static str {
    match urgency {
        Urgency::Immediate => "immediate",
        Urgency::Today => "today",
        Urgency::Review => "review",
    }
}

fn recommendation_category(control_id: &str) -> &'static str {
    if control_id.contains("IDENTITY") {
        "identity"
    } else if control_id.contains("CA.") {
        "access_policy"
    } else if control_id.contains("SIGNAL") || control_id.contains("DEFENDER") {
        "signal"
    } else {
        "cross_cloud"
    }
}

fn bounded_error_code(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
    {
        None
    } else {
        Some(value.to_string())
    }
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    let mut text = value
        .chars()
        .filter(|character| !character.is_control() || matches!(character, '\n' | '\t'))
        .collect::<String>();
    if contains_sensitive_marker(&text) {
        return "[contenido omitido por minimización]".to_string();
    }
    if text.chars().count() > max_chars {
        text = text.chars().take(max_chars.saturating_sub(3)).collect();
        text.push_str("...");
    }
    text
}

fn contains_sensitive_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "access_token",
        "access token",
        "refresh_token",
        "refresh token",
        "bearer ",
        "private_key",
        "client_secret",
        "client secret",
        "secret-token",
        "raw body",
        "rawbody",
        "response body",
        "provider body",
        "authorization:",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::super::security_posture::{
        Confidence, ContextualVerdict, CoverageEntry, CoverageStatus, HumanAnalysis,
        PostureFinding, PostureSeverity, SecurityPostureReport, Urgency,
    };
    use super::*;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    fn sample_finding(subject: &str, finding_id: &str) -> PostureFinding {
        PostureFinding {
            finding_id: finding_id.to_string(),
            control_id: "GOOGLE.IDENTITY.ADMIN_WITHOUT_2SV",
            provider: "googleWorkspace",
            severity: PostureSeverity::Critical,
            contextual_verdict: ContextualVerdict::Alert,
            title: "Administrador activo sin 2-Step Verification".to_string(),
            subject: subject.to_string(),
            actor: None,
            provenance: ProvenanceV1::snapshot_affected_user(),
            summary: "Google informa una cuenta habilitada sin enrolamiento en 2SV.".to_string(),
            evidence: BTreeMap::from([
                ("isEnrolledIn2Sv".to_string(), "false".to_string()),
                ("privileged".to_string(), "true".to_string()),
                (
                    "rawBody".to_string(),
                    "provider secret body must never be copied".to_string(),
                ),
                ("ipAddress".to_string(), "203.0.113.9".to_string()),
                ("token".to_string(), "secret-token".to_string()),
            ]),
            analysis: HumanAnalysis {
                conclusion: "Google Workspace informa una cuenta administrativa activa sin enrolamiento en 2SV.".to_string(),
                escalation_reason: "La cuenta conserva privilegios administrativos y carece de un segundo factor registrado.".to_string(),
                plausible_impact: "Un acceso no autorizado podría afectar los recursos permitidos a la cuenta; el alcance exacto depende de sus permisos efectivos.".to_string(),
                evidence_for: vec![
                    "Estado de cuenta habilitado.".to_string(),
                    "isEnrolledIn2Sv=false informado por Directory API.".to_string(),
                ],
                counter_evidence: vec![
                    "La política puede informar enforcement, aunque eso no demuestra enrolamiento.".to_string(),
                ],
                uncertainty: "No se validó con el usuario si existe una excepción temporal aprobada.".to_string(),
                recommended_action: "Confirmar la identidad y exigir enrolamiento de 2SV mediante una decisión humana.".to_string(),
                urgency: Urgency::Immediate,
                confidence: Confidence::High,
            },
        }
    }

    fn sample_report(
        coverage: Vec<CoverageEntry>,
        findings: Vec<PostureFinding>,
    ) -> SecurityPostureReport {
        SecurityPostureReport {
            schema_version: "security_intelligence_v1",
            generated_at: "2026-08-01T15:00:00+00:00".to_string(),
            coverage_complete: coverage
                .iter()
                .all(|entry| entry.status != CoverageStatus::Unavailable),
            coverage,
            identity_count: findings.len(),
            identity_posture: findings,
            control_posture: Vec::new(),
            cross_cloud_correlations: Vec::new(),
            signal_findings: Vec::new(),
            microsoft_secure_score: None,
        }
    }

    fn first_finding(contract: &SecurityIntelligenceMonitorV1) -> &MonitorFinding {
        contract
            .findings
            .first()
            .expect("sample contract should contain a normalized finding")
    }

    #[test]
    fn normalizes_posture_findings_with_stable_ids_and_separate_severity() {
        let report = sample_report(
            vec![CoverageEntry::available("google.users")],
            vec![sample_finding("Admin@example.com", "legacy-id")],
        );

        let first = build_monitor_integration(&report);
        let second = build_monitor_integration(&report);
        let left = serde_json::to_value(&first).expect("contract must serialize");
        let right = serde_json::to_value(&second).expect("contract must serialize");
        let finding = first_finding(&first.security_intelligence_monitor_v1);

        assert_eq!(left, right, "same posture input must be idempotent");
        assert_eq!(
            first.security_intelligence_monitor_v1.contract_version,
            MONITOR_CONTRACT_VERSION
        );
        assert_eq!(finding.raw_severity, "critical");
        assert_eq!(finding.contextual_verdict, "ALERT");
        assert_eq!(finding.control_id, "GOOGLE.IDENTITY.ADMIN_WITHOUT_2SV");
        assert_ne!(finding.finding_id, "legacy-id");
        assert!(finding.finding_id.starts_with("simv1-finding-"));
        assert!(!finding.finding_id.contains("admin@example.com"));
        assert!(left
            .pointer("/security_intelligence_monitor_v1/findings/0/findingId")
            .is_some());
        assert!(left
            .pointer("/security_intelligence_monitor_v1/findings/0/eventId")
            .is_none());
        assert!(finding.actor.is_none());
    }

    #[test]
    fn posture_subject_is_not_an_actor_and_snapshot_time_is_context_only() {
        let report = sample_report(
            vec![CoverageEntry::available("google.users")],
            vec![sample_finding("Admin@example.com", "legacy-id")],
        );

        let value = serde_json::to_value(build_monitor_integration(&report))
            .expect("contract must serialize");
        let finding = &value["security_intelligence_monitor_v1"]["findings"][0];

        assert!(finding["actor"].is_null());
        assert_eq!(
            finding["provenance"],
            json!({
                "contractVersion": "security_intelligence_provenance_v1",
                "actorRole": "affectedUser",
                "actorSource": "googlePostureSubject",
                "temporalBasis": "snapshotGeneratedAt"
            })
        );
    }

    #[test]
    fn last_login_state_is_not_emitted_as_a_causal_event_time() {
        let mut finding = sample_finding("stale@example.com", "stale-id");
        finding.evidence.insert(
            "lastLoginTime".to_string(),
            "2026-07-20T12:00:00Z".to_string(),
        );
        finding.provenance = ProvenanceV1::last_login_state();
        let report = sample_report(
            vec![CoverageEntry::available("google.users")],
            vec![finding],
        );

        let value = serde_json::to_value(build_monitor_integration(&report))
            .expect("contract must serialize");
        let finding = &value["security_intelligence_monitor_v1"]["findings"][0];

        assert!(finding["eventTime"].is_null());
        assert_eq!(finding["provenance"]["temporalBasis"], "stateLastLoginTime");
    }

    #[test]
    fn quick_view_is_bounded_and_does_not_duplicate_actor_or_ip_data() {
        let mut finding = sample_finding("person@example.com", "legacy-id");
        finding.summary = "x".repeat(600);
        let report = sample_report(
            vec![CoverageEntry::available("google.users")],
            vec![finding],
        );

        let contract = build_monitor_integration(&report).security_intelligence_monitor_v1;
        let normalized = first_finding(&contract);
        let serialized = serde_json::to_string(&contract).expect("contract must serialize");

        assert!(normalized.quick_view.chars().count() <= 300);
        assert_eq!(serialized.matches("person@example.com").count(), 0);
        assert!(!serialized.contains("ipAddress"));
        assert!(!serialized.contains("203.0.113.9"));
    }

    #[test]
    fn unavailable_and_disabled_coverage_fail_closed_without_becoming_clean() {
        let report = sample_report(
            vec![
                CoverageEntry::available("google.users"),
                CoverageEntry::unavailable("microsoft.signIns", "http_403_permission"),
                CoverageEntry::disabled("microsoft.secureScore"),
            ],
            Vec::new(),
        );

        let contract = build_monitor_integration(&report).security_intelligence_monitor_v1;
        let serialized = serde_json::to_string(&contract).expect("contract must serialize");

        assert!(!contract.coverage_complete);
        assert!(!contract.required_coverage_complete);
        assert!(contract.fail_closed);
        assert_eq!(contract.status, "incomplete");
        assert!(serialized.contains("http_403_permission"));
        assert!(serialized.contains("\"status\":\"disabled\""));
        assert!(contract
            .email
            .coverage_notice
            .contains("no debe interpretarse como normalidad"));
    }

    #[test]
    fn unknown_coverage_source_is_not_treated_as_available() {
        let report = sample_report(
            vec![CoverageEntry::available("google.unexpectedSource")],
            Vec::new(),
        );

        let contract = build_monitor_integration(&report).security_intelligence_monitor_v1;

        assert!(!contract.coverage_complete);
        assert!(contract.fail_closed);
        assert!(serde_json::to_string(&contract)
            .expect("contract must serialize")
            .contains("unknown_source"));
    }

    #[test]
    fn partial_data_does_not_generate_a_false_normality_message() {
        let report = sample_report(
            vec![CoverageEntry::disabled("microsoft.signIns")],
            Vec::new(),
        );

        let contract = build_monitor_integration(&report).security_intelligence_monitor_v1;

        assert!(contract.email.subject.contains("limitada"));
        assert!(!contract.coverage_complete);
        assert!(contract.required_coverage_complete);
        assert!(!contract.fail_closed);
        assert_eq!(contract.status, "degraded");
        assert!(!contract.email.subject.contains("limpio"));
        assert!(contract.email.blocks.is_empty());
        assert!(contract
            .email
            .coverage_notice
            .contains("fuentes deshabilitadas"));
    }

    #[test]
    fn source_links_are_static_and_allowlisted() {
        let report = sample_report(
            vec![CoverageEntry::available("google.users")],
            vec![sample_finding("person@example.com", "legacy-id")],
        );

        let contract = build_monitor_integration(&report).security_intelligence_monitor_v1;
        let links = &first_finding(&contract).links;

        assert!(!links.is_empty());
        assert!(links.iter().all(|link| ALLOWED_SOURCE_LINKS
            .iter()
            .any(|allowed| allowed.url == link.url)));
        assert!(links.iter().all(|link| !link.url.contains("legacy-id")));
    }

    #[test]
    fn recommendations_are_separate_and_reference_observed_findings() {
        let report = sample_report(
            vec![CoverageEntry::available("google.users")],
            vec![sample_finding("person@example.com", "legacy-id")],
        );

        let contract = build_monitor_integration(&report).security_intelligence_monitor_v1;
        let finding = first_finding(&contract);
        let recommendation = contract
            .recommendations
            .first()
            .expect("actionable finding should produce a recommendation");

        assert_ne!(recommendation.recommendation_id, finding.finding_id);
        assert_eq!(recommendation.finding_ids, vec![finding.finding_id.clone()]);
        assert!(recommendation
            .evidence
            .iter()
            .all(|observation| observation.kind == AssertionKind::Fact));
        assert!(recommendation
            .evidence
            .iter()
            .any(|observation| observation.text.contains("observ")));
        assert_eq!(recommendation.status, "proposed");
    }

    #[test]
    fn narrative_and_email_payload_contain_specific_human_action_blocks() {
        let report = sample_report(
            vec![CoverageEntry::available("google.users")],
            vec![sample_finding("person@example.com", "legacy-id")],
        );

        let contract = build_monitor_integration(&report).security_intelligence_monitor_v1;
        let finding = first_finding(&contract);
        let block = contract.email.blocks.first().expect("email block expected");

        assert!(!finding.narrative.conclusion.is_empty());
        assert!(!finding.narrative.why_it_matters.is_empty());
        assert!(!finding.narrative.observed_evidence.is_empty());
        assert!(!finding.narrative.what_we_do_not_know.is_empty());
        assert!(finding.narrative.what_to_do_now.contains("2SV"));
        assert_eq!(block.finding_id, finding.finding_id);
        assert!(!block.conclusion.is_empty());
        assert!(!block.why_it_matters.is_empty());
        assert!(!block.evidence_observed.is_empty());
        assert!(!block.what_we_do_not_know.is_empty());
        assert!(block.what_to_do_now.contains("decisión humana"));
        assert_eq!(block.urgency, "immediate");
    }

    #[test]
    fn assertions_distinguish_fact_inference_and_missing_data() {
        let report = sample_report(
            vec![CoverageEntry::available("google.users")],
            vec![sample_finding("tenant", "legacy-id")],
        );

        let contract = build_monitor_integration(&report).security_intelligence_monitor_v1;
        let finding = first_finding(&contract);

        assert!(finding.actor.is_none());
        assert!(finding.event_time.is_none());
        assert!(finding
            .assertions
            .iter()
            .any(|item| item.kind == AssertionKind::Fact));
        assert!(finding
            .assertions
            .iter()
            .any(|item| item.kind == AssertionKind::Inference));
        assert!(finding
            .assertions
            .iter()
            .any(|item| item.kind == AssertionKind::MissingData));
    }

    #[test]
    fn serialization_is_versioned_additive_and_contains_no_secret_or_raw_body() {
        let mut finding = sample_finding("person@example.com", "legacy-id");
        finding.summary = "provider body secret-token".to_string();
        finding.analysis.evidence_for = vec!["raw body contains secret-token".to_string()];
        finding.analysis.counter_evidence = vec!["response body: bearer secret-token".to_string()];
        let report = sample_report(
            vec![CoverageEntry::available("google.users")],
            vec![finding],
        );
        let integration = build_monitor_integration(&report);
        let value = serde_json::to_value(&integration).expect("contract must serialize");
        let serialized = serde_json::to_string(&integration).expect("contract must serialize");
        let legacy = serde_json::to_value(&report).expect("legacy posture must serialize");

        assert!(value.get("security_intelligence_monitor_v1").is_some());
        assert!(serialized.contains("security_intelligence_monitor_v1"));
        assert_eq!(
            legacy.get("schemaVersion").and_then(Value::as_str),
            Some("security_intelligence_v1")
        );
        assert!(legacy.get("monitorIntegration").is_none());
        assert!(!serialized.contains("provider secret body"));
        assert!(!serialized.contains("secret-token"));
        assert!(!serialized.contains("rawBody"));
        assert_eq!(
            json!("security_intelligence_monitor_v1"),
            value["security_intelligence_monitor_v1"]["contractVersion"]
        );
        assert_eq!(
            json!({
                "finding": "posture_finding_v1",
                "case": "posture_case_v1",
                "recommendation": "posture_recommendation_v1"
            }),
            value["security_intelligence_monitor_v1"]["lifecycleSchemas"]
        );
    }
}
