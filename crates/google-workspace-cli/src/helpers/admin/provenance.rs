use chrono::DateTime;
use serde::Serialize;

pub(super) const PROVENANCE_CONTRACT_VERSION: &str = "security_intelligence_provenance_v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum ActorRole {
    HumanUser,
    Application,
    System,
    ResourceOwner,
    Target,
    AffectedUser,
    Subject,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum ActorSource {
    GoogleActor,
    GoogleResourceOwner,
    GooglePostureSubject,
    MicrosoftInitiatedByUser,
    MicrosoftInitiatedByApp,
    MicrosoftInitiatedBySystem,
    MicrosoftInitiatedByOpaqueId,
    MicrosoftSignInUser,
    MicrosoftDefender,
    CrossCloudSubject,
    ProviderSubject,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum TemporalBasis {
    ProviderEventTime,
    SnapshotObservedAt,
    SnapshotGeneratedAt,
    StateLastLoginTime,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProvenanceV1 {
    contract_version: &'static str,
    pub(super) actor_role: ActorRole,
    pub(super) actor_source: ActorSource,
    pub(super) temporal_basis: TemporalBasis,
}

impl ProvenanceV1 {
    pub(super) const fn new(
        actor_role: ActorRole,
        actor_source: ActorSource,
        temporal_basis: TemporalBasis,
    ) -> Self {
        Self {
            contract_version: PROVENANCE_CONTRACT_VERSION,
            actor_role,
            actor_source,
            temporal_basis,
        }
    }

    pub(super) const fn snapshot_affected_user() -> Self {
        Self::new(
            ActorRole::AffectedUser,
            ActorSource::GooglePostureSubject,
            TemporalBasis::SnapshotGeneratedAt,
        )
    }

    pub(super) const fn last_login_state() -> Self {
        Self::new(
            ActorRole::AffectedUser,
            ActorSource::GooglePostureSubject,
            TemporalBasis::StateLastLoginTime,
        )
    }

    pub(super) const fn provider_affected_user(source: ActorSource) -> Self {
        Self::new(
            ActorRole::AffectedUser,
            source,
            TemporalBasis::ProviderEventTime,
        )
    }

    pub(super) const fn provider_system(source: ActorSource) -> Self {
        Self::new(ActorRole::System, source, TemporalBasis::ProviderEventTime)
    }

    pub(super) fn microsoft_application(event_time: Option<&str>) -> Self {
        Self::new(
            ActorRole::Application,
            ActorSource::MicrosoftInitiatedByApp,
            temporal_basis(event_time),
        )
    }

    pub(super) fn microsoft_opaque_id(event_time: Option<&str>) -> Self {
        Self::new(
            ActorRole::Unknown,
            ActorSource::MicrosoftInitiatedByOpaqueId,
            temporal_basis(event_time),
        )
    }

    pub(super) fn google_actor(actor: &str, event_time: Option<&str>) -> Self {
        Self::new(
            if validated_email(actor).is_some() {
                ActorRole::HumanUser
            } else {
                ActorRole::Unknown
            },
            ActorSource::GoogleActor,
            temporal_basis(event_time),
        )
    }

    pub(super) fn google_resource_owner(event_time: Option<&str>) -> Self {
        Self::new(
            ActorRole::ResourceOwner,
            ActorSource::GoogleResourceOwner,
            temporal_basis(event_time),
        )
    }

    pub(super) fn google_unknown(event_time: Option<&str>) -> Self {
        Self::new(
            ActorRole::Unknown,
            ActorSource::Unknown,
            temporal_basis(event_time),
        )
    }

    pub(super) fn microsoft_user_actor(
        actor: &str,
        event_time: Option<&str>,
    ) -> Option<(String, Self)> {
        validated_email(actor).map(|normalized| {
            (
                normalized,
                Self::new(
                    ActorRole::HumanUser,
                    ActorSource::MicrosoftInitiatedByUser,
                    temporal_basis(event_time),
                ),
            )
        })
    }

    pub(super) fn microsoft_initiated_by_system(event_time: Option<&str>) -> Self {
        Self::new(
            ActorRole::System,
            ActorSource::MicrosoftInitiatedBySystem,
            temporal_basis(event_time),
        )
    }

    pub(super) fn microsoft_sign_in_user() -> Self {
        Self::provider_affected_user(ActorSource::MicrosoftSignInUser)
    }

    pub(super) fn microsoft_defender(event_time: Option<&str>) -> Self {
        Self::provider_system(ActorSource::MicrosoftDefender).with_temporal(event_time)
    }

    pub(super) fn cross_cloud_subject() -> Self {
        Self::new(
            ActorRole::AffectedUser,
            ActorSource::CrossCloudSubject,
            TemporalBasis::SnapshotGeneratedAt,
        )
    }

    pub(super) fn with_temporal(self, event_time: Option<&str>) -> Self {
        Self {
            temporal_basis: temporal_basis(event_time),
            ..self
        }
    }

    pub(super) fn actor_correlation_eligible(self) -> bool {
        self.actor_role == ActorRole::HumanUser
            && matches!(
                self.actor_source,
                ActorSource::GoogleActor | ActorSource::MicrosoftInitiatedByUser
            )
            && self.temporal_basis == TemporalBasis::ProviderEventTime
    }

    pub(super) fn temporal_correlation_eligible(self) -> bool {
        self.temporal_basis == TemporalBasis::ProviderEventTime
    }
}

pub(super) fn validated_email(value: &str) -> Option<String> {
    if value.chars().any(char::is_control) {
        return None;
    }
    let normalized = value.trim().to_ascii_lowercase();
    let (local, domain) = normalized.split_once('@')?;
    if local.is_empty()
        || domain.is_empty()
        || normalized.len() > 254
        || normalized.matches('@').count() != 1
        || normalized.chars().any(|character| {
            character.is_whitespace() || character.is_control() || !character.is_ascii()
        })
    {
        return None;
    }
    if !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || local.chars().any(|character| {
            !character.is_ascii_alphanumeric() && !".!#$%&'*+/=?^_`{|}~-".contains(character)
        })
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        return None;
    }
    Some(normalized)
}

fn temporal_basis(event_time: Option<&str>) -> TemporalBasis {
    event_time
        .filter(|value| DateTime::parse_from_rfc3339(value).is_ok())
        .map(|_| TemporalBasis::ProviderEventTime)
        .unwrap_or(TemporalBasis::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versioned_provenance_serializes_only_allowlisted_fields() {
        let value = serde_json::to_value(ProvenanceV1::new(
            ActorRole::HumanUser,
            ActorSource::GoogleActor,
            TemporalBasis::ProviderEventTime,
        ))
        .expect("provenance must serialize");

        assert_eq!(
            value,
            json!({
                "contractVersion": "security_intelligence_provenance_v1",
                "actorRole": "humanUser",
                "actorSource": "googleActor",
                "temporalBasis": "providerEventTime"
            })
        );
    }

    #[test]
    fn actor_and_temporal_eligibility_are_independent_fail_closed_gates() {
        let explicit = ProvenanceV1::new(
            ActorRole::HumanUser,
            ActorSource::MicrosoftInitiatedByUser,
            TemporalBasis::ProviderEventTime,
        );
        assert!(explicit.actor_correlation_eligible());
        assert!(explicit.temporal_correlation_eligible());

        let snapshot = ProvenanceV1::new(
            ActorRole::HumanUser,
            ActorSource::GoogleActor,
            TemporalBasis::SnapshotObservedAt,
        );
        assert!(!snapshot.actor_correlation_eligible());
        assert!(!snapshot.temporal_correlation_eligible());

        let app = ProvenanceV1::new(
            ActorRole::Application,
            ActorSource::MicrosoftInitiatedByApp,
            TemporalBasis::ProviderEventTime,
        );
        assert!(!app.actor_correlation_eligible());
        assert!(app.temporal_correlation_eligible());
    }

    #[test]
    fn email_validation_rejects_identity_ambiguity_and_control_data() {
        assert_eq!(
            validated_email(" Admin@Example.com ").as_deref(),
            Some("admin@example.com")
        );
        for invalid in [
            "admin@example",
            "admin@@example.com",
            "admin @example.com",
            "admin@example.com\n",
            "admin@.example.com",
            "admin@-example.com",
            "admin@example!.com",
            "admin@éxample.com",
        ] {
            assert!(
                validated_email(invalid).is_none(),
                "{invalid:?} must be rejected"
            );
        }
    }
}
