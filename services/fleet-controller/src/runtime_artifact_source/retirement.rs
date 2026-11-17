//! Missing source bytes require an exact signed physical result. The durable
//! native observation makes subsequent Control rollback or resurrection fail.
use super::*;
use crate::qualified_receipts::runtime_artifact::{Inputs, verify};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Committed {
    pub input: ImportIdentity,
    pub deletion_job_id: String,
    pub operation_id: String,
    pub receipt_id: String,
    pub receipt_digest: Digest,
    pub cose_digest: Digest,
    pub retirement_digest: Digest,
    pub disposition_id: String,
    pub native_denial_digest: Digest,
    pub source_root_digest: Digest,
    pub archive_manifest_digest: Digest,
}
impl Committed {
    pub(super) fn validate(&self) -> RuntimeResult<()> {
        self.input.validate()?;
        for id in [
            &self.deletion_job_id,
            &self.operation_id,
            &self.receipt_id,
            &self.disposition_id,
        ] {
            uuid(id)?;
        }
        for digest in [
            &self.receipt_digest,
            &self.cose_digest,
            &self.retirement_digest,
            &self.native_denial_digest,
            &self.source_root_digest,
            &self.archive_manifest_digest,
        ] {
            Digest::parse(digest.as_str())?;
        }
        Ok(())
    }
}
fn text<'a>(value: &'a Value, key: &str) -> RuntimeResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(RuntimeError::InvalidInput)
}
fn digest(value: &str) -> RuntimeResult<Digest> {
    Digest::parse(
        value
            .strip_prefix("sha256:")
            .ok_or(RuntimeError::InvalidInput)?,
    )
}

impl RuntimeArtifactSourceCustody {
    pub(super) async fn read_retirement(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        original: &ImportIdentity,
    ) -> SourceCustodyResult<Committed> {
        let rows = sqlx::query("select openpc.assert_runtime_artifact_retirement_committed(r),jsonb_build_object('deletionJobId',r.deletion_job_id::text,'source',openpc.runtime_artifact_retirement_source(r),'retirementDigest',r.retirement_digest) metadata,j.selection,j.operation_id::text operation_id,a.receipt_id::text receipt_id,a.receipt_cbor,a.cose_sign1,a.before_state_preimage,a.after_state_preimage,a.authority_snapshot,k.public_key_spki_der,k.trust_preimage,e.event_id::text event_id,(floor(extract(epoch from e.occurred_at)*1000000)*1000)::text event_time,e.payload_cbor,archive.manifest->'identity' archive_identity,archive.manifest_digest from control.runtime_artifact_retirement r join control.deletion_job j using(participant_id,privacy_domain_id,deletion_job_id) join control.audit_occurrence a on a.participant_id=j.participant_id and a.privacy_domain_id=j.privacy_domain_id and a.operation_id=j.operation_id and a.aggregate_id=j.deletion_job_id and a.aggregate_type='evidence-deletion' join control.business_signing_key k on k.participant_id=a.participant_id and k.privacy_domain_id=a.privacy_domain_id and k.signer_id=a.signer_id and k.trust_digest=a.signer_trust_snapshot_digest join control.business_signing_key_state ks on ks.participant_id=k.participant_id and ks.privacy_domain_id=k.privacy_domain_id and ks.signer_id=k.signer_id and ks.state<>'COMPROMISED' join control.outbox_event e on e.participant_id=a.participant_id and e.privacy_domain_id=a.privacy_domain_id and e.receipt_id=a.receipt_id and e.aggregate_id=a.aggregate_id and e.aggregate_type=a.aggregate_type and e.event_type='io.openpc.control.command.committed.v1' and e.proof_kind='BUSINESS_RECEIPT_REFERENCE' and e.sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1' and e.business_sequence=1 and e.source='urn:openpc:service:control-api' and e.subject='urn:openpc:evidence-deletion:'||r.deletion_job_id::text and e.correlation_id=j.operation_id and e.causation_id is null and e.authority_generation is null join control.evidence_runtime_artifact_archive archive on archive.participant_id=r.participant_id and archive.privacy_domain_id=r.privacy_domain_id and archive.runtime_configuration_input_id=r.runtime_configuration_input_id where r.participant_id=$1::text::uuid and r.privacy_domain_id=$2::text::uuid and r.runtime_configuration_input_id=$3::text::uuid and r.xmin<>pg_current_xact_id()::xid")
            .bind(&self.installation.participant_id).bind(&self.installation.privacy_domain_id).bind(&original.input_id)
            .fetch_all(&mut **tx).await.map_err(control::unavailable)?;
        if rows.len() != 1 {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        let row = &rows[0];
        let metadata: Value = row.try_get("metadata").map_err(control::unavailable)?;
        let selection: Value = row.try_get("selection").map_err(control::unavailable)?;
        let identity: Value = row
            .try_get("archive_identity")
            .map_err(control::unavailable)?;
        if metadata["source"] != identity
            || identity["runtimeConfigurationInputId"] != original.input_id
            || identity["moduleInstallationId"] != original.module_installation_id
            || identity["moduleConfigurationGenerationId"]
                != original.module_configuration_generation_id
            || digest(text(&identity, "configurationDigest")?)? != original.configuration_digest
        {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        let history = self
            .checked_state()?
            .history
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let archives = history.archives(&self.history_signer)?;
        let archive = archives
            .iter()
            .filter_map(|(_, _, complete)| complete.as_ref())
            .find(|v| v.input == *original)
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let archive_digest = digest(
            &row.try_get::<String, _>("manifest_digest")
                .map_err(control::unavailable)?,
        )?;
        if archive.manifest_digest != archive_digest {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        let disposition = &selection["disposition"];
        let entry = self
            .checked_state()?
            .entries
            .iter()
            .find(|v| {
                v.denial.admission.disposition_id
                    == text(disposition, "dispositionId").unwrap_or_default()
            })
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let denial = entry
            .signed_denial
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let root = self
            .checked_state()?
            .retained_root
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let root_digest = Digest::of(canonical_bytes(
            &serde_json::to_value(root).map_err(|_| RuntimeError::InvalidInput)?,
        )?);
        if entry.denial.admission.input_id != original.input_id
            || entry.denial.admission.installation != self.installation
            || entry.denial.admission.configuration_digest != original.configuration_digest
            || disposition["operationId"] != entry.denial.admission.operation_id
            || disposition["sourceOwnerId"] != self.installation.source_owner_id
            || digest(text(disposition, "receiptDigest")?)?
                != entry.denial.admission.admission_receipt_digest
            || digest(text(disposition, "nativeDenialDigest")?)? != Digest::of(denial)
            || digest(text(disposition, "sourceRootDigest")?)? != root_digest
        {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        let bytes = |name| {
            row.try_get::<Vec<u8>, _>(name)
                .map_err(control::unavailable)
        };
        let payload = bytes("receipt_cbor")?;
        let cose = bytes("cose_sign1")?;
        let operation_id: String = row.try_get("operation_id").map_err(control::unavailable)?;
        let receipt_id: String = row.try_get("receipt_id").map_err(control::unavailable)?;
        let event_id: String = row.try_get("event_id").map_err(control::unavailable)?;
        let event_recorded_ns = row
            .try_get::<String, _>("event_time")
            .map_err(control::unavailable)?
            .parse()
            .map_err(|_| RuntimeError::InvalidInput)?;
        verify(&Inputs {
            public: &bytes("public_key_spki_der")?,
            payload: &payload,
            cose: &cose,
            trust: &bytes("trust_preimage")?,
            before: &bytes("before_state_preimage")?,
            after: &bytes("after_state_preimage")?,
            authority: &bytes("authority_snapshot")?,
            event: &bytes("payload_cbor")?,
            participant: &self.installation.participant_id,
            privacy: &self.installation.privacy_domain_id,
            receipt_id: &receipt_id,
            operation_id: &operation_id,
            event_id: &event_id,
            event_recorded_ns,
            metadata: &metadata,
            selection: &selection,
        })
        .map_err(|_| RuntimeError::InvalidAuthorization)?;
        let committed = Committed {
            input: original.clone(),
            deletion_job_id: text(&metadata, "deletionJobId")?.into(),
            operation_id,
            receipt_id,
            receipt_digest: Digest::of(&payload),
            cose_digest: Digest::of(&cose),
            retirement_digest: digest(text(&metadata, "retirementDigest")?)?,
            disposition_id: entry.denial.admission.disposition_id.clone(),
            native_denial_digest: Digest::of(denial),
            source_root_digest: root_digest,
            archive_manifest_digest: archive_digest,
        };
        committed.validate()?;
        if let Some(prior) = history
            .retirements(&self.history_signer)?
            .iter()
            .find(|v| v.input.input_id == original.input_id)
            && prior != &committed
        {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        Ok(committed)
    }
}
