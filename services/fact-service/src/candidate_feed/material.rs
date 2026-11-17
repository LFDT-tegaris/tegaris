//! Untrusted admission material from the same repeatable-read feed snapshot.
//! Self-consistency is deliberately separate from independent source validation.
use super::{CandidateFeedError as Error, CandidateFeedRead};
use openpc_indexer_adapter::{
    GovernedSourcePublication, PublishedAcquisitionInputs, PublishedSource,
};
use pc_facts_core::sha256;
use pc_provider_api::validate_canonical_pc_cbor_bytes;
use serde_json::Value;
use sqlx::{Row, postgres::PgRow};
use uuid::Uuid;

pub struct CandidateSourceMaterial {
    pub inputs: PublishedAcquisitionInputs,
    pub source_profile_id: Uuid,
    pub source_id: String,
    pub partition_id: String,
}

/// None of the observations below is trusted finality, current authority or a
/// semantic fact. Only a separate admission owner may create those assertions.
pub struct CandidateMaterial {
    pub source: CandidateSourceMaterial,
    pub candidate_id: Uuid,
    pub event_id: Uuid,
    pub sequence: u64,
    pub record_id: String,
    pub record_sequence: u64,
    pub record_kind: String,
    pub schema_digest: Vec<u8>,
    pub payload_cbor: Vec<u8>,
    pub observed_at_ms: i64,
    pub transaction_hash: Option<Vec<u8>>,
    pub transaction_index: Option<u64>,
    pub log_index: Option<u64>,
    pub contract_address: Option<Vec<u8>>,
    pub event_signature: Option<Vec<u8>>,
    pub target_address: Option<Vec<u8>>,
    pub call_parameter_digest: Option<Vec<u8>>,
    pub block_number: u64,
    pub block_hash: Vec<u8>,
    pub parent_hash: Vec<u8>,
    pub finality_head_number: Option<u64>,
    pub finality_head_hash: Option<Vec<u8>>,
    pub checkpoint_id: Uuid,
    pub checkpoint: Value,
    pub checkpoint_digest: Vec<u8>,
    pub batch_sequence: u64,
    pub batch_digest: Vec<u8>,
    pub predecessor_batch_digest: Option<Vec<u8>>,
    pub range_start: u64,
    pub range_end: u64,
}

impl CandidateFeedRead {
    /// Resolve one observed event without skipping any preceding feed event.
    /// This method does not advance the FactStore inbox or establish continuity.
    pub async fn candidate(&mut self, sequence: u64) -> Result<CandidateMaterial, Error> {
        if sequence == 0 {
            return Err(Error::Scope);
        }
        let rows = sqlx::query(r#"
          select event_id,event_type::text,schema_uri::text,outbox_sequence::text,
            event_payload_cbor,event_payload_digest,projection_generation_id,generation_digest,
            generation_state::text,source_profile_id,indexer_profile_id,source_id,partition_id,
            source_profile_cbor,source_profile_digest,mapping_cbor,mapping_digest,
            projection_plan_id,source_state::text,projection_state::text,publication_state::text,
            publication_cbor,publication_digest,source_revision,qualification_operation_id,
            projection_revision,validation_operation_id,configuration_digest,
            acquisition_configuration_cbor,acquisition_configuration_digest,
            finality_rule_cbor,finality_rule_digest,
            candidate_event_id,candidate_state::text,record_kind::text,record_id,
            record_sequence::text,candidate_schema_digest,normalized_digest,
            candidate_payload_cbor,candidate_payload_digest,
            (extract(epoch from candidate_observed_at)*1000)::bigint as observed_at_ms,
            candidate_removed_at is not null as removed,target_address,call_parameter_digest,
            transaction_hash,transaction_index::text,log_index::text,contract_address,event_signature,
            block_number::text,block_hash,parent_hash,finality_head_number::text,finality_head_hash,
            checkpoint_id,checkpoint_state::text,checkpoint_cbor,checkpoint_digest,
            batch_id,batch_sequence::text,batch_digest,predecessor_batch_digest,
            batch_range_start::text,batch_range_end::text,authoritative_empty
          from candidate.fact_bridge_admission_v1
          where participant_id=$1 and privacy_domain_id=$2 and candidate_partition_id=$3
            and outbox_sequence=$4::numeric
            and octet_length(event_payload_cbor)<=131072
            and octet_length(source_profile_cbor)<=131072 and octet_length(mapping_cbor)<=131072
            and octet_length(publication_cbor)<=131072
            and octet_length(acquisition_configuration_cbor)<=131072
            and octet_length(finality_rule_cbor)<=8192
            and octet_length(candidate_payload_cbor)<=131072 and octet_length(checkpoint_cbor)<=131072
          limit 2
        "#).bind(self.scope.participant).bind(self.scope.privacy).bind(self.partition)
          .bind(sequence.to_string()).fetch_all(&mut *self.transaction).await?;
        if rows.len() > 1 {
            return Err(Error::SequenceConflict);
        }
        let row = rows.first().ok_or(Error::Material)?;
        let material = decode(row, self.scope.participant, self.scope.privacy, sequence)?;
        // Check the actual batch event closure, rather than trusting a declared
        // record count. A checkpoint-only or partially observed batch is not complete.
        let expected_count = number(&material.checkpoint, "recordCount")?;
        let counts: (i64, i64, Option<String>, Option<String>) = sqlx::query_as(r#"
          select count(*) filter(where candidate_event_id is not null),
            count(*) filter(where event_type='io.openpc.indexer.projection.checkpoint.completed.v1'),
            min(outbox_sequence)::text,max(outbox_sequence)::text
          from candidate.fact_bridge_admission_v1
          where participant_id=$1 and privacy_domain_id=$2 and candidate_partition_id=$3
            and checkpoint_id=$4
        "#).bind(self.scope.participant).bind(self.scope.privacy).bind(self.partition)
          .bind(material.checkpoint_id).fetch_one(&mut *self.transaction).await?;
        let first = counts
            .2
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or(Error::Material)?;
        let last = counts
            .3
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or(Error::Material)?;
        if u64::try_from(counts.0).ok() != Some(expected_count)
            || counts.1 != 1
            || last.checked_sub(first) != Some(expected_count)
            || sequence < first
            || sequence >= last
            || sequence.checked_sub(first).and_then(|v| v.checked_add(1))
                != Some(material.record_sequence)
        {
            return Err(Error::Material);
        }
        Ok(material)
    }
}

fn decode(
    row: &PgRow,
    participant: Uuid,
    privacy: Uuid,
    sequence: u64,
) -> Result<CandidateMaterial, Error> {
    for (column, expected) in [
        (
            "event_type",
            "io.openpc.indexer.projection.candidate.observed.v1",
        ),
        (
            "schema_uri",
            "https://schemas.openpc.local/event-payloads.schema.json#/$defs/IndexerProjectionCandidateObserved",
        ),
        ("publication_state", "PUBLISHED"),
        ("source_state", "QUALIFIED"),
        ("projection_state", "QUALIFIED"),
        ("candidate_state", "VALIDATED_CANDIDATE"),
        ("checkpoint_state", "COMPLETE"),
    ] {
        if row.try_get::<Option<String>, _>(column)?.as_deref() != Some(expected) {
            return Err(Error::Lineage(column));
        }
    }
    if !matches!(
        row.try_get::<String, _>("generation_state")?.as_str(),
        "READY" | "ACTIVE"
    ) || row.try_get::<bool, _>("removed")?
        || row.try_get::<bool, _>("authoritative_empty")?
        || integer(row, "outbox_sequence")? != sequence
    {
        return Err(Error::Material);
    }
    let source = source_material(row, participant, privacy)?;
    let candidate_id: Uuid = row.try_get("candidate_event_id")?;
    let payload_cbor = bytes(row, "candidate_payload_cbor", "candidate_payload_digest")?;
    let payload_digest = sha256(&payload_cbor);
    if payload_digest.as_slice() != row.try_get::<Vec<u8>, _>("normalized_digest")? {
        return Err(Error::Material);
    }
    let event = document(row, "event_payload_cbor", "event_payload_digest")?;
    let checkpoint = document(row, "checkpoint_cbor", "checkpoint_digest")?;
    let checkpoint_digest: Vec<u8> = row.try_get("checkpoint_digest")?;
    if event
        != serde_json::json!({
            "indexerProfileId":format!("urn:openpc:indexer-profile:{}",source.inputs.source().indexer_profile_id),
            "candidateId":format!("urn:openpc:candidate:{candidate_id}"),
            "candidateDigest":digest(&payload_digest)?, "sourceCursorDigest":digest(&checkpoint_digest)?,
            "authority":"CANDIDATE_ONLY"
        })
    {
        return Err(Error::Material);
    }
    validate_checkpoint(&checkpoint, &source, row).map_err(|_| Error::Lineage("checkpoint"))?;
    Ok(CandidateMaterial {
        source,
        candidate_id,
        event_id: row.try_get("event_id")?,
        sequence,
        record_id: row.try_get("record_id")?,
        record_sequence: integer(row, "record_sequence")?,
        record_kind: row.try_get("record_kind")?,
        schema_digest: row.try_get("candidate_schema_digest")?,
        payload_cbor,
        observed_at_ms: row.try_get("observed_at_ms")?,
        transaction_hash: row.try_get("transaction_hash")?,
        transaction_index: row
            .try_get::<Option<String>, _>("transaction_index")?
            .map(|v| v.parse().map_err(|_| Error::Material))
            .transpose()?,
        log_index: row
            .try_get::<Option<String>, _>("log_index")?
            .map(|v| v.parse().map_err(|_| Error::Material))
            .transpose()?,
        contract_address: row.try_get("contract_address")?,
        event_signature: row.try_get("event_signature")?,
        target_address: row.try_get("target_address")?,
        call_parameter_digest: row.try_get("call_parameter_digest")?,
        block_number: integer(row, "block_number")?,
        block_hash: row.try_get("block_hash")?,
        parent_hash: row.try_get("parent_hash")?,
        finality_head_number: row
            .try_get::<Option<String>, _>("finality_head_number")?
            .map(|v| v.parse().map_err(|_| Error::Material))
            .transpose()?,
        finality_head_hash: row.try_get("finality_head_hash")?,
        checkpoint_id: row.try_get("checkpoint_id")?,
        checkpoint,
        checkpoint_digest,
        batch_sequence: integer(row, "batch_sequence")?,
        batch_digest: row.try_get("batch_digest")?,
        predecessor_batch_digest: row.try_get("predecessor_batch_digest")?,
        range_start: integer(row, "batch_range_start")?,
        range_end: integer(row, "batch_range_end")?,
    })
}

fn validate_checkpoint(
    value: &Value,
    source: &CandidateSourceMaterial,
    row: &PgRow,
) -> Result<(), Error> {
    const KEYS: &[&str] = &[
        "authoritativeEmpty",
        "batchId",
        "batchSequence",
        "completedWatermark",
        "decodeFailures",
        "missingIntervals",
        "orderedObservationEvidence",
        "partitionId",
        "planDigest",
        "predecessorBatchDigest",
        "profileDigest",
        "range",
        "recordCount",
        "sourceId",
    ];
    let object = value.as_object().ok_or(Error::Material)?;
    let start = integer(row, "batch_range_start")?;
    let end = integer(row, "batch_range_end")?;
    let predecessor: Option<Vec<u8>> = row.try_get("predecessor_batch_digest")?;
    let count = number(value, "recordCount")?;
    if object.len() != KEYS.len()
        || KEYS.iter().any(|key| !object.contains_key(*key))
        || value["authoritativeEmpty"] != false
        || value["decodeFailures"] != serde_json::json!([])
        || value["missingIntervals"] != serde_json::json!([])
        || value["sourceId"] != source.source_id
        || value["partitionId"] != source.partition_id
        || value["batchId"] != row.try_get::<String, _>("batch_id")?
        || number(value, "batchSequence")? != integer(row, "batch_sequence")?
        || value["profileDigest"]
            != format!(
                "sha256:{}",
                source
                    .inputs
                    .profile()
                    .profile_digest
                    .trim_start_matches("sha256:")
            )
        || value["planDigest"]
            != format!(
                "sha256:{}",
                source
                    .inputs
                    .plan()
                    .plan_digest
                    .trim_start_matches("sha256:")
            )
        || value["predecessorBatchDigest"]
            != predecessor
                .as_deref()
                .map(digest)
                .transpose()?
                .map_or(Value::Null, Value::String)
        || value["range"] != serde_json::json!({"start":start.to_string(),"end":end.to_string()})
        || end < start
        || count == 0
        || count > source.inputs.plan().limits.max_batch
        || number(&value["completedWatermark"], "blockNumber")? != end
        || value["completedWatermark"]
            .as_object()
            .is_none_or(|v| v.len() != 2)
        || value["orderedObservationEvidence"]
            .as_array()
            .is_none_or(|v| v.is_empty())
    {
        return Err(Error::Material);
    }
    Ok(())
}

fn integer(row: &PgRow, key: &str) -> Result<u64, Error> {
    let text: String = row.try_get(key)?;
    let value: u64 = text.parse().map_err(|_| Error::Material)?;
    if value.to_string() != text {
        return Err(Error::Material);
    }
    Ok(value)
}
fn number(value: &Value, key: &str) -> Result<u64, Error> {
    let text = value[key].as_str().ok_or(Error::Material)?;
    let value: u64 = text.parse().map_err(|_| Error::Material)?;
    if value.to_string() != text {
        return Err(Error::Material);
    }
    Ok(value)
}
fn digest(bytes: &[u8]) -> Result<String, Error> {
    if bytes.len() != 32 {
        return Err(Error::Material);
    }
    Ok(format!(
        "sha256:{}",
        bytes.iter().map(|v| format!("{v:02x}")).collect::<String>()
    ))
}
fn bytes(row: &PgRow, data: &str, hash: &str) -> Result<Vec<u8>, Error> {
    let bytes: Vec<u8> = row.try_get(data)?;
    let expected: Vec<u8> = row.try_get(hash)?;
    checked_document(&bytes, &expected)?;
    Ok(bytes)
}
fn document(row: &PgRow, data: &str, hash: &str) -> Result<Value, Error> {
    let bytes = bytes(row, data, hash)?;
    ciborium::de::from_reader(bytes.as_slice()).map_err(|_| Error::Material)
}
fn checked_document(bytes: &[u8], expected: &[u8]) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > 131072 || sha256(bytes).as_slice() != expected {
        return Err(Error::Material);
    }
    validate_canonical_pc_cbor_bytes(bytes).map_err(|_| Error::Material)
}

/// Reconstruct immutable published source bytes without asserting candidate eligibility.
pub(super) fn source_material(
    row: &PgRow,
    participant: Uuid,
    privacy: Uuid,
) -> Result<CandidateSourceMaterial, Error> {
    let publication = document(row, "publication_cbor", "publication_digest")
        .map_err(|_| Error::Lineage("publication-bytes"))?;
    let profile = bytes(row, "source_profile_cbor", "source_profile_digest")?;
    let mapping = bytes(row, "mapping_cbor", "mapping_digest")?;
    let finality = bytes(row, "finality_rule_cbor", "finality_rule_digest")?;
    let acquisition = bytes(
        row,
        "acquisition_configuration_cbor",
        "acquisition_configuration_digest",
    )?;
    if publication["actionIntentId"] != "ACT-CANDIDATE_WRITE-V1" {
        return Err(Error::Material);
    }
    let source = GovernedSourcePublication {
        participant_id: participant,
        privacy_domain_id: privacy,
        indexer_profile_id: row.try_get("indexer_profile_id")?,
        source_revision: row.try_get("source_revision")?,
        qualification_operation_id: row.try_get("qualification_operation_id")?,
        projection_plan_id: row.try_get("projection_plan_id")?,
        projection_revision: row.try_get("projection_revision")?,
        validation_operation_id: row.try_get("validation_operation_id")?,
        action_intent_id: "ACT-CANDIDATE_WRITE-V1".into(),
        configuration_digest: digest(&row.try_get::<Vec<u8>, _>("configuration_digest")?)?,
        profile_cbor: profile,
        plan_cbor: mapping,
        finality_rule_cbor: finality,
        acquisition_configuration_cbor: acquisition,
    };
    let inputs = PublishedAcquisitionInputs::reconstruct(
        source,
        PublishedSource {
            projection_generation_id: row.try_get("projection_generation_id")?,
            generation_digest: row.try_get("generation_digest")?,
            publication_digest: row.try_get("publication_digest")?,
        },
        &row.try_get::<Vec<u8>, _>("publication_cbor")?,
    )
    .map_err(|_| Error::Lineage("publication-reconstruction"))?;
    Ok(CandidateSourceMaterial {
        inputs,
        source_profile_id: row.try_get("source_profile_id")?,
        source_id: row.try_get("source_id")?,
        partition_id: row.try_get("partition_id")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn candidate_digest_does_not_make_noncanonical_or_substituted_bytes_valid() {
        let valid = [0xa1, 0x61, b'a', 0x01];
        checked_document(&valid, &sha256(&valid)).unwrap();
        assert!(checked_document(&valid, &[0; 32]).is_err());
        for invalid in [
            &[0xa1, 0x61, b'a', 0x18, 0x01][..],
            &[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02][..],
            &[0xa1, 0x61, b'a', 0x01, 0x00][..],
        ] {
            assert!(checked_document(invalid, &sha256(invalid)).is_err());
        }
    }
}
