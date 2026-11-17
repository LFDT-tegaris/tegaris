//! Post-COMMIT archive custody verification through the installed source worker.
use super::*;
use sqlx::{Postgres, Row, Transaction};

impl RuntimeArtifactSourceCustody {
    /// This connection belongs to the installed source worker. It cannot see a
    /// producer's uncommitted rows and never accepts a producer completion flag.
    pub(in crate::runtime_artifact_source) async fn read_archives(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> SourceCustodyResult<Vec<Committed>> {
        let Some(history) = &self.checked_state()?.history else {
            return Ok(Vec::new());
        };
        let pending = history.archives(&self.history_signer)?;
        let mut complete = Vec::new();
        for (pending, original, committed) in pending {
            let custody = self
                .archive
                .as_ref()
                .ok_or(RuntimeError::InvalidAuthorization)?;
            if custody.binding.stream_id != pending.stream_id
                || custody.binding.database_role != pending.materialization.reader_role
            {
                return Err(RuntimeError::InvalidAuthorization.into());
            }
            let row=sqlx::query("select a.manifest,a.manifest_digest,a.source_pending_original,pg_current_xact_id()::text reader_transaction,s.archive_custody from control.evidence_runtime_artifact_archive a join control.runtime_artifact_source s using(participant_id,privacy_domain_id) where a.participant_id=$1::text::uuid and a.privacy_domain_id=$2::text::uuid and a.runtime_configuration_input_id=$3::text::uuid and a.stream_id=$4 and s.source_owner_id=$5::text::uuid and s.database_role=session_user")
                .bind(&self.installation.participant_id).bind(&self.installation.privacy_domain_id).bind(&pending.materialization.input.input_id)
                .bind(&pending.stream_id).bind(&self.installation.source_owner_id).fetch_optional(&mut **tx).await.map_err(control::unavailable)?;
            let Some(row) = row else {
                if committed.is_some() {
                    return Err(RuntimeError::InvalidAuthorization.into());
                }
                continue; // The original remains unknown. Never resubmit it.
            };
            let manifest: serde_json::Value =
                row.try_get("manifest").map_err(control::unavailable)?;
            let manifest_digest = Digest::of(canonical_bytes(&manifest)?);
            #[cfg(test)]
            eprintln!("RUNTIME_ARCHIVE_READBACK|stage=metadata");
            if row
                .try_get::<Vec<u8>, _>("source_pending_original")
                .map_err(control::unavailable)?
                != original
                || row
                    .try_get::<String, _>("reader_transaction")
                    .map_err(control::unavailable)?
                    == pending.materialization.transaction_id
                || row
                    .try_get::<String, _>("manifest_digest")
                    .map_err(control::unavailable)?
                    != format!("sha256:{}", manifest_digest.as_str())
                || row
                    .try_get::<serde_json::Value, _>("archive_custody")
                    .map_err(control::unavailable)?
                    != serde_json::to_value(&custody.binding).map_err(control::unavailable)?
            {
                return Err(RuntimeError::InvalidAuthorization.into());
            }
            #[cfg(test)]
            eprintln!("RUNTIME_ARCHIVE_READBACK|stage=parts");
            let rows=sqlx::query("select part.ordinal,c.record_id,c.evidence_class,c.source_format,c.receipt_digest,to_char(c.occurred_at at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') occurred_at,c.sequence::text, jsonb_build_object('version','OPENPC_EVIDENCE_SEGMENT_V1','participantId',s.participant_id::text,'privacyDomainId',s.privacy_domain_id::text,'streamId',s.stream_id,'segmentId',s.segment_id::text,'firstSequence',s.first_sequence::text,'throughSequence',s.through_sequence::text,'previousSegmentDigest',s.previous_segment_digest,'keyId',s.key_id,'retentionUntil',to_char(s.retention_until at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')) header,s.object_digest,p.encrypted_segment from control.evidence_runtime_artifact_archive_part part join control.evidence_catalogue c using(participant_id,privacy_domain_id,stream_id,record_id) join control.evidence_segment s using(participant_id,privacy_domain_id,stream_id,segment_id) join control.evidence_segment_payload p using(participant_id,privacy_domain_id,stream_id,segment_id) where part.participant_id=$1::text::uuid and part.privacy_domain_id=$2::text::uuid and part.stream_id=$3 and part.manifest_record_id=$4 order by part.ordinal")
                .bind(&self.installation.participant_id).bind(&self.installation.privacy_domain_id).bind(&pending.stream_id)
                .bind(format!("runtime-artifact:{}:manifest",manifest["identityDigest"].as_str().and_then(|s|s.strip_prefix("sha256:")).ok_or(RuntimeError::InvalidInput)?))
                .fetch_all(&mut **tx).await.map_err(control::unavailable)?;
            if rows.len() < 2 || rows.len() > 65 {
                return Err(RuntimeError::InvalidAuthorization.into());
            }
            let mut segments = BTreeMap::new();
            let mut records = Vec::new();
            let mut bindings = Vec::new();
            let mut previous_sequence = 0;
            let mut previous_segment: Option<(u64, String)> = None;
            for (index, row) in rows.iter().enumerate() {
                let header: serde_json::Value =
                    row.try_get("header").map_err(control::unavailable)?;
                let object_digest: String =
                    row.try_get("object_digest").map_err(control::unavailable)?;
                let id = header["segmentId"]
                    .as_str()
                    .ok_or(RuntimeError::InvalidInput)?
                    .to_string();
                let encrypted: Vec<u8> = row
                    .try_get("encrypted_segment")
                    .map_err(control::unavailable)?;
                if !segments.contains_key(&id) {
                    let first = header["firstSequence"]
                        .as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .ok_or(RuntimeError::InvalidInput)?;
                    let through = header["throughSequence"]
                        .as_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .ok_or(RuntimeError::InvalidInput)?;
                    if let Some((previous_through, previous_digest)) = &previous_segment
                        && (previous_through.checked_add(1) != Some(first)
                            || header["previousSegmentDigest"] != *previous_digest)
                    {
                        return Err(RuntimeError::InvalidAuthorization.into());
                    }
                    previous_segment = Some((through, object_digest.clone()));
                    let opened = format::open_segment(&encrypted, &header, &object_digest, custody)
                        .inspect_err(|_| {
                            #[cfg(test)]
                            eprintln!(
                                "RUNTIME_ARCHIVE_READBACK|stage=segment-decrypt-or-chain|FAIL"
                            );
                        })?;
                    segments.insert(id.clone(), (header.clone(), object_digest.clone(), opened));
                }
                let (expected_header, expected_digest, opened) =
                    segments.get(&id).ok_or(RuntimeError::InvalidInput)?;
                let record_id: String = row.try_get("record_id").map_err(control::unavailable)?;
                let record = opened
                    .iter()
                    .find(|r| r["recordId"] == record_id)
                    .ok_or(RuntimeError::InvalidAuthorization)?;
                let sequence: String = row.try_get("sequence").map_err(control::unavailable)?;
                let ordinal = sequence
                    .parse::<u64>()
                    .map_err(|_| RuntimeError::InvalidInput)?;
                if row
                    .try_get::<i32, _>("ordinal")
                    .map_err(control::unavailable)?
                    != index as i32
                    || ordinal <= previous_sequence
                    || expected_header != &header
                    || expected_digest != &object_digest
                    || record["sequence"] != sequence
                    || record["evidenceClass"]
                        != row
                            .try_get::<String, _>("evidence_class")
                            .map_err(control::unavailable)?
                    || record["sourceFormat"]
                        != row
                            .try_get::<String, _>("source_format")
                            .map_err(control::unavailable)?
                    || record["receiptDigest"]
                        != row
                            .try_get::<String, _>("receipt_digest")
                            .map_err(control::unavailable)?
                    || record["occurredAt"]
                        != row
                            .try_get::<String, _>("occurred_at")
                            .map_err(control::unavailable)?
                    || header["participantId"] != self.installation.participant_id
                    || header["privacyDomainId"] != self.installation.privacy_domain_id
                    || header["streamId"] != pending.stream_id
                {
                    return Err(RuntimeError::InvalidAuthorization.into());
                }
                previous_sequence = ordinal;
                records.push(record.clone());
                bindings.push(serde_json::json!({"ordinal":index,"record_id":record_id,"sequence":sequence,"header":header,"object_digest":object_digest}));
            }
            if segments
                .values()
                .map(|(_, _, records)| records.len())
                .sum::<usize>()
                != records.len()
            {
                return Err(RuntimeError::InvalidAuthorization.into());
            }
            format::verify_manifest(&manifest, &records, &pending, &self.installation)
                .inspect_err(|_| {
                    #[cfg(test)]
                    eprintln!("RUNTIME_ARCHIVE_READBACK|stage=manifest|FAIL");
                })?;
            let verified = Committed {
                pending_digest: Digest::of(&original),
                input: pending.materialization.input.clone(),
                stream_id: pending.stream_id,
                manifest_digest,
                custody_digest: Digest::of(canonical_bytes(&bindings)?),
            };
            if committed
                .as_ref()
                .is_some_and(|original| original != &verified)
            {
                return Err(RuntimeError::InvalidAuthorization.into());
            }
            if committed.is_none() {
                complete.push(verified);
            }
        }
        Ok(complete)
    }
}
