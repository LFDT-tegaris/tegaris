//! Historical consumer custody, read through the installed Control reader.
//! This is not a lease on current Fact authority or an acknowledgement by Fleet.
use super::*;
use serde_json::{Value, json};

pub(crate) struct ControlDeliveryBinding {
    pub participant: Uuid,
    pub privacy: Uuid,
    pub candidate: Uuid,
    pub generation: String,
    pub fact_type: String,
    pub sequence: i64,
    pub event: Value,
    pub signed_fact_digest: String,
}

/// Only an exact committed inbox entry covered by the monotonic contiguous
/// cursor can construct this value. All fields stay private to this owner.
pub(crate) struct VerifiedControlDelivery {
    material: Vec<u8>,
}

impl VerifiedControlDelivery {
    pub(crate) fn material(&self) -> &[u8] {
        &self.material
    }
}

impl FactSourceAuthority {
    pub(crate) async fn control_delivery(
        &self,
        expected: &ControlDeliveryBinding,
    ) -> Result<Option<VerifiedControlDelivery>> {
        let event_id = expected.event["id"]
            .as_str()
            .and_then(|id| Uuid::parse_str(id).ok())
            .filter(|id| id.get_version_num() == 7)
            .ok_or(SourceAuthorityError::Binding)?;
        if expected.sequence <= 0 {
            return Err(SourceAuthorityError::Binding);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("set transaction read only")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        let read_only_owner: bool = sqlx::query_scalar("select
            not has_table_privilege(current_user,'control.evidence_fact_admission_inbox','INSERT,UPDATE,DELETE')
            and not has_any_column_privilege(current_user,'control.evidence_fact_admission_inbox','INSERT,UPDATE')
            and not has_table_privilege(current_user,'control.evidence_fact_admission_cursor','INSERT,UPDATE,DELETE')
            and not has_any_column_privilege(current_user,'control.evidence_fact_admission_cursor','INSERT,UPDATE')")
            .fetch_one(&mut *tx).await?;
        if !read_only_owner {
            return Err(SourceAuthorityError::Identity);
        }
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',false)")
            .bind(expected.participant).bind(expected.privacy).bind(Uuid::now_v7())
            .execute(&mut *tx).await?;
        let row = sqlx::query("select i.candidate_id,i.fact_type,i.sequence::text,i.envelope,i.source_receipt_digest,
              i.stream_id,i.record_id,c.sequence::text cursor_sequence
            from control.evidence_fact_admission_inbox i
            join control.evidence_fact_admission_cursor c using(participant_id,privacy_domain_id,fact_type)
            where i.participant_id=$1 and i.privacy_domain_id=$2 and i.event_id=$3")
            .bind(expected.participant).bind(expected.privacy).bind(event_id)
            .fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let receipt = bind_readback(
            expected,
            ControlInboxReadback {
                candidate: row.try_get("candidate_id")?,
                fact_type: row.try_get("fact_type")?,
                sequence: row.try_get("sequence")?,
                envelope: row.try_get("envelope")?,
                source_digest: row.try_get("source_receipt_digest")?,
                stream: row.try_get("stream_id")?,
                record: row.try_get("record_id")?,
                cursor: row.try_get("cursor_sequence")?,
            },
        )?;
        // Both the inbox and custody binding are immutable; the cursor cannot
        // decrease. No cross-store business authority lease is inferred.
        tx.commit().await?;
        Ok(receipt)
    }
}

struct ControlInboxReadback {
    candidate: Uuid,
    fact_type: String,
    sequence: String,
    envelope: Value,
    source_digest: String,
    stream: String,
    record: String,
    cursor: String,
}

fn bind_readback(
    expected: &ControlDeliveryBinding,
    row: ControlInboxReadback,
) -> Result<Option<VerifiedControlDelivery>> {
    if expected.sequence <= 0
        || row.candidate != expected.candidate
        || row.fact_type != expected.fact_type
        || row.sequence != expected.sequence.to_string()
        || row.envelope != expected.event
        || row.source_digest != expected.signed_fact_digest
    {
        return Err(SourceAuthorityError::Binding);
    }
    let cursor = row
        .cursor
        .parse::<u64>()
        .map_err(|_| SourceAuthorityError::Binding)?;
    if cursor < expected.sequence as u64 {
        return Ok(None);
    }
    let material = serde_json::to_vec(&json!({
        "participantId":expected.participant,"privacyDomainId":expected.privacy,
        "candidateId":expected.candidate,"generationId":expected.generation,
        "factType":expected.fact_type,"sequence":expected.sequence.to_string(),
        "eventId":expected.event["id"],"consumerId":"LS-CONTROL-WORK",
        "streamId":row.stream,"recordId":row.record,
        "sourceReceiptDigest":expected.signed_fact_digest,"envelope":expected.event,
    }))
    .map_err(|_| SourceAuthorityError::Binding)?;
    Ok(Some(VerifiedControlDelivery { material }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> ControlDeliveryBinding {
        ControlDeliveryBinding {
            participant: Uuid::now_v7(),
            privacy: Uuid::now_v7(),
            candidate: Uuid::now_v7(),
            generation: Uuid::now_v7().to_string(),
            fact_type: "CONTRACT_STATE_CALL".into(),
            sequence: 9,
            event: json!({"id": Uuid::now_v7(), "datadigest": "original"}),
            signed_fact_digest: format!("sha256:{}", "01".repeat(32)),
        }
    }
    fn row(expected: &ControlDeliveryBinding) -> ControlInboxReadback {
        ControlInboxReadback {
            candidate: expected.candidate,
            fact_type: expected.fact_type.clone(),
            sequence: expected.sequence.to_string(),
            envelope: expected.event.clone(),
            source_digest: expected.signed_fact_digest.clone(),
            stream: "original-stream".into(),
            record: "original-record".into(),
            cursor: "9".into(),
        }
    }
    #[test]
    fn original_binding_rejects_changed_consumer_material() {
        let expected = expected();
        for field in [
            "candidate",
            "type",
            "sequence",
            "envelope",
            "digest",
            "cursor",
        ] {
            let mut row = row(&expected);
            match field {
                "candidate" => row.candidate = Uuid::now_v7(),
                "type" => row.fact_type = "RELATIONSHIP".into(),
                "sequence" => row.sequence = "10".into(),
                "envelope" => row.envelope["datadigest"] = "other".into(),
                "digest" => row.source_digest = format!("sha256:{}", "02".repeat(32)),
                "cursor" => row.cursor = "18446744073709551616".into(),
                _ => unreachable!(),
            }
            assert!(bind_readback(&expected, row).is_err(), "{field}");
        }
    }
    #[test]
    fn gap_blocks_ack_and_later_cursor_keeps_original_receipt() {
        let expected = expected();
        let original = bind_readback(&expected, row(&expected)).unwrap().unwrap();
        let mut gap = row(&expected);
        gap.cursor = "8".into();
        assert!(bind_readback(&expected, gap).unwrap().is_none());
        let mut advanced = row(&expected);
        advanced.cursor = u64::MAX.to_string();
        assert_eq!(
            original.material(),
            bind_readback(&expected, advanced)
                .unwrap()
                .unwrap()
                .material()
        );
        let material: Value = serde_json::from_slice(original.material()).unwrap();
        assert_eq!(material["consumerId"], "LS-CONTROL-WORK");
        assert_eq!(material["sequence"], "9");
        assert_eq!(material["envelope"], expected.event);
        assert!(material.get("ready").is_none());
    }
}
