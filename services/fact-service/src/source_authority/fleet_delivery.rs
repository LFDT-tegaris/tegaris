//! Independent readback of Fleet's committed original-event admission effect.
use super::delivery::ControlDeliveryBinding;
use super::*;
use serde_json::json;

pub(crate) struct VerifiedFleetDelivery {
    material: Vec<u8>,
}
impl VerifiedFleetDelivery {
    pub(crate) fn material(&self) -> &[u8] {
        &self.material
    }
}
impl FactSourceAuthority {
    pub(crate) async fn fleet_delivery(
        &self,
        expected: &ControlDeliveryBinding,
        fact_digest: &str,
    ) -> Result<Option<VerifiedFleetDelivery>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("set transaction read only")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        let readonly: bool = sqlx::query_scalar("select
            not has_table_privilege(current_user,'control.fleet_fact_admission_inbox','INSERT,UPDATE,DELETE')
            and not has_any_column_privilege(current_user,'control.fleet_fact_admission_inbox','INSERT,UPDATE')
            and not has_table_privilege(current_user,'control.fleet_fact_admission_cursor','INSERT,UPDATE,DELETE')
            and not has_any_column_privilege(current_user,'control.fleet_fact_admission_cursor','INSERT,UPDATE')
            and not has_table_privilege(current_user,'control.fleet_fact_admission_key','SELECT')")
            .fetch_one(&mut *tx).await?;
        if !readonly {
            return Err(SourceAuthorityError::Identity);
        }
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-OPERATIONS_READ_OPERATION-V1',false)")
            .bind(expected.participant).bind(expected.privacy).bind(Uuid::now_v7()).execute(&mut *tx).await?;
        let row = sqlx::query("select i.material,i.material_digest,c.sequence::text cursor_sequence
            from control.fleet_fact_admission_inbox i
            join control.fleet_fact_admission_cursor c using(participant_id,privacy_domain_id,fact_type)
            where i.participant_id=$1 and i.privacy_domain_id=$2 and i.candidate_id=$3")
            .bind(expected.participant).bind(expected.privacy).bind(expected.candidate)
            .fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let material: Vec<u8> = row.try_get("material")?;
        let expected_material = serde_json::to_vec(&json!({
            "participantId":expected.participant,"privacyDomainId":expected.privacy,
            "candidateId":expected.candidate,"generationId":expected.generation,
            "factType":expected.fact_type,"sequence":expected.sequence.to_string(),
            "envelope":expected.event,"signedFactDigest":expected.signed_fact_digest,
            "factDigest":fact_digest,"consumerId":"LS-FLEET-CONTROL",
        }))
        .map_err(|_| SourceAuthorityError::Binding)?;
        if material != expected_material
            || row.try_get::<Vec<u8>, _>("material_digest")? != pc_facts_core::sha256(&material)
        {
            return Err(SourceAuthorityError::Binding);
        }
        let cursor: i64 = row
            .try_get::<String, _>("cursor_sequence")?
            .parse()
            .map_err(|_| SourceAuthorityError::Binding)?;
        if expected.sequence <= 0 || cursor < expected.sequence {
            tx.rollback().await?;
            return Ok(None);
        }
        tx.commit().await?;
        Ok(Some(VerifiedFleetDelivery { material }))
    }
}
