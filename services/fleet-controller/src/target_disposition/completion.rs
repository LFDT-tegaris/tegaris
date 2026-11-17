//! Settlement of an already acknowledged initial installation. This owner
//! verifies history; it cannot publish transport or issue current authority.
use super::*;
use serde_json::Value;

/// The maintenance selector is accepted only for untouched parked work. The
/// verifier takes canonical locks before its caller can claim that exact row.
pub enum HistoricalCompletionClaim<'a> {
    Leased { owner: &'a str, count: i64 },
    Parked { count: i64 },
}

/// Selectors from the worker's original claim, never a readiness assertion.
pub struct HistoricalActivationCandidate<'a> {
    pub work_id: &'a str,
    pub operation_id: &'a str,
    pub execution_attempt_id: &'a str,
    pub occurrence_id: &'a str,
    pub generation_id: &'a str,
    pub generation_digest: &'a Digest,
    pub configuration_digest: &'a Digest,
    pub xds_version_digest: &'a Digest,
    pub capsule_digest: &'a Digest,
    pub receipt_digest: &'a Digest,
    pub claim: HistoricalCompletionClaim<'a>,
}

/// Constructed only by the verifier below. Keep this result and all completion
/// writes in the same transaction; no serialization or signing capability exists.
pub struct VerifiedHistoricalActivation {
    capsule_digest: Digest,
    receipt: Value,
    receipt_digest: Digest,
    observed_at_ns: u64,
}
impl VerifiedHistoricalActivation {
    pub fn capsule_digest(&self) -> &Digest {
        &self.capsule_digest
    }
    pub fn receipt(&self) -> &Value {
        &self.receipt
    }
    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }
    pub fn observed_at_ns(&self) -> u64 {
        self.observed_at_ns
    }
}

fn completion_database_error(error: sqlx::Error) -> String {
    if matches!(&error, sqlx::Error::Database(db) if db.code().as_deref() == Some("55P03")) {
        TARGET_DISPOSITION_BUSY.into()
    } else {
        database_error(error)
    }
}

fn same_original_occurrence(expected: &str, token: &str, stored: &str, proof: &Value) -> bool {
    expected == token
        && expected == stored
        && proof.get("occurrenceId").and_then(Value::as_str) == Some(expected)
}

fn original_window(
    start: u64,
    end: u64,
    observed: u64,
    admission: u64,
    delivery: u64,
    ack: u64,
) -> bool {
    start <= observed
        && observed <= admission
        && admission <= delivery
        && delivery <= ack
        && ack < end
}

fn untouched_other_generation(state: &str, active: bool, activated_history: bool) -> bool {
    !active && !activated_history && !matches!(state, "ACTIVE" | "RETIRED")
}

impl TargetDispositionStore {
    /// Initial, predecessor-free settlement only. The caller retains this
    /// transaction through result writes/commit and restores its worker context.
    pub async fn verify_original_activation_completion_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        original: OriginalTargetActivation<'_>,
        candidate: HistoricalActivationCandidate<'_>,
    ) -> Result<VerifiedHistoricalActivation> {
        let (lease_owner, claim_count, parked) = match candidate.claim {
            HistoricalCompletionClaim::Leased { owner, count } => (owner, count, false),
            HistoricalCompletionClaim::Parked { count } => ("", count, true),
        };
        self.context(tx).await?;
        sqlx::query("select openpc.assert_runtime_target_disposition_owner()")
            .execute(&mut **tx)
            .await
            .map_err(completion_database_error)?;
        // Same root order as result/source admission, before Identity rows and
        // generation/resource fences. These locks are reentrant in completion.
        let lifecycle: bool = sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0))")
            .fetch_one(&mut **tx).await.map_err(completion_database_error)?;
        if !lifecycle {
            return Err(TARGET_DISPOSITION_BUSY.into());
        }
        // The root/source owner deliberately accepts only its scoped read
        // purpose. Retain that guard, then restore activation-result context
        // before Identity and generation/target/work fences.
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',false)")
            .bind(&self.participant).bind(&self.privacy).execute(&mut **tx)
            .await.map_err(completion_database_error)?;
        crate::cigl_publication::profile_invalidation::lock_sources(tx)
            .await
            .map_err(|_| unavailable())?;
        self.context(tx).await?;
        let identity = self.bootstrap_identity(tx, original.peer).await?;
        // A completion writes generation state, so take an exclusive generation
        // fence directly, never upgrade a shared lock after taking target rows.
        for query in [
            "select pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0))",
            "select pg_try_advisory_xact_lock(hashtextextended('openpc-policy-generations:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0))",
            "select pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text||':'||($1::text::uuid)::text,0))",
        ] {
            let query = if query.contains("$1") {
                sqlx::query_scalar::<_, bool>(query).bind(&original.peer.target_id)
            } else {
                sqlx::query_scalar::<_, bool>(query)
            };
            if !query
                .fetch_one(&mut **tx)
                .await
                .map_err(completion_database_error)?
            {
                return Err(TARGET_DISPOSITION_BUSY.into());
            }
        }
        let row = sqlx::query(r#"select a.revision::text,a.binding,a.activation_proof,a.admission_digest,
          d.claims,d.signed_delivery,d.delivery_digest,k.signed_acknowledgement,
          o.activation_receipt,o.activation_receipt_digest,pg.scope_digest,occ.activation_occurrence_id::text occurrence_id,
          trunc(extract(epoch from a.created_at)*1000000000)::text admission_ns,
          trunc(extract(epoch from d.created_at)*1000000000)::text delivery_ns,
          trunc(extract(epoch from k.created_at)*1000000000)::text ack_ns,
          jsonb_build_object('runtime_configuration_input_id',i.runtime_configuration_input_id::text,
            'configuration_digest',encode(i.configuration_digest,'hex'),
            'module_installation_id',i.module_installation_id::text,
            'module_configuration_generation_id',i.module_configuration_generation_id::text,
            'runtime_configuration_generation_id',w.runtime_configuration_generation_id::text,
            'capsule_digest',substring(o.capsule_digest from 8),
            'xds_version_digest',substring(w.xds_version_digest from 8),
            'predecessor_capsule_digest',substring(w.predecessor_digest from 8),
            'original_work_id',w.configuration_work_id::text,'original_operation_id',w.operation_id::text,
            'original_execution_attempt_id',w.execution_attempt_id::text) original_source
          from (select * from control.runtime_target_disposition_admission
            where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id()
              and runtime_target_id=$1::text::uuid order by revision desc limit 1) a
          join control.runtime_target_disposition_delivery d using(participant_id,privacy_domain_id,runtime_target_id,revision)
          join control.runtime_target_disposition_acknowledgement k using(participant_id,privacy_domain_id,runtime_target_id,delivery_digest)
          join control.configuration_work w on w.participant_id=a.participant_id and w.privacy_domain_id=a.privacy_domain_id
            and w.runtime_target_id=a.runtime_target_id and w.configuration_work_id::text=a.binding->'source'->>'original_work_id'
          join control.runtime_activation_observation o on o.participant_id=w.participant_id and o.privacy_domain_id=w.privacy_domain_id
            and o.configuration_work_id=w.configuration_work_id and o.operation_id=w.operation_id
            and o.execution_attempt_id=w.execution_attempt_id and o.runtime_target_id=w.runtime_target_id
            and o.runtime_configuration_generation_id=w.runtime_configuration_generation_id
            and o.generation_digest=w.generation_digest and o.xds_version_digest=w.xds_version_digest
          join control.runtime_configuration_input i on i.participant_id=w.participant_id and i.privacy_domain_id=w.privacy_domain_id
            and i.configuration_digest=decode(substring(w.configuration_digest from 8),'hex')
            and i.runtime_configuration_input_id::text=a.binding->'source'->>'runtime_configuration_input_id'
          join control.runtime_configuration_generation rg on rg.participant_id=w.participant_id and rg.privacy_domain_id=w.privacy_domain_id
            and rg.runtime_configuration_generation_id=w.runtime_configuration_generation_id and rg.runtime_target_id=w.runtime_target_id
            and rg.generation_digest=w.generation_digest and rg.policy_generation_digest=w.policy_generation_digest
          join control.runtime_target rt on rt.participant_id=w.participant_id and rt.privacy_domain_id=w.privacy_domain_id and rt.runtime_target_id=w.runtime_target_id
          join control.policy_activation_occurrence_target c on c.participant_id=w.participant_id and c.privacy_domain_id=w.privacy_domain_id
            and c.configuration_work_id=w.configuration_work_id and c.runtime_target_id=w.runtime_target_id and c.phase='FORWARD'
          join control.policy_activation_occurrence occ on occ.participant_id=c.participant_id and occ.privacy_domain_id=c.privacy_domain_id
            and occ.activation_occurrence_id=c.activation_occurrence_id
          join control.policy_activation pa on pa.participant_id=occ.participant_id and pa.privacy_domain_id=occ.privacy_domain_id
            and pa.policy_activation_id=occ.activation_occurrence_id and pa.policy_generation_id=occ.policy_generation_id and pa.exact_cohort_digest=occ.exact_cohort_digest
          join control.policy_generation pg on pg.participant_id=occ.participant_id and pg.privacy_domain_id=occ.privacy_domain_id
            and pg.policy_generation_id=occ.policy_generation_id and pg.generation_digest=occ.target_generation_digest
            and w.policy_generation_digest='sha256:'||encode(pg.generation_digest,'hex')
          join control.policy_release_bundle bundle on bundle.participant_id=occ.participant_id and bundle.privacy_domain_id=occ.privacy_domain_id
            and bundle.release_bundle_id=occ.release_bundle_id and bundle.policy_version_id=pg.policy_version_id
            and bundle.dependency_closure_digest=pg.dependency_closure_digest
          where a.binding->>'action'='ConfirmActivation' and a.restoration_proof is null
            and w.configuration_work_id=$2::text::uuid and w.operation_id=$3::text::uuid and w.execution_attempt_id=$4::text::uuid
            and w.runtime_configuration_generation_id=$5::text::uuid and w.generation_digest=$6 and w.configuration_digest=$7 and w.xds_version_digest=$8
            and o.capsule_digest=$9 and o.activation_receipt_digest=$10
            and w.work_kind='RUNTIME_ACTIVATION'
            and ((not $14::boolean and w.state='LEASED' and w.lease_owner=$11 and w.lease_until>clock_timestamp())
              or ($14::boolean and w.state='RECONCILING' and w.reconcile_after='infinity'::timestamptz
                and w.lease_owner is null and w.lease_until is null))
            and w.execution_started_at is not null and w.predecessor_digest is null
            and w.result_event_id is null and w.completed_at is null and w.attempt_count=$13
            and w.policy_generation_digest='sha256:'||(a.activation_proof->>'policyGenerationDigest')
            and rg.state='ACTIVATING' and rg.predecessor_digest is null and rg.cigl_profile_selection is null
            and rt.state='STAGING' and rt.active_generation_digest is null and rt.desired_generation_digest=w.generation_digest
            and rt.policy_generation_digest=w.policy_generation_digest
            and c.state in ('STAGING','WRITE_AMBIGUITY') and occ.state in ('STAGING','PARTIAL')
            and occ.activation_occurrence_id=$12::text::uuid
            and a.activation_proof->>'occurrenceId'=occ.activation_occurrence_id::text
            and (select count(*) from control.policy_activation_occurrence_target linked
              where linked.configuration_work_id=w.configuration_work_id)=1
            and occ.total_target_count=(select count(*) from control.policy_activation_occurrence_target member
              where member.participant_id=occ.participant_id and member.privacy_domain_id=occ.privacy_domain_id
                and member.activation_occurrence_id=occ.activation_occurrence_id and member.phase='FORWARD')
            and pa.state='PREPARED' and pa.prior_generation_digest is null and pa.activated_at is null and pa.retired_at is null
            and pg.state='PREPARED' and not pg.active and bundle.state in ('PUBLISHED','STAGED')
          for update of w,rg,rt,c,occ,pa,pg,bundle nowait for share of i nowait"#)
            .bind(&original.peer.target_id).bind(candidate.work_id).bind(candidate.operation_id)
            .bind(candidate.execution_attempt_id).bind(candidate.generation_id)
            .bind(format!("sha256:{}", candidate.generation_digest.as_str()))
            .bind(format!("sha256:{}", candidate.configuration_digest.as_str()))
            .bind(format!("sha256:{}", candidate.xds_version_digest.as_str()))
            .bind(format!("sha256:{}", candidate.capsule_digest.as_str()))
            .bind(format!("sha256:{}", candidate.receipt_digest.as_str()))
            .bind(lease_owner).bind(candidate.occurrence_id).bind(claim_count).bind(parked).fetch_one(&mut **tx).await.map_err(completion_database_error)?;
        let verified = self.verify_historical_confirmation_record(&row, &identity)?;
        if verified.confirmation.signed_acknowledgement.is_none() {
            return Err(unavailable());
        }
        let proof: Value = row
            .try_get("activation_proof")
            .map_err(completion_database_error)?;
        let token = self
            .runtime_control
            .verify_activation_token(original.signed_token)
            .map_err(|_| unavailable())?;
        let stored_occurrence: String = row
            .try_get("occurrence_id")
            .map_err(completion_database_error)?;
        if !same_original_occurrence(
            candidate.occurrence_id,
            &token.occurrence_id,
            &stored_occurrence,
            &proof,
        ) || proof.get("originalTokenDigest").and_then(Value::as_str)
            != Some(Digest::of(original.signed_token).as_str())
            || proof.get("originalReceiptDigest").and_then(Value::as_str)
                != Some(Digest::of(original.signed_receipt).as_str())
            || proof.get("capsuleValidUntilNs").and_then(Value::as_str)
                != Some(original.capsule.hard_expiry_ns.to_string().as_str())
            || original.capsule.previous_capsule_digest.is_some()
        {
            return Err(unavailable());
        }
        // This is verification AT the signed original observation, not a new
        // admission using a backdated clock. No signing owner is called.
        restore_custody::require_original_custody(
            original.capsule,
            &token,
            &verified.observed,
            &verified.source,
            &original.peer.target_id,
            verified.observed.observed_at_ns,
        )?;
        let timestamp = |name| -> Result<u64> {
            row.try_get::<String, _>(name)
                .map_err(completion_database_error)?
                .parse()
                .map_err(|_| unavailable())
        };
        if !original_window(
            original.capsule.not_before_ns,
            original.capsule.hard_expiry_ns,
            verified.observed.observed_at_ns,
            timestamp("admission_ns")?,
            timestamp("delivery_ns")?,
            timestamp("ack_ns")?,
        ) {
            return Err(unavailable());
        }
        let scope: Vec<u8> = row
            .try_get("scope_digest")
            .map_err(completion_database_error)?;
        let others = sqlx::query(r#"select g.state::text,g.active,
          exists(select 1 from control.policy_activation a where a.participant_id=g.participant_id
            and a.privacy_domain_id=g.privacy_domain_id and a.policy_generation_id=g.policy_generation_id
            and (a.activated_at is not null or a.retired_at is not null or a.state in ('ACTIVE','RETIRED'))) activated_history
          from control.policy_generation g where g.participant_id=openpc.current_participant_id()
            and g.privacy_domain_id=openpc.current_privacy_domain_id() and g.scope_digest=$1
          order by g.policy_generation_id for update of g nowait"#)
            .bind(scope)
            .fetch_all(&mut **tx).await.map_err(completion_database_error)?;
        for other in others {
            if !untouched_other_generation(
                &other
                    .try_get::<String, _>("state")
                    .map_err(completion_database_error)?,
                other.try_get("active").map_err(completion_database_error)?,
                other
                    .try_get("activated_history")
                    .map_err(completion_database_error)?,
            ) {
                return Err("historical completion policy scope advanced".into());
            }
        }
        if self.bootstrap_identity(tx, original.peer).await? != identity {
            return Err(unavailable());
        }
        Ok(VerifiedHistoricalActivation {
            capsule_digest: candidate.capsule_digest.clone(),
            receipt: row
                .try_get("activation_receipt")
                .map_err(completion_database_error)?,
            receipt_digest: candidate.receipt_digest.clone(),
            observed_at_ns: verified.observed.observed_at_ns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn occurrence_identity_cannot_be_missing_foreign_or_relinked() {
        let proof = serde_json::json!({"occurrenceId":"original"});
        assert!(same_original_occurrence(
            "original", "original", "original", &proof
        ));
        assert!(!same_original_occurrence(
            "foreign", "original", "original", &proof
        ));
        assert!(!same_original_occurrence(
            "original", "foreign", "original", &proof
        ));
        assert!(!same_original_occurrence(
            "original", "original", "foreign", &proof
        ));
        assert!(!same_original_occurrence(
            "original",
            "original",
            "original",
            &serde_json::json!({})
        ));
        assert!(!same_original_occurrence(
            "original",
            "original",
            "original",
            &serde_json::json!({"occurrenceId":"foreign"})
        ));
    }
    #[test]
    fn original_effect_and_ack_must_precede_the_original_deadline() {
        assert!(original_window(10, 100, 10, 20, 30, 99));
        for times in [
            (9, 20, 30, 99),
            (10, 9, 30, 99),
            (10, 20, 19, 99),
            (10, 20, 30, 29),
            (10, 20, 30, 100),
        ] {
            assert!(!original_window(
                10, 100, times.0, times.1, times.2, times.3
            ));
        }
    }
    #[test]
    fn an_initial_settlement_cannot_rewind_an_active_or_intervening_head() {
        assert!(untouched_other_generation("PREPARED", false, false));
        for state in ["ACTIVE", "RETIRED"] {
            assert!(!untouched_other_generation(state, false, false));
        }
        assert!(!untouched_other_generation("PREPARED", true, false));
        assert!(!untouched_other_generation("PREPARED", false, true));
    }
}
