//! Adapter to the existing command/outbox and global reservation owners. The
//! table's constraints and transition trigger remain authoritative. A lost
//! commit reply never grants this process a dispatch transition.
use super::{Result, failure};
use openpc_multi_rpc::deployment::{
    projection::ProjectionExpectation,
    rejection::{Reason, ReservationRejection},
};
use pc_runtime_types::{Digest, PurposeSigner, canonical_bytes};
use serde_json::{Value, json};
use sqlx::{Acquire, PgPool, Row};

pub(super) struct Command {
    pub command_id: String,
    pub attempt_id: String,
    pub candidate: Value,
    pub candidate_digest: Digest,
    pub evidence_digest: Digest,
    pub preparation: Vec<u8>,
    pub publication: Vec<u8>,
    pub principal_id: String,
}
impl Command {
    pub(super) fn predecessor(&self) -> Result<Option<String>> {
        let Some(value) = self.candidate.get("predecessorOperationId") else {
            return Ok(None);
        };
        let id = value
            .as_str()
            .and_then(|value| value.strip_prefix("urn:openpc:operation:"))
            .ok_or_else(failure)?;
        if id == self.command_id
            || !uuid::Uuid::try_parse(id)
                .is_ok_and(|value| value.get_version_num() == 7 && value.to_string() == id)
        {
            return Err(failure());
        }
        Ok(Some(id.into()))
    }
}

pub(super) struct Rejection<'a> {
    pub command: &'a Command,
    pub binding: &'a ProjectionExpectation,
    pub signer: &'a PurposeSigner,
}

pub(super) async fn scoped(
    pool: &PgPool,
    participant: &str,
    privacy: &str,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pool.begin().await.map_err(|_| failure())?;
    sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',true),openpc.assert_request_context(true)")
        .bind(participant).bind(privacy).execute(&mut *tx).await.map_err(|_| failure())?;
    Ok(tx)
}

pub(super) async fn next(
    pool: &PgPool,
    participant: &str,
    privacy: &str,
    target: &str,
    workload: &str,
) -> Result<Option<Command>> {
    let mut tx = scoped(pool, participant, privacy).await?;
    let row = sqlx::query(r#"select c.consumed_operation_id::text command_id,c.resource_id::text attempt_id,
        c.candidate_document,c.candidate_digest,e.evidence_digest,i.preparation_bytes,i.publication_bytes,
        i.execution_principal_id::text
      from control.mutation_candidate c
      join control.idempotency_record r on r.participant_id=c.participant_id and r.privacy_domain_id=c.privacy_domain_id
        and r.operation_id=c.consumed_operation_id and r.catalog_operation_id=c.catalog_operation_id
        and r.input_digest=c.candidate_digest and r.principal_id=c.maker_principal_id and r.terminal_state='COMMITTED'
      join control.mutation_evidence e on e.participant_id=c.participant_id and e.privacy_domain_id=c.privacy_domain_id
        and e.operation_id=c.consumed_operation_id and e.catalog_operation_id=c.catalog_operation_id
        and e.candidate_digest=c.candidate_digest and e.aggregate_id=c.resource_id
      join control.deployment_intent i on i.participant_id=c.participant_id and i.privacy_domain_id=c.privacy_domain_id
        and 'urn:openpc:resource:'||i.deployment_intent_id::text=c.candidate_document->>'deploymentIntentId'
        and i.actor_principal_id=c.maker_principal_id
      where c.participant_id=$1::text::uuid and c.privacy_domain_id=$2::text::uuid
        and c.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT' and c.state='CONSUMED'
        and c.action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
        and c.resource_type='deployment-submission' and c.operation_class='CREATE'
        and i.runtime_target_id=$3::text::uuid and i.execution_workload_id=$4
        and exists(select 1 from control.outbox_event o where o.participant_id=c.participant_id
          and o.privacy_domain_id=c.privacy_domain_id and o.aggregate_id=c.resource_id
          and o.event_type='openpc.deployment.submission.requested.v1'
          and convert_from(o.payload_cbor,'UTF8')::jsonb->>'candidateDigest'='sha256:'||encode(c.candidate_digest,'hex')
          and convert_from(o.payload_cbor,'UTF8')::jsonb->>'authorizationEvidenceDigest'='sha256:'||encode(e.evidence_digest,'hex'))
        and not exists(select 1 from control.deployment_address_reservation reservation
          where reservation.participant_id=c.participant_id and reservation.privacy_domain_id=c.privacy_domain_id
            and reservation.attempt_id=c.resource_id and reservation.state<>'RESERVED')
        and not exists(select 1 from control.deployment_result result
          where result.command_id=c.consumed_operation_id and result.participant_id=c.participant_id
            and result.privacy_domain_id=c.privacy_domain_id)
      order by c.created_at,c.mutation_candidate_id limit 1"#)
        .bind(participant).bind(privacy).bind(target).bind(workload).fetch_optional(&mut *tx).await.map_err(|_| failure())?;
    tx.commit().await.map_err(|_| failure())?;
    row.map(|row| {
        let digest = |field| -> Result<Digest> {
            let bytes: Vec<u8> = row.try_get(field).map_err(|_| failure())?;
            if bytes.len() != 32 {
                return Err(failure());
            }
            Digest::parse(super::hex(&bytes)).map_err(|_| failure())
        };
        let command = Command {
            command_id: row.try_get("command_id").map_err(|_| failure())?,
            attempt_id: row.try_get("attempt_id").map_err(|_| failure())?,
            candidate: row.try_get("candidate_document").map_err(|_| failure())?,
            candidate_digest: digest("candidate_digest")?,
            evidence_digest: digest("evidence_digest")?,
            preparation: row.try_get("preparation_bytes").map_err(|_| failure())?,
            publication: row.try_get("publication_bytes").map_err(|_| failure())?,
            principal_id: row
                .try_get("execution_principal_id")
                .map_err(|_| failure())?,
        };
        if Digest::of(canonical_bytes(&command.candidate).map_err(|_| failure())?)
            != command.candidate_digest
        {
            return Err(failure());
        }
        Ok(command)
    })
    .transpose()
}

pub(super) async fn handoff(
    pool: &PgPool,
    binding: &Value,
    sender_nonce: u64,
    participant: &str,
    privacy: &str,
    rejection: Option<Rejection<'_>>,
) -> Result<Option<u64>> {
    let mut fields = serde_json::Map::new();
    for (key, value) in binding.as_object().ok_or_else(failure)? {
        let mut column = String::new();
        for ch in key.chars() {
            if ch.is_ascii_uppercase() {
                column.push('_');
            }
            column.push(ch.to_ascii_lowercase());
        }
        fields.insert(column, value.clone());
    }
    // Derived from the verified signed transaction. Keep this database custody
    // field outside the signed handoff binding, preserving prior journal bytes.
    fields.insert("sender_nonce".into(), json!(sender_nonce.to_string()));
    let predecessor = rejection
        .as_ref()
        .map(|rejection| rejection.command.predecessor())
        .transpose()?
        .flatten();
    fields.insert("predecessor_command_id".into(), json!(predecessor));
    let expected = Value::Object(fields);
    if expected["participant_id"] != participant || expected["privacy_domain_id"] != privacy {
        return Err(failure());
    }
    let mut tx = scoped(pool, participant, privacy).await?;
    // The same database lock is enforced by both result and reservation
    // triggers. Keep it outside the savepoint: rollback of a failed claim must
    // not let another worker hand off this command before rejection commits.
    sqlx::query("select openpc.lock_deployment_command(($1->>'command_id')::uuid)")
        .bind(&expected)
        .execute(&mut *tx)
        .await
        .map_err(|_| failure())?;
    let terminal: bool = sqlx::query_scalar("select exists(select 1 from control.deployment_result where command_id=($1->>'command_id')::uuid)")
        .bind(&expected).fetch_one(&mut *tx).await.map_err(|_| failure())?;
    if terminal {
        tx.commit().await.map_err(|_| failure())?;
        return Ok(None);
    }
    let mut claim = tx.begin().await.map_err(|_| failure())?;
    // Freeze the exact module contribution generation through custody. This
    // fence grants no workload, policy or sender authority of its own.
    sqlx::query(
        "select pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||$1||':'||$2,0))",
    )
    .bind(participant)
    .bind(privacy)
    .execute(&mut *claim)
    .await
    .map_err(|_| failure())?;
    let module_current: bool = sqlx::query_scalar("select exists(select 1 from control.deployment_intent i where i.participant_id=$1::text::uuid and i.privacy_domain_id=$2::text::uuid and i.preparation_digest=$3 and i.module_generation_digest is not null and i.module_generation_digest=openpc.deployment_module_generation(i.participant_id,i.privacy_domain_id))")
        .bind(participant).bind(privacy).bind(expected["prepared_record_digest"].as_str().ok_or_else(failure)?)
        .fetch_one(&mut *claim).await.map_err(|_| failure())?;
    if !module_current {
        claim.rollback().await.map_err(|_| failure())?;
        return reject_unheld(
            tx,
            rejection,
            participant,
            privacy,
            Reason::ModuleGenerationUnavailable,
        )
        .await;
    }
    let inserted = sqlx::query(r#"insert into control.deployment_address_reservation(
        attempt_id,command_id,predecessor_command_id,participant_id,privacy_domain_id,target_runtime_id,chain_id,genesis_digest,
        contract_address,helper_address,sender_address,sender_nonce,creator_address,mechanism,salt_namespace_digest,effective_salt,
        artifact_digest,init_code_hash,intent_digest,profile_digest,generation_digest,transaction_hash,prepared_record_digest,
        native_value_authorization_id,native_value_authorization_digest,expires_at)
      select x.attempt_id,x.command_id,x.predecessor_command_id,x.participant_id,x.privacy_domain_id,x.target_runtime_id,x.chain_id,x.genesis_digest,
        x.contract_address,x.helper_address,x.sender_address,x.sender_nonce,x.creator_address,x.mechanism,x.salt_namespace_digest,x.effective_salt,
        x.artifact_digest,x.init_code_hash,x.intent_digest,x.profile_digest,x.generation_digest,x.transaction_hash,x.prepared_record_digest,
        x.native_value_authorization_id,x.native_value_authorization_digest,x.expires_at
      from jsonb_populate_record(null::control.deployment_address_reservation,$1) x on conflict do nothing"#)
        .bind(&expected).execute(&mut *claim).await;
    if let Err(error) = inserted {
        // Cross-address arbitration is an AFTER trigger, so PostgreSQL reports
        // its conflict as a named unique violation. Other errors remain errors;
        // neither outages nor an uncertain commit become a no-handoff claim.
        let conflict = error.as_database_error().is_some_and(|error| {
            error.code().as_deref() == Some("23505")
                && error.constraint() == Some("deployment_address_claim_active_uq")
        });
        claim.rollback().await.map_err(|_| failure())?;
        if !conflict {
            return Err(failure());
        }
        return reject_unheld(tx, rejection, participant, privacy, Reason::CustodyConflict).await;
    }
    let row=sqlx::query(r#"select state,
        (to_jsonb(r)-array['state','created_at','handoff_at','expired_at'])=
        (to_jsonb(jsonb_populate_record(null::control.deployment_address_reservation,$1))-array['state','created_at','handoff_at','expired_at']) exact
      from control.deployment_address_reservation r where attempt_id=($1->>'attempt_id')::uuid for update"#)
        .bind(&expected).fetch_optional(&mut *claim).await.map_err(|_| failure())?;
    let Some(row) = row else {
        claim.rollback().await.map_err(|_| failure())?;
        return reject_unheld(tx, rejection, participant, privacy, Reason::CustodyConflict).await;
    };
    if !row.try_get::<bool, _>("exact").map_err(|_| failure())? {
        return Err(failure());
    }
    if row.try_get::<String, _>("state").map_err(|_| failure())? != "RESERVED" {
        claim.commit().await.map_err(|_| failure())?;
        tx.commit().await.map_err(|_| failure())?;
        return Ok(None);
    }
    let at: i64 = sqlx::query_scalar(r#"update control.deployment_address_reservation set state='HANDOFF'
        where attempt_id=($1->>'attempt_id')::uuid and state='RESERVED' and expires_at>clock_timestamp()
        returning floor(extract(epoch from handoff_at)*1000)::bigint"#)
        .bind(json!({"attempt_id":expected["attempt_id"]})).fetch_one(&mut *claim).await.map_err(|_| failure())?;
    claim.commit().await.map_err(|_| failure())?;
    // Do not retry commit. Reconnect sees HANDOFF and returns no transition.
    tx.commit().await.map_err(|_| failure())?;
    Ok(Some(u64::try_from(at).map_err(|_| failure())?))
}

/// Expiry asserts only that this exact approved command never obtained custody.
/// The result trigger takes the shared command lock and independently checks
/// the immutable preparation deadline; a concurrent HANDOFF defeats rejection.
pub(super) async fn reject_expired(
    pool: &PgPool,
    rejection: Rejection<'_>,
    participant: &str,
    privacy: &str,
) -> Result<()> {
    let tx = scoped(pool, participant, privacy).await?;
    reject_unheld(
        tx,
        Some(rejection),
        participant,
        privacy,
        Reason::PreparationExpired,
    )
    .await?;
    Ok(())
}

async fn reject_unheld(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    rejection: Option<Rejection<'_>>,
    participant: &str,
    privacy: &str,
    reason: Reason,
) -> Result<Option<u64>> {
    let rejection = rejection.ok_or_else(failure)?;
    sqlx::query("select openpc.lock_deployment_command($1::text::uuid)")
        .bind(&rejection.command.command_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| failure())?;
    let held_or_completed: bool = sqlx::query_scalar("select exists(select 1 from control.deployment_address_reservation where command_id=$1::text::uuid) or exists(select 1 from control.deployment_result where command_id=$1::text::uuid)")
        .bind(&rejection.command.command_id).fetch_one(&mut *tx).await.map_err(|_| failure())?;
    if held_or_completed {
        tx.commit().await.map_err(|_| failure())?;
        return Ok(None);
    }
    let bytes = ReservationRejection::sign(
        rejection.binding.clone(),
        rejection.command.candidate_digest.clone(),
        rejection.command.evidence_digest.clone(),
        reason,
        super::now_ms()?,
        rejection.signer,
    )
    .map_err(|_| failure())?;
    // The result guard independently requires the exact approved command and
    // absence of any reservation. Its immutable result also fences future claims.
    sqlx::query("insert into control.deployment_result(participant_id,privacy_domain_id,command_id,sequence,signed_bytes,result_digest) values($1::text::uuid,$2::text::uuid,$3::text::uuid,1,$4,$5)")
        .bind(participant).bind(privacy).bind(&rejection.command.command_id).bind(&bytes)
        .bind(format!("sha256:{}", Digest::of(&bytes).as_str()))
        .execute(&mut *tx).await.map_err(|_| failure())?;
    super::result_event::emit(
        &mut tx,
        rejection.binding,
        &Digest::of(&bytes),
        super::result_event::ResultKind::ReservationRejection,
    )
    .await?;
    tx.commit().await.map_err(|_| failure())?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires the least-privilege PostgreSQL reservation owner"]
    async fn postgres_worker_handoff_requires_current_public_module_authority() {
        let url = std::env::var("OPENPC_DEPLOYMENT_RESERVATION_DATABASE_URL").unwrap();
        let pool = PgPool::connect(&url).await.unwrap();
        let expiry:String=sqlx::query_scalar("select to_char(clock_timestamp()+interval '1 minute','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')")
            .fetch_one(&pool).await.unwrap();
        let id = || uuid::Uuid::now_v7().to_string();
        let d = format!("sha256:{}", Digest::of(id()).as_str());
        let address = format!("0x{}", &Digest::of(id()).as_str()[..40]);
        let hash = format!("0x{}", Digest::of(id()).as_str());
        let participant = id();
        let privacy = id();
        let binding = json!({"attemptId":id(),"commandId":id(),"participantId":participant,"privacyDomainId":privacy,
            "targetRuntimeId":format!("urn:openpc:resource:{}",id()),"chainId":"31337","genesisDigest":d,
            "contractAddress":address,"senderAddress":address,"creatorAddress":address,"mechanism":"TRANSACTION_CREATE",
            "saltNamespaceDigest":null,"effectiveSalt":null,"artifactDigest":d,"initCodeHash":hash,
            "intentDigest":d,"profileDigest":d,"generationDigest":d,"transactionHash":hash,"preparedRecordDigest":d,"expiresAt":expiry});
        let (a, b) = tokio::join!(
            handoff(&pool, &binding, 9, &participant, &privacy, None),
            handoff(&pool, &binding, 9, &participant, &privacy, None)
        );
        // Caller-created reservation bytes cannot establish a public prepared
        // intent or an enabled module generation. Both concurrent attempts deny.
        assert_eq!(a.unwrap_err(), failure());
        assert_eq!(b.unwrap_err(), failure());
        pool.close().await;
        let pool = PgPool::connect(&url).await.unwrap();
        assert!(
            handoff(&pool, &binding, 9, &participant, &privacy, None)
                .await
                .is_err()
        );
        for field in [
            "transactionHash",
            "intentDigest",
            "targetRuntimeId",
            "expiresAt",
        ] {
            let mut changed = binding.clone();
            changed[field] = match field {
                "transactionHash" => {
                    json!(format!("0x{}", Digest::of("other transaction").as_str()))
                }
                "intentDigest" => json!(format!("sha256:{}", Digest::of("other intent").as_str())),
                "targetRuntimeId" => json!(format!("urn:openpc:resource:{}", id())),
                _ => json!("2099-01-01T00:00:00.000Z"),
            };
            assert!(
                handoff(&pool, &changed, 9, &participant, &privacy, None)
                    .await
                    .is_err(),
                "{field}"
            );
        }
        let mut other = binding.clone();
        let foreign = id();
        let foreign_privacy = id();
        other["attemptId"] = json!(id());
        other["commandId"] = json!(id());
        other["participantId"] = json!(foreign);
        other["privacyDomainId"] = json!(foreign_privacy);
        assert_eq!(
            handoff(&pool, &other, 9, &foreign, &foreign_privacy, None)
                .await
                .unwrap_err(),
            failure()
        );
        assert!(
            handoff(&pool, &binding, 9, &participant, &privacy, None)
                .await
                .is_err()
        );
        let mut tx = scoped(&pool, &participant, &privacy).await.unwrap();
        let count: i64 = sqlx::query_scalar(
            "select count(*) from control.deployment_address_reservation where command_id=$1::text::uuid",
        )
        .bind(binding["commandId"].as_str().unwrap())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(count, 0);
        tx.commit().await.unwrap();
        pool.close().await;
    }
}
