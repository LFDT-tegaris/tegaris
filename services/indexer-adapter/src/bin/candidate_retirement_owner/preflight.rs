use super::{Database, Result, read_file};
use pc_runtime_types::{
    Digest,
    store_retirement::{RetirementAttempt, RetirementRejection, RetirementStore},
    store_retirement_authority::RetirementHost,
};
use serde::Deserialize;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::{path::Path, time::Duration};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Configuration {
    host: RetirementHost,
    database: Database,
}

pub(super) async fn observe(path: &Path, attempt: &RetirementAttempt) -> Result<()> {
    let config: Configuration = serde_json::from_slice(&read_file(path, 65_536, true)?)?;
    attempt.validate()?;
    if config.host.store != RetirementStore::CandidateIndex
        || attempt.store != config.host.store
        || attempt.scope != config.host.scope
        || config.database.name != "openpc_candidate_index"
        || config.database.user != "openpc_candidate_index_reader"
    {
        return Err("installed observation scope rejected".into());
    }
    let password = read_file(&config.database.password_file, 4096, true)?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(
            PgConnectOptions::new()
                .host(&config.database.host)
                .port(config.database.port)
                .database(&config.database.name)
                .username(&config.database.user)
                .password(std::str::from_utf8(&password)?.trim()),
        )
        .await?;
    let observed = async {
        let mut tx = pool.begin().await?;
        let safe: bool = sqlx::query_scalar("select current_database()='openpc_candidate_index'
          and current_user=session_user and session_user='openpc_candidate_index_reader'
          and not r.rolsuper and not r.rolbypassrls and not r.rolcreaterole
          and not pg_has_role(current_user,'openpc_candidate_index_owner','MEMBER')
          and not pg_has_role(current_user,'openpc_indexer_writer','USAGE')
          and not has_table_privilege(current_user,'candidate.candidate_event','INSERT,UPDATE,DELETE,TRUNCATE')
          and not has_table_privilege(current_user,'candidate.retirement_capability_secret','SELECT')
          from pg_roles r where r.rolname=current_user").fetch_one(&mut *tx).await?;
        if !safe { return Err("installed observation role rejected".into()); }
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-CANDIDATE_WRITE-V1',false)")
            .bind(Uuid::parse_str(&attempt.scope.participant_id)?)
            .bind(Uuid::parse_str(&attempt.scope.privacy_domain_id)?)
            .bind(Uuid::now_v7()).execute(&mut *tx).await?;
        sqlx::query("set local lock_timeout='5s'").execute(&mut *tx).await?;
        sqlx::query("set local statement_timeout='10s'").execute(&mut *tx).await?;
        // The established security-definer predicate obtains the same native
        // locks as execution but cannot delete or issue a capability. This
        // role has no writes; rollback releases every observation lock.
        let blocker: Option<String> = sqlx::query_scalar("select candidate.check_store_retirement($1::jsonb)")
            .bind(serde_json::to_string(attempt)?).fetch_one(&mut *tx).await?;
        let now: String = sqlx::query_scalar("select floor(extract(epoch from clock_timestamp())*1000)::text")
            .fetch_one(&mut *tx).await?;
        let blocker: Option<RetirementRejection> = blocker.map(|value| serde_json::from_value(serde_json::Value::String(value))).transpose()?;
        tx.rollback().await?;
        Ok::<_, Box<dyn std::error::Error>>((now, blocker))
    }.await;
    pool.close().await;
    let (now, blocker) = observed?;
    let result = match blocker {
        Some(blocker) => serde_json::json!({"state":"BLOCKED","blocker":blocker}),
        None => {
            serde_json::json!({"state":"CLEAR","checkedAtMs":now,"selection":attempt.selection})
        }
    };
    println!(
        "{}",
        serde_json::json!({"identity":"OPENPC-CANDIDATE-RETIREMENT-PREFLIGHT-1",
        "hostDigest":Digest::of(serde_json::to_vec(&config.host)?),"authority":"ADVISORY_ONLY",
        "attemptDigest":attempt.digest()?,"selectionDigest":attempt.selection_digest,"result":result})
    );
    Ok(())
}
