//! Scoped compatibility for a prospectively enrolled, stopped predecessor.
//! The independent cluster marker is consumed once by the host installer.
//! Neither this identity nor an old installation proves source non-use.
use super::*;
use sqlx::{Postgres, Row, Transaction};

const PURPOSE: &str = "openpc:runtime-source-predecessor:v1";
const SOURCE_MIGRATION: &str =
    "/migrations/postgres/control-api/0171_runtime_artifact_source_custody.sql";
const REVISION: &str = "5baddf3d4ed503f0b9a7112c34521048671409a7";

pub(super) fn marker(participant: &str, privacy: &str) -> RuntimeResult<String> {
    Ok(installation::rooted_login(participant, privacy)?.replacen(
        "openpc_rs_login_",
        "openpc_rs_pre_",
        1,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Enrollment {
    participant_id: String,
    privacy_domain_id: String,
    installation_id: String,
    legacy_role: String,
    source_revision: String,
    executable_digest: Digest,
    cluster_identifier: String,
    database_oid: u32,
    database_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Profile {
    purpose: String,
    enrollment: Enrollment,
    state: String,
    run_id: String,
    capture_digest: Digest,
    successor_schema_digest: Digest,
    successor_migration_paths: Vec<String>,
    prior_connection_limit: i32,
}

fn decode(
    profile: &str,
    participant: &str,
    privacy: &str,
    role: &str,
) -> SourceCustodyResult<Profile> {
    let pin: Profile =
        serde_json::from_str(profile).map_err(|_| RuntimeError::InvalidAuthorization)?;
    let e = &pin.enrollment;
    uuid(&e.installation_id)?;
    uuid(&pin.run_id)?;
    Digest::parse(e.executable_digest.as_str())?;
    Digest::parse(pin.capture_digest.as_str())?;
    Digest::parse(pin.successor_schema_digest.as_str())?;
    if pin.purpose != PURPOSE
        || pin.state != "CONSUMED"
        || e.source_revision != REVISION
        || e.participant_id != participant
        || e.privacy_domain_id != privacy
        || e.legacy_role != role
        || e.cluster_identifier.is_empty()
        || e.cluster_identifier.len() > 20
        || !e
            .cluster_identifier
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        || e.database_oid == 0
        || pin.prior_connection_limit < -1
        || !pin
            .successor_migration_paths
            .iter()
            .any(|path| path == SOURCE_MIGRATION)
        || pin.successor_migration_paths.len() > 2048
        || pin
            .successor_migration_paths
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || pin
            .successor_migration_paths
            .iter()
            .any(|path| path.is_empty() || path.len() > 512)
    {
        return Err(RuntimeError::InvalidAuthorization.into());
    }
    Ok(pin)
}

pub(super) async fn authenticate(
    tx: &mut Transaction<'_, Postgres>,
    profile: &str,
    participant: &str,
    privacy: &str,
    role: &str,
) -> SourceCustodyResult<()> {
    let pin = decode(profile, participant, privacy, role)?;
    let e = &pin.enrollment;
    // Cluster identity and catalog shape remain observable without application
    // schema privileges. Absence of a table required by the consumed checkpoint
    // is a schema mismatch; inability to read an existing ledger is unavailable.
    let identity = sqlx::query("select s.system_identifier::text cluster_id,d.oid::bigint database_oid,d.datname::text database_name from pg_catalog.pg_control_system() s,pg_catalog.pg_database d where d.datname=current_database()")
        .fetch_one(&mut **tx).await.map_err(control::unavailable)?;
    if identity
        .try_get::<String, _>("cluster_id")
        .map_err(control::unavailable)?
        != e.cluster_identifier
        || identity
            .try_get::<i64, _>("database_oid")
            .map_err(control::unavailable)?
            != i64::from(e.database_oid)
        || identity
            .try_get::<String, _>("database_name")
            .map_err(control::unavailable)?
            != e.database_name
    {
        return Err(SourceCustodyError::PredecessorRollback);
    }
    let schema_present: bool = sqlx::query_scalar("select count(*)=2 from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid=c.relnamespace where c.relkind='r' and ((n.nspname='openpc_local' and c.relname='migration') or (n.nspname='control' and c.relname='runtime_artifact_source'))")
        .fetch_one(&mut **tx).await.map_err(control::unavailable)?;
    if !schema_present {
        return Err(SourceCustodyError::PredecessorRollback);
    }
    // Additional later migrations are allowed. Every installed checkpoint path
    // must remain present with identical bytes; permission/SQL errors never
    // establish a historical rollback.
    let actual: Option<String> = sqlx::query_scalar(
        "select encode(sha256(convert_to(jsonb_agg(jsonb_build_array(path,sha256)
         order by path)::text,'UTF8')),'hex') from openpc_local.migration
         where path=any($1::text[])",
    )
    .bind(&pin.successor_migration_paths)
    .fetch_one(&mut **tx)
    .await
    .map_err(control::unavailable)?;
    if actual.as_deref() != Some(pin.successor_schema_digest.as_str()) {
        return Err(SourceCustodyError::PredecessorRollback);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn predecessor_profile_requires_consumed_exact_identity_and_ordered_schema() {
        let participant = "018f0000-0000-7000-8000-000000000101";
        let privacy = "018f0000-0000-7000-8000-000000000201";
        let role = "openpc_local_control_worker";
        let original = json!({
            "purpose": PURPOSE, "state": "CONSUMED",
            "enrollment": { "participantId": participant, "privacyDomainId": privacy,
                "installationId": "018f0000-0000-7000-8000-000000000301",
                "legacyRole": role, "sourceRevision": REVISION,
                "executableDigest": "a".repeat(64), "clusterIdentifier": "123456789",
                "databaseOid": 16384, "databaseName": "openpc_control" },
            "runId": "018f0000-0000-7000-8000-000000000401",
            "captureDigest": "b".repeat(64), "successorSchemaDigest": "c".repeat(64),
            "successorMigrationPaths": [SOURCE_MIGRATION], "priorConnectionLimit": -1
        });
        assert!(decode(&original.to_string(), participant, privacy, role).is_ok());
        for (pointer, value) in [
            ("/state", json!("CAPTURED")),
            ("/purpose", json!("other")),
            ("/enrollment/sourceRevision", json!("0".repeat(40))),
            ("/enrollment/participantId", json!(privacy)),
            ("/enrollment/privacyDomainId", json!(participant)),
            ("/enrollment/legacyRole", json!("postgres")),
            ("/enrollment/installationId", json!("not-an-id")),
            ("/enrollment/executableDigest", json!("a".repeat(63))),
            ("/enrollment/clusterIdentifier", json!("caller-server")),
            ("/enrollment/databaseOid", json!(0)),
            ("/runId", serde_json::Value::Null),
            ("/captureDigest", json!("bad")),
            ("/successorMigrationPaths", json!([])),
            ("/successorMigrationPaths", json!(["/b.sql", "/a.sql"])),
            ("/successorMigrationPaths", json!(["/a.sql", "/a.sql"])),
            ("/priorConnectionLimit", json!(-2)),
        ] {
            let mut altered = original.clone();
            *altered.pointer_mut(pointer).expect("known profile field") = value;
            assert!(
                decode(&altered.to_string(), participant, privacy, role).is_err(),
                "{pointer}"
            );
        }
        let mut extra = original;
        extra["sourceAuthority"] = json!("NONE");
        assert!(decode(&extra.to_string(), participant, privacy, role).is_err());
        assert_eq!(
            worker::SourceStartupError::PredecessorRollback.stage(),
            "installation"
        );
        assert_eq!(
            worker::SourceStartupError::PredecessorRollback.reason(),
            "predecessor_rollback"
        );
    }
}
