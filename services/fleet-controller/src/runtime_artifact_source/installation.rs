//! Cluster-owned installation identity survives a supported per-database
//! Control restore. This is not qualification for restoring cluster globals.
//! Marker roles have no product privileges and cannot be administered or SET by
//! consumers. A rooted installation creates a new, dedicated login atomically;
//! it never promotes the shared legacy login or reenrolls an existing login.
use super::*;
pub(super) use pc_runtime_types::runtime_source_identity::runtime_source_login as rooted_login;
use pc_runtime_types::runtime_source_identity::{
    RUNTIME_SOURCE_SCOPE_PREFIX as PREFIX, runtime_source_scope_marker as marker,
};
use sqlx::{Postgres, Row, Transaction};

const LEGACY: &str = "openpc_runtime_source_legacy";
const LEGACY_PROFILE: &str = "openpc:runtime-artifact-source:legacy-unproven:v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HostBinding {
    pub version: u16,
    pub installation: SourceCustodyInstallation,
    pub root: SourceRootBinding,
    pub database_role: String,
    pub source_public_key: Vec<u8>,
    pub commit_key_digest: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_custody: Option<archive::Binding>,
}

impl HostBinding {
    fn marker(&self) -> RuntimeResult<String> {
        marker(
            &self.installation.participant_id,
            &self.installation.privacy_domain_id,
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Mode {
    LegacyUnproven,
    Rooted(Box<HostBinding>),
}

/// Read actual session identity and cluster catalogs, never a session GUC or
/// current Control-table absence. An independent rooted scope also excludes
/// every legacy/shared login, even when restored Control has lost its rows.
pub(super) async fn authenticate(
    tx: &mut Transaction<'_, Postgres>,
    participant: &str,
    privacy: &str,
) -> SourceCustodyResult<Mode> {
    let expected = marker(participant, privacy)?;
    let predecessor = super::predecessor::marker(participant, privacy)?;
    let login = sqlx::query(
        "select r.rolname::text,
          r.rolcanlogin and not r.rolsuper and not r.rolbypassrls and not r.rolcreaterole
          and not r.rolcreatedb and not r.rolreplication and current_user=session_user
          and pg_catalog.pg_has_role(r.oid,'openpc_control_worker','USAGE')
          and not pg_catalog.pg_has_role(r.oid,'openpc_control_owner','MEMBER')
          and not pg_catalog.pg_has_role(r.oid,'openpc_control_key_governor','MEMBER')
          and not pg_catalog.pg_has_role(r.oid,'openpc_control_runtime','MEMBER')
          and not exists(select 1 from pg_catalog.pg_auth_members m
            join pg_catalog.pg_roles parent on parent.oid=m.roleid join pg_catalog.pg_roles g on g.oid=m.grantor
            where m.member=r.oid and (m.admin_option or not g.rolsuper
              or parent.rolname not in ('openpc_control_worker','openpc_runtime_source_legacy',$1,$2)))
          and not exists(select 1 from pg_catalog.pg_shdepend d where d.refclassid='pg_catalog.pg_authid'::regclass
            and d.refobjid=r.oid and d.deptype in ('a','o','r','i')) safe
         from pg_catalog.pg_roles r where r.rolname=session_user",
    )
    .bind(&expected)
    .bind(&predecessor)
    .fetch_one(&mut **tx)
    .await
    .map_err(control::unavailable)?;
    if !login
        .try_get::<bool, _>("safe")
        .map_err(control::unavailable)?
    {
        return Err(RuntimeError::InvalidAuthorization.into());
    }
    let role: String = login.try_get("rolname").map_err(control::unavailable)?;
    let dedicated = rooted_login(participant, privacy)?;
    let protected: bool =
        sqlx::query_scalar("select exists(select 1 from pg_catalog.pg_roles where rolname=$1)")
            .bind(&dedicated)
            .fetch_one(&mut **tx)
            .await
            .map_err(control::unavailable)?;
    if protected && role != dedicated {
        return Err(SourceCustodyError::ProtectedScopeLogin);
    }
    let rows = sqlx::query("select r.rolname::text,pg_catalog.shobj_description(r.oid,'pg_authid') profile,not r.rolcanlogin and not r.rolsuper and not r.rolbypassrls and not r.rolcreaterole and not r.rolcreatedb and not r.rolreplication and not exists(select 1 from pg_catalog.pg_auth_members p where p.member=r.oid) and not exists(select 1 from pg_catalog.pg_shdepend d where d.refclassid='pg_catalog.pg_authid'::regclass and d.refobjid=r.oid and d.deptype in ('a','o','r','i')) safe,exists(select 1 from pg_catalog.pg_auth_members m join pg_catalog.pg_roles g on g.oid=m.grantor where m.roleid=r.oid and m.member=(select oid from pg_catalog.pg_roles where rolname=session_user) and not m.admin_option and not m.inherit_option and not m.set_option and g.rolsuper) direct,count(members.member)::bigint members from pg_catalog.pg_roles r left join pg_catalog.pg_auth_members members on members.roleid=r.oid where (r.rolname=$1 or r.rolname=$2 or pg_catalog.left(r.rolname,pg_catalog.length($3))=$3 or r.rolname=$4) and (r.rolname=$1 or pg_catalog.pg_has_role(session_user,r.oid,'MEMBER')) group by r.oid,r.rolname,r.rolcanlogin,r.rolsuper,r.rolbypassrls,r.rolcreaterole,r.rolcreatedb,r.rolreplication")
        .bind(&expected).bind(LEGACY).bind(PREFIX).bind(&predecessor).fetch_all(&mut **tx).await.map_err(control::unavailable)?;
    let row = rows
        .first()
        .filter(|_| rows.len() == 1)
        .ok_or(RuntimeError::InvalidAuthorization)?;
    if !row
        .try_get::<bool, _>("safe")
        .map_err(control::unavailable)?
        || !row
            .try_get::<bool, _>("direct")
            .map_err(control::unavailable)?
    {
        return Err(RuntimeError::InvalidAuthorization.into());
    }
    let name: String = row.try_get("rolname").map_err(control::unavailable)?;
    let profile: String = row.try_get("profile").map_err(control::unavailable)?;
    if name == LEGACY && profile == LEGACY_PROFILE {
        return Ok(Mode::LegacyUnproven);
    }
    if name == predecessor
        && row
            .try_get::<i64, _>("members")
            .map_err(control::unavailable)?
            == 1
    {
        super::predecessor::authenticate(tx, &profile, participant, privacy, &role).await?;
        return Ok(Mode::LegacyUnproven);
    }
    let binding: HostBinding =
        serde_json::from_str(&profile).map_err(|_| RuntimeError::InvalidAuthorization)?;
    binding.installation.validate()?;
    binding.root.validate()?;
    if let Some(archive) = &binding.archive_custody {
        archive.validate(&binding.installation)?;
    }
    if name != expected
        || binding.marker()? != expected
        || binding.version != 1
        || binding.database_role != role
        || role != dedicated
        || row
            .try_get::<i64, _>("members")
            .map_err(control::unavailable)?
            != 1
    {
        return Err(RuntimeError::InvalidAuthorization.into());
    }
    Ok(Mode::Rooted(Box::new(binding)))
}

/// Privileged initial host trust. Role uniqueness serializes duplicate scope
/// installation even across database restores. Native genesis is performed by
/// the caller before this same transaction commits; failed/unknown bytes stay.
pub(super) async fn install(
    tx: &mut Transaction<'_, Postgres>,
    binding: &HostBinding,
    password: &str,
) -> SourceCustodyResult<()> {
    binding.installation.validate()?;
    binding.root.validate()?;
    if let Some(archive) = &binding.archive_custody {
        archive.validate(&binding.installation)?;
    }
    if let Some(database) = &binding.root.database {
        let actual: serde_json::Value = sqlx::query_scalar("select jsonb_build_object('system_identifier',s.system_identifier::text,'database_oid',d.oid::text) from pg_catalog.pg_control_system() s,pg_catalog.pg_database d where d.datname=current_database()")
            .fetch_one(&mut **tx).await.map_err(control::unavailable)?;
        if actual != serde_json::to_value(database).map_err(control::unavailable)? {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
    }
    if binding.database_role
        != rooted_login(
            &binding.installation.participant_id,
            &binding.installation.privacy_domain_id,
        )?
    {
        return Err(RuntimeError::InvalidAuthorization.into());
    }
    let privileged: bool = sqlx::query_scalar(
        "select current_user=session_user and rolsuper from pg_catalog.pg_roles where rolname=session_user",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(control::unavailable)?;
    if !privileged
        || password.len() < 32
        || password.len() > 256
        || !password.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(RuntimeError::InvalidAuthorization.into());
    }
    let locked: bool = sqlx::query_scalar(
        "select pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended('evidence-lifecycle:'||$1,0))",
    )
    .bind(&binding.installation.participant_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(control::unavailable)?;
    if !locked {
        return Err(SourceCustodyError::Busy);
    }
    let name = binding.marker()?;
    // No IF NOT EXISTS and no ALTER of an existing LOGIN. A restored database
    // cannot consume the original role/scope identity to create another root.
    for (format, first, second) in [
        (
            "CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS",
            name.as_str(),
            "",
        ),
        (
            "CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L",
            binding.database_role.as_str(),
            password,
        ),
        (
            "GRANT openpc_control_worker TO %I",
            binding.database_role.as_str(),
            "",
        ),
        (
            "GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET FALSE",
            name.as_str(),
            binding.database_role.as_str(),
        ),
    ] {
        let statement: String =
            sqlx::query_scalar("select pg_catalog.format($1,$2::text,$3::text)")
                .bind(format)
                .bind(first)
                .bind(second)
                .fetch_one(&mut **tx)
                .await
                .map_err(control::unavailable)?;
        // The fixed templates above are escaped by PostgreSQL's %I/%L format
        // conversions; no caller-provided SQL is interpolated directly.
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&mut **tx)
            .await
            .map_err(control::unavailable)?;
    }
    let profile =
        String::from_utf8(canonical_bytes(binding)?).map_err(|_| RuntimeError::InvalidInput)?;
    let statement: String = sqlx::query_scalar(
        "select pg_catalog.format('COMMENT ON ROLE %I IS %L',$1::text,$2::text)",
    )
    .bind(name)
    .bind(profile)
    .fetch_one(&mut **tx)
    .await
    .map_err(control::unavailable)?;
    // Both dynamic fields were quoted by PostgreSQL's %I/%L conversions.
    sqlx::query(sqlx::AssertSqlSafe(statement))
        .execute(&mut **tx)
        .await
        .map_err(control::unavailable)?;
    Ok(())
}
