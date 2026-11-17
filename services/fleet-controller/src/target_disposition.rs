//! Durable Control handoff, separate from activation outcomes. An admission is
//! committed before signing/delivery. This module never clears a bootstrap,
//! resubmits activation or treats a missing ACK as reference clearance.
use hmac::{Hmac, KeyInit, Mac};
use pc_runtime_types::target_disposition::{
    TARGET_DISPOSITION_DELIVERY_PURPOSE, TargetDispositionDelivery, TargetDispositionVerifier,
    encode_target_disposition_delivery,
};
use pc_runtime_types::{Digest, PurposeSigner, canonical_bytes};
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};

#[path = "target_disposition/restore_custody.rs"]
mod restore_custody;
pub use restore_custody::VerifiedRestoreCustody;

#[path = "target_disposition/expired.rs"]
mod expired;

#[path = "target_disposition/activation.rs"]
mod activation;
#[path = "target_disposition/bootstrap.rs"]
mod bootstrap;
#[path = "target_disposition/completion.rs"]
mod completion;
#[path = "target_disposition/fact_custody.rs"]
mod fact_custody;
#[path = "target_disposition/history.rs"]
mod history;
pub use completion::{
    HistoricalActivationCandidate, HistoricalCompletionClaim, VerifiedHistoricalActivation,
};
#[path = "target_disposition/issuance.rs"]
mod issuance;
#[path = "target_disposition/unsigned_recovery.rs"]
mod unsigned_recovery;
pub use history::HistoricalTargetConfirmation;
#[path = "target_disposition/diagnostics.rs"]
mod diagnostics;
#[path = "target_disposition/readback.rs"]
mod readback;
#[path = "target_disposition/restore.rs"]
mod restore;
use fact_custody::DispositionSource;
pub use fact_custody::{OriginalTargetActivation, PreparedRuntimeFacts, TargetFactTrust};

type Result<T> = std::result::Result<T, String>;
pub const TARGET_DISPOSITION_BUSY: &str = "target disposition owner busy";

/// Only closed diagnostic labels cross into service logs. Database messages,
/// signed claims and external transport errors are never returned as inputs.
pub fn withdrawal_failure_diagnostic(error: &str) -> (&'static str, &'static str, &str) {
    let Some(value) = error
        .strip_prefix("target disposition owner unavailable [")
        .and_then(|v| v.strip_suffix(']'))
    else {
        return ("signed_withdrawal", "unavailable", "none");
    };
    let fields: Vec<_> = value.split(':').collect();
    if fields.len() == 3 {
        for stage in [
            "prior_revision",
            "admission",
            "current_head",
            "issuance",
            "delivery",
            "delivery_commit",
        ] {
            for class in [
                "column_decode",
                "decode",
                "row_missing",
                "cause_unavailable",
                "database",
                "transport_or_driver",
            ] {
                if fields[0] == stage
                    && fields[1] == class
                    && (safe_sqlstate(fields[2]) || matches!(fields[2], "other" | "none"))
                {
                    return (stage, class, fields[2]);
                }
            }
        }
    }
    ("signed_withdrawal", "unavailable", "none")
}
fn safe_sqlstate(value: &str) -> bool {
    value.len() == 5
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn unavailable() -> String {
    "target disposition owner unavailable".into()
}
fn database_error(error: sqlx::Error) -> String {
    if matches!(&error, sqlx::Error::Database(db) if db.code().as_deref() == Some("P0001") && db.message() == "PC-DATA-6007")
    {
        TARGET_DISPOSITION_BUSY.into()
    } else {
        unavailable()
    }
}

// Never expose database messages, SQL, bound claims or decoder details. Keep
// contention's existing retry signal exact; all other classes remain failures.
fn withdrawal_database_error(stage: &'static str, error: sqlx::Error) -> String {
    if database_error_class(&error) == "busy" {
        return TARGET_DISPOSITION_BUSY.into();
    }
    let code = match &error {
        sqlx::Error::Database(db) => db
            .code()
            .filter(|code| safe_sqlstate(code))
            .map_or_else(|| "other".to_owned(), |code| code.into_owned()),
        _ => "none".into(),
    };
    format!(
        "{} [{stage}:{}:{code}]",
        unavailable(),
        database_error_class(&error)
    )
}

fn database_error_class(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::ColumnDecode { .. } => "column_decode",
        sqlx::Error::Decode(_) => "decode",
        sqlx::Error::RowNotFound => "row_missing",
        sqlx::Error::Database(db)
            if db.code().as_deref() == Some("P0001") && db.message() == "PC-DATA-6007" =>
        {
            "busy"
        }
        sqlx::Error::Database(db)
            if db.code().as_deref() == Some("P0001")
                && db.message() == "TARGET-DISPOSITION-CAUSE-UNAVAILABLE" =>
        {
            "cause_unavailable"
        }
        sqlx::Error::Database(_) => "database",
        _ => "transport_or_driver",
    }
}

// SQL disposition admission/issuance still accepts bigint ordinals. Decode the
// numeric(20,0) column through its canonical text without widening those bounds.
fn supported_disposition_revision(text: &str) -> Result<u64> {
    let value: u64 = text.parse().map_err(|_| unavailable())?;
    if value.to_string() != text || i64::try_from(value).is_err() {
        return Err(unavailable());
    }
    Ok(value)
}

/// Host-installed native verification bridge. Its private key is a distinct
/// installation secret; SQL workers cannot read it or install a replacement.
pub struct TargetDispositionStore {
    pool: PgPool,
    participant: String,
    privacy: String,
    control_signer: PurposeSigner,
    runtime_control: openpc_runtime_agent::RuntimeWireVerifier,
    commit_key: [u8; 32],
    target_keys: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    runtime_target_keys: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
    source_custody: Option<crate::runtime_artifact_source::RuntimeArtifactSourceWorker>,
    identity_runtime_trust: Option<Vec<u8>>,
    source_diagnostics: std::sync::Mutex<diagnostics::SourceDiagnostics>,
}

/// Original committed bytes. An unsigned pending admission is deliberately not
/// represented as a delivery and remains a denial for target reconciliation.
pub struct PendingTargetDisposition {
    claims: TargetDispositionDelivery,
    first_issue: Option<issuance::FirstIssuePermit>,
    worker: String,
}

/// Authenticated readback is only a reconciliation input. `None` means no
/// disposition has been established, not permission to serve. A present head
/// without signed delivery is a durable pending withdrawal.
pub struct CurrentTargetDisposition {
    pub revision: u64,
    pub admission_digest: Digest,
    pub signed_delivery: Option<Vec<u8>>,
    pub signed_acknowledgement: Option<Vec<u8>>,
}
impl PendingTargetDisposition {
    pub fn claims(&self) -> &TargetDispositionDelivery {
        &self.claims
    }
}

impl TargetDispositionStore {
    pub fn from_host_installation(
        pool: PgPool,
        participant: String,
        privacy: String,
        control_key: [u8; 32],
        commit_key: [u8; 32],
        target_keys: std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<Self> {
        if control_key == commit_key {
            return Err(unavailable());
        }
        let store = Self {
            pool,
            participant,
            privacy,
            control_signer: PurposeSigner::from_secret_bytes(
                TARGET_DISPOSITION_DELIVERY_PURPOSE,
                control_key,
            )
            .map_err(|_| unavailable())?,
            runtime_control: openpc_runtime_agent::RuntimeWireSigner::from_secret_bytes(
                control_key,
            )
            .map_err(|_| unavailable())?
            .verifier(),
            commit_key,
            target_keys: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            runtime_target_keys: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            source_custody: None,
            identity_runtime_trust: None,
            source_diagnostics: std::sync::Mutex::new(diagnostics::SourceDiagnostics::default()),
        };
        for (target, key) in target_keys {
            store.register_host_target_key(&target, &key)?;
        }
        Ok(store)
    }

    pub fn with_source_custody(
        mut self,
        source: crate::runtime_artifact_source::RuntimeArtifactSourceWorker,
    ) -> Self {
        self.source_custody = Some(source);
        self
    }

    /// Native host installation only, used after Fleet registers the actual
    /// target certificate. No RPC accepts this key, and an existing target's
    /// trust cannot be replaced through this method.
    pub fn register_host_target_key(&self, target: &str, key: &[u8]) -> Result<()> {
        if !uuid::Uuid::parse_str(target)
            .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == target)
        {
            return Err(unavailable());
        }
        let key = pc_runtime_types::PurposeVerifier::from_sec1_bytes(
            pc_runtime_types::target_disposition::TARGET_DISPOSITION_ACK_PURPOSE,
            key,
        )
        .map_err(|_| unavailable())?
        .sec1_bytes();
        if key == self.control_signer.verifier().sec1_bytes() {
            return Err(unavailable());
        }
        let mut installed = self.target_keys.lock().map_err(|_| unavailable())?;
        if let Some(prior) = installed.get(target) {
            return if prior == &key {
                Ok(())
            } else {
                Err(unavailable())
            };
        }
        installed.insert(target.into(), key);
        Ok(())
    }

    /// Primary activation receipts use their own runtime-wire key. A
    /// disposition P-256 ACK key is never a substitute for that trust domain.
    pub fn register_host_runtime_target_key(&self, target: &str, key: &[u8]) -> Result<()> {
        if !self
            .target_keys
            .lock()
            .map_err(|_| unavailable())?
            .contains_key(target)
        {
            return Err(unavailable());
        }
        let key = openpc_runtime_agent::RuntimeWireVerifier::from_public_key_bytes(key)
            .map_err(|_| unavailable())?
            .public_key_bytes();
        if key == self.runtime_control.public_key_bytes() {
            return Err(unavailable());
        }
        let mut installed = self.runtime_target_keys.lock().map_err(|_| unavailable())?;
        if let Some(prior) = installed.get(target) {
            return if prior == &key {
                Ok(())
            } else {
                Err(unavailable())
            };
        }
        installed.insert(target.into(), key);
        Ok(())
    }

    async fn context(&self, tx: &mut Transaction<'_, Postgres>) -> Result<()> {
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true)")
            .bind(&self.participant).bind(&self.privacy).execute(&mut **tx).await.map_err(|_| unavailable())?;
        sqlx::query("set local statement_timeout='5s'")
            .execute(&mut **tx)
            .await
            .map_err(|_| unavailable())?;
        Ok(())
    }

    /// Same advisory keys/order as current-source SQL, before any Fact-source
    /// row lock. Each acquisition is fail-fast, including the existing CIGL
    /// fence; no partial acquisition is permission to continue after an error.
    async fn lock_fact_disposition_roots(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        target: &str,
    ) -> Result<()> {
        sqlx::query("select openpc.assert_runtime_target_disposition_owner()")
            .execute(&mut **tx)
            .await
            .map_err(database_error)?;
        let lifecycle: bool = sqlx::query_scalar("select pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0))")
            .fetch_one(&mut **tx).await.map_err(database_error)?;
        if !lifecycle {
            return Err(TARGET_DISPOSITION_BUSY.into());
        }
        sqlx::query("select openpc.lock_cigl_grant_sources(true)")
            .execute(&mut **tx)
            .await
            .map_err(database_error)?;
        // Derive scope from the database's typed request context, exactly as
        // the SQL owner does; alternate textual UUID spellings get no new key.
        for query in [
            "select pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0)) where $1::text::uuid is not null",
            "select pg_try_advisory_xact_lock_shared(hashtextextended('openpc-policy-generations:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0)) where $1::text::uuid is not null",
            "select pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0)) where $1::text::uuid is not null",
            "select pg_try_advisory_xact_lock(hashtextextended('runtime-target-disposition:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text||':'||($1::text::uuid)::text,0))",
        ] {
            let acquired: bool = sqlx::query_scalar(query)
                .bind(target)
                .fetch_one(&mut **tx)
                .await
                .map_err(database_error)?;
            if !acquired {
                return Err(TARGET_DISPOSITION_BUSY.into());
            }
        }
        Ok(())
    }

    pub async fn current(
        &self,
        extensions: &http::Extensions,
        fleet: &crate::FleetController,
    ) -> Result<Option<CurrentTargetDisposition>> {
        let (peer, _) = crate::runtime_tls::authenticated_target(extensions, fleet)
            .map_err(|_| unavailable())?;
        self.current_for_installed_peer(&peer).await
    }

    async fn current_for_installed_peer(
        &self,
        peer: &crate::TargetIdentity,
    ) -> Result<Option<CurrentTargetDisposition>> {
        for attempt in 0..5 {
            let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
            match self.current_for_installed_peer_in(&mut tx, peer).await {
                Ok(current) => {
                    // A failed commit is unknown; never retry it.
                    tx.commit().await.map_err(|_| unavailable())?;
                    return Ok(current);
                }
                Err(error) => {
                    if !retry_current_read_after_rollback(tx, &error, attempt).await? {
                        return Err(error);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10 * 3_u64.pow(attempt)))
                        .await;
                }
            }
        }
        Err(unavailable())
    }

    // Every attempt rechecks current Identity, source custody and the latest
    // disposition head. This transaction neither admits nor signs a delivery.
    async fn current_for_installed_peer_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        peer: &crate::TargetIdentity,
    ) -> Result<Option<CurrentTargetDisposition>> {
        self.context(tx).await?;
        sqlx::query("select openpc.assert_runtime_target_disposition_owner()")
            .execute(&mut **tx)
            .await
            .map_err(|_| unavailable())?;
        // This is a fresh real authority read on every request, including after
        // a target has restored its entire old journal and local revision floor.
        let current_identity = self.bootstrap_identity(tx, peer).await?;
        let row = sqlx::query(r#"select a.revision::text,a.admission_digest,a.binding,a.restoration_proof,a.activation_proof,d.signed_delivery,k.signed_acknowledgement
          from control.runtime_target_disposition_admission a
          left join control.runtime_target_disposition_delivery d on d.participant_id=a.participant_id
           and d.privacy_domain_id=a.privacy_domain_id and d.runtime_target_id=a.runtime_target_id and d.revision=a.revision
          left join control.runtime_target_disposition_acknowledgement k on k.participant_id=d.participant_id
           and k.privacy_domain_id=d.privacy_domain_id and k.runtime_target_id=d.runtime_target_id and k.delivery_digest=d.delivery_digest
          where a.participant_id=openpc.current_participant_id() and a.privacy_domain_id=openpc.current_privacy_domain_id()
           and a.runtime_target_id=$1::text::uuid order by a.revision desc limit 1"#)
            .bind(&peer.target_id).fetch_optional(&mut **tx).await.map_err(|_| unavailable())?;
        if let Some(row) = &row {
            let binding: serde_json::Value = row.try_get("binding").map_err(|_| unavailable())?;
            let action = binding.get("action").and_then(|v| v.as_str());
            if matches!(action, Some("Restore" | "ConfirmActivation")) {
                let proof: Option<serde_json::Value> = row
                    .try_get(if action == Some("Restore") {
                        "restoration_proof"
                    } else {
                        "activation_proof"
                    })
                    .map_err(|_| unavailable())?;
                self.lock_current_sources(
                    tx,
                    &peer.target_id,
                    binding.get("source").ok_or_else(unavailable)?,
                    &proof.ok_or_else(unavailable)?,
                    if action == Some("Restore") {
                        "RESTORE"
                    } else {
                        "CONFIRM"
                    },
                )
                .await?;
                // Source locks precede the target head fence. Re-read after
                // acquiring it; an intervening withdrawal always wins.
                let latest: String = sqlx::query_scalar("select admission_digest from control.runtime_target_disposition_admission where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id() and runtime_target_id=$1::text::uuid order by revision desc limit 1")
                    .bind(&peer.target_id).fetch_one(&mut **tx).await.map_err(|_| unavailable())?;
                if latest
                    != row
                        .try_get::<String, _>("admission_digest")
                        .map_err(|_| unavailable())?
                {
                    return Err(unavailable());
                }
            }
        }
        let mut historical_unsigned = false;
        if let Some(row) = &row {
            let binding: serde_json::Value = row.try_get("binding").map_err(|_| unavailable())?;
            let identity: pc_runtime_types::target_disposition::TargetDispositionIdentity =
                serde_json::from_value(binding.get("target").cloned().ok_or_else(unavailable)?)
                    .map_err(|_| unavailable())?;
            if identity != current_identity {
                let delivery: Option<Vec<u8>> =
                    row.try_get("signed_delivery").map_err(|_| unavailable())?;
                let acknowledgement: Option<Vec<u8>> = row
                    .try_get("signed_acknowledgement")
                    .map_err(|_| unavailable())?;
                if binding.get("action").and_then(|v| v.as_str()) != Some("Withdraw")
                    || delivery.is_some()
                    || acknowledgement.is_some()
                {
                    return Err(unavailable());
                }
                let (transition, _) = self.expired_credential_binding_in(tx, peer).await?;
                if transition.target != current_identity
                    || transition.credential_predecessor.as_ref() != Some(&identity)
                    || serde_json::to_value(&transition.source).map_err(|_| unavailable())?
                        != binding["source"]
                {
                    return Err(unavailable());
                }
                historical_unsigned = true;
            }
        }
        let result = row
            .map(|row| -> Result<CurrentTargetDisposition> {
                let binding: serde_json::Value =
                    row.try_get("binding").map_err(|_| unavailable())?;
                let identity: pc_runtime_types::target_disposition::TargetDispositionIdentity =
                    serde_json::from_value(binding.get("target").cloned().ok_or_else(unavailable)?)
                        .map_err(|_| unavailable())?;
                // A retained signature under withdrawn/reassigned credentials
                // is historical custody, never a current serving instruction.
                if identity != current_identity && !historical_unsigned {
                    return Err(unavailable());
                }
                let revision: String = row.try_get("revision").map_err(|_| unavailable())?;
                let digest: String = row.try_get("admission_digest").map_err(|_| unavailable())?;
                Ok(CurrentTargetDisposition {
                    revision: revision.parse().map_err(|_| unavailable())?,
                    admission_digest: Digest::parse(
                        digest.strip_prefix("sha256:").ok_or_else(unavailable)?,
                    )
                    .map_err(|_| unavailable())?,
                    signed_delivery: row.try_get("signed_delivery").map_err(|_| unavailable())?,
                    signed_acknowledgement: row
                        .try_get("signed_acknowledgement")
                        .map_err(|_| unavailable())?,
                })
            })
            .transpose()?;
        Ok(result)
    }

    /// Native publisher only. The host supplies its installed target identity;
    /// SQL independently admits the actual live leased successor and constructs
    /// every source/cause claim. This never marks activation STARTED.
    pub async fn publish_activation_withdrawal(
        &self,
        peer: &crate::TargetIdentity,
        cause_work: &str,
        worker: &str,
    ) -> Result<bool> {
        self.publish_withdrawal(peer, cause_work, worker, false)
            .await
    }

    /// Denial-only owner for an approved Platform replacement. The database
    /// resolves its immutable target cohort; this cannot replay activation.
    pub async fn publish_platform_scope_withdrawal(
        &self,
        peer: &crate::TargetIdentity,
        replacement: &str,
        worker: &str,
    ) -> Result<bool> {
        self.publish_withdrawal(peer, replacement, worker, true)
            .await
    }

    async fn publish_withdrawal(
        &self,
        peer: &crate::TargetIdentity,
        cause_id: &str,
        worker: &str,
        platform: bool,
    ) -> Result<bool> {
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        self.context(&mut tx).await?;
        let previous: String = sqlx::query_scalar(r#"select coalesce((select case
          when binding->>'action'='Withdraw' and ((not $3 and binding->'cause'->>'kind' in ('Activation','UnsignedWithdrawalRecovery')
           and binding->'cause'->>'work_id'=$2) or ($3 and binding->'cause'->>'kind'='Dependency'
           and binding->'cause'->>'owner'='Platform' and binding->'cause'->>'resource_id'=$2)) then revision-1 else revision end
          from control.runtime_target_disposition_admission
          where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id()
           and runtime_target_id=$1::text::uuid order by revision desc limit 1),0)::text"#)
            .bind(&peer.target_id).bind(cause_id).bind(platform).fetch_one(&mut *tx).await.map_err(|_| unavailable())?;
        tx.commit().await.map_err(|_| unavailable())?;
        let pending = self
            .begin_withdrawal(
                &peer.target_id,
                cause_id,
                worker,
                &peer.certificate_fingerprint,
                supported_disposition_revision(&previous)?,
                platform,
            )
            .await?;
        if pending.first_issue.is_some() {
            // The committed NEW admission already supplies these claims. The
            // signing transaction independently rechecks current head, Identity
            // and sources; an extra current-read must not drop this permit.
            self.sign_committed_withdrawal(pending).await?;
            return Ok(false);
        }
        let current = self
            .current_for_installed_peer(peer)
            .await
            .inspect_err(|error| withdrawal_stage_failure("current_head", &pending.claims, error))?
            .ok_or_else(unavailable)?;
        if current.revision != pending.claims.revision
            || current.admission_digest != pending.claims.committed_admission_digest
        {
            return Err(unavailable());
        }
        let claims = pending.claims.clone();
        // Read the original committed delivery after a lost result. Never
        // replace it with another signature or infer ACK from local bootstrap.
        let delivery = match current.signed_delivery {
            Some(bytes) => bytes,
            None => self.sign_committed_withdrawal(pending).await?,
        };
        let target_key = self
            .target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(&peer.target_id)
            .cloned()
            .ok_or_else(unavailable)?;
        let verifier = TargetDispositionVerifier::from_host_keys(
            claims.target.clone(),
            &self.control_signer.verifier().sec1_bytes(),
            &target_key,
        )
        .map_err(|_| unavailable())?;
        let verified = verifier
            .verify_delivery(&delivery, &claims.source)
            .map_err(|_| unavailable())?;
        if verified.claims() != &claims {
            return Err(unavailable());
        }
        match current.signed_acknowledgement {
            None => Ok(false),
            Some(bytes) => {
                verifier
                    .verify_acknowledgement(&bytes, &verified)
                    .map_err(|_| unavailable())?;
                Ok(true)
            }
        }
    }

    /// The SQL owner resolves original input/module/capsule/work custody and
    /// current target credentials; these arguments are selectors, never claims.
    pub async fn begin_activation_withdrawal(
        &self,
        target: &str,
        cause_work: &str,
        worker: &str,
        certificate: &Digest,
        previous_revision: u64,
    ) -> Result<PendingTargetDisposition> {
        self.begin_withdrawal(
            target,
            cause_work,
            worker,
            certificate,
            previous_revision,
            false,
        )
        .await
    }

    async fn begin_withdrawal(
        &self,
        target: &str,
        cause_id: &str,
        worker: &str,
        certificate: &Digest,
        previous_revision: u64,
        platform: bool,
    ) -> Result<PendingTargetDisposition> {
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        self.context(&mut tx).await?;
        // The same authoritative target fence serializes the prior read and
        // INSERT. An unlocked absence check cannot establish first issuance.
        self.lock_fact_disposition_roots(&mut tx, target).await?;
        if !platform {
            self.verify_unsigned_recovery(&mut tx, target).await?;
        }
        let prior_revision: Option<String> = sqlx::query_scalar("select a.revision::text from control.runtime_target_disposition_admission a where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id() and runtime_target_id=$1::text::uuid order by a.revision desc limit 1")
            .bind(target).fetch_optional(&mut *tx).await.map_err(|error| withdrawal_database_error("prior_revision", error))?;
        let prior_revision = prior_revision
            .as_deref()
            .map(supported_disposition_revision)
            .transpose()?;
        let admission = if platform {
            "select binding,admission_digest from openpc.begin_platform_scope_target_withdrawal($1::text::uuid,$2::text::uuid,$3,$4,$5)"
        } else {
            "select binding,admission_digest from openpc.begin_runtime_target_withdrawal($1::text::uuid,$2::text::uuid,$3,$4,$5)"
        };
        let row = sqlx::query(admission)
            .bind(target)
            .bind(cause_id)
            .bind(worker)
            .bind(format!("sha256:{}", certificate.as_str()))
            .bind(i64::try_from(previous_revision).map_err(|_| unavailable())?)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| withdrawal_database_error("admission", error))?;
        let mut binding: serde_json::Value = row.try_get("binding").map_err(|_| unavailable())?;
        let admission_digest: String =
            row.try_get("admission_digest").map_err(|_| unavailable())?;
        let digest = Digest::parse(
            admission_digest
                .strip_prefix("sha256:")
                .ok_or_else(unavailable)?,
        )
        .map_err(|_| unavailable())?;
        if Digest::of(canonical_bytes(&binding).map_err(|_| unavailable())?) != digest {
            return Err(unavailable());
        }
        binding.as_object_mut().ok_or_else(unavailable)?.insert(
            "committed_admission_digest".into(),
            serde_json::to_value(&digest).map_err(|_| unavailable())?,
        );
        let claims: TargetDispositionDelivery =
            serde_json::from_value(binding).map_err(|_| unavailable())?;
        claims.validate().map_err(|_| unavailable())?;
        if claims.target.participant_id != self.participant
            || claims.target.privacy_domain_id != self.privacy
            || claims.target.target_id != target
            || claims.target.certificate_digest != *certificate
        {
            return Err(unavailable());
        }
        i64::try_from(claims.revision).map_err(|_| unavailable())?;
        let newly_inserted = claims.revision
            == prior_revision
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(unavailable)?;
        let first_issue = if newly_inserted {
            Some(issuance::FirstIssuePermit::commit_new(tx, None, claims.clone()).await?)
        } else {
            // Existing unsigned admission is UNKNOWN, never a reconstructed
            // capability, even if a former process died before signing.
            tx.commit().await.map_err(|_| unavailable())?;
            None
        };
        eprintln!(
            "{}",
            serde_json::json!({"level":"info","event":"target_withdrawal_admission_readback",
            "target_id":target,"work_id":cause_id,"revision":claims.revision,"first_issue":first_issue.is_some()})
        );
        Ok(PendingTargetDisposition {
            claims,
            first_issue,
            worker: worker.into(),
        })
    }

    pub async fn sign_committed_withdrawal(
        &self,
        pending: PendingTargetDisposition,
    ) -> Result<Vec<u8>> {
        if pending.claims.target.participant_id != self.participant
            || pending.claims.target.privacy_domain_id != self.privacy
        {
            return Err(unavailable());
        }
        let permit = pending.first_issue.ok_or_else(|| {
            withdrawal_stage_failure("first_issue_absent", &pending.claims, &unavailable());
            unavailable()
        })?;
        let wait_ms = match std::env::var("OPENPC_TARGET_WITHDRAWAL_PRE_SIGN_RETRY_MS") {
            Ok(value) => value
                .parse::<u64>()
                .ok()
                .filter(|value| *value <= 15_000)
                .ok_or_else(unavailable)?,
            Err(std::env::VarError::NotPresent) => 1000,
            Err(_) => return Err(unavailable()),
        };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
        let mut tx = loop {
            let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
            let ready = async {
                self.context(&mut tx).await?;
                self.lock_fact_disposition_roots(&mut tx, &pending.claims.target.target_id)
                    .await?;
                self.lock_issuance(&mut tx, &pending.claims, Some(&pending.worker))
                    .await
            }
            .await;
            match ready {
                Ok(()) => break tx,
                Err(error)
                    if error == TARGET_DISPOSITION_BUSY
                        && tokio::time::Instant::now() < deadline =>
                {
                    tx.rollback().await.map_err(|_| unavailable())?;
                    // Retain this very permit through definitely pre-sign
                    // contention. Never reconstruct one or retry a commit/sign.
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                Err(error) => {
                    withdrawal_stage_failure("issuance", &pending.claims, &error);
                    return Err(error);
                }
            }
        };
        // Expired-effect denial has its own short operator authority. Check
        // it after all source locks and immediately before consuming NEW.
        let operator= pending.claims.action==pc_runtime_types::target_disposition::TargetDispositionAction::Withdraw
            && (matches!(&pending.claims.cause,pc_runtime_types::target_disposition::TargetDispositionCause::ExpiredObservedDenialHandover {..}
                |pc_runtime_types::target_disposition::TargetDispositionCause::ExpiredObservedCredentialDenialHandover {..})
                || matches!(&pending.claims.cause,pc_runtime_types::target_disposition::TargetDispositionCause::Activation {
                    work_id,execution_attempt_id:Some(_),..} if work_id==&pending.claims.source.original_work_id));
        let window: Result<()> = async {
            if !operator {
                return Ok(());
            }
            let valid: bool = sqlx::query_scalar(
                "select openpc.expired_operator_issuance_window_matches($1::text::uuid,$2,$3,$4)",
            )
            .bind(&pending.claims.target.target_id)
            .bind(i64::try_from(pending.claims.revision).map_err(|_| unavailable())?)
            .bind(format!(
                "sha256:{}",
                pending.claims.committed_admission_digest.as_str()
            ))
            .bind(&pending.worker)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| unavailable())?;
            if !valid {
                return Err(unavailable());
            }
            Ok(())
        }
        .await;
        if let Err(error) = window {
            if tx.rollback().await.is_err() {
                return Err(format!("{error}; denial signing rollback unconfirmed"));
            }
            return Err(error);
        }
        let bytes = permit
            .sign(&self.control_signer)
            .inspect_err(|error| withdrawal_stage_failure("signer", &pending.claims, error))?;
        self.commit_in_transaction(&mut tx, "DELIVERY", &bytes)
            .await
            .inspect_err(|error| withdrawal_stage_failure("delivery", &pending.claims, error))?;
        tx.commit().await.map_err(|error| {
            let diagnostic = withdrawal_database_error("delivery_commit", error);
            withdrawal_stage_failure("delivery_commit", &pending.claims, &diagnostic);
            diagnostic
        })?;
        Ok(bytes)
    }

    /// Actual TLS authentication and host-installed trust precede verification.
    /// Delivery/source come from durable Control custody, never the request.
    pub async fn acknowledge(
        &self,
        extensions: &http::Extensions,
        fleet: &crate::FleetController,
        delivery_digest: &Digest,
        acknowledgement: &[u8],
    ) -> Result<bool> {
        let (peer, _) = crate::runtime_tls::authenticated_target(extensions, fleet)
            .map_err(|_| unavailable())?;
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        self.context(&mut tx).await?;
        sqlx::query("select openpc.assert_runtime_target_disposition_owner()")
            .execute(&mut *tx)
            .await
            .map_err(|_| unavailable())?;
        let row = sqlx::query("select claims,signed_delivery from control.runtime_target_disposition_delivery where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id() and runtime_target_id=$1::text::uuid and delivery_digest=$2")
            .bind(&peer.target_id).bind(format!("sha256:{}",delivery_digest.as_str()))
            .fetch_one(&mut *tx).await.map_err(|_| unavailable())?;
        let claims: TargetDispositionDelivery =
            serde_json::from_value(row.try_get("claims").map_err(|_| unavailable())?)
                .map_err(|_| unavailable())?;
        let delivery: Vec<u8> = row.try_get("signed_delivery").map_err(|_| unavailable())?;
        if claims.target.participant_id != self.participant
            || claims.target.privacy_domain_id != self.privacy
            || claims.target.target_id != peer.target_id
            || claims.target.certificate_digest != peer.certificate_fingerprint
            || Digest::of(&delivery) != *delivery_digest
        {
            return Err(unavailable());
        }
        let target_key = self
            .target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(&peer.target_id)
            .cloned()
            .ok_or_else(unavailable)?;
        let verifier = TargetDispositionVerifier::from_host_keys(
            claims.target.clone(),
            &self.control_signer.verifier().sec1_bytes(),
            &target_key,
        )
        .map_err(|_| unavailable())?;
        let verified = verifier
            .verify_delivery(&delivery, &claims.source)
            .map_err(|_| unavailable())?;
        verifier
            .verify_acknowledgement(acknowledgement, &verified)
            .map_err(|_| unavailable())?;
        tx.rollback().await.map_err(|_| unavailable())?;
        self.commit("ACK", acknowledgement).await
    }

    async fn commit(&self, kind: &str, wire: &[u8]) -> Result<bool> {
        let mut tx = self.pool.begin().await.map_err(|_| unavailable())?;
        self.context(&mut tx).await?;
        let changed = self.commit_in_transaction(&mut tx, kind, wire).await?;
        tx.commit().await.map_err(|_| unavailable())?;
        Ok(changed)
    }

    async fn commit_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        kind: &str,
        wire: &[u8],
    ) -> Result<bool> {
        let mut nonce = [0u8; 32];
        nonce[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        nonce[16..].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
        let mac = bridge_mac(&self.commit_key, kind, wire, &nonce)?;
        sqlx::query_scalar("select openpc.commit_runtime_target_disposition($1,$2,$3,$4)")
            .bind(kind)
            .bind(wire)
            .bind(nonce.as_slice())
            .bind(mac)
            .fetch_one(&mut **tx)
            .await
            .map_err(database_error)
    }
}

fn withdrawal_stage_failure(stage: &'static str, claims: &TargetDispositionDelivery, error: &str) {
    let (_, class, sqlstate) = withdrawal_failure_diagnostic(error);
    eprintln!(
        "{}",
        serde_json::json!({"level":"warn","event":"target_withdrawal_failed",
        "stage":stage,"target_id":claims.target.target_id,"revision":claims.revision,
        "error_class":class,"sqlstate":sqlstate,"retry_disposition":"PRESERVE_ORIGINAL_ADMISSION"})
    );
}

fn bridge_mac(key: &[u8; 32], kind: &str, wire: &[u8], nonce: &[u8; 32]) -> Result<Vec<u8>> {
    let domain: &[u8] = match kind {
        "DELIVERY" => b"OPENPC_TARGET_DISPOSITION_DELIVERY_V1",
        "ACK" => b"OPENPC_TARGET_DISPOSITION_ACK_V1",
        _ => return Err(unavailable()),
    };
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| unavailable())?;
    mac.update(domain);
    mac.update(&Sha256::digest(wire));
    mac.update(nonce);
    Ok(mac.finalize().into_bytes().to_vec())
}

async fn retry_current_read_after_rollback(
    tx: Transaction<'_, Postgres>,
    error: &str,
    attempt: u32,
) -> Result<bool> {
    tx.rollback().await.map_err(|_| unavailable())?;
    Ok(error == TARGET_DISPOSITION_BUSY && attempt < 4)
}

#[cfg(test)]
#[path = "target_disposition/current_read_tests.rs"]
mod current_read_tests;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn withdrawal_log_labels_exclude_unknown_and_secret_inputs() {
        assert_eq!(
            withdrawal_failure_diagnostic(
                "target disposition owner unavailable [issuance:database:42501]"
            ),
            ("issuance", "database", "42501")
        );
        assert_eq!(
            withdrawal_failure_diagnostic(
                "target disposition owner unavailable [admission:database:42501]"
            ),
            ("admission", "database", "42501")
        );
        for input in [
            "secret driver details",
            "target disposition owner unavailable [secret:database:42501]",
            "target disposition owner unavailable [admission:secret:42501]",
            "target disposition owner unavailable [admission:database:secret signed bytes]",
        ] {
            assert_eq!(
                withdrawal_failure_diagnostic(input),
                ("signed_withdrawal", "unavailable", "none")
            );
        }
    }
    #[test]
    fn disposition_numeric_revision_preserves_canonical_bigint_bounds() {
        for value in [0, 1, i64::MAX as u64] {
            assert_eq!(
                supported_disposition_revision(&value.to_string()).unwrap(),
                value
            );
        }
        for value in [
            "-1",
            "+1",
            "01",
            "1.0",
            " 1",
            "",
            "9223372036854775808",
            "18446744073709551615",
            "100000000000000000000",
        ] {
            assert!(supported_disposition_revision(value).is_err());
        }
    }

    #[test]
    fn withdrawal_decode_diagnostics_do_not_expose_driver_details() {
        let error = sqlx::Error::ColumnDecode {
            index: "private column or bound claim".into(),
            source: std::io::Error::other("secret driver diagnostic").into(),
        };
        assert_eq!(
            withdrawal_database_error("prior_revision", error),
            "target disposition owner unavailable [prior_revision:column_decode:none]"
        );
    }

    #[tokio::test]
    async fn host_registration_cannot_replace_target_trust_or_reuse_control_keys() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1:1/unavailable")
            .unwrap();
        let make = |commit| {
            TargetDispositionStore::from_host_installation(
                pool.clone(),
                "018f0000-0000-7000-8000-000000000101".into(),
                "018f0000-0000-7000-8000-000000007201".into(),
                [31; 32],
                commit,
                std::collections::BTreeMap::new(),
            )
        };
        assert!(make([31; 32]).is_err());
        let store = make([32; 32]).unwrap();
        let target = "018f0000-0000-7000-8000-000000000102";
        let key = PurposeSigner::from_secret_bytes(
            pc_runtime_types::target_disposition::TARGET_DISPOSITION_ACK_PURPOSE,
            [33; 32],
        )
        .unwrap()
        .verifier()
        .sec1_bytes();
        store.register_host_target_key(target, &key).unwrap();
        store.register_host_target_key(target, &key).unwrap();
        assert!(
            store
                .register_host_target_key(target, &store.control_signer.verifier().sec1_bytes())
                .is_err()
        );
        let other = PurposeSigner::from_secret_bytes(
            pc_runtime_types::target_disposition::TARGET_DISPOSITION_ACK_PURPOSE,
            [34; 32],
        )
        .unwrap()
        .verifier()
        .sec1_bytes();
        assert!(store.register_host_target_key(target, &other).is_err());
        assert!(
            store
                .register_host_target_key("unknown-target", &key)
                .is_err()
        );
        assert_eq!(store.target_keys.lock().unwrap().get(target), Some(&key));
        assert!(
            store
                .register_host_runtime_target_key(target, &key)
                .is_err()
        );
        assert!(
            store
                .register_host_runtime_target_key(target, &store.runtime_control.public_key_bytes())
                .is_err()
        );
        let runtime_key = openpc_runtime_agent::RuntimeWireSigner::from_secret_bytes([33; 32])
            .unwrap()
            .verifier()
            .public_key_bytes();
        store
            .register_host_runtime_target_key(target, &runtime_key)
            .unwrap();
        store
            .register_host_runtime_target_key(target, &runtime_key)
            .unwrap();
        assert!(
            store
                .register_host_runtime_target_key(target, &[42; 32])
                .is_err()
        );
        assert!(
            store
                .register_host_runtime_target_key("unknown-target", &runtime_key)
                .is_err()
        );
    }
    #[test]
    fn native_commit_capabilities_bind_operation_bytes_and_nonce() {
        let delivery = bridge_mac(&[32; 32], "DELIVERY", b"original", &[1; 32]).unwrap();
        assert_ne!(
            delivery,
            bridge_mac(&[32; 32], "ACK", b"original", &[1; 32]).unwrap()
        );
        assert_ne!(
            delivery,
            bridge_mac(&[32; 32], "DELIVERY", b"changed", &[1; 32]).unwrap()
        );
        assert_ne!(
            delivery,
            bridge_mac(&[32; 32], "DELIVERY", b"original", &[2; 32]).unwrap()
        );
        assert!(bridge_mac(&[32; 32], "RESTORE", b"original", &[1; 32]).is_err());
    }
}
