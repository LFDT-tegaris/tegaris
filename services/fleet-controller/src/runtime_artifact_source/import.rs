//! Bind the actual SQL INSERT to its independently retained pending original.
//! This admission is purpose-separated from source denial and grants no use.
use super::*;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use sqlx::{Postgres, Transaction};

impl RuntimeArtifactSourceWorker {
    pub(crate) async fn bind_import(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        input: ImportIdentity,
        fresh: bool,
    ) -> SourceCustodyResult<()> {
        self.lock_consumer_scope(tx).await?;
        let Some(custody) = &self.custody else {
            return Self::require_uninstalled_in(tx, &self.participant, &self.privacy).await;
        };
        let mut custody = custody.lock().await;
        custody.verify_installed_root(tx).await?;
        if fresh {
            custody.record_observation(history::Observation::ImportPending(input.clone()))?;
        }
        let state = custody.checked_state()?;
        let Some(root) = &custody.retained_root else {
            return Ok(()); // Legacy history remains unproven.
        };
        let pending = state
            .history
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?
            .import_original(&custody.history_signer, &input)?;
        let pending: serde_json::Value =
            serde_json::from_slice(&pending).map_err(|_| RuntimeError::InvalidInput)?;
        let wire =
            canonical_bytes(&serde_json::json!({"pending":pending,"root":root.original(state)?}))?;
        if wire.len() > 8192 {
            return Err(RuntimeError::EvidenceCapacity.into());
        }
        let transaction: String = sqlx::query_scalar("select pg_current_xact_id()::text")
            .fetch_one(&mut **tx)
            .await
            .map_err(control::unavailable)?;
        let nonce = control::nonce()?;
        let key = self
            .commit_key
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(control::unavailable)?;
        mac.update(b"OPENPC_RUNTIME_ARTIFACT_SOURCE_IMPORT_V1");
        mac.update(transaction.as_bytes());
        mac.update(Digest::of(&wire).as_str().as_bytes());
        mac.update(&nonce);
        sqlx::query("select set_config('openpc.runtime_source_import_wire',encode($1,'hex'),true),set_config('openpc.runtime_source_import_nonce',encode($2,'hex'),true),set_config('openpc.runtime_source_import_mac',encode($3,'hex'),true)")
            .bind(wire).bind(nonce.to_vec()).bind(mac.finalize().into_bytes().to_vec())
            .execute(&mut **tx).await.map_err(control::unavailable)?;
        Ok(())
    }
}
