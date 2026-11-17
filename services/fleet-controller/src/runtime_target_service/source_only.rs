//! Source-only custody observes the real protected transport, while ordinary
//! invocation remains denied. Source dispatch has its own authorization owner.
use super::*;
use crate::runtime_target::{TargetBootstrapManifest, build_governed_source_owners};
use openpc_runtime_agent::{
    ext_proc::{EnvoyGeneration, ProtectedRequest},
    ext_proc_server::serve_ext_proc,
    fact_lease::FactLease,
    identity_custody::IdentityArtifactAdmission,
    indexer_custody::{IndexerArtifactAdmission, InstalledIndexerPolicies},
};

mod dispatch;
mod dispatch_read;

#[derive(Clone)]
struct SourceTransportOwner {
    agent: Arc<RuntimeAgent>,
    policies: SourcePolicyOwner,
    classes: Digest,
    privacy: String,
    evidence: Arc<FileEvidence>,
    decisions: Arc<DecisionEvidenceStore>,
    identity: Arc<IdentityArtifactAdmission>,
    control: Option<sqlx::PgPool>,
    providers: PathBuf,
}

#[derive(Clone)]
enum SourcePolicyOwner {
    SourceOnly(Arc<IndexerArtifactAdmission>),
    Mixed(Arc<TargetState>),
}

impl SourcePolicyOwner {
    fn acquire(
        &self,
        active: &openpc_runtime_agent::ActiveCapsuleLease<'_>,
        peer: &WorkloadPeer,
    ) -> RuntimeResult<(InstalledIndexerPolicies, Option<FactLease>)> {
        match self {
            Self::SourceOnly(owner) => {
                let (policies, _) = owner.admit_policies(active.capsule(), active.artifacts()?)?;
                Ok((policies, None))
            }
            Self::Mixed(owner) => {
                let (policies, facts) = owner.acquire_source_policies(active, peer, 1_000)?;
                Ok((policies, Some(facts)))
            }
        }
    }
}

/// Selection never grants authority. An assertion-bearing request stays with
/// invocation, including malformed/empty/duplicate assertions and denials.
struct MixedTransportOwner {
    invocation: Arc<dyn ExtProcRequestOwner>,
    source: Arc<dyn ExtProcRequestOwner>,
}

impl MixedTransportOwner {
    fn select(&self, headers: &[(String, Vec<u8>)]) -> &dyn ExtProcRequestOwner {
        if headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-openpc-identity-assertion"))
        {
            self.invocation.as_ref()
        } else {
            self.source.as_ref()
        }
    }
}

impl ExtProcRequestOwner for MixedTransportOwner {
    fn prepare_begin<'a>(
        &'a self,
        peer: &'a WorkloadPeer,
        generation: &'a EnvoyGeneration,
        headers: &'a [(String, Vec<u8>)],
        trace: &'a RequestTraceId,
    ) -> openpc_runtime_agent::ext_proc::RequestBeginFuture<'a> {
        self.select(headers)
            .prepare_begin(peer, generation, headers, trace)
    }

    fn begin(
        &self,
        peer: &WorkloadPeer,
        generation: &EnvoyGeneration,
        headers: &[(String, Vec<u8>)],
        trace: &RequestTraceId,
    ) -> RuntimeResult<Box<dyn ProtectedRequest>> {
        self.select(headers).begin(peer, generation, headers, trace)
    }

    fn record_transport_denial(
        &self,
        error: &RuntimeError,
        trace: &RequestTraceId,
    ) -> RuntimeResult<()> {
        self.invocation.record_transport_denial(error, trace)
    }
}

pub(super) async fn mixed_owner(
    config: &TargetConfig,
    manifest: &TargetBootstrapManifest,
    agent: Arc<RuntimeAgent>,
    state: Arc<TargetState>,
    identity: Arc<IdentityArtifactAdmission>,
    evidence: Arc<FileEvidence>,
    invocation: Arc<dyn ExtProcRequestOwner>,
) -> TargetResult<Arc<dyn ExtProcRequestOwner>> {
    let directory = config
        .runtime_root
        .join("evidence")
        .join(&config.target_id)
        .join("source-reads");
    let decisions = Arc::new(
        open_decision_evidence(config, manifest, &directory, "source")
            .map_err(|_| "mixed source decision evidence unavailable")?,
    );
    Ok(Arc::new(MixedTransportOwner {
        invocation,
        source: Arc::new(SourceTransportOwner {
            agent,
            policies: SourcePolicyOwner::Mixed(state),
            classes: manifest.protected_class_set_digest.clone(),
            privacy: manifest.privacy_domain_id.clone(),
            evidence,
            decisions,
            identity,
            control: dispatch::control_reader().await?,
            providers: config.provider_directory.clone(),
        }),
    }))
}

impl ExtProcRequestOwner for SourceTransportOwner {
    fn begin(
        &self,
        peer: &WorkloadPeer,
        generation: &EnvoyGeneration,
        _headers: &[(String, Vec<u8>)],
        trace: &RequestTraceId,
    ) -> RuntimeResult<Box<dyn ProtectedRequest>> {
        Ok(Box::new(dispatch::SourceRequest::new(
            self.clone(),
            peer,
            generation,
            trace,
        )))
    }
    fn record_transport_denial(
        &self,
        error: &RuntimeError,
        trace: &RequestTraceId,
    ) -> RuntimeResult<()> {
        self.evidence
            .record("source-only-invocation-denial", error, Some(trace.as_str()))
    }
}

pub(super) async fn run(
    config: TargetConfig,
    manifest: TargetBootstrapManifest,
    bootstrap_public: Vec<u8>,
    agent: Arc<RuntimeAgent>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> TargetResult<lifecycle::Exit> {
    if !manifest.source_only
        || !manifest.routing_source.is_empty()
        || !manifest.certification_source.is_empty()
    {
        return Err("source-only bootstrap contains invocation routes".into());
    }
    let owners = build_governed_source_owners(
        GovernedOwnerTrust {
            participant_id: &manifest.participant_id,
            privacy_domain_id: &manifest.privacy_domain_id,
            target_runtime_id: &manifest.target_runtime_id,
            authority_signer_id: &manifest.authority_signer_id,
            authority_public_key: &manifest.fleet_runtime_public_key,
            identity_runtime_public_key: &manifest.identity_runtime_public_key,
            identity_profile_digest: manifest.identity_profile_digest.clone(),
            fact_verify_key: &manifest.fact_verify_key,
            fact_verify_key_id: &manifest.fact_verify_key_id,
            mrpc_runtime_profile: &[],
        },
        passthrough_admission,
    )?;
    agent
        .with_active_capsule(|capsule, artifacts| {
            owners.indexer.admit_policies(capsule, artifacts)?;
            owners.identity.admit_identity(capsule, artifacts)?;
            Ok(())
        })
        .map_err(|_| "active source custody rejected")?;
    let evidence_directory = config.runtime_root.join("evidence").join(&config.target_id);
    secure_directory(&evidence_directory, "source evidence directory unavailable")?;

    let pds = Arc::new(
        PolicyDecisionService::with_identity_trust(
            read_key(&config.pds_key_file)?,
            5_000,
            IdentityAssertionVerifier::new(
                std::slice::from_ref(&manifest.identity_runtime_public_key),
                60_000,
            )
            .map_err(|_| "source PDS identity trust rejected")?,
        )
        .map_err(|_| "source PDS rejected")?,
    );
    let control = dispatch::control_reader().await?;
    let decisions = Arc::new(
        open_decision_evidence(
            &config,
            &manifest,
            &evidence_directory.join("source-reads"),
            "source",
        )
        .map_err(|_| "source decision evidence unavailable")?,
    );
    let evidence = Arc::new(FileEvidence {
        agent: agent.clone(),
        decisions: decisions.clone(),
    });
    let service = ExtProcService::new(
        pds,
        Arc::new(SourceTransportOwner {
            agent: agent.clone(),
            policies: SourcePolicyOwner::SourceOnly(owners.indexer),
            classes: manifest.protected_class_set_digest.clone(),
            privacy: manifest.privacy_domain_id.clone(),
            evidence,
            decisions,
            identity: owners.identity,
            control,
            providers: config.provider_directory.clone(),
        }),
        ExtProcLimits {
            headers: 128,
            header_bytes: 64 * 1024,
            body_bytes: 131_072,
        },
    )
    .map_err(|_| "source transport owner rejected")?;
    let parent = config
        .pds_socket
        .parent()
        .ok_or("source socket parent rejected")?;
    let policy = socket_policy(parent, config.envoy_uid, "source socket directory rejected")?;
    if let Err(exit) = lifecycle::reconcile(
        &agent,
        &manifest,
        agent.reconcile_target_disposition(),
        &mut stop,
    )
    .await
    {
        return Ok(exit);
    }
    if refresh_target_restrictions(
        &agent,
        &manifest,
        &config.bootstrap_directory,
        &bootstrap_public,
        wall_clock_ns().map_err(|_| "source clock unavailable")?,
    )
    .is_err()
    {
        return Ok(lifecycle::Exit::BootstrapChanged);
    }
    let listener = OwnedUnixListener::bind(&config.pds_socket, policy)
        .await
        .map_err(|_| "source socket rejected")?;
    let (server_stop, mut stopped) = tokio::sync::watch::channel(false);
    // JoinSet also aborts the owned server if the surrounding session is dropped.
    let mut servers = tokio::task::JoinSet::new();
    servers.spawn(serve_ext_proc(service, listener, async move {
        while !*stopped.borrow() && stopped.changed().await.is_ok() {}
    }));
    let result = tokio::select! {
        result = servers.join_next() => {
            match result {
                Some(Ok(Ok(()))) => Err("source listener stopped without reconciliation".into()),
                _ => Err("source server stopped".into()),
            }
        },
        result = lifecycle::watch_current(&agent, &manifest, &config.bootstrap_directory, &bootstrap_public, &mut stop) => {
            result.map_err(|error| format!("source custody unavailable: {}", error.pc_code()))
        },
    };
    // Fence even cancellation/listener failure before signalling transport drain.
    // Preserve a failed fence while still joining the owned server.
    let fenced = agent.fence_target_disposition();
    let _ = server_stop.send(true);
    let draining = Arc::new(tokio::sync::Notify::new());
    draining.notify_one();
    lifecycle::drain(
        async {
            while let Some(joined) = servers.join_next().await {
                joined
                    .map_err(|_| "source server task stopped")?
                    .map_err(|_| "source server stopped")?;
            }
            Ok::<(), String>(())
        },
        draining,
    )
    .await??;
    fenced.map_err(|_| "source final admission fence unavailable")?;
    crate::runtime_target_observation::clear(&config.bootstrap_directory)
        .map_err(|_| "source stopped observation retirement failed")?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DenyingOwner(RuntimeError);
    impl ExtProcRequestOwner for DenyingOwner {
        fn begin(
            &self,
            _: &WorkloadPeer,
            _: &EnvoyGeneration,
            _: &[(String, Vec<u8>)],
            _: &RequestTraceId,
        ) -> RuntimeResult<Box<dyn ProtectedRequest>> {
            Err(self.0.clone())
        }
        fn record_transport_denial(
            &self,
            _: &RuntimeError,
            _: &RequestTraceId,
        ) -> RuntimeResult<()> {
            Err(self.0.clone())
        }
    }

    #[test]
    fn mixed_transport_never_falls_back_from_an_assertion_to_source_authority() {
        let owner = MixedTransportOwner {
            invocation: Arc::new(DenyingOwner(RuntimeError::InvalidAuthorization)),
            source: Arc::new(DenyingOwner(RuntimeError::Denied)),
        };
        for value in [vec![], b"malformed".to_vec(), vec![0xff]] {
            for name in ["x-openpc-identity-assertion", "X-OpenPC-Identity-Assertion"] {
                let mut headers = vec![(name.into(), value.clone())];
                for _ in 0..2 {
                    assert!(std::ptr::eq(
                        owner.select(&headers),
                        owner.invocation.as_ref()
                    ));
                    headers.push(("x-openpc-identity-assertion".into(), b"another".to_vec()));
                }
            }
        }
        for headers in [
            vec![],
            vec![(
                "x-openpc-identity-assertion-extra".into(),
                b"value".to_vec(),
            )],
        ] {
            assert!(std::ptr::eq(owner.select(&headers), owner.source.as_ref()));
        }
    }
}
