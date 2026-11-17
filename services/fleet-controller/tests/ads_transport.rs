//! Real TLS and gRPC boundary tests. Resource payloads here test ADS custody;
//! real Envoy resource admission is exercised by the deployed target journey.
use openpc_fleet_controller::{
    FleetController, REQUIRED_XDS_TYPES, TargetIdentity,
    ads::AdsService,
    ads_wire::{DiscoveryRequest, DiscoveryResponse, Node, RpcStatus},
    runtime_tls, serve_ads,
};
use pc_runtime_types::{
    DesiredGeneration, Digest, PURPOSE_ACTIVATION_RECEIPT_V1, PurposeSigner, TargetState,
};
use prost::Message;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
    time::{sleep, timeout},
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    Request, Streaming,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
#[path = "support/canonical_custody.rs"]
mod custody;
struct Certificates {
    path: PathBuf,
}
impl Certificates {
    fn directory(root: &Path) -> PathBuf {
        // Keep the caller's owned root, including the bounded runner default.
        // Atomic directory creation provides process isolation without a long
        // PID/name suffix that consumes the Unix socket pathname budget.
        for _ in 0..1024 {
            let path = root.join(format!("a{:x}", NEXT.fetch_add(1, Ordering::Relaxed)));
            assert!(
                path.join("pds.sock").as_os_str().len() < 108,
                "OPENPC_TEST_TMP_ROOT cannot fit the protected Unix socket"
            );
            match fs::create_dir(&path) {
                Ok(()) => return path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("Cannot allocate owned ADS test directory: {error}"),
            }
        }
        panic!("ADS test directory allocation exhausted");
    }

    fn new() -> Self {
        let root = std::env::var_os("OPENPC_TEST_TMP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        fs::create_dir_all(&root).unwrap();
        let path = Self::directory(&root);
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let fixture = Self { path };
        fixture.openssl(&[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-subj",
            "/CN=OpenPC local ADS test CA",
            "-days",
            "1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]);
        fixture.issue("server", "DNS:localhost", "serverAuth");
        fixture.issue(
            "client",
            "URI:spiffe://openpc.local/runtime-target/target-1",
            "clientAuth",
        );
        fixture.issue(
            "wrong",
            "URI:spiffe://openpc.local/runtime-target/other",
            "clientAuth",
        );
        fixture
    }
    fn openssl(&self, args: &[&str]) {
        assert!(
            Command::new("openssl")
                .args(args)
                .current_dir(&self.path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }
    fn issue(&self, name: &str, san: &str, eku: &str) {
        self.openssl(&[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
            "-subj",
            "/CN=OpenPC local transport test",
        ]);
        fs::write(self.path.join(format!("{name}.ext")),format!("subjectAltName={san}\nextendedKeyUsage={eku}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n")).unwrap();
        self.openssl(&[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            &format!("{name}.crt"),
            "-days",
            "1",
            "-extfile",
            &format!("{name}.ext"),
        ]);
    }
    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.path.join(name)).unwrap()
    }
    fn fingerprint(&self, name: &str) -> Digest {
        Digest::of(
            CertificateDer::from_pem_slice(&self.read(name))
                .unwrap()
                .as_ref(),
        )
    }
}
impl Drop for Certificates {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}
struct Harness {
    certs: Certificates,
    fleet: Arc<FleetController>,
    address: std::net::SocketAddr,
    protected_port: u32,
    stop: Option<oneshot::Sender<()>>,
    version: Digest,
    identity: TargetIdentity,
    canonical: Option<custody::CanonicalHarness>,
    ads: AdsService,
}
impl Harness {
    async fn new() -> Self {
        Self::with_envoy(false).await
    }
    async fn with_envoy(real: bool) -> Self {
        Self::build(real, None, None).await
    }
    async fn build(
        real: bool,
        discovery: Option<Arc<dyn openpc_fleet_controller::ads_discovery::TargetDiscovery>>,
        disposition: Option<
            Arc<openpc_fleet_controller::target_disposition::TargetDispositionStore>,
        >,
    ) -> Self {
        let certs = Certificates::new();
        let signer =
            PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, [33; 32]).unwrap();
        let fleet = Arc::new(
            FleetController::new([32; 32], &signer.verifier().sec1_bytes(), 30_000)
                .unwrap()
                .with_canonical_signing(
                    [32; 32],
                    &openpc_runtime_agent::RuntimeWireSigner::from_secret_bytes([33; 32])
                        .unwrap()
                        .verifier()
                        .public_key_bytes(),
                )
                .unwrap(),
        );
        let identity = TargetIdentity {
            target_id: "target-1".into(),
            uri_san: "spiffe://openpc.local/runtime-target/target-1".into(),
            certificate_fingerprint: certs.fingerprint("client.crt"),
            workload_epoch: 1,
        };
        fleet.register_target(identity.clone(), &identity).unwrap();
        let mut ads = AdsService::new(Arc::clone(&fleet));
        if let Some(store) = disposition {
            ads = ads.with_target_disposition(store);
        }
        let resources: BTreeMap<_, _> = REQUIRED_XDS_TYPES
            .iter()
            .map(|kind| {
                let name = format!("openpc/target-1/{}", kind.rsplit('.').next().unwrap());
                // Field 1 is the resource name in all four Envoy primary messages.
                let bytes = Name { name }.encode_to_vec();
                (
                    (*kind).to_string(),
                    vec![prost_types::Any {
                        type_url: (*kind).into(),
                        value: bytes,
                    }],
                )
            })
            .collect();
        let mut protected_port = 0;
        let mut canonical = None;
        let version = if let Some(discovery) = discovery {
            ads = ads.with_discovery(discovery);
            Digest::of(b"discovery has no published snapshot")
        } else if real {
            let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = reservation.local_addr().unwrap().port() as u32;
            protected_port = port;
            let fixture = custody::CanonicalHarness::prepare(
                Arc::clone(&fleet),
                &certs.path,
                openpc_fleet_controller::envoy_resources::ProtectedListenerConfig {
                    target_id: "target-1",
                    capsule_id: "capsule-1",
                    capsule_generation: 1,
                    request_timeout_ms: 1000,
                    bind_address: "127.0.0.1",
                    port,
                    pds_socket: "/runtime/pds.sock",
                    broker_socket: "/runtime/broker.sock",
                    certificate_file: "/runtime/server.crt",
                    private_key_file: "/runtime/server.key",
                    workload_ca_file: "/runtime/ca.crt",
                },
            );
            ads = fixture.coordinator.ads();
            let version = fixture.prepared.xds_version().clone();
            canonical = Some(fixture);
            version
        } else {
            let version = AdsService::resource_version(&resources).unwrap();
            let capsule = Digest::of(b"admitted capsule");
            fleet
                .command_generation(DesiredGeneration {
                    occurrence_id: "occurrence-1".into(),
                    target_id: "target-1".into(),
                    capsule_digest: capsule.clone(),
                    xds_snapshot_digest: version.clone(),
                    expected_previous_generation_digest: None,
                    expires_at_ms: u64::MAX,
                })
                .unwrap();
            fleet.accept_prepared("target-1", &capsule).unwrap();
            ads.publish("target-1", resources).unwrap();
            version
        };
        let tls = runtime_tls::server_config(
            &certs.read("server.crt"),
            &certs.read("server.key"),
            &certs.read("ca.crt"),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = oneshot::channel();
        let retained_ads = ads.clone();
        tokio::spawn(async move {
            serve_ads(ads, listener, tls, async {
                let _ = receiver.await;
            })
            .await
            .unwrap();
        });
        Self {
            certs,
            fleet,
            address,
            protected_port,
            stop: Some(sender),
            version,
            identity,
            canonical,
            ads: retained_ads,
        }
    }
    async fn channel(&self, client: Option<&str>) -> Result<Channel, tonic::transport::Error> {
        let mut tls = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(Certificate::from_pem(self.certs.read("ca.crt")));
        if let Some(name) = client {
            tls = tls.identity(Identity::from_pem(
                self.certs.read(&format!("{name}.crt")),
                self.certs.read(&format!("{name}.key")),
            ));
        }
        Endpoint::from_shared(format!("https://{}", self.address))
            .unwrap()
            .connect_timeout(Duration::from_secs(3))
            .tls_config(tls)
            .unwrap()
            .connect()
            .await
    }
    async fn stream(
        &self,
        client: Option<&str>,
    ) -> Result<
        (mpsc::Sender<DiscoveryRequest>, Streaming<DiscoveryResponse>),
        Box<dyn std::error::Error>,
    > {
        let channel = self.channel(client).await?;
        let mut grpc = tonic::client::Grpc::new(channel);
        grpc.ready().await?;
        let (sender, receiver) = mpsc::channel(8);
        let response=grpc.streaming(Request::new(ReceiverStream::new(receiver)),http::uri::PathAndQuery::from_static("/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources"),tonic_prost::ProstCodec::<DiscoveryRequest,DiscoveryResponse>::default()).await?;
        Ok((sender, response.into_inner()))
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
#[derive(Clone, PartialEq, Message)]
struct Name {
    #[prost(string, tag = "1")]
    name: String,
}
fn subscribe(kind: &str) -> DiscoveryRequest {
    DiscoveryRequest {
        node: Some(Node {
            id: "target-1".into(),
        }),
        type_url: kind.into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn disposition_transport_requires_registered_tls_deadline_and_available_current_owner() {
    use openpc_fleet_controller::target_disposition::TargetDispositionStore;
    use openpc_fleet_controller::target_disposition_transport::{
        ReadDispositionRequest, ReadDispositionResponse,
    };
    // Explicitly unavailable real database endpoint: it must never become an
    // empty/allowing current-state answer. No mock supplies an internal result.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://unused@127.0.0.1:1/unavailable")
        .unwrap();
    let store = Arc::new(
        TargetDispositionStore::from_host_installation(
            pool,
            "018f0000-0000-7000-8000-000000000101".into(),
            "018f0000-0000-7000-8000-000000007201".into(),
            [32; 32],
            [34; 32],
            BTreeMap::new(),
        )
        .unwrap(),
    );
    let h = Harness::build(false, None, Some(store)).await;
    for (peer, challenge, deadline, expected) in [
        ("wrong", vec![1; 32], true, tonic::Code::FailedPrecondition),
        ("client", vec![1; 31], true, tonic::Code::InvalidArgument),
        ("client", vec![1; 32], false, tonic::Code::InvalidArgument),
        ("client", vec![1; 32], true, tonic::Code::FailedPrecondition),
    ] {
        let channel = h.channel(Some(peer)).await.unwrap();
        let mut grpc = tonic::client::Grpc::new(channel);
        grpc.ready().await.unwrap();
        let mut request = Request::new(ReadDispositionRequest { challenge });
        if deadline {
            request.set_timeout(Duration::from_secs(2));
        }
        let result: Result<tonic::Response<ReadDispositionResponse>, _> = grpc
            .unary(
                request,
                http::uri::PathAndQuery::from_static(
                    "/openpc.internal.runtime.v1.TargetDispositionService/ReadCurrent",
                ),
                tonic_prost::ProstCodec::default(),
            )
            .await;
        assert_eq!(result.unwrap_err().code(), expected);
    }
}

#[tokio::test]
#[ignore = "requires an original public target credential and the retained migrated Control store"]
async fn disposition_current_reads_original_identity_over_real_tls_without_business_mutation() {
    use openpc_fleet_controller::target_disposition::TargetDispositionStore;
    use openpc_fleet_controller::target_disposition_transport::{
        ReadDispositionRequest, ReadDispositionResponse,
    };
    let root = PathBuf::from(std::env::var("OPENPC_TARGET_DISPOSITION_ORIGINAL_ROOT").unwrap());
    let input: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("evidence/runtime-bootstrap/discovery-credential-input.json")).unwrap(),
    )
    .unwrap();
    let original_tls = root.join("data/runtime-bootstrap/runtime/tls");
    let client_certificate = fs::read(original_tls.join("ads-client.pem")).unwrap();
    let peer = runtime_tls::target_identity_from_pem(&client_certificate).unwrap();
    assert_eq!(Some(peer.target_id.as_str()), input["targetId"].as_str());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&std::env::var("OPENPC_I02_RUNTIME_DATABASE_URL").unwrap())
        .await
        .unwrap();
    let agent = PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, [33; 32]).unwrap();
    let fleet =
        Arc::new(FleetController::new([32; 32], &agent.verifier().sec1_bytes(), 30_000).unwrap());
    fleet.register_target(peer.clone(), &peer).unwrap();
    // This read-only check does not sign dispositions or install business state.
    let store = Arc::new(
        TargetDispositionStore::from_host_installation(
            pool.clone(),
            input["participantId"].as_str().unwrap().into(),
            input["privacyDomainId"].as_str().unwrap().into(),
            [32; 32],
            [34; 32],
            BTreeMap::new(),
        )
        .unwrap(),
    );
    let certs = Certificates::new();
    let tls = runtime_tls::server_config(
        &certs.read("server.crt"),
        &certs.read("server.key"),
        &fs::read(root.join("secrets/identity_mtls_ca.pem")).unwrap(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel();
    let server = tokio::spawn(serve_ads(
        AdsService::new(fleet).with_target_disposition(Arc::clone(&store)),
        listener,
        tls,
        async {
            let _ = stopped.await;
        },
    ));
    let channel = Endpoint::from_shared(format!("https://{address}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(3))
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("localhost")
                .ca_certificate(Certificate::from_pem(certs.read("ca.crt")))
                .identity(Identity::from_pem(
                    client_certificate,
                    fs::read(original_tls.join("ads-client.key")).unwrap(),
                )),
        )
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut grpc = tonic::client::Grpc::new(channel);
    // Each challenge requires a fresh SQL owner/credential read. Empty current
    // state is explicit absence, never an affirmative restore/serving answer.
    for challenge in [vec![17; 32], vec![19; 32]] {
        grpc.ready().await.unwrap();
        let mut request = Request::new(ReadDispositionRequest {
            challenge: challenge.clone(),
        });
        request.set_timeout(Duration::from_secs(4));
        let response: tonic::Response<ReadDispositionResponse> = grpc
            .unary(
                request,
                http::uri::PathAndQuery::from_static(
                    "/openpc.internal.runtime.v1.TargetDispositionService/ReadCurrent",
                ),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .unwrap();
        let result = response.into_inner();
        assert_eq!(result.challenge, challenge);
        assert!(!result.established);
        assert_eq!(result.revision, 0);
        assert!(
            result.admission_digest.is_empty()
                && result.signed_delivery.is_empty()
                && result.signed_acknowledgement.is_empty()
        );
    }
    assert_eq!(store.unstarted_restore_cause(&peer).await.unwrap(), None);

    // Resolve bootstrap custody from the actual retained signed capsule and
    // completed SQL work. The caller supplies no source/credential assertions.
    let journal: serde_json::Value = serde_json::from_slice(
        &fs::read(std::env::var("OPENPC_TARGET_DISPOSITION_ORIGINAL_JOURNAL").unwrap()).unwrap(),
    )
    .unwrap();
    let signed: Vec<u8> =
        serde_json::from_value(journal["canonical"]["active"]["custody"]["signed_capsule"].clone())
            .unwrap();
    let key_text =
        fs::read_to_string(root.join("secrets/fleet_controller_signing_secret.txt")).unwrap();
    let key_text = key_text.trim();
    assert_eq!(key_text.len(), 64);
    let key: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&key_text[i..i + 2], 16).unwrap())
        .collect();
    let verifier =
        openpc_runtime_agent::RuntimeWireSigner::from_secret_bytes(key.try_into().unwrap())
            .unwrap()
            .verifier();
    let capsule = verifier.verify_capsule(&signed).unwrap();
    let binding = store
        .bootstrap_for_activation(&peer, &capsule)
        .await
        .unwrap();
    assert_eq!(binding.source.capsule_digest, capsule.digest().unwrap());
    assert_eq!(
        binding.source.runtime_configuration_generation_id,
        capsule.capsule_id
    );
    assert_eq!(binding.target.target_id, peer.target_id);
    assert_eq!(
        binding.target.certificate_digest,
        peer.certificate_fingerprint
    );
    let mut changed = capsule.clone();
    changed.capsule_id = uuid::Uuid::now_v7().to_string();
    assert!(
        store
            .bootstrap_for_activation(&peer, &changed)
            .await
            .is_err()
    );
    changed = capsule.clone();
    changed.hard_expiry_ns += 1;
    assert!(
        store
            .bootstrap_for_activation(&peer, &changed)
            .await
            .is_err()
    );

    // A held disposition fence is a retryable admission conflict, without
    // inventing or consuming an activation cause or mutating original work.
    let mut held = pool.begin().await.unwrap();
    sqlx::query("select pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!(
            "runtime-target-disposition:{}:{}:{}",
            input["participantId"].as_str().unwrap(),
            input["privacyDomainId"].as_str().unwrap(),
            peer.target_id
        ))
        .execute(&mut *held)
        .await
        .unwrap();
    assert_eq!(
        store
            .publish_activation_withdrawal(
                &peer,
                &uuid::Uuid::now_v7().to_string(),
                "readback-only-unknown-worker"
            )
            .await
            .unwrap_err(),
        openpc_fleet_controller::target_disposition::TARGET_DISPOSITION_BUSY
    );
    held.rollback().await.unwrap();
    // An authenticated target with real historical custody is not a new
    // activation cause. No pending admission may be fabricated from it.
    assert!(
        store
            .publish_activation_withdrawal(
                &peer,
                &uuid::Uuid::now_v7().to_string(),
                "readback-only-unknown-worker"
            )
            .await
            .is_err()
    );
    stop.send(()).unwrap();
    timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    pool.close().await;
}

#[derive(Default)]
struct DiscoveryProbe {
    connection: std::sync::Mutex<Option<String>>,
    reject: std::sync::atomic::AtomicBool,
    expected_target: Option<String>,
}
#[tonic::async_trait]
impl openpc_fleet_controller::ads_discovery::TargetDiscovery for DiscoveryProbe {
    async fn observe(
        &self,
        identity: &TargetIdentity,
        connection: &str,
        until: u64,
    ) -> Result<(), tonic::Status> {
        assert_eq!(
            identity.target_id,
            self.expected_target.as_deref().unwrap_or("target-1")
        );
        assert!(until > 0);
        if self.reject.load(Ordering::SeqCst) {
            return Err(tonic::Status::permission_denied("credential revoked"));
        }
        *self.connection.lock().unwrap() = Some(connection.into());
        Ok(())
    }
    async fn disconnect(&self, _: &TargetIdentity, connection: &str) {
        let mut current = self.connection.lock().unwrap();
        if current.as_deref() == Some(connection) {
            *current = None;
        }
    }
}

#[tokio::test]
async fn discovery_accepts_the_public_workload_identity_over_verified_tls() {
    let participant = "018f0000-0000-7000-8000-000000000101";
    let target = "018f0000-0000-7000-8000-000000007201";
    let probe = Arc::new(DiscoveryProbe {
        expected_target: Some(target.into()),
        ..DiscoveryProbe::default()
    });
    let h = Harness::build(false, Some(probe.clone()), None).await;
    h.certs.issue(
        "workload",
        &format!("URI:urn:openpc:participant:{participant}:workload:{target}"),
        "clientAuth",
    );
    h.certs.issue(
        "foreign-workload",
        &format!(
            "URI:urn:openpc:participant:018f0000-0000-7000-8000-000000000102:workload:{target}"
        ),
        "clientAuth",
    );
    let identity = runtime_tls::target_identity_from_pem(&h.certs.read("workload.crt")).unwrap();
    assert_eq!(identity.target_id, target);
    assert_eq!(
        identity.certificate_fingerprint,
        h.certs.fingerprint("workload.crt")
    );
    let mut wrong = identity.clone();
    wrong.target_id = participant.into();
    assert!(h.fleet.register_target(wrong.clone(), &wrong).is_err());
    h.fleet
        .register_target(identity.clone(), &identity)
        .unwrap();
    assert!(h.stream(Some("foreign-workload")).await.is_err());
    assert!(probe.connection.lock().unwrap().is_none());
    let (sender, mut stream) = h.stream(Some("workload")).await.unwrap();
    let mut request = subscribe(REQUIRED_XDS_TYPES[0]);
    request.node.as_mut().unwrap().id = target.into();
    sender.send(request.clone()).await.unwrap();
    let connection = timeout(Duration::from_secs(3), async {
        loop {
            if let Some(id) = probe.connection.lock().unwrap().clone() {
                break id;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        h.ads
            .with_current_connection(target, &connection, || ())
            .is_ok()
    );
    assert!(
        timeout(Duration::from_millis(50), stream.message())
            .await
            .is_err()
    );
    assert_eq!(h.fleet.state(target).unwrap(), TargetState::Discovered);
    probe.reject.store(true, Ordering::SeqCst);
    sender.send(request).await.unwrap();
    assert!(
        timeout(Duration::from_secs(3), stream.message())
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        h.ads
            .with_current_connection(target, &connection, || ())
            .is_err()
    );
}

#[tokio::test]
async fn discovery_requires_real_tls_and_valid_subscription_and_grants_no_snapshot() {
    let probe = Arc::new(DiscoveryProbe::default());
    let h = Harness::build(false, Some(probe.clone()), None).await;
    assert!(probe.connection.lock().unwrap().is_none());
    assert!(h.stream(Some("wrong")).await.is_err());
    assert!(probe.connection.lock().unwrap().is_none());
    let (sender, mut stream) = h.stream(Some("client")).await.unwrap();
    let mut bad = subscribe(REQUIRED_XDS_TYPES[0]);
    bad.node.as_mut().unwrap().id = "foreign".into();
    sender.send(bad).await.unwrap();
    assert!(stream.message().await.is_err());
    assert!(probe.connection.lock().unwrap().is_none());
    let (sender, mut stream) = h.stream(Some("client")).await.unwrap();
    sender.send(subscribe(REQUIRED_XDS_TYPES[0])).await.unwrap();
    let id = timeout(Duration::from_secs(3), async {
        loop {
            if let Some(id) = probe.connection.lock().unwrap().clone() {
                break id;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        h.ads
            .with_current_connection("target-1", &id, || ())
            .is_ok()
    );
    assert_eq!(h.fleet.state("target-1").unwrap(), TargetState::Discovered);
    assert!(
        timeout(Duration::from_millis(50), stream.message())
            .await
            .is_err()
    );
    probe.reject.store(true, Ordering::SeqCst);
    sender.send(subscribe(REQUIRED_XDS_TYPES[0])).await.unwrap();
    assert!(
        timeout(Duration::from_secs(3), stream.message())
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        h.ads
            .with_current_connection("target-1", &id, || ())
            .is_err()
    );
    assert!(probe.connection.lock().unwrap().is_none());
    probe.reject.store(false, Ordering::SeqCst);
    let (sender, _stream) = h.stream(Some("client")).await.unwrap();
    sender.send(subscribe(REQUIRED_XDS_TYPES[0])).await.unwrap();
    let replacement = timeout(Duration::from_secs(3), async {
        loop {
            if let Some(id) = probe.connection.lock().unwrap().clone() {
                break id;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_ne!(id, replacement);
    drop(sender);
    timeout(Duration::from_secs(3), async {
        while probe.connection.lock().unwrap().is_some() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        h.ads
            .with_current_connection("target-1", &replacement, || ())
            .is_err()
    );
}

#[tokio::test]
async fn four_authenticated_envoy_ack_messages_advance_only_the_xds_barrier() {
    let h = Harness::new().await;
    let (sender, mut stream) = h.stream(Some("client")).await.unwrap();
    for kind in REQUIRED_XDS_TYPES {
        sender.send(subscribe(kind)).await.unwrap();
        let response = timeout(Duration::from_secs(3), stream.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.version_info, h.version.as_str());
        assert_eq!(response.resources.len(), 1);
        sender
            .send(DiscoveryRequest {
                version_info: response.version_info,
                response_nonce: response.nonce,
                ..subscribe(kind)
            })
            .await
            .unwrap();
    }
    timeout(Duration::from_secs(3), async {
        while h.fleet.state("target-1").unwrap() != TargetState::XdsAckedNotActive {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_ne!(
        h.fleet.state("target-1").unwrap(),
        TargetState::ActiveMatched
    );
    drop(sender);
    assert!(
        timeout(Duration::from_secs(3), stream.message())
            .await
            .unwrap()
            .is_err()
    );
    for state in [TargetState::XdsAckedNotActive, TargetState::Activating] {
        if state == TargetState::Activating {
            h.fleet.issue_activation_token("target-1", 100, 20).unwrap();
        }
        let (sender, mut stream) = h.stream(Some("client")).await.unwrap();
        for kind in REQUIRED_XDS_TYPES {
            sender.send(subscribe(kind)).await.unwrap();
            let response = timeout(Duration::from_secs(3), stream.message())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(response.version_info, h.version.as_str());
            sender
                .send(DiscoveryRequest {
                    version_info: response.version_info,
                    response_nonce: response.nonce,
                    ..subscribe(kind)
                })
                .await
                .unwrap();
        }
        // A replay must keep the authenticated stream available for the next
        // governed generation without changing the activation state.
        assert!(
            timeout(Duration::from_millis(50), stream.message())
                .await
                .is_err()
        );
        assert_eq!(h.fleet.state("target-1").unwrap(), state);
        drop(sender);
        assert!(
            timeout(Duration::from_secs(3), stream.message())
                .await
                .unwrap()
                .is_err()
        );
    }
}
#[tokio::test]
async fn expired_canonical_preparation_recovers_only_after_a_new_authenticated_ack_barrier() {
    let h = Harness::with_envoy(true).await;
    let canonical = h.canonical.as_ref().unwrap();
    // RuntimePlane re-registers the verified target before each new work item.
    // Controller ACK state resets; the agent's durable orphan remains intact.
    h.fleet
        .register_target(h.identity.clone(), &h.identity)
        .unwrap();
    let now = canonical.capsule.hard_expiry_ns;
    let mut replacement = canonical.capsule.clone();
    replacement.capsule_id = "replacement-after-missing-ack".into();
    replacement.issued_at_ns = now - 2;
    replacement.not_before_ns = now - 1;
    replacement.hard_expiry_ns = now + 60_000_000_000;
    let signer = openpc_runtime_agent::RuntimeWireSigner::from_secret_bytes([32; 32]).unwrap();
    let prepared = canonical
        .coordinator
        .prepare(
            signer.sign_capsule(&replacement).unwrap(),
            canonical.artifacts.clone(),
            "occurrence-recovered-preparation",
            openpc_fleet_controller::envoy_resources::ProtectedListenerConfig {
                target_id: "target-1",
                capsule_id: &replacement.capsule_id,
                capsule_generation: replacement.generation,
                request_timeout_ms: 1000,
                bind_address: "127.0.0.1",
                port: h.protected_port,
                pds_socket: "/runtime/pds.sock",
                broker_socket: "/runtime/broker.sock",
                certificate_file: "/runtime/server.crt",
                private_key_file: "/runtime/server.key",
                workload_ca_file: "/runtime/ca.crt",
            },
            now,
        )
        .unwrap();
    assert_ne!(prepared.xds_version(), canonical.prepared.xds_version());
    assert!(canonical.coordinator.activate(&prepared, now).is_err());
    assert!(
        canonical
            .coordinator
            .activate(&canonical.prepared, now)
            .is_err()
    );
    assert!(
        canonical
            .agent
            .replay_canonical_receipts()
            .unwrap()
            .is_empty()
    );
    let (sender, mut stream) = h.stream(Some("client")).await.unwrap();
    for kind in REQUIRED_XDS_TYPES {
        sender.send(subscribe(kind)).await.unwrap();
        let response = timeout(Duration::from_secs(3), stream.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.version_info, prepared.xds_version().as_str());
        sender
            .send(DiscoveryRequest {
                version_info: response.version_info,
                response_nonce: response.nonce,
                ..subscribe(kind)
            })
            .await
            .unwrap();
    }
    timeout(Duration::from_secs(3), async {
        while h.fleet.state("target-1").unwrap() != TargetState::XdsAckedNotActive {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    canonical.coordinator.activate(&prepared, now + 1).unwrap();
    assert_eq!(
        canonical
            .agent
            .with_active_capsule(|c, _| c.digest())
            .unwrap(),
        replacement.digest().unwrap()
    );
    assert_eq!(
        canonical.agent.replay_canonical_receipts().unwrap().len(),
        1
    );
}

#[tokio::test]
async fn missing_certificate_wrong_san_and_caller_node_cannot_ack() {
    let h = Harness::new().await;
    assert!(
        timeout(Duration::from_secs(4), h.stream(None))
            .await
            .unwrap()
            .is_err()
    );
    assert!(h.stream(Some("wrong")).await.is_err());
    let (sender, mut stream) = h.stream(Some("client")).await.unwrap();
    let mut input = subscribe(REQUIRED_XDS_TYPES[0]);
    input.node = Some(Node { id: "other".into() });
    sender.send(input).await.unwrap();
    assert!(
        timeout(Duration::from_secs(3), stream.message())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(h.fleet.state("target-1").unwrap(), TargetState::XdsPending);
}
#[tokio::test]
async fn stale_nonce_rejects_and_nack_quarantines_sent_version_even_with_old_version_info() {
    let h = Harness::new().await;
    let (sender, mut stream) = h.stream(Some("client")).await.unwrap();
    let kind = REQUIRED_XDS_TYPES[0];
    sender.send(subscribe(kind)).await.unwrap();
    let response = stream.message().await.unwrap().unwrap();
    sender
        .send(DiscoveryRequest {
            version_info: response.version_info.clone(),
            response_nonce: "forged".into(),
            ..subscribe(kind)
        })
        .await
        .unwrap();
    assert!(stream.message().await.is_err());
    assert_eq!(h.fleet.state("target-1").unwrap(), TargetState::XdsPending);
    let (sender, mut stream) = h.stream(Some("client")).await.unwrap();
    sender.send(subscribe(kind)).await.unwrap();
    let response = stream.message().await.unwrap().unwrap();
    sender
        .send(DiscoveryRequest {
            version_info: "previous-version".into(),
            response_nonce: response.nonce,
            error_detail: Some(RpcStatus {
                code: 3,
                message: "invalid cluster".into(),
                details: vec![],
            }),
            ..subscribe(kind)
        })
        .await
        .unwrap();
    assert!(stream.message().await.is_err());
    assert_eq!(h.fleet.state("target-1").unwrap(), TargetState::Nacked);
}
#[tokio::test]
async fn credential_epoch_change_invalidates_an_existing_tls_stream() {
    let h = Harness::new().await;
    let (sender, mut stream) = h.stream(Some("client")).await.unwrap();
    let kind = REQUIRED_XDS_TYPES[0];
    sender.send(subscribe(kind)).await.unwrap();
    let response = stream.message().await.unwrap().unwrap();
    let mut renewed = h.identity.clone();
    renewed.workload_epoch = 2;
    h.fleet.register_target(renewed.clone(), &renewed).unwrap();
    sender
        .send(DiscoveryRequest {
            version_info: response.version_info,
            response_nonce: response.nonce,
            ..subscribe(kind)
        })
        .await
        .unwrap();
    assert!(stream.message().await.is_err());
    assert_eq!(h.fleet.state("target-1").unwrap(), TargetState::Discovered);
}

struct EnvoyContainer {
    name: String,
}
impl Drop for EnvoyContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
#[tokio::test]
#[ignore = "requires Docker, a short explicit OPENPC_TEST_TMP_ROOT, and bounded external-memory admission"]
async fn pinned_envoy_applies_all_four_real_protected_target_resource_types() {
    use std::os::unix::fs::MetadataExt;
    let h = Harness::with_envoy(true).await;
    h.certs.issue("workload", "URI:urn:openpc:participant:019936ed-0000-7000-8000-000000000001:workload:019936ed-0000-7000-8000-000000000002", "clientAuth");
    let metadata = fs::metadata(&h.certs.path).unwrap();
    let listener = openpc_runtime_agent::ipc::OwnedUnixListener::bind(
        &h.certs.path.join("pds.sock"),
        openpc_runtime_agent::ipc::UnixSocketPolicy {
            owner_uid: metadata.uid(),
            group_gid: metadata.gid(),
            envoy_uid: metadata.uid(),
        },
    )
    .await
    .unwrap();
    let observed = Arc::new(RejectingRuntimeOwner {
        agent: Arc::clone(&h.canonical.as_ref().unwrap().agent),
        peers: Default::default(),
        generations: Default::default(),
        denials: AtomicU64::new(0),
    });
    let pds = openpc_runtime_agent::ext_proc::ExtProcService::new(
        Arc::new(openpc_pds::PolicyDecisionService::new([7; 32], 10).unwrap()),
        observed.clone(),
        openpc_runtime_agent::ext_proc::ExtProcLimits {
            headers: 64,
            header_bytes: 32 * 1024,
            body_bytes: 4096,
        },
    )
    .unwrap();
    let (pds_stop, pds_stopped) = oneshot::channel();
    let pds_server = tokio::spawn(openpc_runtime_agent::ext_proc_server::serve_ext_proc(
        pds,
        listener,
        async {
            let _ = pds_stopped.await;
        },
    ));
    let bootstrap = serde_json::json!({
        "node":{"id":"target-1","cluster":"openpc-local-runtime"},
        "dynamic_resources":{"ads_config":{"api_type":"GRPC","transport_api_version":"V3","set_node_on_first_message_only":true,
            "grpc_services":[{"envoy_grpc":{"cluster_name":"ads"}}]},
            "cds_config":{"ads":{},"resource_api_version":"V3"},"lds_config":{"ads":{},"resource_api_version":"V3"}},
        "static_resources":{"clusters":[{"name":"ads","type":"STATIC","connect_timeout":"1s",
            "load_assignment":{"cluster_name":"ads","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"127.0.0.1","port_value":h.address.port()}}}}]}]},
            "typed_extension_protocol_options":{"envoy.extensions.upstreams.http.v3.HttpProtocolOptions":{"@type":"type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions","explicit_http_config":{"http2_protocol_options":{}}}},
            "transport_socket":{"name":"envoy.transport_sockets.tls","typed_config":{"@type":"type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext","sni":"localhost",
                "common_tls_context":{"tls_params":{"tls_minimum_protocol_version":"TLSv1_3","tls_maximum_protocol_version":"TLSv1_3"},
                    "tls_certificates":[{"certificate_chain":{"filename":"/runtime/client.crt"},"private_key":{"filename":"/runtime/client.key"}}],
                    "validation_context":{"trusted_ca":{"filename":"/runtime/ca.crt"},"match_typed_subject_alt_names":[{"san_type":"DNS","matcher":{"exact":"localhost"}}]}}}}}]}
    });
    fs::write(
        h.certs.path.join("envoy.json"),
        serde_json::to_vec(&bootstrap).unwrap(),
    )
    .unwrap();
    let name = format!(
        "openpc-astra05-envoy-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let metadata = fs::metadata(&h.certs.path).unwrap();
    let output=Command::new("docker").args(["run","--detach","--name",&name,"--label","io.openpc.test.owner=astra05-envoy","--network","host",
        "--memory","384m","--cpus","0.5","--pids-limit","128","--user",&format!("{}:{}",metadata.uid(),metadata.gid()),
        "--mount",&format!("type=bind,src={},dst=/runtime,readonly",h.certs.path.display()),
        "docker.io/envoyproxy/envoy:v1.39.0@sha256:f6e2f57b1bef8235083a2553b523508cf97d8991c893fd2aae3a94a6b21096a2",
        "-c","/runtime/envoy.json","--concurrency","1","--log-level","warning"]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let container = EnvoyContainer { name };
    let result = timeout(Duration::from_secs(20), async {
        loop {
            let state = h.fleet.state("target-1").unwrap();
            if state == TargetState::XdsAckedNotActive {
                return true;
            }
            if state == TargetState::Nacked {
                return false;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let logs = Command::new("docker")
        .args(["logs", &container.name])
        .output()
        .unwrap();
    if result != Ok(true) {
        let path = h
            .certs
            .path
            .parent()
            .unwrap_or(&h.certs.path)
            .join(format!("{}-failure.log", container.name));
        let mut bytes = logs.stdout.clone();
        bytes.extend(&logs.stderr);
        fs::write(&path, bytes).unwrap();
        panic!(
            "real Envoy did not ACK: {result:?}; diagnostics {}: {}",
            path.display(),
            String::from_utf8_lossy(&logs.stderr)
        );
    }
    let path = h.certs.path.clone();
    let canonical = h.canonical.as_ref().unwrap();
    let signed = canonical
        .coordinator
        .activate(&canonical.prepared, custody::now_ns())
        .unwrap();
    assert_eq!(
        canonical
            .coordinator
            .activate(&canonical.prepared, custody::now_ns())
            .unwrap(),
        signed
    );
    let receipt = openpc_runtime_agent::RuntimeWireSigner::from_secret_bytes([33; 32])
        .unwrap()
        .verifier()
        .verify_receipt(&signed)
        .unwrap();
    assert_eq!(
        receipt.capsule_digest,
        canonical.prepared.capsule_digest().unwrap()
    );
    assert_eq!(receipt.reason_code, "ACTIVE_LOCAL");
    assert_eq!(
        canonical.agent.active_canonical_generation().unwrap(),
        Some((
            canonical.prepared.capsule_digest().unwrap(),
            canonical.prepared.xds_version().clone(),
            receipt.agent_sequence,
        ))
    );
    assert_eq!(h.fleet.state("target-1").unwrap(), TargetState::Activating);
    canonical
        .agent
        .with_active_capsule(|capsule, _| {
            assert_eq!(capsule.digest()?, canonical.prepared.capsule_digest()?);
            Ok(())
        })
        .unwrap();
    let port = h.protected_port;
    let output = tokio::task::spawn_blocking(move || {
        Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "--tlsv1.3",
                "--cacert",
            ])
            .arg(path.join("ca.crt"))
            .arg("--cert")
            .arg(path.join("workload.crt"))
            .arg("--key")
            .arg(path.join("workload.key"))
            .args([
                "--header",
                "content-type: application/json",
                "--header",
                "x-forwarded-client-cert: URI=forged-caller",
                "--header",
                "x-openpc-runtime-capsule-id: forged-caller",
                "--header",
                "x-openpc-runtime-generation: 999",
                "--data",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[]}",
                "--write-out",
                "\n%{http_code}",
            ])
            .arg(format!("https://localhost:{port}/"))
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request_logs = Command::new("docker")
        .args(["logs", &container.name])
        .output()
        .unwrap();
    let output = String::from_utf8(output.stdout).unwrap();
    let (body, status) = output.rsplit_once('\n').unwrap();
    assert_eq!(
        status,
        "403",
        "peers={:?}; denials={}; Envoy={}",
        observed.peers.lock().unwrap(),
        observed.denials.load(Ordering::Relaxed),
        String::from_utf8_lossy(&request_logs.stderr)
            .lines()
            .filter(|line| line.contains("http2")
                || line.contains("ext_proc")
                || line.contains("protocol")
                || line.contains("grpc"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let error: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(error["jsonrpc"], "2.0");
    assert!(error["id"].is_null());
    assert_eq!(error["error"]["code"], -32001);
    assert_eq!(error["error"]["data"]["pcCode"], "PC-RUNTIME-3001");
    assert_eq!(error["error"]["data"]["truthState"], "DENIED");
    assert_eq!(error["error"]["data"]["retryable"], false);
    let peers = observed.peers.lock().unwrap().clone();
    assert_eq!(peers.len(), 1);
    assert_eq!(
        peers[0].0,
        "urn:openpc:workload:019936ed-0000-7000-8000-000000000002"
    );
    assert_eq!(peers[0].1, h.certs.fingerprint("workload.crt"));
    assert_eq!(
        *observed.generations.lock().unwrap(),
        vec![canonical.prepared.capsule_digest().unwrap()]
    );
    assert_eq!(observed.denials.load(Ordering::Relaxed), 1);
    drop(container);
    pds_stop.send(()).unwrap();
    pds_server.await.unwrap().unwrap();
    // Restarted Fleet recovers custody from the actual active target journal,
    // but old controller ACKs cannot authorize a new activation command.
    let (active, artifacts) = canonical
        .agent
        .with_active_capsule(|capsule, artifacts| Ok((capsule.clone(), artifacts.clone())))
        .unwrap();
    let fleet_key = openpc_runtime_agent::RuntimeWireSigner::from_secret_bytes([32; 32]).unwrap();
    let receipt_key = openpc_runtime_agent::RuntimeWireSigner::from_secret_bytes([33; 32]).unwrap();
    let restarted_fleet = Arc::new(
        FleetController::new(
            [32; 32],
            &PurposeSigner::from_secret_bytes(PURPOSE_ACTIVATION_RECEIPT_V1, [33; 32])
                .unwrap()
                .verifier()
                .sec1_bytes(),
            30_000,
        )
        .unwrap()
        .with_canonical_trust(
            &fleet_key.verifier().public_key_bytes(),
            &receipt_key.verifier().public_key_bytes(),
        )
        .unwrap(),
    );
    restarted_fleet
        .register_target(h.identity.clone(), &h.identity)
        .unwrap();
    let restarted = openpc_fleet_controller::canonical_target::CanonicalTargetCoordinator::new(
        Arc::clone(&restarted_fleet),
        Arc::clone(&canonical.agent),
    );
    let recovered = restarted
        .prepare(
            fleet_key.sign_capsule(&active).unwrap(),
            artifacts,
            "occurrence-1",
            openpc_fleet_controller::envoy_resources::ProtectedListenerConfig {
                target_id: "target-1",
                capsule_id: "capsule-1",
                capsule_generation: 1,
                request_timeout_ms: 1000,
                bind_address: "127.0.0.1",
                port: h.protected_port,
                pds_socket: "/runtime/pds.sock",
                broker_socket: "/runtime/broker.sock",
                certificate_file: "/runtime/server.crt",
                private_key_file: "/runtime/server.key",
                workload_ca_file: "/runtime/ca.crt",
            },
            custody::now_ns(),
        )
        .unwrap();
    assert_eq!(recovered.xds_version(), canonical.prepared.xds_version());
    assert_eq!(
        restarted_fleet.state("target-1").unwrap(),
        TargetState::XdsPending
    );
    assert!(restarted.activate(&recovered, custody::now_ns()).is_err());
    assert_eq!(
        canonical.agent.replay_canonical_receipts().unwrap(),
        vec![signed]
    );
    assert_ne!(
        h.fleet.state("target-1").unwrap(),
        TargetState::ActiveMatched
    );
}

/// Component observer deliberately refuses runtime authority. This proves actual
/// Envoy TLS/UDS certificate provenance and fail-closed routing, not the allow journey.
struct RejectingRuntimeOwner {
    agent: Arc<openpc_runtime_agent::RuntimeAgent>,
    peers: std::sync::Mutex<Vec<(String, Digest)>>,
    generations: std::sync::Mutex<Vec<Digest>>,
    denials: AtomicU64,
}
impl openpc_runtime_agent::ext_proc::ExtProcRequestOwner for RejectingRuntimeOwner {
    fn begin(
        &self,
        peer: &openpc_runtime_agent::WorkloadPeer,
        generation: &openpc_runtime_agent::ext_proc::EnvoyGeneration,
        _: &[(String, Vec<u8>)],
        _: &openpc_runtime_agent::ext_proc::RequestTraceId,
    ) -> pc_runtime_types::RuntimeResult<Box<dyn openpc_runtime_agent::ext_proc::ProtectedRequest>>
    {
        assert_eq!(generation.capsule_id(), "capsule-1");
        assert_eq!(generation.generation(), 1);
        let lease = self.agent.acquire_observed_capsule(
            &custody::protected_classes(),
            generation,
            custody::now_ns(),
        )?;
        self.generations
            .lock()
            .unwrap()
            .push(lease.capsule().digest()?);
        self.peers.lock().unwrap().push((
            peer.workload_id().into(),
            peer.certificate_fingerprint().clone(),
        ));
        Err(pc_runtime_types::RuntimeError::InvalidAuthorization)
    }
    fn record_transport_denial(
        &self,
        _: &pc_runtime_types::RuntimeError,
        _: &openpc_runtime_agent::ext_proc::RequestTraceId,
    ) -> pc_runtime_types::RuntimeResult<()> {
        self.denials.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
