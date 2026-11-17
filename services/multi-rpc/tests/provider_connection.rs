//! MRPC-CONTRACT-005 endpoint/DNS/TLS boundary against a real, controlled mTLS
//! HTTPS provider. Bootstrap certificates establish external test identities;
//! these tests do not claim signed routing, PDS or full journey acceptance.
use openpc_multi_rpc::provider_connection::*;
use pc_runtime_types::Digest;
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::{
    fs,
    net::IpAddr,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::Instant,
};
use tokio_rustls::TlsAcceptor;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn endpoint(host: &str, port: u16) -> EndpointDescriptor {
    EndpointDescriptor {
        endpoint_id: "endpoint-1".into(),
        normalized_uri: format!("https://{host}:{port}/rpc"),
        reference_identity: host.into(),
        port,
        path: "/rpc".into(),
        dns_policy_ref: "dns-1".into(),
        tls_policy_ref: "tls-1".into(),
        credential_ref: "credential-1".into(),
        egress_policy_ref: "egress-1".into(),
        endpoint_generation: 1,
    }
}
fn ranges(values: &[&str]) -> Vec<NetworkRange> {
    values
        .iter()
        .map(|v| NetworkRange::parse(v).unwrap())
        .collect()
}
fn policy() -> DestinationPolicy {
    DestinationPolicy {
        allowed_ranges: ranges(&["127.0.0.1/32"]),
        private_network_ranges: ranges(&["127.0.0.1/32"]),
        allow_ip_endpoint: false,
    }
}
fn resolution(addresses: &[&str]) -> Resolution {
    Resolution {
        addresses: addresses.iter().map(|s| s.parse().unwrap()).collect(),
        resolved_at_ms: now(),
        valid_until_ms: now() + 30_000,
        generation: 1,
    }
}
fn prepared(port: u16) -> PreparedEndpoint {
    endpoint("provider.openpc.test", port)
        .prepare(&policy(), resolution(&["127.0.0.1"]))
        .unwrap()
}

#[test]
fn endpoint_normalization_and_whole_answer_egress_reject_ambiguity() {
    for uri in [
        "http://provider.openpc.test:443/rpc",
        "https://provider.openpc.test:443/rpc",
        "https://user@provider.openpc.test:444/rpc",
        "https://@provider.openpc.test:444/rpc",
        "https://provider.openpc.test:444/rpc#fragment",
        "https://PROVIDER.openpc.test:444/rpc",
        "https://provider.openpc.test:444/a/../rpc",
        "https://provider.openpc.test:444/other",
        "https://provider:444/rpc",
        "https://*.openpc.test:444/rpc",
        "https://provider.openpc.test.:444/rpc",
        "https://127.0.0.1:444/rpc",
    ] {
        let mut e = endpoint("provider.openpc.test", 444);
        e.normalized_uri = uri.into();
        assert!(
            e.prepare(&policy(), resolution(&["127.0.0.1"])).is_err(),
            "{uri}"
        );
    }
    let e = endpoint("provider.openpc.test", 444);
    let mut p = policy();
    p.allowed_ranges = ranges(&["0.0.0.0/0", "::/0"]);
    p.private_network_ranges.clear();
    assert!(e.prepare(&p, resolution(&["8.8.8.8"])).is_ok());
    for denied in [
        "127.0.0.1",
        "169.254.169.254",
        "100.100.100.200",
        "10.0.0.1",
        "192.168.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "fc00::1",
        "fe80::1",
        "2002:7f00:1::",
        "2001:db8::1",
    ] {
        assert!(
            e.prepare(&p, resolution(&["8.8.8.8", denied])).is_err(),
            "{denied}"
        );
    }
    p.private_network_ranges = ranges(&["0.0.0.0/0"]);
    assert!(e.prepare(&p, resolution(&["127.0.0.1"])).is_err());
    assert!(
        e.prepare(&policy(), resolution(&["127.0.0.1", "127.0.0.1"]))
            .is_err()
    );
    let mut r = resolution(&["127.0.0.1"]);
    r.valid_until_ms = now();
    assert!(matches!(
        e.prepare(&policy(), r),
        Err(ConnectionError::Expired)
    ));
    let mut r = resolution(&["127.0.0.1"]);
    r.resolved_at_ms += 60_000;
    assert!(matches!(
        e.prepare(&policy(), r),
        Err(ConnectionError::Expired)
    ));
    let mut p = policy();
    p.allow_ip_endpoint = true;
    assert!(
        endpoint("127.0.0.1", 444)
            .prepare(&p, resolution(&["127.0.0.1"]))
            .is_ok()
    );
    assert!(
        endpoint("127.0.0.2", 444)
            .prepare(&p, resolution(&["127.0.0.1"]))
            .is_err()
    );
    for cidr in ["127.0.0.1/8", "0.0.0.0/33", "::/129", "127.0.0.0/008"] {
        assert!(NetworkRange::parse(cidr).is_err());
    }
}

struct Certificates {
    path: PathBuf,
}
impl Certificates {
    fn new() -> Self {
        let root = std::env::var_os("OPENPC_TEST_TMP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = root.join(format!("provider-tls-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let c = Self { path };
        c.openssl(&[
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
            "/CN=OpenPC provider test CA",
            "-days",
            "1",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ]);
        c.issue("server", Some("DNS:provider.openpc.test"), "serverAuth");
        c.issue("wrong", Some("DNS:wrong.openpc.test"), "serverAuth");
        c.issue("cn-only", None, "serverAuth");
        c.issue(
            "client",
            Some("URI:spiffe://openpc.local/broker/test"),
            "clientAuth",
        );
        c
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
    fn issue(&self, name: &str, san: Option<&str>, eku: &str) {
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
            "/CN=provider.openpc.test",
        ]);
        let extension = format!(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={eku}\n{}",
            san.map(|s| format!("subjectAltName={s}\n"))
                .unwrap_or_default()
        );
        fs::write(self.path.join(format!("{name}.ext")), extension).unwrap();
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
    fn cert(&self, name: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(&fs::read(self.path.join(format!("{name}.crt"))).unwrap())
            .unwrap()
    }
    fn key(&self, name: &str) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_slice(&fs::read(self.path.join(format!("{name}.key"))).unwrap())
            .unwrap()
    }
    fn material(&self, server: &str) -> LocalTlsMaterial {
        LocalTlsMaterial {
            roots: vec![self.cert("ca")],
            client_chain: vec![self.cert("client")],
            client_key: self.key("client"),
            expected_server_certificate: Digest::of(self.cert(server)),
        }
    }
    fn server_config(&self, name: &str) -> Arc<ServerConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(self.cert("ca")).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        Arc::new(
            ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![self.cert(name)], self.key(name))
                .unwrap(),
        )
    }
    fn server_only_config(&self, name: &str) -> Arc<ServerConfig> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![self.cert(name)], self.key(name))
                .unwrap(),
        )
    }
}
impl Drop for Certificates {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

struct Provider {
    port: u16,
    contacts: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Provider {
    async fn start(config: Arc<ServerConfig>, response: &'static [u8], delay: Duration) -> Self {
        Self::start_with_handler(config, move |_| response.to_vec(), delay).await
    }
    async fn start_with_handler(
        config: Arc<ServerConfig>,
        response: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
        delay: Duration,
    ) -> Self {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let contacts = Arc::new(AtomicUsize::new(0));
        let observed = contacts.clone();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stored = requests.clone();
        let task = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(config);
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    continue;
                };
                let mut request = Vec::new();
                let mut buffer = [0u8; 2048];
                while let Ok(size) = tls.read(&mut buffer).await {
                    if size == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..size]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).unwrap();
                        let length: usize = headers
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(str::to_owned)
                            })
                            .unwrap()
                            .parse()
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                    assert!(request.len() < 8192);
                }
                if !request.is_empty() {
                    observed.fetch_add(1, Ordering::SeqCst);
                    let response = response(&request);
                    stored.lock().unwrap().push(request);
                    tokio::time::sleep(delay).await;
                    let _ = tls.write_all(&response).await;
                    let _ = tls.shutdown().await;
                }
            }
        });
        Self {
            port,
            contacts,
            requests,
            task,
        }
    }
    fn contacts(&self) -> usize {
        self.contacts.load(Ordering::SeqCst)
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.task.abort();
    }
}
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";

#[path = "provider_connection/cigl_method.rs"]
mod cigl_method_tests;
#[path = "provider_connection/cigl.rs"]
mod cigl_tests;
#[path = "support/deployment.rs"]
mod deployment_fixture;
#[path = "provider_connection/deployment.rs"]
mod deployment_tests;
#[path = "provider_connection/submission_observation.rs"]
mod submission_observation_tests;
#[path = "provider_connection/write_preflight.rs"]
mod write_preflight_tests;

// Transport-owner regression only; full actor/policy/approval acceptance lives
// in the protected transaction journey, not in this local admission stand-in.
#[tokio::test]
async fn signed_write_uses_pinned_transport_and_recovers_without_rebroadcast() {
    use openpc_multi_rpc::{
        governed_write,
        journal::{GovernedCommand, JournalState, WriteJournal},
        signed_transaction::SignedTransaction,
    };
    use pc_runtime_types::{RuntimeError, RuntimeResult};
    struct Authority {
        command: GovernedCommand,
        connection: ConnectionRecord,
        allowed: bool,
    }
    struct Lease;
    impl governed_write::WriteAuthorityLease for Lease {
        fn revalidate(&self) -> RuntimeResult<()> {
            Ok(())
        }
    }
    impl governed_write::LiveWriteAuthority for Authority {
        fn acquire<'a>(
            &'a self,
            _: &SignedTransaction,
            command: &GovernedCommand,
            connection: &ConnectionRecord,
        ) -> RuntimeResult<Box<dyn governed_write::WriteAuthorityLease + 'a>> {
            if !self.allowed || command != &self.command || connection != &self.connection {
                Err(RuntimeError::InvalidAuthorization)
            } else {
                Ok(Box::new(Lease))
            }
        }
    }
    let raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    let raw = (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>();
    let tx = SignedTransaction::decode(&raw).unwrap();
    let hash = format!(
        "0x{}",
        tx.hash()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    let certs = Certificates::new();
    for mode in [
        "ack",
        "lost",
        "wrong-hash",
        "wrong-id",
        "duplicate-id",
        "rpc-error",
        "http-500",
        "oversized",
        "truncated",
    ] {
        let command_id = uuid::Uuid::now_v7().to_string();
        let response_id = command_id.clone();
        let response_hash = hash.clone();
        let journal_observer = Arc::new(Mutex::new(None::<Arc<Mutex<WriteJournal>>>));
        let observed_status = Arc::new(AtomicUsize::new(0));
        let observe_journal = journal_observer.clone();
        let observe_status = observed_status.clone();
        let provider = Provider::start_with_handler(certs.server_config("server"), move |_| {
            let journal = observe_journal.lock().unwrap().as_ref().unwrap().clone();
            assert_eq!(journal.try_lock().expect("no journal lock across provider I/O").latest_state(&response_id), Some(JournalState::Started));
            observe_status.fetch_add(1, Ordering::SeqCst);
            if mode == "lost" { return Vec::new(); }
            let mut value = serde_json::json!({"jsonrpc":"2.0","id":response_id,"result":response_hash});
            match mode {
                "wrong-hash" => value["result"] = serde_json::json!(format!("0x{}", "0".repeat(64))),
                "wrong-id" => value["id"] = serde_json::json!("another request"),
                "rpc-error" => value = serde_json::json!({"jsonrpc":"2.0","id":response_id,"error":{"code":-32000,"message":"uncertified rejection contains private provider detail"}}),
                "oversized" => value["result"] = serde_json::json!("x".repeat(8192)),
                _ => {},
            }
            let mut body = serde_json::to_vec(&value).unwrap();
            if mode == "duplicate-id" {
                body = format!("{{\"jsonrpc\":\"2.0\",\"id\":\"{response_id}\",\"id\":\"{response_id}\",\"result\":\"{response_hash}\"}}").into_bytes();
            }
            let status = if mode == "http-500" { "500 Internal Server Error" } else { "200 OK" };
            let length = body.len();
            if mode == "truncated" { body.truncate(length / 2); }
            let mut response = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n").into_bytes();
            response.extend(body);
            response
        }, Duration::ZERO).await;
        let root = certs.path.join(format!("write-{mode}"));
        fs::create_dir(&root).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let registry = ConnectionRegistry::open(&root, "target-1", 4).unwrap();
        let connection = ProviderConnection::prepare(
            prepared(provider.port),
            certs.material("server"),
            4096,
            4096,
        )
        .unwrap();
        let record = registry.install("provider-1", 0, connection).await.unwrap();
        let lease = registry
            .acquire("provider-1", "endpoint-1", record.dispatcher_generation)
            .unwrap();
        let body = governed_write::submission_body(&tx, &command_id).unwrap();
        let command = GovernedCommand {
            command_id: command_id.clone(),
            method: "eth_sendRawTransaction".into(),
            immutable_request_digest: Digest::of(&body).as_str().into(),
            request_or_transaction_hash: hash.clone(),
            submitted_bytes_digest: Digest::of(&body).as_str().into(),
            provider_profile_digest: "qualified-profile".into(),
            provider_instance_id: "provider-1".into(),
            attempt_id: uuid::Uuid::now_v7().to_string(),
            anchor_digest: "qualified-anchor".into(),
            participant_id: "participant-1".into(),
            privacy_domain_id: "privacy-1".into(),
            correlation_id: uuid::Uuid::now_v7().to_string(),
            occurred_at: "2026-09-15T00:00:00.000000Z".into(),
        };
        let mut authority = Authority {
            command: command.clone(),
            connection: record,
            allowed: false,
        };
        let path = root.join("write.journal");
        let journal = Mutex::new(WriteJournal::create_new(&path).unwrap());
        // A live denial has a terminal no-send record. A separate legacy
        // component command below exercises the acknowledged/ambiguous path.
        let mut denied = command.clone();
        denied.command_id = uuid::Uuid::now_v7().to_string();
        denied.attempt_id = uuid::Uuid::now_v7().to_string();
        denied.submitted_bytes_digest =
            Digest::of(governed_write::submission_body(&tx, &denied.command_id).unwrap())
                .as_str()
                .into();
        authority.command = denied.clone();
        let denied_id = denied.command_id.clone();
        let prepared_command = journal.lock().unwrap().prepare_signed(denied, &tx).unwrap();
        assert_eq!(
            governed_write::submit(
                &journal,
                prepared_command,
                &tx,
                &lease,
                &authority,
                Instant::now() + Duration::from_secs(2)
            )
            .await,
            Err(RuntimeError::InvalidAuthorization)
        );
        assert_eq!(provider.contacts(), 0);
        assert_eq!(
            journal.lock().unwrap().latest_state(&denied_id),
            Some(JournalState::FailedPreStart)
        );
        drop(journal);
        let journal = Arc::new(Mutex::new(WriteJournal::open(&path).unwrap()));
        assert!(journal.lock().unwrap().resume_prepared(&denied_id).is_err());
        *journal_observer.lock().unwrap() = Some(journal.clone());
        authority.allowed = true;
        authority.command = command.clone();
        let prepared_command = journal
            .lock()
            .unwrap()
            .prepare_signed(command.clone(), &tx)
            .unwrap();
        let expected = if mode == "ack" {
            JournalState::Acknowledged
        } else {
            JournalState::Ambiguous
        };
        assert_eq!(
            governed_write::submit(
                &journal,
                prepared_command,
                &tx,
                &lease,
                &authority,
                Instant::now() + Duration::from_secs(2)
            )
            .await
            .unwrap(),
            expected
        );
        assert_eq!(provider.contacts(), 1);
        assert_eq!(observed_status.load(Ordering::SeqCst), 1);
        journal_observer.lock().unwrap().take();
        assert!(
            journal
                .lock()
                .unwrap()
                .prepare_signed(command, &tx)
                .is_err()
        );
        drop(journal);
        let mut journal = WriteJournal::open(&path).unwrap();
        assert_eq!(journal.latest_state(&command_id), Some(expected));
        assert!(journal.resume_prepared(&command_id).is_err());
        assert_eq!(provider.contacts(), 1);
        let request = provider.requests.lock().unwrap()[0].clone();
        assert!(request.ends_with(&body));
    }
}
async fn send(connection: &ProviderConnection) -> Result<Vec<u8>, ConnectionError> {
    connection
        .post_json(
            b"{\"jsonrpc\":\"2.0\"}".to_vec(),
            Instant::now() + Duration::from_secs(2),
        )
        .await
}

#[tokio::test]
async fn real_tls_pins_identity_before_http_and_never_falls_back_to_cn() {
    let certs = Certificates::new();
    let provider = Provider::start(certs.server_config("server"), OK, Duration::ZERO).await;
    let connection = ProviderConnection::prepare(
        prepared(provider.port),
        certs.material("server"),
        4096,
        4096,
    )
    .unwrap();
    assert_eq!(send(&connection).await.unwrap(), b"{}");
    assert_eq!(provider.contacts(), 1);
    let requests = provider.requests.lock().unwrap().clone();
    let request = String::from_utf8(requests[0].clone()).unwrap();
    assert!(request.starts_with("POST /rpc HTTP/1.1\r\n"));
    assert!(request.contains(&format!("host: provider.openpc.test:{}\r\n", provider.port)));
    assert!(request.ends_with("{\"jsonrpc\":\"2.0\"}"));
    // Trusted CA and correct SAN are insufficient when the admitted provider
    // fingerprint differs. The HTTP body must not reach that TLS peer.
    let wrong_pin =
        ProviderConnection::prepare(prepared(provider.port), certs.material("wrong"), 4096, 4096)
            .unwrap();
    assert_eq!(send(&wrong_pin).await, Err(ConnectionError::Unavailable));
    assert_eq!(provider.contacts(), 1);
    for name in ["wrong", "cn-only"] {
        let peer = Provider::start(certs.server_config(name), OK, Duration::ZERO).await;
        let c = ProviderConnection::prepare(prepared(peer.port), certs.material(name), 4096, 4096)
            .unwrap();
        assert_eq!(send(&c).await, Err(ConnectionError::Unavailable));
        assert_eq!(peer.contacts(), 0);
    }
    let foreign = Certificates::new();
    let mut material = certs.material("server");
    material.roots = vec![foreign.cert("ca")];
    let untrusted =
        ProviderConnection::prepare(prepared(provider.port), material, 4096, 4096).unwrap();
    assert_eq!(send(&untrusted).await, Err(ConnectionError::Unavailable));
    assert_eq!(provider.contacts(), 1);
    let mut material = certs.material("server");
    material.client_chain = vec![foreign.cert("client")];
    material.client_key = foreign.key("client");
    let untrusted_client =
        ProviderConnection::prepare(prepared(provider.port), material, 4096, 4096).unwrap();
    assert_eq!(
        send(&untrusted_client).await,
        Err(ConnectionError::Unavailable)
    );
    assert_eq!(provider.contacts(), 1);
    let mut material = certs.material("server");
    material.client_chain.clear();
    assert!(matches!(
        ProviderConnection::prepare(prepared(provider.port), material, 4096, 4096),
        Err(ConnectionError::Tls)
    ));
}

#[tokio::test]
async fn server_certificate_overlap_accepts_only_the_two_committed_leaves() {
    let certs = Certificates::new();
    let material = |alternate: Option<&str>| ServerTlsMaterial {
        roots: vec![certs.cert("ca")],
        expected_server_certificate: Digest::of(certs.cert("server")),
        server_certificate_overlap: alternate.map(|name| Digest::of(certs.cert(name))),
    };
    let primary = Provider::start(certs.server_only_config("server"), OK, Duration::ZERO).await;
    let connection =
        ProviderConnection::prepare(prepared(primary.port), material(Some("wrong")), 4096, 4096)
            .unwrap();
    assert_eq!(send(&connection).await.unwrap(), b"{}");

    // The overlap leaf still requires the admitted hostname, so use a second
    // valid leaf rather than the intentionally wrong-SAN fixture.
    let overlap_name = "server-overlap";
    certs.issue(overlap_name, Some("DNS:provider.openpc.test"), "serverAuth");
    let overlap = Provider::start(certs.server_only_config(overlap_name), OK, Duration::ZERO).await;
    let connection = ProviderConnection::prepare(
        prepared(overlap.port),
        material(Some(overlap_name)),
        4096,
        4096,
    )
    .unwrap();
    assert_eq!(send(&connection).await.unwrap(), b"{}");

    let third_name = "server-third";
    certs.issue(third_name, Some("DNS:provider.openpc.test"), "serverAuth");
    let third = Provider::start(certs.server_only_config(third_name), OK, Duration::ZERO).await;
    let connection = ProviderConnection::prepare(
        prepared(third.port),
        material(Some(overlap_name)),
        4096,
        4096,
    )
    .unwrap();
    assert_eq!(send(&connection).await, Err(ConnectionError::Unavailable));
    assert_eq!(third.contacts(), 0);

    let duplicate = ServerTlsMaterial {
        roots: vec![certs.cert("ca")],
        expected_server_certificate: Digest::of(certs.cert("server")),
        server_certificate_overlap: Some(Digest::of(certs.cert("server"))),
    };
    assert!(matches!(
        ProviderConnection::prepare(prepared(primary.port), duplicate, 4096, 4096),
        Err(ConnectionError::Tls)
    ));
}

#[tokio::test]
async fn redirect_response_size_expiry_and_deadline_remain_closed() {
    let certs = Certificates::new();
    for response in [
        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/stolen\r\nContent-Length: 0\r\n\r\n"
            .as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
    ] {
        let peer = Provider::start(certs.server_config("server"), response, Duration::ZERO).await;
        let c = ProviderConnection::prepare(prepared(peer.port), certs.material("server"), 4096, 4)
            .unwrap();
        assert_eq!(send(&c).await, Err(ConnectionError::Response));
        assert_eq!(peer.contacts(), 1);
    }
    let peer = Provider::start(
        certs.server_config("server"),
        OK,
        Duration::from_millis(100),
    )
    .await;
    let c = ProviderConnection::prepare(prepared(peer.port), certs.material("server"), 4096, 4096)
        .unwrap();
    assert_eq!(
        c.post_json(b"{}".to_vec(), Instant::now()).await,
        Err(ConnectionError::Expired)
    );
    assert_eq!(peer.contacts(), 0);
    assert_eq!(
        c.post_json(b"{}".to_vec(), Instant::now() + Duration::from_millis(50))
            .await,
        Err(ConnectionError::Expired)
    );
    assert_eq!(peer.contacts(), 1);
    let mut r = resolution(&["127.0.0.1"]);
    r.valid_until_ms = now() + 30;
    let e = endpoint("provider.openpc.test", peer.port)
        .prepare(&policy(), r)
        .unwrap();
    let c = ProviderConnection::prepare(e, certs.material("server"), 4096, 4096).unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(send(&c).await, Err(ConnectionError::Expired));
    assert_eq!(peer.contacts(), 1);
    // Keep the family semantics explicit in the test corpus.
    assert!("::ffff:127.0.0.1".parse::<IpAddr>().unwrap().is_ipv6());
}

fn connection_generation(
    certs: &Certificates,
    port: u16,
    endpoint_generation: u64,
    resolution_generation: u64,
) -> ProviderConnection {
    let mut e = endpoint("provider.openpc.test", port);
    e.endpoint_generation = endpoint_generation;
    let mut r = resolution(&["127.0.0.1"]);
    r.generation = resolution_generation;
    ProviderConnection::prepare(
        e.prepare(&policy(), r).unwrap(),
        certs.material("server"),
        4096,
        4096,
    )
    .unwrap()
}

#[tokio::test]
async fn durable_connection_cutover_and_retirement_wait_for_actual_request_lease() {
    let certs = Certificates::new();
    let first = Provider::start(certs.server_config("server"), OK, Duration::ZERO).await;
    let second = Provider::start(certs.server_config("server"), OK, Duration::ZERO).await;
    let directory = certs.path.join("connections");
    let registry = ConnectionRegistry::open(&directory, "target-1", 1).unwrap();
    assert!(matches!(
        ConnectionRegistry::open(&directory, "target-1", 1),
        Err(ConnectionError::Owner)
    ));
    let installed = registry
        .install(
            "provider-1",
            0,
            connection_generation(&certs, first.port, 1, 1),
        )
        .await
        .unwrap();
    assert_eq!(installed.dispatcher_generation, 1);
    let lease = registry.acquire("provider-1", "endpoint-1", 1).unwrap();
    // Poll the replacement until it is waiting on the real request fence.
    let cutover = registry.install(
        "provider-1",
        1,
        connection_generation(&certs, second.port, 2, 1),
    );
    tokio::pin!(cutover);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut cutover)
            .await
            .is_err()
    );
    assert!(matches!(
        registry.acquire("provider-1", "endpoint-1", 1),
        Err(ConnectionError::Owner)
    ));
    assert_eq!(send(lease.connection().unwrap()).await.unwrap(), b"{}");
    assert_eq!(first.contacts(), 1);
    assert_eq!(second.contacts(), 0);
    drop(lease);
    let installed = cutover.await.unwrap();
    assert_eq!(installed.dispatcher_generation, 2);
    assert!(matches!(
        registry.acquire("provider-1", "endpoint-1", 1),
        Err(ConnectionError::Generation)
    ));
    assert!(matches!(
        registry.acquire("foreign-provider", "endpoint-1", 2),
        Err(ConnectionError::Generation)
    ));
    let lease = registry.acquire("provider-1", "endpoint-1", 2).unwrap();
    assert_eq!(send(lease.connection().unwrap()).await.unwrap(), b"{}");
    assert_eq!(second.contacts(), 1);
    let retirement = registry.retire("endpoint-1", 2);
    tokio::pin!(retirement);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), &mut retirement)
            .await
            .is_err()
    );
    drop(lease);
    retirement.await.unwrap();
    assert!(matches!(
        registry.acquire("provider-1", "endpoint-1", 2),
        Err(ConnectionError::NotInstalled)
    ));
    let record = registry.readback("endpoint-1").await.unwrap();
    assert_eq!(record.status, ConnectionStatus::Retired);
    let metadata = serde_json::to_string(&record).unwrap();
    for restricted in [
        "provider.openpc.test",
        "127.0.0.1",
        "credential-1",
        "BEGIN",
        "/rpc",
    ] {
        assert!(!metadata.contains(restricted));
    }
}

#[tokio::test]
async fn restart_requires_fresh_preparation_and_preserves_generation_and_capacity() {
    let certs = Certificates::new();
    let peer = Provider::start(certs.server_config("server"), OK, Duration::ZERO).await;
    let directory = certs.path.join("restart");
    let installed = {
        let registry = ConnectionRegistry::open(&directory, "target-1", 1).unwrap();
        registry
            .install(
                "provider-1",
                0,
                connection_generation(&certs, peer.port, 1, 1),
            )
            .await
            .unwrap()
    };
    assert!(matches!(
        ConnectionRegistry::open(&directory, "foreign-target", 1),
        Err(ConnectionError::Generation)
    ));
    let registry = ConnectionRegistry::open(&directory, "target-1", 1).unwrap();
    assert_eq!(
        registry.readback("endpoint-1").await.unwrap().status,
        ConnectionStatus::PreparationLost
    );
    assert!(matches!(
        registry.acquire("provider-1", "endpoint-1", 1),
        Err(ConnectionError::NotInstalled)
    ));
    assert!(matches!(
        registry
            .install(
                "provider-1",
                1,
                connection_generation(&certs, peer.port, 1, 1)
            )
            .await,
        Err(ConnectionError::Generation)
    ));
    let refreshed = registry
        .install(
            "provider-1",
            1,
            connection_generation(&certs, peer.port, 1, 2),
        )
        .await
        .unwrap();
    assert_eq!(refreshed.dispatcher_generation, 2);
    assert_eq!(
        refreshed.configuration_digest, installed.configuration_digest,
        "a fresh target-local resolution of the same admitted connection must retain its certified identity"
    );
    assert_ne!(
        refreshed.resolution_content_digest, installed.resolution_content_digest,
        "freshness state must remain independently committed"
    );
    // An endpoint mutation cannot hide behind a newer DNS answer while keeping
    // the signed endpoint generation unchanged.
    let wrong = connection_generation(&certs, peer.port + 1, 1, 3);
    assert!(matches!(
        registry.install("provider-1", 2, wrong).await,
        Err(ConnectionError::Generation)
    ));
    let mut e = endpoint("provider.openpc.test", peer.port);
    e.endpoint_id = "endpoint-2".into();
    let second = ProviderConnection::prepare(
        e.prepare(&policy(), resolution(&["127.0.0.1"])).unwrap(),
        certs.material("server"),
        4096,
        4096,
    )
    .unwrap();
    assert!(matches!(
        registry.install("provider-2", 0, second).await,
        Err(ConnectionError::Capacity)
    ));
    let lease = registry.acquire("provider-1", "endpoint-1", 2).unwrap();
    assert_eq!(send(lease.connection().unwrap()).await.unwrap(), b"{}");
    assert_eq!(peer.contacts(), 1);
}

#[tokio::test]
async fn failed_durable_replacement_withholds_existing_connection() {
    let certs = Certificates::new();
    let peer = Provider::start(certs.server_config("server"), OK, Duration::ZERO).await;
    let directory = certs.path.join("failure");
    let registry = ConnectionRegistry::open(&directory, "target-1", 1).unwrap();
    let (one, two) = tokio::join!(
        registry.install(
            "provider-1",
            0,
            connection_generation(&certs, peer.port, 1, 1)
        ),
        registry.install(
            "provider-1",
            0,
            connection_generation(&certs, peer.port, 1, 1)
        ),
    );
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    // A real atomic-file failure poisons the owner. No old connection may be
    // used after the new durable state has become uncertain.
    fs::create_dir(directory.join("provider-connections.next")).unwrap();
    assert_eq!(
        registry.retire("endpoint-1", 1).await,
        Err(ConnectionError::Owner)
    );
    assert!(matches!(
        registry.acquire("provider-1", "endpoint-1", 1),
        Err(ConnectionError::Owner)
    ));
    assert_eq!(peer.contacts(), 0);
}

#[path = "provider_connection/external_decision.rs"]
mod external_decision_tests;
#[path = "provider_connection/fact_observation.rs"]
mod fact_observation_tests;
#[path = "support/provider_probe.rs"]
mod probe_tests;
