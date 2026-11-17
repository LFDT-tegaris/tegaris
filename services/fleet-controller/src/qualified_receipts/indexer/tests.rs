use super::*;
use p256::ecdsa::{SigningKey, signature::Signer};

fn map(values: impl IntoIterator<Item = (u64, Value)>) -> Value {
    Value::Map(
        values
            .into_iter()
            .map(|(key, value)| (uint(key), value))
            .collect(),
    )
}
fn raw(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn hash(value: &[u8]) -> Value {
    raw(&Sha256::digest(value))
}
fn string(value: &str) -> Value {
    Value::Text(value.into())
}
fn set(value: &mut Value, key: u64, next: Value) {
    value
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(k, _)| integer(k) == Ok(key))
        .unwrap()
        .1 = next;
}
fn signer() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

struct Fixture {
    public: Vec<u8>,
    receipt: Value,
    payload: Vec<u8>,
    cose: Vec<u8>,
    trust: Vec<u8>,
    before: Vec<u8>,
    after: Vec<u8>,
    authority: Vec<u8>,
    event: Vec<u8>,
}
impl Fixture {
    fn new(profile: &str, present: bool) -> Self {
        let profile: serde_json::Value = serde_json::from_str(profile).unwrap();
        let version = profile["profileVersion"].as_u64().unwrap();
        let operation = "018f0000-0000-7000-8000-000000000010";
        let id = |n| raw(&uuid(&format!("018f0000-0000-7000-8000-{n:012}")).unwrap());
        let digest = raw(&unhex(
            profile["definitionDigest"]
                .as_str()
                .unwrap()
                .strip_prefix("sha256:")
                .unwrap(),
        )
        .unwrap());
        let action = string(profile["actionIntentId"].as_str().unwrap());
        let catalog = string(profile["catalogOperationId"].as_str().unwrap());
        let create = profile["transition"]["command"] == "CREATE";
        let mut public = unhex("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
        public.extend_from_slice(signer().verifying_key().to_sec1_point(false).as_bytes());
        let kid = string(&format!("sha256:{}", hex(&Sha256::digest(&public))));
        let profile_id = string(profile["profileId"].as_str().unwrap());
        let grants = Value::Array(vec![Value::Array(vec![
            profile_id.clone(),
            uint(version),
            digest.clone(),
            action.clone(),
            catalog.clone(),
        ])]);
        let trust = encode(&Value::Array(vec![
            string("pc.control.business-signing-trust.v1"),
            id(101),
            id(7201),
            string("local"),
            kid.clone(),
            raw(&public),
            id(195),
            uint(1),
            uint(1),
            uint(1000),
            uint(100000),
            string("BOOTSTRAP"),
            string("local initial trust"),
            raw(&[6; 32]),
            string("SECRET-SIGNING-KEY"),
            string("urn:openpc:secret:018f0000-0000-7000-8000-000000000600"),
            string("1"),
            uint(24001),
            uint(1),
            uint(338),
            grants,
        ]))
        .unwrap();
        let authority =
            serde_json::to_vec(&serde_json::json!({"operationId":operation,"decision":"ALLOW"}))
                .unwrap();
        let projection = |method| {
            let mut values = vec![
                (0, string("CLIENT_INDEXER")),
                (1, string("1.0.0")),
                (2, raw(&[method; 32])),
                (3, string("REGISTERED")),
            ];
            if version == 1 {
                values.push((4, raw(&[5; 32])));
            } else {
                values.push((4, uint(u64::from(present))));
                if present {
                    values.push((5, raw(&[5; 32])));
                }
            }
            map(values)
        };
        let state = |existence, revision, projection| {
            encode(&Value::Array(vec![
                string("pc.control.transition-state.v1"),
                digest.clone(),
                id(101),
                id(7201),
                string("indexer-profile"),
                id(20),
                uint(existence),
                uint(revision),
                projection,
            ]))
            .unwrap()
        };
        let before = if create {
            state(0, 0, map([]))
        } else {
            state(1, 1, projection(4))
        };
        let after = state(1, if create { 1 } else { 2 }, projection(8));
        let subject = string("urn:openpc:indexer-profile:018f0000-0000-7000-8000-000000000020");
        let event = encode(&map([
            (0, id(10)),
            (1, subject.clone()),
            (2, action.clone()),
            (3, raw(&[9; 32])),
        ]))
        .unwrap();
        let reference = |existence, revision, bytes: &[u8]| {
            map([(0, uint(existence)), (1, uint(revision)), (2, hash(bytes))])
        };
        let receipt = map([
            (0, id(1)),
            (1, raw(&unhex(DEFINITION).unwrap())),
            (2, profile_id),
            (3, uint(version)),
            (4, digest),
            (5, string("local")),
            (6, id(101)),
            (7, id(7201)),
            (8, id(10)),
            (9, action),
            (10, catalog),
            (11, string("indexer-profile")),
            (12, id(20)),
            (13, raw(&[7; 32])),
            (14, hash(&authority)),
            (15, raw(&[9; 32])),
            (16, raw(&[10; 32])),
            (17, id(30)),
            (
                18,
                reference(
                    if create { 0 } else { 1 },
                    if create { 0 } else { 1 },
                    &before,
                ),
            ),
            (19, reference(1, if create { 1 } else { 2 }, &after)),
            (
                20,
                Value::Array(vec![map([
                    (0, uint(2)),
                    (1, string("urn:openpc:identity-runtime-assertion:proof")),
                    (2, raw(&[11; 32])),
                ])]),
            ),
            (
                21,
                Value::Array(vec![map([
                    (0, id(40)),
                    (1, string("io.openpc.control.command.committed.v1")),
                    (
                        2,
                        string(
                            "https://schemas.openpc.local/event-payloads.schema.json#/$defs/CommandCommitted",
                        ),
                    ),
                    (3, string("urn:openpc:service:control-api")),
                    (4, subject),
                    (5, uint(1)),
                    (6, uint(10000)),
                    (7, id(10)),
                    (9, hash(&event)),
                ])]),
            ),
            (22, uint(1)),
            (23, uint(10000)),
            (24, kid),
            (25, hash(&trust)),
            (26, raw(&[12; 32])),
        ]);
        let mut result = Self {
            public,
            receipt,
            payload: vec![],
            cose: vec![],
            trust,
            before,
            after,
            authority,
            event,
        };
        result.sign();
        result
    }
    fn sign(&mut self) {
        self.payload = encode(&self.receipt).unwrap();
        let protected = encode(&map([
            (1, Value::Integer((-7).into())),
            (
                2,
                Value::Array(vec![uint(100), uint(101), uint(102), uint(103)]),
            ),
            (3, string("application/pc+cbor")),
            (
                4,
                raw(text(field(&self.receipt, 24).unwrap()).unwrap().as_bytes()),
            ),
            (100, uint(24001)),
            (101, uint(1)),
            (102, uint(338)),
            (103, uint(2)),
        ]))
        .unwrap();
        let signed = encode(&Value::Array(vec![
            string("Signature1"),
            raw(&protected),
            raw(b"pcplane:cose-sign1:v2\0"),
            raw(&self.payload),
        ]))
        .unwrap();
        let signature: Signature = signer().sign(&signed);
        self.cose = vec![0xd2];
        self.cose.extend(
            encode(&Value::Array(vec![
                raw(&protected),
                map([]),
                raw(&self.payload),
                raw(&signature.to_bytes()),
            ]))
            .unwrap(),
        );
    }
    fn check(&self) -> Result<Value> {
        verify(&Inputs {
            public: &self.public,
            payload: &self.payload,
            cose: &self.cose,
            trust: &self.trust,
            before: &self.before,
            after: &self.after,
            authority: &self.authority,
            event: &self.event,
        })
    }
    fn after(&mut self, mutate: impl FnOnce(&mut Value)) {
        let mut state = decode(&self.after).unwrap();
        mutate(&mut state);
        self.after = encode(&state).unwrap();
        let mut reference = field(&self.receipt, 19).unwrap().clone();
        set(&mut reference, 2, hash(&self.after));
        set(&mut self.receipt, 19, reference);
        self.sign();
    }
    fn trust(&mut self, mutate: impl FnOnce(&mut Vec<Value>)) {
        let mut trust = decode(&self.trust).unwrap();
        mutate(trust.as_array_mut().unwrap());
        self.trust = encode(&trust).unwrap();
        set(&mut self.receipt, 25, hash(&self.trust));
        self.sign();
    }
}
const PROFILES: [&str; 4] = [
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/canonical/business-transition-profiles/indexer-profile-create-v1.json"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/canonical/business-transition-profiles/indexer-profile-update-v1.json"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/canonical/business-transition-profiles/indexer-profile-create-v2.json"
    )),
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schemas/canonical/business-transition-profiles/indexer-profile-update-v2.json"
    )),
];

#[test]
fn signed_indexer_profiles_preserve_v1_and_bind_v2_presence_to_grant_state_and_outbox() {
    for profile in PROFILES {
        for present in [false, true] {
            let fixture = Fixture::new(profile, present);
            assert_eq!(
                fixture.check().unwrap(),
                fixture.receipt,
                "readback preserves signed bytes"
            );
            for change in 0..7 {
                let mut bad = Fixture::new(profile, present);
                match change {
                    0 => bad.trust(|v| v[18] = uint(2)), // lifecycle schema cannot sign ordinary state
                    1 => bad.trust(|v| v[14] = string("SECRET-API-TOKEN")),
                    2 => bad.trust(|v| {
                        v[20].as_array_mut().unwrap()[0].as_array_mut().unwrap()[1] = uint(3)
                    }),
                    3 => bad.trust(|v| {
                        v[20].as_array_mut().unwrap()[0].as_array_mut().unwrap()[2] = raw(&[0; 32])
                    }),
                    4 => bad.trust(|v| {
                        v[20].as_array_mut().unwrap()[0].as_array_mut().unwrap()[3] =
                            string("ACT-RUNTIME_READ_RPC-V1")
                    }),
                    5 => bad.trust(|v| {
                        let grant = v[20].as_array().unwrap()[0].clone();
                        v[20].as_array_mut().unwrap().push(grant);
                    }),
                    _ => bad.after(|v| v.as_array_mut().unwrap()[3] = raw(&[0; 16])),
                }
                assert!(
                    bad.check().is_err(),
                    "signed malformed trust/state {change}"
                );
            }
            let mut bad = Fixture::new(profile, present);
            bad.authority=serde_json::to_vec(&serde_json::json!({"operationId":"018f0000-0000-7000-8000-000000000010","decision":"DENY"})).unwrap();
            set(&mut bad.receipt, 14, hash(&bad.authority));
            bad.sign();
            assert!(bad.check().is_err());
            let mut bad = Fixture::new(profile, present);
            let mut event = decode(&bad.event).unwrap();
            set(&mut event, 2, string("ACT-RUNTIME_READ_RPC-V1"));
            bad.event = encode(&event).unwrap();
            let mut events = field(&bad.receipt, 21).unwrap().clone();
            set(&mut events.as_array_mut().unwrap()[0], 9, hash(&bad.event));
            set(&mut bad.receipt, 21, events);
            bad.sign();
            assert!(bad.check().is_err());
        }
    }
}

#[test]
fn signed_v2_state_rejects_ambiguous_absence_and_unknown_projection_fields() {
    for profile in &PROFILES[2..] {
        for present in [false, true] {
            for case in 0..7 {
                let mut bad = Fixture::new(profile, present);
                bad.after(|state| {
                    let projection = &mut state.as_array_mut().unwrap()[8];
                    let fields = projection.as_map_mut().unwrap();
                    match case {
                        0 => fields.retain(|(k, _)| integer(k) != Ok(4)),
                        1 => set(projection, 4, Value::Null),
                        2 => set(projection, 4, uint(2)),
                        3 => {
                            fields.retain(|(k, _)| integer(k) != Ok(5));
                            set(projection, 4, uint(1));
                        }
                        4 => {
                            fields.retain(|(k, _)| integer(k) != Ok(5));
                            fields.push((uint(5), raw(&[0; 32])));
                            set(projection, 4, uint(0));
                        }
                        5 => fields.push((uint(9), uint(0))),
                        _ => {
                            fields.retain(|(k, _)| integer(k) != Ok(5));
                            fields.push((uint(5), raw(&[0; 31])));
                            set(projection, 4, uint(1));
                        }
                    }
                });
                assert!(
                    bad.check().is_err(),
                    "signed malformed presence {present} case {case}"
                );
            }
        }
    }
}
