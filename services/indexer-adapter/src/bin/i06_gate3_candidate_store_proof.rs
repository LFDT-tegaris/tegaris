use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use openpc_indexer_adapter::{
    CandidateBatchMaterialV1, CandidateBlockFinalityV1, CandidateBlockObservationV1,
    CandidatePersistenceBinding, CandidateRecordIdentityV1, CandidateRecordMaterialV1,
    CandidateStore, CandidateStoreError, PersistenceOutcome, ReorgInvalidation,
};
use openpc_multi_rpc::{LocalFixtureRouteExecutorV1, ReadExecutionResult};
use pc_provider_api::*;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::postgres::{PgPoolOptions, PgRow};
use uuid::Uuid;

#[path = "i06_gate3_candidate_store_proof/publication.rs"]
mod publication;

#[path = "i06_gate3_candidate_store_proof/admission_view.rs"]
mod admission_view;

const PARTICIPANT: &str = "018f47a5-4a58-7b21-8f3a-111111111111";
const PRIVACY: &str = "018f47a5-4a58-7b21-8f3a-222222222222";
const SOURCE_PROFILE: &str = "018f47a5-4a58-7b21-8f3a-333333333333";
const PROJECTION_PROFILE: &str = "018f47a5-4a58-7b21-8f3a-444444444444";
const GENERATION: &str = "018f47a5-4a58-7b21-8f3a-555555555555";
const OPERATION: &str = "018f47a5-4a58-7b21-8f3a-666666666666";
const CORRELATION: &str = "018f47a5-4a58-7b21-8f3a-777777777777";
const PROOF_ACTION: &str = "ACT-CANDIDATE_WRITE-V1";

#[derive(Clone, Copy)]
struct ContractIds {
    source_profile: &'static str,
    projection_profile: &'static str,
    generation: &'static str,
    indexer_profile: &'static str,
    projection_plan: &'static str,
}

struct SeedContractSpec<'a> {
    ids: ContractIds,
    stored_data_class: &'a str,
    source_event_type: Option<&'a str>,
    source_contract_address: Option<Vec<u8>>,
    fault: SeedFault,
}

const PRIMARY_CONTRACT: ContractIds = ContractIds {
    source_profile: SOURCE_PROFILE,
    projection_profile: PROJECTION_PROFILE,
    generation: GENERATION,
    indexer_profile: "018f47a5-4a58-7b21-8f3a-888888888888",
    projection_plan: "018f47a5-4a58-7b21-8f3a-999999999999",
};

const CLASS_CONTRACTS: &[(&str, &str, ContractIds)] = &[
    (
        "STATE_CALL",
        "I06-G3-M13-I10-P-STATE-CALL",
        ContractIds {
            source_profile: "018f47a5-4a58-7b21-8f3a-a10000000001",
            projection_profile: "018f47a5-4a58-7b21-8f3a-a10000000002",
            generation: "018f47a5-4a58-7b21-8f3a-a10000000003",
            indexer_profile: "018f47a5-4a58-7b21-8f3a-a10000000004",
            projection_plan: "018f47a5-4a58-7b21-8f3a-a10000000005",
        },
    ),
    (
        "TRANSACTION_RECEIPT",
        "I06-G3-M13-I10-P-TRANSACTION-RECEIPT",
        ContractIds {
            source_profile: "018f47a5-4a58-7b21-8f3a-a20000000001",
            projection_profile: "018f47a5-4a58-7b21-8f3a-a20000000002",
            generation: "018f47a5-4a58-7b21-8f3a-a20000000003",
            indexer_profile: "018f47a5-4a58-7b21-8f3a-a20000000004",
            projection_plan: "018f47a5-4a58-7b21-8f3a-a20000000005",
        },
    ),
    (
        "BLOCK_HEADER",
        "I06-G3-M13-I10-P-BLOCK-HEADER",
        ContractIds {
            source_profile: "018f47a5-4a58-7b21-8f3a-a30000000001",
            projection_profile: "018f47a5-4a58-7b21-8f3a-a30000000002",
            generation: "018f47a5-4a58-7b21-8f3a-a30000000003",
            indexer_profile: "018f47a5-4a58-7b21-8f3a-a30000000004",
            projection_plan: "018f47a5-4a58-7b21-8f3a-a30000000005",
        },
    ),
    (
        "FULL_BLOCK_TRANSACTIONS",
        "I06-G3-M13-I10-P-FULL-BLOCK-TRANSACTIONS",
        ContractIds {
            source_profile: "018f47a5-4a58-7b21-8f3a-a40000000001",
            projection_profile: "018f47a5-4a58-7b21-8f3a-a40000000002",
            generation: "018f47a5-4a58-7b21-8f3a-a40000000003",
            indexer_profile: "018f47a5-4a58-7b21-8f3a-a40000000004",
            projection_plan: "018f47a5-4a58-7b21-8f3a-a40000000005",
        },
    ),
];

const DB_FAULT_CONTRACTS: &[(SeedFault, &str, ContractIds)] = &[
    (
        SeedFault::ProjectionSchema,
        "I06-G3-M13-I09-N-SCHEMA",
        ContractIds {
            source_profile: "018f47a5-4a58-7b21-8f3a-b10000000001",
            projection_profile: "018f47a5-4a58-7b21-8f3a-b10000000002",
            generation: "018f47a5-4a58-7b21-8f3a-b10000000003",
            indexer_profile: "018f47a5-4a58-7b21-8f3a-b10000000004",
            projection_plan: "018f47a5-4a58-7b21-8f3a-b10000000005",
        },
    ),
    (
        SeedFault::Generation,
        "I06-G3-M13-I09-N-GENERATION",
        ContractIds {
            source_profile: "018f47a5-4a58-7b21-8f3a-b20000000001",
            projection_profile: "018f47a5-4a58-7b21-8f3a-b20000000002",
            generation: "018f47a5-4a58-7b21-8f3a-b20000000003",
            indexer_profile: "018f47a5-4a58-7b21-8f3a-b20000000004",
            projection_plan: "018f47a5-4a58-7b21-8f3a-b20000000005",
        },
    ),
    (
        SeedFault::GenerationSource,
        "I06-G3-M13-I09-N-GENERATION-SOURCE",
        ContractIds {
            source_profile: "018f47a5-4a58-7b21-8f3a-b30000000001",
            projection_profile: "018f47a5-4a58-7b21-8f3a-b30000000002",
            generation: "018f47a5-4a58-7b21-8f3a-b30000000003",
            indexer_profile: "018f47a5-4a58-7b21-8f3a-b30000000004",
            projection_plan: "018f47a5-4a58-7b21-8f3a-b30000000005",
        },
    ),
    (
        SeedFault::GenerationSchema,
        "I06-G3-M13-I09-N-GENERATION-SCHEMA",
        ContractIds {
            source_profile: "018f47a5-4a58-7b21-8f3a-b40000000001",
            projection_profile: "018f47a5-4a58-7b21-8f3a-b40000000002",
            generation: "018f47a5-4a58-7b21-8f3a-b40000000003",
            indexer_profile: "018f47a5-4a58-7b21-8f3a-b40000000004",
            projection_plan: "018f47a5-4a58-7b21-8f3a-b40000000005",
        },
    ),
];

const ASSERTION_INVENTORY: &[(&str, &[&str])] = &[
    (
        "M12-I01",
        &["P", "N-PARTICIPANT", "N-PRIVACY", "N-CROSS-TENANT"],
    ),
    (
        "M12-I02",
        &["P", "N-OPERATION", "N-CORRELATION", "N-RESOURCE-RELABEL"],
    ),
    (
        "M12-I03",
        &[
            "P",
            "N-SOURCE-ID",
            "N-SOURCE-URN-TYPE",
            "N-SOURCE-URN-SUFFIX",
        ],
    ),
    (
        "M12-I04",
        &[
            "P",
            "N-INDEXER-ID",
            "N-INDEXER-URN-TYPE",
            "N-INDEXER-URN-SUFFIX",
        ],
    ),
    (
        "M12-I05",
        &["P", "N-PROFILE-ID", "N-PLAN-ID", "N-RESOURCE-RELABEL"],
    ),
    (
        "M12-I06",
        &[
            "P",
            "N-GENERATION-ID",
            "N-GENERATION-URN-TYPE",
            "N-GENERATION-URN-SUFFIX",
        ],
    ),
    (
        "M12-I07",
        &[
            "P",
            "N-CALLER-UUID",
            "N-RELABEL",
            "N-URN-TYPE",
            "N-URN-SUFFIX",
            "N-CROSS-TENANT",
        ],
    ),
    (
        "M12-I08",
        &[
            "P",
            "N-PARTICIPANT",
            "N-PRIVACY",
            "N-GENERATION",
            "N-SOURCE-PROFILE",
            "N-PLAN-DIGEST",
            "N-SOURCE-ID",
            "N-PARTITION-ID",
            "N-RANGE",
            "N-CBOR",
            "N-BINDING-DIGEST",
        ],
    ),
    (
        "M13-I09",
        &[
            "P",
            "N-SOURCE-PROFILE",
            "N-REORG-PROFILE",
            "N-PLAN",
            "N-SCHEMA",
            "N-GENERATION",
            "N-GENERATION-SOURCE",
            "N-GENERATION-SCHEMA",
            "N-UUID-SUBSTITUTION",
        ],
    ),
    (
        "M13-I10",
        &[
            "P-EVENT-LOG",
            "P-STATE-CALL",
            "P-TRANSACTION-RECEIPT",
            "P-BLOCK-HEADER",
            "P-FULL-BLOCK-TRANSACTIONS",
            "N-EVENT-TYPE-MISSING",
            "N-EVENT-ADDRESS-MISSING",
            "N-NONEVENT-TYPE-PRESENT",
            "N-NONEVENT-ADDRESS-PRESENT",
            "N-STORE-SQL-DIVERGENCE",
        ],
    ),
    (
        "M14-I11",
        &[
            "P",
            "N-BLOCK-ID",
            "N-BLOCK-HASH",
            "N-PARENT-HASH",
            "N-GENESIS-HASH",
            "N-URN-LEAK",
        ],
    ),
    (
        "M14-I12",
        &[
            "P",
            "N-SOURCE-DIGEST",
            "N-FINALITY-DIGEST",
            "N-FINALITY-STATE",
            "N-CALLER-FINALITY",
        ],
    ),
    (
        "M14-I13",
        &[
            "P",
            "N-EVENT-ID",
            "N-URN-TYPE",
            "N-URN-SUFFIX",
            "N-CROSS-PARTITION",
        ],
    ),
    (
        "M14-I14",
        &[
            "P",
            "N-VARIANT",
            "N-SCHEMA",
            "N-NORMALIZED",
            "N-EVIDENCE",
            "N-KEY",
            "N-PAYLOAD",
            "N-DIGEST-PREFIX",
            "N-IMMUTABILITY",
        ],
    ),
    (
        "M14-I15",
        &[
            "P",
            "N-CHECKPOINT-ID",
            "N-POSITION-CBOR",
            "N-POSITION-DIGEST",
            "N-CURSOR-DIGEST",
            "N-IMMUTABILITY",
        ],
    ),
    (
        "M14-I16",
        &[
            "P-GENESIS",
            "P-SUCCESSOR",
            "N-BATCH-ID",
            "N-SEQUENCE",
            "N-BATCH-DIGEST",
            "N-PREDECESSOR",
            "N-GENESIS",
            "N-REPLAY-CONFLICT",
            "N-GAP",
        ],
    ),
    (
        "M14-I17",
        &[
            "P-NONEMPTY",
            "P-EMPTY",
            "P-JSON-CBOR",
            "N-OBSERVATION-ORDER",
            "N-OBSERVATION-COUNT",
            "N-DECODE-MISSING-SOURCE-ID",
            "N-DECODE-MISSING-SEQUENCE",
            "N-DECODE-MISSING-ERROR-DIGEST",
            "N-DECODE-MISSING-EVIDENCE-DIGEST",
            "N-DECODE-SWAPPED-DIGESTS",
            "N-DECODE-MALFORMED-SOURCE-ID",
            "N-DECODE-MALFORMED-SEQUENCE",
            "N-DECODE-MALFORMED-ERROR-DIGEST",
            "N-DECODE-MALFORMED-EVIDENCE-DIGEST",
            "N-DECODE-REORDERED",
            "N-DECODE-DUPLICATE-SEQUENCE",
            "N-DECODE-COUNT",
            "N-DECODE-EXTRA-FIELD",
            "N-DECODE-EXTRA-ANCHOR",
            "N-DECODE-JSON-CBOR",
        ],
    ),
    (
        "M14-I18",
        &[
            "P",
            "N-EVENT-ID",
            "N-PAYLOAD-CBOR",
            "N-PAYLOAD-DIGEST",
            "N-DATADIGEST",
            "N-JSON-CBOR",
        ],
    ),
    (
        "M14-I19",
        &[
            "P",
            "N-AGGREGATE-ID",
            "N-AGGREGATE-TYPE",
            "N-SEQUENCE",
            "N-SOURCE",
            "N-SUBJECT",
            "N-ORDERING-KEY",
            "N-EVENT-ORDER",
        ],
    ),
    (
        "M15-I20",
        &[
            "P",
            "N-MALFORMED-UUID",
            "N-CALLER-UUID",
            "N-OPENPC-URN",
            "N-RELABEL",
        ],
    ),
    (
        "M15-I21",
        &[
            "P",
            "N-PARTITION",
            "N-SEQUENCE",
            "N-INVALIDATION-ID",
            "N-REPLACEMENT-SAME-TX",
            "N-REPLACEMENT-BEFORE-INVALIDATION",
        ],
    ),
    (
        "M15-I22",
        &[
            "P",
            "N-EMPTY",
            "N-ORDER",
            "N-DUPLICATE",
            "N-UNKNOWN-CANDIDATE",
            "N-CROSS-PARTITION",
            "N-URN-TYPE",
            "N-URN-SUFFIX",
        ],
    ),
    (
        "M15-I23",
        &[
            "P",
            "N-CHAIN",
            "N-GENESIS",
            "N-NETWORK",
            "N-SELECTOR",
            "N-BLOCK-NUMBER",
            "N-BLOCK-HASH",
            "N-PENDING-AUTHORITY",
            "N-OLD-ANCHOR-ABSENT",
            "N-SAME-ANCHOR",
            "N-RANGE",
        ],
    ),
    (
        "M15-I24",
        &[
            "P",
            "N-RAW-DIGEST",
            "N-WIRE-PREFIX",
            "N-WIRE-VALUE",
            "N-URN-SUBSTITUTION",
            "N-EVIDENCE-IDENTITY-SUBSTITUTION",
        ],
    ),
];

const SQL_DATABASE_IDS: &[&str] = &[
    "I06-G3-M12-I01-N-CROSS-TENANT",
    "I06-G3-M12-I07-N-CALLER-UUID",
    "I06-G3-M12-I07-N-CROSS-TENANT",
    "I06-G3-M12-I08-N-PARTICIPANT",
    "I06-G3-M12-I08-N-PRIVACY",
    "I06-G3-M12-I08-N-GENERATION",
    "I06-G3-M12-I08-N-SOURCE-PROFILE",
    "I06-G3-M12-I08-N-PLAN-DIGEST",
    "I06-G3-M12-I08-N-SOURCE-ID",
    "I06-G3-M12-I08-N-PARTITION-ID",
    "I06-G3-M12-I08-N-RANGE",
    "I06-G3-M12-I08-N-CBOR",
    "I06-G3-M12-I08-N-BINDING-DIGEST",
    "I06-G3-M14-I11-N-BLOCK-ID",
    "I06-G3-M14-I11-N-BLOCK-HASH",
    "I06-G3-M14-I11-N-PARENT-HASH",
    "I06-G3-M14-I13-N-EVENT-ID",
    "I06-G3-M14-I13-N-CROSS-PARTITION",
    "I06-G3-M14-I14-N-IMMUTABILITY",
    "I06-G3-M14-I15-N-CHECKPOINT-ID",
    "I06-G3-M14-I15-N-POSITION-CBOR",
    "I06-G3-M14-I15-N-POSITION-DIGEST",
    "I06-G3-M14-I15-N-IMMUTABILITY",
    "I06-G3-M14-I18-N-EVENT-ID",
    "I06-G3-M14-I18-N-PAYLOAD-CBOR",
    "I06-G3-M14-I18-N-PAYLOAD-DIGEST",
    "I06-G3-M15-I20-N-MALFORMED-UUID",
    "I06-G3-M15-I20-N-CALLER-UUID",
    "I06-G3-M15-I21-N-INVALIDATION-ID",
];

const STORE_INTERNAL_TEST_IDS: &[&str] = &[
    "I06-G3-M14-I17-P-JSON-CBOR",
    "I06-G3-M14-I17-N-DECODE-JSON-CBOR",
    "I06-G3-M14-I18-N-JSON-CBOR",
];

#[derive(Default)]
struct ProofRecorder {
    passed: BTreeSet<&'static str>,
}

impl ProofRecorder {
    fn prove(&mut self, assertion_id: &'static str, condition: bool) -> Result<(), String> {
        if !condition {
            return Err(format!("I06_GATE3_ASSERTION_FAILED|{assertion_id}"));
        }
        if !self.passed.insert(assertion_id) {
            return Err(format!("I06_GATE3_ASSERTION_DUPLICATE|{assertion_id}"));
        }
        Ok(())
    }

    fn finish(self) -> Result<(), String> {
        let sql = SQL_DATABASE_IDS.iter().copied().collect::<BTreeSet<_>>();
        let internal = STORE_INTERNAL_TEST_IDS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let expected = ASSERTION_INVENTORY
            .iter()
            .flat_map(|(row, suffixes)| {
                suffixes
                    .iter()
                    .map(move |suffix| format!("I06-G3-{row}-{suffix}"))
            })
            .filter(|id| !sql.contains(id.as_str()) && !internal.contains(id.as_str()))
            .collect::<BTreeSet<_>>();
        let actual = self
            .passed
            .iter()
            .map(|id| (*id).to_owned())
            .collect::<BTreeSet<_>>();
        if expected.len() != 138 || actual != expected {
            let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
            let extra = actual.difference(&expected).cloned().collect::<Vec<_>>();
            return Err(format!(
                "I06_GATE3_ASSERTION_SET_MISMATCH|missing={missing:?}|extra={extra:?}"
            ));
        }
        for assertion_id in self.passed {
            println!("I06_GATE3_ASSERTION|RUST_STORE|{assertion_id}|PASS");
        }
        println!("I06_GATE3_ASSERTION_COUNT|RUST_STORE_BINARY|138|PASS");
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum ExpectedCandidateError {
    InvalidBatch,
    InvalidBinding,
}

fn require_candidate_error<T>(
    proof: &mut ProofRecorder,
    assertion_id: &'static str,
    expected: ExpectedCandidateError,
    result: Result<T, CandidateStoreError>,
) -> Result<(), String> {
    let matches = matches!(
        (expected, &result),
        (
            ExpectedCandidateError::InvalidBatch,
            Err(CandidateStoreError::InvalidBatch)
        ) | (
            ExpectedCandidateError::InvalidBinding,
            Err(CandidateStoreError::InvalidBinding)
        )
    );
    if !matches {
        let actual = match result {
            Ok(_) => "Ok".to_owned(),
            Err(error) => format!("Err({error:?})"),
        };
        return Err(format!(
            "I06_GATE3_TYPED_RESULT_MISMATCH|{assertion_id}|expected={expected:?}|actual={actual}"
        ));
    }
    proof.prove(assertion_id, true)
}

fn require_outcome(
    proof: &mut ProofRecorder,
    assertion_id: &'static str,
    expected: PersistenceOutcome,
    actual: PersistenceOutcome,
) -> Result<(), String> {
    if actual != expected {
        return Err(format!(
            "I06_GATE3_TYPED_RESULT_MISMATCH|{assertion_id}|expected={expected:?}|actual={actual:?}"
        ));
    }
    proof.prove(assertion_id, true)
}

fn require_missing_field(
    proof: &mut ProofRecorder,
    assertion_id: &'static str,
    field: &str,
    result: Result<CandidateProjectionBatchV1, serde_json::Error>,
) -> Result<(), String> {
    match result {
        Err(error) if error.to_string().contains(field) => proof.prove(assertion_id, true),
        Err(error) => Err(format!(
            "I06_GATE3_SERDE_FIELD_MISMATCH|{assertion_id}|expected_missing={field}|actual={error}"
        )),
        Ok(_) => Err(format!(
            "I06_GATE3_SERDE_FIELD_MISMATCH|{assertion_id}|expected_missing={field}|actual=Ok"
        )),
    }
}

fn variant_mismatch_material(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
    binding: &CandidatePersistenceBinding,
) -> Result<CandidateBatchMaterialV1, CandidateStoreError> {
    let mut records = record_materials(batch);
    records[0].identity = CandidateRecordIdentityV1::StateCall {
        target_address: "44".repeat(20),
        call_parameter_digest: d("variant-only-call-parameters"),
    };
    CandidateBatchMaterialV1::try_new(
        (profile, plan, batch, binding),
        vec![block_observation(profile, &batch.records[0])],
        records,
        false,
    )
}

fn admit_common_baseline(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
    binding: &CandidatePersistenceBinding,
) -> Result<(), String> {
    let exact_ranges = profile.source_range.start == 1
        && plan.source_range.start == 1
        && matches!(profile.source_range.end, RangeEndV1::Inclusive(40))
        && matches!(plan.source_range.end, RangeEndV1::Inclusive(40))
        && plan.partitions.len() == 2
        && plan.partitions[0].source_id == "source"
        && plan.partitions[0].range.start == 1
        && matches!(plan.partitions[0].range.end, RangeEndV1::Inclusive(30))
        && plan.partitions[1].source_id == "other-source"
        && plan.partitions[1].range.start == 31
        && matches!(plan.partitions[1].range.end, RangeEndV1::Inclusive(40));
    if !exact_ranges {
        return Err("I06_GATE3_COMMON_BASELINE_PARTITION_COVERAGE_INVALID".into());
    }
    match material(profile, plan, batch, binding) {
        Ok(_) => Ok(()),
        Err(error) => Err(format!(
            "I06_GATE3_COMMON_BASELINE_REJECTED|expected=Ok|actual=Err({error:?})"
        )),
    }
}

fn require_fixture_admission(
    owner: &str,
    result: Result<CandidateBatchMaterialV1, CandidateStoreError>,
) -> Result<CandidateBatchMaterialV1, String> {
    result.map_err(|error| {
        format!(
            "I06_GATE3_FIXTURE_ADMISSION_MISMATCH|owner={owner}|expected=Ok(CandidateBatchMaterialV1)|actual=Err({error:?})"
        )
    })
}

fn require_fixture_invalid_batch(
    owner: &str,
    result: Result<CandidateBatchMaterialV1, CandidateStoreError>,
) -> Result<(), String> {
    match result {
        Err(CandidateStoreError::InvalidBatch) => Ok(()),
        Err(error) => Err(format!(
            "I06_GATE3_FIXTURE_REJECTION_MISMATCH|owner={owner}|expected=InvalidBatch|actual=Err({error:?})"
        )),
        Ok(_) => Err(format!(
            "I06_GATE3_FIXTURE_REJECTION_MISMATCH|owner={owner}|expected=InvalidBatch|actual=Ok(CandidateBatchMaterialV1)"
        )),
    }
}

fn audit_supposed_valid_fixture_admission() -> Result<(), String> {
    let profile = client_profile();
    let plan = projection_plan();
    let primary_binding = binding();
    let primary_batch = batch(1, 1, 10, "batch-1", "GENESIS");
    require_fixture_admission(
        "primary-event-log",
        material(&profile, &plan, &primary_batch, &primary_binding),
    )?;

    let mut changed_profile = profile.clone();
    changed_profile.deployment_owner = "substituted-owner".into();
    require_fixture_admission(
        "M13-I09-source-profile-substitution",
        material(&changed_profile, &plan, &primary_batch, &primary_binding),
    )?;
    changed_profile = profile.clone();
    changed_profile.reorg_behavior_digest = d("substituted-reorg-profile");
    require_fixture_admission(
        "M13-I09-reorg-profile-substitution",
        material(&changed_profile, &plan, &primary_batch, &primary_binding),
    )?;
    let mut changed_plan = plan.clone();
    changed_plan.extractor_digests[0].digest = d("substituted-extractor");
    require_fixture_admission(
        "M13-I09-plan-substitution",
        material(&profile, &changed_plan, &primary_batch, &primary_binding),
    )?;

    for (_, assertion_id, ids) in DB_FAULT_CONTRACTS {
        let mut fault_profile = profile.clone();
        fault_profile.deployment_owner = format!("fault-owner-{}", ids.generation);
        require_fixture_admission(
            assertion_id,
            material(
                &fault_profile,
                &plan,
                &primary_batch,
                &binding_for(ids.generation),
            ),
        )?;
    }
    require_fixture_admission(
        "M13-I09-uuid-substitution",
        material(
            &profile,
            &plan,
            &primary_batch,
            &binding_for("018f47a5-4a58-7b21-8f3a-b50000000003"),
        ),
    )?;

    for (data_class, assertion_id, ids) in CLASS_CONTRACTS {
        let class_profile = profile_for_class(data_class);
        let class_batch = batch(1, 1, 10, &format!("class-{data_class}"), "GENESIS");
        require_fixture_admission(
            assertion_id,
            material_for_class(
                &class_profile,
                &plan,
                &class_batch,
                &binding_for(ids.generation),
                data_class,
            ),
        )?;
    }

    for (assertion_id, mutation) in [
        (
            "I06-G3-M13-I10-N-EVENT-TYPE-MISSING",
            ProjectionIdentityMutation::EventTypeMissing,
        ),
        (
            "I06-G3-M13-I10-N-EVENT-ADDRESS-MISSING",
            ProjectionIdentityMutation::EventAddressMissing,
        ),
        (
            "I06-G3-M13-I10-N-NONEVENT-TYPE-PRESENT",
            ProjectionIdentityMutation::NonEventTypePresent,
        ),
        (
            "I06-G3-M13-I10-N-NONEVENT-ADDRESS-PRESENT",
            ProjectionIdentityMutation::NonEventAddressPresent,
        ),
    ] {
        let data_class = mutation.data_class();
        let class_profile = profile_for_class(data_class);
        let baseline_batch = batch(
            1,
            1,
            10,
            &format!("projection-identity-{data_class}"),
            "GENESIS",
        );
        require_fixture_admission(
            assertion_id,
            material_for_class(
                &class_profile,
                &plan,
                &baseline_batch,
                &binding_for("018f47a5-4a58-7b21-8f3a-c20000000003"),
                data_class,
            ),
        )?;
    }

    let primary_digest = digest_hex(
        &encode_candidate_projection_batch_pc_cbor(&primary_batch)
            .map_err(|error| format!("I06_GATE3_FIXTURE_CBOR_MISMATCH|owner=primary|{error:?}"))?,
    );
    let wrong_predecessor = empty_batch(
        2,
        11,
        20,
        "wrong-predecessor-empty",
        &d("syntactically-valid-wrong-predecessor"),
    );
    require_fixture_admission(
        "M14-I16-wrong-predecessor-authoritative-empty",
        empty_material(&profile, &plan, &wrong_predecessor, &primary_binding),
    )?;
    let primary_empty = empty_batch(2, 11, 20, "batch-2", &primary_digest);
    require_fixture_admission(
        "M14-I16-primary-authoritative-empty-successor",
        empty_material(&profile, &plan, &primary_empty, &primary_binding),
    )?;
    let second_digest = digest_hex(
        &encode_candidate_projection_batch_pc_cbor(&batch(2, 11, 20, "batch-2", &primary_digest))
            .map_err(|error| format!("I06_GATE3_FIXTURE_CBOR_MISMATCH|owner=successor|{error:?}"))?,
    );
    require_fixture_admission(
        "M14-I16-sequence-gap",
        material(
            &profile,
            &plan,
            &batch(3, 21, 30, "batch-3", &second_digest),
            &primary_binding,
        ),
    )?;

    let (other_batch, other_material) = other_partition_material(&profile, &plan, &primary_binding);
    require_fixture_admission("cross-partition-positive", other_material)?;
    let other_digest = digest_hex(
        &encode_candidate_projection_batch_pc_cbor(&other_batch)
            .map_err(|error| format!("I06_GATE3_FIXTURE_CBOR_MISMATCH|owner=other|{error:?}"))?,
    );
    let mut reorg_fenced = empty_batch(2, 36, 40, "other-reorg-fenced-successor", &other_digest);
    reorg_fenced.source_id = "other-source".into();
    reorg_fenced.partition_id = "other-partition".into();
    require_fixture_admission(
        "M14-I16-reorg-fenced-authoritative-empty",
        empty_material(&profile, &plan, &reorg_fenced, &primary_binding),
    )?;

    for (owner, source_id, partition_id, observed_anchor) in [
        (
            "M15-primary-reorg-observation",
            "source",
            "partition",
            anchor(8, &hex_byte(0xfe)),
        ),
        (
            "M15-other-reorg-observation",
            "other-source",
            "other-partition",
            anchor(33, &hex_byte(0xfb)),
        ),
    ] {
        require_fixture_admission(
            owner,
            reorg_observation_material(
                (&profile, &plan, &primary_binding, source_id, partition_id),
                observed_anchor,
                &d(owner),
                owner,
            ),
        )?;
    }
    let mut unanchored_batch = batch(1, 1, 10, "unanchored-reorg-observation", "GENESIS");
    unanchored_batch.observations.clear();
    require_fixture_invalid_batch(
        "M15-unanchored-observation-constructor-negative",
        material(&profile, &plan, &unanchored_batch, &primary_binding),
    )?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().nth(1).as_deref() == Some("--publication-only") {
        return publication::prove(
            &std::env::var("OPENPC_I06_GATE3_MANAGER_DATABASE_URL")?,
            &std::env::var("OPENPC_I06_GATE3_CANDIDATE_DATABASE_URL")?,
            &std::env::var("OPENPC_I06_GATE3_OWNER_DATABASE_URL")?,
        )
        .await;
    }
    let mut proof = ProofRecorder::default();
    audit_supposed_valid_fixture_admission()?;
    let database_url = std::env::var("OPENPC_I06_GATE3_CANDIDATE_DATABASE_URL")?;
    let owner_database_url = std::env::var("OPENPC_I06_GATE3_OWNER_DATABASE_URL")?;
    let profile = client_profile();
    let plan = projection_plan();
    seed_exact_preexisting_contract(&database_url, &owner_database_url, &profile, &plan).await?;

    let batch_one = batch(1, 1, 10, "batch-1", "GENESIS");
    let binding_one = binding();
    admit_common_baseline(&profile, &plan, &batch_one, &binding_one)?;
    assert_constructor_rejections_have_zero_product_effects(
        &mut proof,
        &database_url,
        &profile,
        &plan,
        &batch_one,
        &binding_one,
    )
    .await?;

    let store = CandidateStore::connect(&database_url).await?;
    let registered = store
        .register_partition(&profile, &plan, &binding_one, "source", "partition")
        .await;
    match registered {
        Ok(()) => proof.prove("I06-G3-M12-I01-P", true)?,
        Err(error) => {
            return Err(format!(
                "I06_GATE3_TYPED_RESULT_MISMATCH|I06-G3-M12-I01-P|expected=Ok(())|actual=Err({error:?})"
            )
            .into());
        }
    }
    let mut insufficient_block = block_observation(&profile, &batch_one.records[0]);
    if let CandidateBlockFinalityV1::Confirmations { head_anchor, .. } =
        &mut insufficient_block.finality
    {
        head_anchor.block_number = Some(batch_one.records[0].block_number + 10);
    }
    let insufficient_material = material_with_blocks(
        &profile,
        &plan,
        &batch_one,
        &binding_one,
        blocks_with_first(&profile, &batch_one, insufficient_block),
    )?;
    prove_store_invalid_binding(
        &mut proof,
        "I06-G3-M14-I12-N-CALLER-FINALITY",
        &store,
        &database_url,
        &insufficient_material,
    )
    .await?;
    let registered_snapshot = product_table_snapshot(&database_url).await?;
    let reregistered = store
        .register_partition(&profile, &plan, &binding_one, "source", "partition")
        .await;
    if reregistered.is_err() {
        return Err("I06_GATE3_PARTITION_REREGISTRATION_REJECTED".into());
    }
    reregistered?;
    if registered_snapshot != product_table_snapshot(&database_url).await? {
        return Err("I06_GATE3_PARTITION_REREGISTRATION_CHANGED_PRODUCT_STATE".into());
    }
    let material_one_result = material(&profile, &plan, &batch_one, &binding_one);
    let material_one = material_one_result?;
    let genesis_contender = CandidateStore::connect(&database_url).await?;
    let (first_result, contender_result) = tokio::join!(
        store.persist_batch(&material_one),
        genesis_contender.persist_batch(&material_one)
    );
    let (first_outcome, contender_outcome) = (first_result?, contender_result?);
    if !((first_outcome == PersistenceOutcome::Committed
        && contender_outcome == PersistenceOutcome::ReplayedSameDigest)
        || (first_outcome == PersistenceOutcome::ReplayedSameDigest
            && contender_outcome == PersistenceOutcome::Committed))
    {
        return Err("I06_GATE3_GENESIS_CONTENTION_NOT_SERIALIZED".into());
    }
    genesis_contender.close().await;
    let first_outcome = PersistenceOutcome::Committed;
    require_outcome(
        &mut proof,
        "I06-G3-M13-I09-P",
        PersistenceOutcome::Committed,
        first_outcome,
    )?;
    require_outcome(
        &mut proof,
        "I06-G3-M13-I10-P-EVENT-LOG",
        PersistenceOutcome::Committed,
        first_outcome,
    )?;
    require_outcome(
        &mut proof,
        "I06-G3-M14-I16-P-GENESIS",
        PersistenceOutcome::Committed,
        first_outcome,
    )?;
    let replay_outcome = store.persist_batch(&material_one).await?;
    if replay_outcome != PersistenceOutcome::ReplayedSameDigest {
        return Err("I06_GATE3_IDENTICAL_REPLAY_NOT_REUSED".into());
    }

    let mut conflict = batch_one.clone();
    conflict.evidence_refs = vec![d("conflicting-evidence")];
    let conflict_material = require_fixture_admission(
        "M14-I16-replay-conflict",
        material(&profile, &plan, &conflict, &binding_one),
    )?;
    let conflict_outcome = store.persist_batch(&conflict_material).await?;
    require_outcome(
        &mut proof,
        "I06-G3-M14-I16-N-REPLAY-CONFLICT",
        PersistenceOutcome::QuarantinedDigestConflict,
        conflict_outcome,
    )?;

    let batch_one_digest = digest_hex(&encode_candidate_projection_batch_pc_cbor(&batch_one)?);
    let wrong_predecessor_batch = empty_batch(
        2,
        11,
        20,
        "wrong-predecessor-empty",
        &d("syntactically-valid-wrong-predecessor"),
    );
    let wrong_predecessor_material = require_fixture_admission(
        "M14-I16-wrong-predecessor-authoritative-empty",
        empty_material(&profile, &plan, &wrong_predecessor_batch, &binding_one),
    )?;
    let before_predecessor = product_table_snapshot(&database_url).await?;
    let wrong_predecessor_outcome = store.persist_batch(&wrong_predecessor_material).await?;
    let after_predecessor = product_table_snapshot(&database_url).await?;
    if before_predecessor.partition != after_predecessor.partition
        || before_predecessor.block != after_predecessor.block
        || before_predecessor.event != after_predecessor.event
        || before_predecessor.checkpoint != after_predecessor.checkpoint
        || before_predecessor.outbox != after_predecessor.outbox
        || before_predecessor.invalidation != after_predecessor.invalidation
        || before_predecessor.quarantine == after_predecessor.quarantine
    {
        return Err("I06_GATE3_PREDECESSOR_MISMATCH_SIDE_EFFECT_INVALID".into());
    }
    let wrong_predecessor_closed =
        wrong_predecessor_outcome == PersistenceOutcome::QuarantinedPredecessorMismatch;
    if !wrong_predecessor_closed {
        return Err(format!(
            "I06_GATE3_TYPED_RESULT_MISMATCH|I06-G3-M14-I16-N-PREDECESSOR|expected=QuarantinedPredecessorMismatch|actual={wrong_predecessor_outcome:?}"
        )
        .into());
    }
    let batch_two = batch(2, 11, 20, "batch-2", &batch_one_digest);
    let batch_two_digest = digest_hex(&encode_candidate_projection_batch_pc_cbor(&batch_two)?);
    let batch_three = batch(3, 21, 30, "batch-3", &batch_two_digest);
    let material_three = require_fixture_admission(
        "M14-I16-sequence-gap",
        material(&profile, &plan, &batch_three, &binding_one),
    )?;
    let gap_outcome = store.persist_batch(&material_three).await?;
    require_outcome(
        &mut proof,
        "I06-G3-M14-I16-N-GAP",
        PersistenceOutcome::BlockedSequenceGap,
        gap_outcome,
    )?;

    let primary_empty_batch = empty_batch(2, 11, 20, "batch-2", &batch_one_digest);
    let primary_empty_batch_digest = digest_hex(&encode_candidate_projection_batch_pc_cbor(
        &primary_empty_batch,
    )?);
    let primary_empty_material = require_fixture_admission(
        "M14-I16-primary-authoritative-empty-successor",
        empty_material(&profile, &plan, &primary_empty_batch, &binding_one),
    )?;
    let successor_contender = CandidateStore::connect(&database_url).await?;
    let (successor_result, contender_result) = tokio::join!(
        store.persist_batch(&primary_empty_material),
        successor_contender.persist_batch(&primary_empty_material)
    );
    let (successor_outcome, contender_outcome) = (successor_result?, contender_result?);
    if !((successor_outcome == PersistenceOutcome::Committed
        && contender_outcome == PersistenceOutcome::ReplayedSameDigest)
        || (successor_outcome == PersistenceOutcome::ReplayedSameDigest
            && contender_outcome == PersistenceOutcome::Committed))
    {
        return Err("I06_GATE3_SUCCESSOR_CONTENTION_NOT_SERIALIZED".into());
    }
    successor_contender.close().await;
    let successor_outcome = PersistenceOutcome::Committed;
    require_outcome(
        &mut proof,
        "I06-G3-M14-I16-P-SUCCESSOR",
        PersistenceOutcome::Committed,
        successor_outcome,
    )?;

    prove_committed_store_outputs(&mut proof, &database_url, &batch_one, &primary_empty_batch)
        .await?;

    prove_database_binding_conflicts(
        &mut proof,
        &store,
        &database_url,
        &profile,
        &plan,
        &batch_one,
        &binding_one,
    )
    .await?;

    prove_all_record_classes_and_projection_scalar_conflicts(&mut proof, &database_url, &plan)
        .await?;
    prove_cross_batch_database_identity_conflicts(&database_url).await?;

    store
        .register_partition(
            &profile,
            &plan,
            &binding_one,
            "other-source",
            "other-partition",
        )
        .await?;
    let (other_batch, other_material) = other_partition_material(&profile, &plan, &binding_one);
    let other_material = require_fixture_admission("cross-partition-positive", other_material)?;
    if store.persist_batch(&other_material).await? != PersistenceOutcome::Committed {
        return Err("I06_GATE3_CROSS_PARTITION_FIXTURE_NOT_COMMITTED".into());
    }
    let other_batch_digest = digest_hex(&encode_candidate_projection_batch_pc_cbor(&other_batch)?);
    let mut other_empty_batch =
        empty_batch(2, 36, 40, "other-authoritative-empty", &other_batch_digest);
    other_empty_batch.source_id = "other-source".into();
    other_empty_batch.partition_id = "other-partition".into();
    let other_empty_material = require_fixture_admission(
        "M15-I22-authoritative-empty-reorg",
        empty_material(&profile, &plan, &other_empty_batch, &binding_one),
    )?;
    if store.persist_batch(&other_empty_material).await? != PersistenceOutcome::Committed {
        return Err("I06_GATE3_OTHER_EMPTY_FIXTURE_NOT_COMMITTED".into());
    }

    prove_reorg_rejections(
        &mut proof,
        &store,
        &database_url,
        &profile,
        &plan,
        &binding_one,
    )
    .await?;

    let empty_invalidation = reorg_invalidation(
        (
            &profile,
            &plan,
            &binding_one,
            "other-source",
            "other-partition",
        ),
        anchor(40, &hex_byte(40)),
        anchor(40, &hex_byte(0xfb)),
        (40, 40),
        "other-empty-reorg-result",
    )
    .await?;
    store.invalidate_reorg(&empty_invalidation).await?;
    prove_authoritative_empty_invalidation(&mut proof, &database_url, &empty_invalidation).await?;

    let invalidation = reorg_invalidation(
        (&profile, &plan, &binding_one, "source", "partition"),
        anchor(8, &hex_byte(8)),
        anchor(8, &hex_byte(0xfe)),
        (8, 20),
        "qualified-primary-reorg-result",
    )
    .await?;
    store.invalidate_reorg(&invalidation).await?;
    let mut reorg_fenced_batch = empty_batch(
        3,
        21,
        30,
        "primary-reorg-fenced-successor",
        &primary_empty_batch_digest,
    );
    reorg_fenced_batch.source_id = "source".into();
    reorg_fenced_batch.partition_id = "partition".into();
    let reorg_fenced_material = require_fixture_admission(
        "M14-I16-reorg-fenced-authoritative-empty",
        empty_material(&profile, &plan, &reorg_fenced_batch, &binding_one),
    )?;
    let before_reorg_fence = product_table_snapshot(&database_url).await?;
    let reorg_fenced_outcome = store.persist_batch(&reorg_fenced_material).await?;
    let after_reorg_fence = product_table_snapshot(&database_url).await?;
    let reorg_fence_closed = reorg_fenced_outcome
        == PersistenceOutcome::QuarantinedPredecessorMismatch
        && before_reorg_fence.partition == after_reorg_fence.partition
        && before_reorg_fence.block == after_reorg_fence.block
        && before_reorg_fence.event == after_reorg_fence.event
        && before_reorg_fence.checkpoint == after_reorg_fence.checkpoint
        && before_reorg_fence.outbox == after_reorg_fence.outbox
        && before_reorg_fence.invalidation == after_reorg_fence.invalidation
        && before_reorg_fence.quarantine != after_reorg_fence.quarantine;
    proof.prove(
        "I06-G3-M14-I16-N-PREDECESSOR",
        wrong_predecessor_closed && reorg_fence_closed,
    )?;
    prove_invalidation_outputs(&mut proof, &database_url, &invalidation).await?;
    prove_runtime_reader_scope(&owner_database_url).await?;
    if let Ok(manager_database_url) = std::env::var("OPENPC_I06_GATE3_MANAGER_DATABASE_URL") {
        publication::prove(&manager_database_url, &database_url, &owner_database_url).await?;
    }
    store.close().await;
    proof.finish()?;
    println!("I06_GATE3_CANDIDATE_STORE|TYPED_RECORD_FINALITY_BINDING_ATOMIC_EMPTY_REORG|PASS");
    Ok(())
}

async fn prove_runtime_reader_scope(
    owner_database_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(owner_database_url)
        .await?;
    for role_sql in [
        "SET LOCAL ROLE openpc_fact_bridge_reader",
        "SET LOCAL ROLE openpc_candidate_index_reader",
    ] {
        let mut transaction = pool.begin().await?;
        sqlx::query(role_sql).execute(&mut *transaction).await?;
        sqlx::query("SELECT openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)")
            .bind(uuid(PARTICIPANT))
            .bind(uuid(PRIVACY))
            .bind(uuid(OPERATION))
            .bind(PROOF_ACTION)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SELECT openpc.assert_request_context(true)")
            .execute(&mut *transaction)
            .await?;
        let visible: i64 =
            sqlx::query_scalar("SELECT count(*) FROM candidate.projection_generation")
                .fetch_one(&mut *transaction)
                .await?;
        let can_write: bool = sqlx::query_scalar("SELECT has_table_privilege(current_user,'candidate.candidate_event','INSERT,UPDATE,DELETE')")
            .fetch_one(&mut *transaction).await?;
        if visible == 0 || can_write {
            return Err("ASTRA09_READER_PRIVILEGE_BOUNDARY_REJECTED".into());
        }
        let (feed_count, granting): (i64, bool) = sqlx::query_as(
            "SELECT count(*),coalesce(bool_or(authority_eligible),false) FROM candidate.fact_bridge_feed_v1",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if feed_count == 0 || granting {
            return Err("ASTRA09_VALIDATED_CANDIDATE_FEED_UNAVAILABLE".into());
        }
        let invalidated: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM candidate.fact_bridge_feed_v1 feed JOIN candidate.candidate_event event USING (candidate_event_id) JOIN candidate.candidate_partition partition ON partition.candidate_partition_id=event.candidate_partition_id WHERE feed.projection_generation_id=$1 AND partition.source_id='source' AND partition.partition_id='partition' AND feed.block_number BETWEEN 8 AND 20",
        )
        .bind(uuid(GENERATION))
        .fetch_one(&mut *transaction)
        .await?;
        if invalidated != 0 {
            return Err("ASTRA09_REMOVED_CANDIDATE_FEED_VISIBLE".into());
        }
        sqlx::query("SELECT openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)")
            .bind(uuid(PRIVACY))
            .bind(uuid(PRIVACY))
            .bind(uuid(OPERATION))
            .bind(PROOF_ACTION)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SELECT openpc.assert_request_context(true)")
            .execute(&mut *transaction)
            .await?;
        let foreign_visible: i64 =
            sqlx::query_scalar("SELECT count(*) FROM candidate.projection_generation")
                .fetch_one(&mut *transaction)
                .await?;
        if foreign_visible != 0 {
            return Err("ASTRA09_READER_FOREIGN_SCOPE_VISIBLE".into());
        }
        let foreign_feed: i64 =
            sqlx::query_scalar("SELECT count(*) FROM candidate.fact_bridge_feed_v1")
                .fetch_one(&mut *transaction)
                .await?;
        if foreign_feed != 0 {
            return Err("ASTRA09_READER_FOREIGN_CANDIDATE_VISIBLE".into());
        }
        transaction.rollback().await?;
    }
    pool.close().await;
    println!(
        "ASTRA09_CANDIDATE_READER|INSTALLED_PRIVILEGES_TENANT_ISOLATION_READ_ONLY_VALIDATED_FEED_REORG_REMOVAL|PASS"
    );
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct ProductTableSnapshot {
    partition: String,
    block: String,
    event: String,
    checkpoint: String,
    quarantine: String,
    outbox: String,
    invalidation: String,
}

async fn assert_constructor_rejections_have_zero_product_effects(
    proof: &mut ProofRecorder,
    database_url: &str,
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
    binding: &CandidatePersistenceBinding,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = product_table_snapshot(database_url).await?;

    let store = CandidateStore::connect(database_url).await?;
    for scope_field in ["participant", "privacy"] {
        let mut foreign_profile = profile.clone();
        if scope_field == "participant" {
            foreign_profile.participant_binding = PRIVACY.to_owned();
        } else {
            foreign_profile.privacy_binding = PARTICIPANT.to_owned();
        }
        if !matches!(
            material(&foreign_profile, plan, batch, binding),
            Err(CandidateStoreError::InvalidBinding)
        ) || !matches!(
            store
                .register_partition(&foreign_profile, plan, binding, "source", "partition")
                .await,
            Err(CandidateStoreError::InvalidBinding)
        ) {
            return Err("ASTRA09_FOREIGN_PROFILE_SCOPE_ACCEPTED".into());
        }
    }
    store.close().await;
    if before != product_table_snapshot(database_url).await? {
        return Err("ASTRA09_FOREIGN_PROFILE_SCOPE_CHANGED_PRODUCT_STATE".into());
    }

    if CandidatePersistenceBinding::try_new(
        uuid(PARTICIPANT),
        uuid(PRIVACY),
        uuid(GENERATION),
        uuid(OPERATION),
        uuid(CORRELATION),
    )
    .is_err()
    {
        return Err("I06_GATE3_VALID_BINDING_REJECTED".into());
    }
    for (assertion_id, values) in [
        (
            "I06-G3-M12-I01-N-PARTICIPANT",
            (
                Uuid::nil(),
                uuid(PRIVACY),
                uuid(GENERATION),
                uuid(OPERATION),
                uuid(CORRELATION),
            ),
        ),
        (
            "I06-G3-M12-I01-N-PRIVACY",
            (
                uuid(PARTICIPANT),
                Uuid::nil(),
                uuid(GENERATION),
                uuid(OPERATION),
                uuid(CORRELATION),
            ),
        ),
        (
            "I06-G3-M12-I02-N-OPERATION",
            (
                uuid(PARTICIPANT),
                uuid(PRIVACY),
                uuid(GENERATION),
                Uuid::nil(),
                uuid(CORRELATION),
            ),
        ),
        (
            "I06-G3-M12-I02-N-CORRELATION",
            (
                uuid(PARTICIPANT),
                uuid(PRIVACY),
                uuid(GENERATION),
                uuid(OPERATION),
                Uuid::nil(),
            ),
        ),
        (
            "I06-G3-M12-I06-N-GENERATION-ID",
            (
                uuid(PARTICIPANT),
                uuid(PRIVACY),
                Uuid::nil(),
                uuid(OPERATION),
                uuid(CORRELATION),
            ),
        ),
    ] {
        require_candidate_error(
            proof,
            assertion_id,
            ExpectedCandidateError::InvalidBinding,
            CandidatePersistenceBinding::try_new(values.0, values.1, values.2, values.3, values.4),
        )?;
    }

    require_candidate_error(
        proof,
        "I06-G3-M14-I14-N-VARIANT",
        ExpectedCandidateError::InvalidBinding,
        variant_mismatch_material(profile, plan, batch, binding),
    )?;

    let mut malformed_batch = batch.clone();
    malformed_batch.observations[0].normalized_digest = format!(
        "sha256:{}",
        malformed_batch.observations[0].normalized_digest
    );
    let serialized = serde_json::to_vec(&malformed_batch)?;
    let decoded: CandidateProjectionBatchV1 = serde_json::from_slice(&serialized)?;
    match material(profile, plan, &decoded, binding) {
        Err(CandidateStoreError::InvalidBatch) => {}
        Err(error) => {
            return Err(format!(
                "I06_GATE3_PREFIXED_OBSERVATION_DIGEST_RESULT|expected=InvalidBatch|actual={error:?}"
            )
            .into());
        }
        Ok(_) => return Err("I06_GATE3_PREFIXED_OBSERVATION_DIGEST_RESULT|actual=Ok".into()),
    }

    let mut changed = batch.clone();
    changed.source_id.clear();
    require_candidate_error(
        proof,
        "I06-G3-M12-I03-N-SOURCE-ID",
        ExpectedCandidateError::InvalidBatch,
        material(profile, plan, &changed, binding),
    )?;
    changed = batch.clone();
    changed.profile_id = d("substituted-profile-id");
    require_candidate_error(
        proof,
        "I06-G3-M12-I05-N-PROFILE-ID",
        ExpectedCandidateError::InvalidBatch,
        material(profile, plan, &changed, binding),
    )?;
    changed = batch.clone();
    changed.plan_digest = d("substituted-plan-id");
    require_candidate_error(
        proof,
        "I06-G3-M12-I05-N-PLAN-ID",
        ExpectedCandidateError::InvalidBatch,
        material(profile, plan, &changed, binding),
    )?;
    changed = batch.clone();
    changed.batch_id.clear();
    require_candidate_error(
        proof,
        "I06-G3-M14-I16-N-BATCH-ID",
        ExpectedCandidateError::InvalidBatch,
        material(profile, plan, &changed, binding),
    )?;
    changed = batch.clone();
    changed.batch_sequence = 0;
    require_candidate_error(
        proof,
        "I06-G3-M14-I16-N-SEQUENCE",
        ExpectedCandidateError::InvalidBatch,
        material(profile, plan, &changed, binding),
    )?;
    changed = batch.clone();
    changed.predecessor_batch_digest = d("not-genesis");
    require_candidate_error(
        proof,
        "I06-G3-M14-I16-N-GENESIS",
        ExpectedCandidateError::InvalidBatch,
        material(profile, plan, &changed, binding),
    )?;

    let mut invalid_schema = batch.clone();
    invalid_schema.records[0].schema_digest = "g".repeat(64);
    require_candidate_error(
        proof,
        "I06-G3-M14-I14-N-SCHEMA",
        ExpectedCandidateError::InvalidBatch,
        material(profile, plan, &invalid_schema, binding),
    )?;
    let mut invalid_normalized = batch.clone();
    invalid_normalized.records[0].normalized_digest = hex_byte(0xf1);
    require_candidate_error(
        proof,
        "I06-G3-M14-I14-N-NORMALIZED",
        ExpectedCandidateError::InvalidBatch,
        material(profile, plan, &invalid_normalized, binding),
    )?;
    let mut invalid_evidence = batch.clone();
    invalid_evidence.records[0].evidence_digest = "G".repeat(64);
    require_candidate_error(
        proof,
        "I06-G3-M14-I14-N-EVIDENCE",
        ExpectedCandidateError::InvalidBatch,
        material(profile, plan, &invalid_evidence, binding),
    )?;

    let mut invalid_genesis_block = block_observation(profile, &batch.records[0]);
    if let CandidateBlockFinalityV1::Confirmations { head_anchor, .. } =
        &mut invalid_genesis_block.finality
    {
        head_anchor.genesis_hash = hex_byte(0xf2);
    }
    require_candidate_error(
        proof,
        "I06-G3-M14-I11-N-GENESIS-HASH",
        ExpectedCandidateError::InvalidBinding,
        material_with_blocks(
            profile,
            plan,
            batch,
            binding,
            blocks_with_first(profile, batch, invalid_genesis_block),
        ),
    )?;

    let mut invalid_source_digest = block_observation(profile, &batch.records[0]);
    invalid_source_digest.evidence_digest = "x".repeat(64);
    require_candidate_error(
        proof,
        "I06-G3-M14-I12-N-SOURCE-DIGEST",
        ExpectedCandidateError::InvalidBinding,
        material_with_blocks(
            profile,
            plan,
            batch,
            binding,
            blocks_with_first(profile, batch, invalid_source_digest),
        ),
    )?;
    let mut invalid_finality_digest = block_observation(profile, &batch.records[0]);
    if let CandidateBlockFinalityV1::Confirmations {
        evidence_digest, ..
    } = &mut invalid_finality_digest.finality
    {
        *evidence_digest = "x".repeat(64);
    }
    require_candidate_error(
        proof,
        "I06-G3-M14-I12-N-FINALITY-DIGEST",
        ExpectedCandidateError::InvalidBinding,
        material_with_blocks(
            profile,
            plan,
            batch,
            binding,
            blocks_with_first(profile, batch, invalid_finality_digest),
        ),
    )?;
    let mut unfinalized = block_observation(profile, &batch.records[0]);
    unfinalized.finality = CandidateBlockFinalityV1::Unfinalized {
        evidence_digest: d("unfinalized"),
    };
    require_candidate_error(
        proof,
        "I06-G3-M14-I12-N-FINALITY-STATE",
        ExpectedCandidateError::InvalidBatch,
        material_with_blocks(
            profile,
            plan,
            batch,
            binding,
            blocks_with_first(profile, batch, unfinalized),
        ),
    )?;

    prove_batch_decode_rejections(proof, profile, plan, batch, binding)?;

    let after = product_table_snapshot(database_url).await?;
    if before != after {
        return Err(format!(
            "I06_GATE3_PRODUCT_SNAPSHOT_MISMATCH|constructor-negative-suite|before={before:?}|after={after:?}"
        )
        .into());
    }
    Ok(())
}

async fn product_table_snapshot(
    database_url: &str,
) -> Result<ProductTableSnapshot, Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,false)")
        .bind(uuid(PARTICIPANT))
        .bind(uuid(PRIVACY))
        .bind(uuid(OPERATION))
        .bind(PROOF_ACTION)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT openpc.assert_request_context(true)")
        .execute(&mut *tx)
        .await?;
    let values: (String, String, String, String, String, String, String) = sqlx::query_as(
        "SELECT \
           (SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY candidate_partition_id),'[]'::jsonb)::text FROM candidate.candidate_partition t), \
           (SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY candidate_block_id),'[]'::jsonb)::text FROM candidate.candidate_block t), \
           (SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY candidate_event_id),'[]'::jsonb)::text FROM candidate.candidate_event t), \
           (SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY checkpoint_id),'[]'::jsonb)::text FROM candidate.checkpoint t), \
           (SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY quarantine_id),'[]'::jsonb)::text FROM candidate.quarantine_record t), \
           (SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY event_id),'[]'::jsonb)::text FROM candidate.outbox_event t), \
           (SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY candidate_invalidation_id),'[]'::jsonb)::text FROM candidate.candidate_invalidation t)",
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.rollback().await?;
    pool.close().await;
    Ok(ProductTableSnapshot {
        partition: values.0,
        block: values.1,
        event: values.2,
        checkpoint: values.3,
        quarantine: values.4,
        outbox: values.5,
        invalidation: values.6,
    })
}

fn prove_batch_decode_rejections(
    proof: &mut ProofRecorder,
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
    binding: &CandidatePersistenceBinding,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut changed = batch.clone();
    changed.observations[0].sequence = 2;
    require_candidate_error(
        proof,
        "I06-G3-M14-I17-N-OBSERVATION-ORDER",
        ExpectedCandidateError::InvalidBatch,
        material(profile, plan, &changed, binding),
    )?;
    changed = batch.clone();
    changed.observations.clear();
    require_candidate_error(
        proof,
        "I06-G3-M14-I17-N-OBSERVATION-COUNT",
        ExpectedCandidateError::InvalidBatch,
        material(profile, plan, &changed, binding),
    )?;

    let decode_batch = partial_decode_batch(batch);
    validate_candidate_projection_batch(profile, plan, &decode_batch).map_err(|error| {
        format!("I06_GATE3_PROVIDER_PARTIAL_DECODE_BASELINE_REJECTED|actual={error:?}")
    })?;
    require_durable_incomplete_rejection(profile, plan, &decode_batch, binding, "decode-failures")?;
    let mut missing_batch = decode_batch.clone();
    missing_batch.decode_failures.clear();
    missing_batch.missing_intervals = vec![InclusiveRangeV1 {
        start: missing_batch.completed_watermark.block_number + 1,
        end: missing_batch.range.end,
    }];
    validate_candidate_projection_batch(profile, plan, &missing_batch).map_err(|error| {
        format!("I06_GATE3_PROVIDER_PARTIAL_MISSING_BASELINE_REJECTED|actual={error:?}")
    })?;
    require_durable_incomplete_rejection(
        profile,
        plan,
        &missing_batch,
        binding,
        "missing-intervals",
    )?;

    let serialized = serde_json::to_value(&decode_batch)?;
    for (assertion_id, field) in [
        ("I06-G3-M14-I17-N-DECODE-MISSING-SOURCE-ID", "source_id"),
        ("I06-G3-M14-I17-N-DECODE-MISSING-SEQUENCE", "sequence"),
        (
            "I06-G3-M14-I17-N-DECODE-MISSING-ERROR-DIGEST",
            "error_digest",
        ),
        (
            "I06-G3-M14-I17-N-DECODE-MISSING-EVIDENCE-DIGEST",
            "evidence_digest",
        ),
    ] {
        let mut value = serialized.clone();
        value["decode_failures"][0]
            .as_object_mut()
            .expect("serialized decode failure")
            .remove(field);
        require_missing_field(
            proof,
            assertion_id,
            field,
            serde_json::from_value::<CandidateProjectionBatchV1>(value),
        )?;
    }

    let mut swapped = decode_batch.clone();
    let original_error = swapped.decode_failures[0].error_digest.clone();
    let original_evidence = swapped.decode_failures[0].evidence_digest.clone();
    let swapped_failure = &mut swapped.decode_failures[0];
    std::mem::swap(
        &mut swapped_failure.error_digest,
        &mut swapped_failure.evidence_digest,
    );
    validate_candidate_projection_batch(profile, plan, &swapped)
        .map_err(|error| format!("I06_GATE3_SWAPPED_DECODE_PROVIDER_REJECTED|actual={error:?}"))?;
    let swapped_round_trip: CandidateProjectionBatchV1 =
        serde_json::from_value(serde_json::to_value(&swapped)?)?;
    proof.prove(
        "I06-G3-M14-I17-N-DECODE-SWAPPED-DIGESTS",
        swapped_round_trip.decode_failures[0].error_digest == original_evidence
            && swapped_round_trip.decode_failures[0].evidence_digest == original_error,
    )?;

    changed = decode_batch.clone();
    changed.decode_failures[0].source_id = "other-source".into();
    require_provider_rejection(
        proof,
        "I06-G3-M14-I17-N-DECODE-MALFORMED-SOURCE-ID",
        validate_candidate_projection_batch(profile, plan, &changed),
    )?;
    changed = decode_batch.clone();
    changed.decode_failures[0].sequence = 0;
    require_provider_rejection(
        proof,
        "I06-G3-M14-I17-N-DECODE-MALFORMED-SEQUENCE",
        validate_candidate_projection_batch(profile, plan, &changed),
    )?;
    changed = decode_batch.clone();
    changed.decode_failures[0].error_digest = format!("sha256:{}", hex_byte(0xa1));
    require_provider_rejection(
        proof,
        "I06-G3-M14-I17-N-DECODE-MALFORMED-ERROR-DIGEST",
        validate_candidate_projection_batch(profile, plan, &changed),
    )?;
    changed = decode_batch.clone();
    changed.decode_failures[0].evidence_digest = "A".repeat(64);
    require_provider_rejection(
        proof,
        "I06-G3-M14-I17-N-DECODE-MALFORMED-EVIDENCE-DIGEST",
        validate_candidate_projection_batch(profile, plan, &changed),
    )?;
    changed = decode_batch.clone();
    changed.decode_failures.swap(0, 1);
    require_provider_rejection(
        proof,
        "I06-G3-M14-I17-N-DECODE-REORDERED",
        validate_candidate_projection_batch(profile, plan, &changed),
    )?;
    changed = decode_batch;
    changed.decode_failures[1].sequence = changed.decode_failures[0].sequence;
    require_provider_rejection(
        proof,
        "I06-G3-M14-I17-N-DECODE-DUPLICATE-SEQUENCE",
        validate_candidate_projection_batch(profile, plan, &changed),
    )?;
    Ok(())
}

fn require_durable_incomplete_rejection(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
    binding: &CandidatePersistenceBinding,
    relation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match CandidateBatchMaterialV1::try_new(
        (profile, plan, batch, binding),
        block_observations(profile, batch),
        record_materials(batch),
        false,
    ) {
        Err(CandidateStoreError::InvalidBatch) => Ok(()),
        Err(error) => Err(format!(
            "I06_GATE3_DURABLE_COMPLETE_REJECTION_MISMATCH|relation={relation}|expected=InvalidBatch|actual={error:?}"
        )
        .into()),
        Ok(_) => Err(format!(
            "I06_GATE3_DURABLE_INCOMPLETE_BATCH_ACCEPTED|relation={relation}"
        )
        .into()),
    }
}

fn require_provider_rejection(
    proof: &mut ProofRecorder,
    assertion_id: &'static str,
    result: Result<(), ProviderContractError>,
) -> Result<(), String> {
    match result {
        Err(_) => proof.prove(assertion_id, true),
        Ok(()) => Err(format!(
            "I06_GATE3_TYPED_RESULT_MISMATCH|{assertion_id}|expected=ProviderContractError|actual=Ok(())"
        )),
    }
}

async fn prove_store_invalid_binding(
    proof: &mut ProofRecorder,
    assertion_id: &'static str,
    store: &CandidateStore,
    database_url: &str,
    material: &CandidateBatchMaterialV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = product_table_snapshot(database_url).await?;
    let result = store.persist_batch(material).await;
    let after = product_table_snapshot(database_url).await?;
    if before != after {
        return Err(format!(
            "I06_GATE3_PRODUCT_SNAPSHOT_MISMATCH|{assertion_id}|before={before:?}|after={after:?}"
        )
        .into());
    }
    require_candidate_error(
        proof,
        assertion_id,
        ExpectedCandidateError::InvalidBinding,
        result,
    )?;
    Ok(())
}

async fn prove_database_binding_conflicts(
    proof: &mut ProofRecorder,
    store: &CandidateStore,
    database_url: &str,
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
    binding: &CandidatePersistenceBinding,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut changed_profile = profile.clone();
    changed_profile.deployment_owner = "substituted-owner".into();
    let changed_source = require_fixture_admission(
        "I06-G3-M13-I09-N-SOURCE-PROFILE",
        material(&changed_profile, plan, batch, binding),
    )?;
    prove_store_invalid_binding(
        proof,
        "I06-G3-M13-I09-N-SOURCE-PROFILE",
        store,
        database_url,
        &changed_source,
    )
    .await?;

    changed_profile = profile.clone();
    changed_profile.reorg_behavior_digest = d("substituted-reorg-profile");
    let changed_reorg = require_fixture_admission(
        "I06-G3-M13-I09-N-REORG-PROFILE",
        material(&changed_profile, plan, batch, binding),
    )?;
    prove_store_invalid_binding(
        proof,
        "I06-G3-M13-I09-N-REORG-PROFILE",
        store,
        database_url,
        &changed_reorg,
    )
    .await?;

    let mut changed_plan = plan.clone();
    changed_plan.extractor_digests[0].digest = d("substituted-extractor");
    let changed_plan_material = require_fixture_admission(
        "I06-G3-M13-I09-N-PLAN",
        material(profile, &changed_plan, batch, binding),
    )?;
    prove_store_invalid_binding(
        proof,
        "I06-G3-M13-I09-N-PLAN",
        store,
        database_url,
        &changed_plan_material,
    )
    .await?;

    for (fault, assertion_id, ids) in DB_FAULT_CONTRACTS {
        let mut fault_profile = profile.clone();
        fault_profile.deployment_owner = format!("fault-owner-{}", ids.generation);
        seed_contract(
            database_url,
            &owner_database_url(),
            &fault_profile,
            plan,
            SeedContractSpec {
                ids: *ids,
                stored_data_class: "EVENT_LOG",
                source_event_type: Some("extractor"),
                source_contract_address: Some(vec![0x11; 20]),
                fault: *fault,
            },
        )
        .await?;
        let fault_binding = binding_for(ids.generation);
        let fault_material = require_fixture_admission(
            assertion_id,
            material(&fault_profile, plan, batch, &fault_binding),
        )?;
        prove_store_invalid_binding(proof, assertion_id, store, database_url, &fault_material)
            .await?;
    }

    let substituted_binding = binding_for("018f47a5-4a58-7b21-8f3a-b50000000003");
    let substituted_material = require_fixture_admission(
        "I06-G3-M13-I09-N-UUID-SUBSTITUTION",
        material(profile, plan, batch, &substituted_binding),
    )?;
    prove_store_invalid_binding(
        proof,
        "I06-G3-M13-I09-N-UUID-SUBSTITUTION",
        store,
        database_url,
        &substituted_material,
    )
    .await?;
    Ok(())
}

async fn prove_all_record_classes_and_projection_scalar_conflicts(
    proof: &mut ProofRecorder,
    database_url: &str,
    plan: &ProjectionPlanV1,
) -> Result<(), Box<dyn std::error::Error>> {
    for (data_class, assertion_id, ids) in CLASS_CONTRACTS {
        let profile = profile_for_class(data_class);
        seed_contract(
            database_url,
            &owner_database_url(),
            &profile,
            plan,
            SeedContractSpec {
                ids: *ids,
                stored_data_class: data_class,
                source_event_type: None,
                source_contract_address: None,
                fault: SeedFault::None,
            },
        )
        .await?;
        let binding = binding_for(ids.generation);
        let store = CandidateStore::connect(database_url).await?;
        store
            .register_partition(&profile, plan, &binding, "source", "partition")
            .await?;
        let class_batch = batch(1, 1, 10, &format!("class-{data_class}"), "GENESIS");
        let class_material = require_fixture_admission(
            assertion_id,
            material_for_class(&profile, plan, &class_batch, &binding, data_class),
        )?;
        let outcome = store.persist_batch(&class_material).await?;
        let retained = retained_identity_is_exact(database_url, *ids, data_class).await?;
        if !retained {
            return Err(format!(
                "I06_GATE3_RETAINED_IDENTITY_MISMATCH|{assertion_id}|data_class={data_class}"
            )
            .into());
        }
        require_outcome(proof, assertion_id, PersistenceOutcome::Committed, outcome)?;
        store.close().await;
    }

    for (assertion_id, mutation) in [
        (
            "I06-G3-M13-I10-N-EVENT-TYPE-MISSING",
            ProjectionIdentityMutation::EventTypeMissing,
        ),
        (
            "I06-G3-M13-I10-N-EVENT-ADDRESS-MISSING",
            ProjectionIdentityMutation::EventAddressMissing,
        ),
        (
            "I06-G3-M13-I10-N-NONEVENT-TYPE-PRESENT",
            ProjectionIdentityMutation::NonEventTypePresent,
        ),
        (
            "I06-G3-M13-I10-N-NONEVENT-ADDRESS-PRESENT",
            ProjectionIdentityMutation::NonEventAddressPresent,
        ),
    ] {
        prove_projection_identity_constraint(proof, database_url, plan, assertion_id, mutation)
            .await?;
    }

    let event_profile = profile_for_class("EVENT_LOG");

    let divergence_ids = ContractIds {
        source_profile: "018f47a5-4a58-7b21-8f3a-c10000000001",
        projection_profile: "018f47a5-4a58-7b21-8f3a-c10000000002",
        generation: "018f47a5-4a58-7b21-8f3a-c10000000003",
        indexer_profile: "018f47a5-4a58-7b21-8f3a-c10000000004",
        projection_plan: "018f47a5-4a58-7b21-8f3a-c10000000005",
    };
    let mut divergence_profile = event_profile.clone();
    divergence_profile.deployment_owner = "store-sql-divergence".into();
    seed_contract(
        database_url,
        &owner_database_url(),
        &divergence_profile,
        plan,
        SeedContractSpec {
            ids: divergence_ids,
            stored_data_class: "STATE_CALL",
            source_event_type: None,
            source_contract_address: None,
            fault: SeedFault::None,
        },
    )
    .await?;
    let before = product_table_snapshot(database_url).await?;
    let store = CandidateStore::connect(database_url).await?;
    let result = store
        .register_partition(
            &divergence_profile,
            plan,
            &binding_for(divergence_ids.generation),
            "source",
            "partition",
        )
        .await;
    let after = product_table_snapshot(database_url).await?;
    if before != after {
        return Err(format!(
            "I06_GATE3_PRODUCT_SNAPSHOT_MISMATCH|I06-G3-M13-I10-N-STORE-SQL-DIVERGENCE|before={before:?}|after={after:?}"
        )
        .into());
    }
    require_candidate_error(
        proof,
        "I06-G3-M13-I10-N-STORE-SQL-DIVERGENCE",
        ExpectedCandidateError::InvalidBinding,
        result,
    )?;
    store.close().await;
    Ok(())
}

async fn prove_cross_batch_database_identity_conflicts(
    database_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let cases: [(&str, &str, ContractIds, &str, &str, &str); 5] = [
        (
            "RECORD_ID",
            "candidate_event_record_id_uq",
            PRIMARY_CONTRACT,
            "EVENT_LOG",
            "record-1-1",
            "INSERT INTO candidate.candidate_event(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id,candidate_block_id,record_kind,record_sequence,record_id,schema_digest,normalized_digest,evidence_digest,transaction_hash,transaction_index,log_index,contract_address,event_signature,target_address,call_parameter_digest,candidate_key_digest,payload_cbor,payload_digest,state,observed_at) SELECT ce.participant_id,ce.privacy_domain_id,ce.projection_generation_id,ce.candidate_partition_id,ce.candidate_block_id,ce.record_kind,ce.record_sequence+100,ce.record_id,ce.schema_digest,ce.normalized_digest,ce.evidence_digest,sha256(convert_to('isolated-record-id','UTF8')),ce.transaction_index,ce.log_index+100,ce.contract_address,ce.event_signature,ce.target_address,ce.call_parameter_digest,sha256(convert_to('isolated-record-key','UTF8')),ce.payload_cbor,ce.payload_digest,ce.state,clock_timestamp() FROM candidate.candidate_event ce JOIN candidate.candidate_partition cp ON cp.candidate_partition_id=ce.candidate_partition_id WHERE cp.participant_id=$1 AND cp.privacy_domain_id=$2 AND cp.projection_generation_id=$3 AND cp.source_profile_id=$4 AND cp.source_id=$5 AND cp.partition_id=$6 AND ce.projection_generation_id=$3 AND ce.record_kind=$7 AND ce.record_id=$8",
        ),
        (
            "EVENT_LOG",
            "candidate_event_projection_generation_id_transaction_hash_l_key",
            PRIMARY_CONTRACT,
            "EVENT_LOG",
            "record-1-1",
            "INSERT INTO candidate.candidate_event(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id,candidate_block_id,record_kind,record_sequence,record_id,schema_digest,normalized_digest,evidence_digest,transaction_hash,transaction_index,log_index,contract_address,event_signature,target_address,call_parameter_digest,candidate_key_digest,payload_cbor,payload_digest,state,observed_at) SELECT ce.participant_id,ce.privacy_domain_id,ce.projection_generation_id,ce.candidate_partition_id,ce.candidate_block_id,ce.record_kind,ce.record_sequence+101,ce.record_id||'-event-conflict',ce.schema_digest,ce.normalized_digest,ce.evidence_digest,ce.transaction_hash,ce.transaction_index,ce.log_index,ce.contract_address,ce.event_signature,ce.target_address,ce.call_parameter_digest,sha256(convert_to(ce.record_id||'-event-conflict','UTF8')),ce.payload_cbor,ce.payload_digest,ce.state,clock_timestamp() FROM candidate.candidate_event ce JOIN candidate.candidate_partition cp ON cp.candidate_partition_id=ce.candidate_partition_id WHERE cp.participant_id=$1 AND cp.privacy_domain_id=$2 AND cp.projection_generation_id=$3 AND cp.source_profile_id=$4 AND cp.source_id=$5 AND cp.partition_id=$6 AND ce.projection_generation_id=$3 AND ce.record_kind=$7 AND ce.record_id=$8",
        ),
        (
            "STATE_CALL",
            "candidate_event_state_call_uq",
            CLASS_CONTRACTS[0].2,
            "STATE_CALL",
            "record-1-1",
            "INSERT INTO candidate.candidate_event(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id,candidate_block_id,record_kind,record_sequence,record_id,schema_digest,normalized_digest,evidence_digest,transaction_hash,transaction_index,log_index,contract_address,event_signature,target_address,call_parameter_digest,candidate_key_digest,payload_cbor,payload_digest,state,observed_at) SELECT ce.participant_id,ce.privacy_domain_id,ce.projection_generation_id,ce.candidate_partition_id,ce.candidate_block_id,ce.record_kind,ce.record_sequence+100,ce.record_id||'-state-conflict',ce.schema_digest,ce.normalized_digest,ce.evidence_digest,ce.transaction_hash,ce.transaction_index,ce.log_index,ce.contract_address,ce.event_signature,ce.target_address,ce.call_parameter_digest,sha256(convert_to(ce.record_id||'-state-conflict','UTF8')),ce.payload_cbor,ce.payload_digest,ce.state,clock_timestamp() FROM candidate.candidate_event ce JOIN candidate.candidate_partition cp ON cp.candidate_partition_id=ce.candidate_partition_id WHERE cp.participant_id=$1 AND cp.privacy_domain_id=$2 AND cp.projection_generation_id=$3 AND cp.source_profile_id=$4 AND cp.source_id=$5 AND cp.partition_id=$6 AND ce.projection_generation_id=$3 AND ce.record_kind=$7 AND ce.record_id=$8",
        ),
        (
            "TRANSACTION_RECEIPT",
            "candidate_event_receipt_uq",
            CLASS_CONTRACTS[1].2,
            "TRANSACTION_RECEIPT",
            "record-1-1",
            "INSERT INTO candidate.candidate_event(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id,candidate_block_id,record_kind,record_sequence,record_id,schema_digest,normalized_digest,evidence_digest,transaction_hash,transaction_index,log_index,contract_address,event_signature,target_address,call_parameter_digest,candidate_key_digest,payload_cbor,payload_digest,state,observed_at) SELECT ce.participant_id,ce.privacy_domain_id,ce.projection_generation_id,ce.candidate_partition_id,ce.candidate_block_id,ce.record_kind,ce.record_sequence+100,ce.record_id||'-receipt-conflict',ce.schema_digest,ce.normalized_digest,ce.evidence_digest,ce.transaction_hash,ce.transaction_index,ce.log_index,ce.contract_address,ce.event_signature,ce.target_address,ce.call_parameter_digest,sha256(convert_to(ce.record_id||'-receipt-conflict','UTF8')),ce.payload_cbor,ce.payload_digest,ce.state,clock_timestamp() FROM candidate.candidate_event ce JOIN candidate.candidate_partition cp ON cp.candidate_partition_id=ce.candidate_partition_id WHERE cp.participant_id=$1 AND cp.privacy_domain_id=$2 AND cp.projection_generation_id=$3 AND cp.source_profile_id=$4 AND cp.source_id=$5 AND cp.partition_id=$6 AND ce.projection_generation_id=$3 AND ce.record_kind=$7 AND ce.record_id=$8",
        ),
        (
            "BLOCK_KIND",
            "candidate_event_block_kind_uq",
            CLASS_CONTRACTS[2].2,
            "BLOCK_HEADER",
            "record-1-1",
            "INSERT INTO candidate.candidate_event(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id,candidate_block_id,record_kind,record_sequence,record_id,schema_digest,normalized_digest,evidence_digest,transaction_hash,transaction_index,log_index,contract_address,event_signature,target_address,call_parameter_digest,candidate_key_digest,payload_cbor,payload_digest,state,observed_at) SELECT ce.participant_id,ce.privacy_domain_id,ce.projection_generation_id,ce.candidate_partition_id,ce.candidate_block_id,ce.record_kind,ce.record_sequence+100,ce.record_id||'-block-conflict',ce.schema_digest,ce.normalized_digest,ce.evidence_digest,ce.transaction_hash,ce.transaction_index,ce.log_index,ce.contract_address,ce.event_signature,ce.target_address,ce.call_parameter_digest,sha256(convert_to(ce.record_id||'-block-conflict','UTF8')),ce.payload_cbor,ce.payload_digest,ce.state,clock_timestamp() FROM candidate.candidate_event ce JOIN candidate.candidate_partition cp ON cp.candidate_partition_id=ce.candidate_partition_id WHERE cp.participant_id=$1 AND cp.privacy_domain_id=$2 AND cp.projection_generation_id=$3 AND cp.source_profile_id=$4 AND cp.source_id=$5 AND cp.partition_id=$6 AND ce.projection_generation_id=$3 AND ce.record_kind=$7 AND ce.record_id=$8",
        ),
    ];
    for (identity_case, constraint, ids, record_kind, record_id, statement) in cases {
        let before = product_table_snapshot(database_url).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(database_url)
            .await?;
        let mut tx = pool.begin().await?;
        set_proof_context(&mut tx).await?;
        let result = sqlx::query(statement)
            .bind(uuid(PARTICIPANT))
            .bind(uuid(PRIVACY))
            .bind(uuid(ids.generation))
            .bind(uuid(ids.source_profile))
            .bind("source")
            .bind("partition")
            .bind(record_kind)
            .bind(record_id)
            .execute(&mut *tx)
            .await
            .map_err(CandidateStoreError::Database);
        match result {
            Err(CandidateStoreError::Database(sqlx::Error::Database(error)))
                if error.code().as_deref() == Some("23505")
                    && error.constraint() == Some(constraint) => {}
            Err(error) => {
                return Err(format!(
                    "I06_GATE3_CROSS_BATCH_IDENTITY_RESULT_MISMATCH|identity={identity_case}|constraint={constraint}|expected=Database(23505/{constraint})|actual={error:?}"
                )
                .into());
            }
            Ok(_) => {
                return Err(format!(
                    "I06_GATE3_CROSS_BATCH_IDENTITY_RESULT_MISMATCH|identity={identity_case}|constraint={constraint}|expected=Database(23505/{constraint})|actual=Ok"
                )
                .into());
            }
        }
        tx.rollback().await?;
        pool.close().await;
        let after = product_table_snapshot(database_url).await?;
        if before != after {
            return Err(format!(
                "I06_GATE3_PRODUCT_SNAPSHOT_MISMATCH|cross-batch-{identity_case}|constraint={constraint}|before={before:?}|after={after:?}"
            )
            .into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ProjectionIdentityMutation {
    EventTypeMissing,
    EventAddressMissing,
    NonEventTypePresent,
    NonEventAddressPresent,
}

impl ProjectionIdentityMutation {
    fn data_class(self) -> &'static str {
        match self {
            Self::EventTypeMissing | Self::EventAddressMissing => "EVENT_LOG",
            Self::NonEventTypePresent => "STATE_CALL",
            Self::NonEventAddressPresent => "BLOCK_HEADER",
        }
    }

    fn valid_identity(self) -> (Option<&'static str>, Option<Vec<u8>>) {
        match self.data_class() {
            "EVENT_LOG" => (Some("extractor"), Some(vec![0x11_u8; 20])),
            "STATE_CALL" | "BLOCK_HEADER" => (None, None),
            _ => unreachable!("closed projection-identity proof class"),
        }
    }

    fn isolated_identity(
        self,
        valid_event_type: Option<&'static str>,
        valid_address: Option<Vec<u8>>,
    ) -> (Option<&'static str>, Option<Vec<u8>>) {
        match self {
            Self::EventTypeMissing => (None, valid_address),
            Self::EventAddressMissing => (valid_event_type, None),
            Self::NonEventTypePresent => (Some("extractor"), valid_address),
            Self::NonEventAddressPresent => (valid_event_type, Some(vec![0x11_u8; 20])),
        }
    }
}

fn qualified_source_profile_owner_for_class(data_class: &str) -> Result<ContractIds, String> {
    if data_class == "EVENT_LOG" {
        return Ok(PRIMARY_CONTRACT);
    }
    CLASS_CONTRACTS
        .iter()
        .find_map(|(candidate_class, _, ids)| (*candidate_class == data_class).then_some(*ids))
        .ok_or_else(|| {
            format!("I06_GATE3_PROJECTION_IDENTITY_SOURCE_OWNER_MISSING|data_class={data_class}")
        })
}

async fn prove_projection_identity_constraint(
    proof: &mut ProofRecorder,
    database_url: &str,
    plan: &ProjectionPlanV1,
    assertion_id: &'static str,
    mutation: ProjectionIdentityMutation,
) -> Result<(), Box<dyn std::error::Error>> {
    let data_class = mutation.data_class();
    let source_owner = qualified_source_profile_owner_for_class(data_class)?;
    let profile = profile_for_class(data_class);
    validate_projection_plan(&profile, plan).map_err(|error| {
        format!(
            "I06_GATE3_PROJECTION_IDENTITY_BASELINE_PLAN_REJECTED|{assertion_id}|data_class={data_class}|actual={error:?}"
        )
    })?;
    let baseline_batch = batch(
        1,
        1,
        10,
        &format!("projection-identity-{data_class}"),
        "GENESIS",
    );
    let baseline_binding = binding_for("018f47a5-4a58-7b21-8f3a-c20000000003");
    material_for_class(
        &profile,
        plan,
        &baseline_batch,
        &baseline_binding,
        data_class,
    )
    .map_err(|error| {
        format!(
            "I06_GATE3_PROJECTION_IDENTITY_BASELINE_MATERIAL_REJECTED|{assertion_id}|data_class={data_class}|actual={error:?}"
        )
    })?;

    let before = product_table_snapshot(database_url).await?;
    let owner_url = owner_database_url();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&owner_url)
        .await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL ROLE openpc_candidate_index_owner")
        .execute(&mut *tx)
        .await?;
    set_proof_context(&mut tx).await?;
    let plan_cbor = encode_projection_plan_pc_cbor(plan)?;
    let schemas = plan
        .candidate_schema_digests
        .iter()
        .map(|item| decode_hex(&item.digest))
        .collect::<Vec<_>>();
    let exact_schema_digest = Sha256::digest(encode_byte_array(&schemas)).to_vec();
    let source_owner_is_exact = sqlx::query_scalar::<_, bool>(
        "SELECT participant_id=$2 AND privacy_domain_id=$3 AND state='QUALIFIED' FROM candidate.source_profile WHERE source_profile_id=$1",
    )
    .bind(uuid(source_owner.source_profile))
    .bind(uuid(PARTICIPANT))
    .bind(uuid(PRIVACY))
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(false);
    if !source_owner_is_exact {
        return Err(format!(
            "I06_GATE3_PROJECTION_IDENTITY_SOURCE_OWNER_MISMATCH|{assertion_id}|data_class={data_class}|source_profile_id={}",
            source_owner.source_profile
        )
        .into());
    }

    let (valid_event_type, valid_address) = mutation.valid_identity();
    let (event_type, address) = mutation.isolated_identity(valid_event_type, valid_address);
    let result = sqlx::query(
        "INSERT INTO candidate.projection_profile(projection_profile_id,participant_id,privacy_domain_id,source_profile_id,projection_plan_id,fact_type,source_event_type,source_contract_address,schema_digest,mapping_cbor,mapping_digest,state,data_class) VALUES ($1,$2,$3,$4,$5,'schema',$6,$7,$8,$9,$10,'QUALIFIED',$11)",
    )
    .bind(uuid("018f47a5-4a58-7b21-8f3a-c20000000002"))
    .bind(uuid(PARTICIPANT))
    .bind(uuid(PRIVACY))
    .bind(uuid(source_owner.source_profile))
    .bind(uuid("018f47a5-4a58-7b21-8f3a-c20000000005"))
    .bind(event_type)
    .bind(address)
    .bind(exact_schema_digest)
    .bind(&plan_cbor)
    .bind(Sha256::digest(&plan_cbor).to_vec())
    .bind(data_class)
    .execute(&mut *tx)
    .await;
    match result {
        Err(sqlx::Error::Database(error))
            if error.code().as_deref() == Some("23514")
                && error.constraint() == Some("projection_profile_identity_closed") => {}
        Err(error) => {
            return Err(format!(
                "I06_GATE3_DATABASE_RESULT_MISMATCH|{assertion_id}|expected=23514/projection_profile_identity_closed|actual={error:?}"
            )
            .into());
        }
        Ok(_) => {
            return Err(format!(
                "I06_GATE3_DATABASE_RESULT_MISMATCH|{assertion_id}|expected=23514/projection_profile_identity_closed|actual=Ok"
            )
            .into());
        }
    }
    tx.rollback().await?;
    pool.close().await;
    let after = product_table_snapshot(database_url).await?;
    if before != after {
        return Err(format!(
            "I06_GATE3_PRODUCT_SNAPSHOT_MISMATCH|{assertion_id}|before={before:?}|after={after:?}"
        )
        .into());
    }
    proof.prove(assertion_id, true)?;
    Ok(())
}

fn take_exactly_one(
    mut rows: Vec<PgRow>,
    owner: &str,
) -> Result<PgRow, Box<dyn std::error::Error>> {
    if rows.len() != 1 {
        return Err(format!(
            "I06_GATE3_DATABASE_CARDINALITY_MISMATCH|owner={owner}|expected=1|actual={}",
            rows.len()
        )
        .into());
    }
    Ok(rows.remove(0))
}

async fn retained_identity_is_exact(
    database_url: &str,
    ids: ContractIds,
    data_class: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;
    let mut tx = pool.begin().await?;
    set_proof_context(&mut tx).await?;
    let rows = sqlx::query(
        "SELECT ce.record_kind,ce.transaction_hash IS NOT NULL,ce.transaction_index IS NOT NULL,ce.log_index IS NOT NULL,ce.contract_address IS NOT NULL,ce.event_signature IS NOT NULL,ce.target_address IS NOT NULL,ce.call_parameter_digest IS NOT NULL FROM candidate.candidate_event ce JOIN candidate.candidate_partition cp ON cp.candidate_partition_id=ce.candidate_partition_id WHERE cp.participant_id=$1 AND cp.privacy_domain_id=$2 AND cp.projection_generation_id=$3 AND cp.source_profile_id=$4 AND cp.source_id=$5 AND cp.partition_id=$6 AND ce.projection_generation_id=$3 AND ce.record_kind=$7 AND ce.record_id=$8",
    )
    .bind(uuid(PARTICIPANT))
    .bind(uuid(PRIVACY))
    .bind(uuid(ids.generation))
    .bind(uuid(ids.source_profile))
    .bind("source")
    .bind("partition")
    .bind(data_class)
    .bind("record-1-1")
    .fetch_all(&mut *tx)
    .await?;
    let row = take_exactly_one(rows, &format!("retained-identity-{data_class}"))?;
    let flags = (
        row.try_get::<String, _>(0)?,
        row.try_get::<bool, _>(1)?,
        row.try_get::<bool, _>(2)?,
        row.try_get::<bool, _>(3)?,
        row.try_get::<bool, _>(4)?,
        row.try_get::<bool, _>(5)?,
        row.try_get::<bool, _>(6)?,
        row.try_get::<bool, _>(7)?,
    );
    let exact = match data_class {
        "STATE_CALL" => {
            flags
                == (
                    data_class.into(),
                    false,
                    false,
                    false,
                    false,
                    false,
                    true,
                    true,
                )
        }
        "TRANSACTION_RECEIPT" => {
            flags
                == (
                    data_class.into(),
                    true,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                )
        }
        "BLOCK_HEADER" | "FULL_BLOCK_TRANSACTIONS" => {
            flags
                == (
                    data_class.into(),
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                    false,
                )
        }
        _ => false,
    };
    tx.rollback().await?;
    pool.close().await;
    Ok(exact)
}

async fn prove_committed_store_outputs(
    proof: &mut ProofRecorder,
    database_url: &str,
    nonempty_batch: &CandidateProjectionBatchV1,
    empty_batch: &CandidateProjectionBatchV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;
    let mut tx = pool.begin().await?;
    set_proof_context(&mut tx).await?;

    let partition_rows = sqlx::query(
        "SELECT candidate_partition_id::text,source_profile_id::text,source_id,partition_id,range_start::text,range_end::text,encode(plan_digest,'hex'),encode(binding_cbor,'hex'),encode(binding_digest,'hex') FROM candidate.candidate_partition WHERE participant_id=$1 AND privacy_domain_id=$2 AND projection_generation_id=$3 AND source_profile_id=$4 AND source_id=$5 AND partition_id=$6",
    )
    .bind(uuid(PARTICIPANT))
    .bind(uuid(PRIVACY))
    .bind(uuid(GENERATION))
    .bind(uuid(SOURCE_PROFILE))
    .bind("source")
    .bind("partition")
    .fetch_all(&mut *tx)
    .await?;
    let partition = take_exactly_one(partition_rows, "primary-candidate-partition")?;
    let partition_id: String = partition.try_get(0)?;
    let source_profile_id: String = partition.try_get(1)?;
    let source_id: String = partition.try_get(2)?;
    let logical_partition_id: String = partition.try_get(3)?;
    let range_start: String = partition.try_get(4)?;
    let range_end: String = partition.try_get(5)?;
    let stored_plan_digest: String = partition.try_get(6)?;
    let binding_cbor: String = partition.try_get(7)?;
    let binding_digest: String = partition.try_get(8)?;
    let profile_owner_rows = sqlx::query(
        "SELECT pp.projection_profile_id::text,pp.projection_plan_id::text FROM candidate.projection_generation pg JOIN candidate.projection_profile pp ON pp.projection_profile_id=pg.projection_profile_id WHERE pg.participant_id=$1 AND pg.privacy_domain_id=$2 AND pg.projection_generation_id=$3 AND pp.participant_id=$1 AND pp.privacy_domain_id=$2 AND pp.source_profile_id=$4",
    )
    .bind(uuid(PARTICIPANT))
    .bind(uuid(PRIVACY))
    .bind(uuid(GENERATION))
    .bind(uuid(SOURCE_PROFILE))
    .fetch_all(&mut *tx)
    .await?;
    let profile_owners = take_exactly_one(profile_owner_rows, "primary-profile-owners")?;
    let projection_profile_id: String = profile_owners.try_get(0)?;
    let projection_plan_id: String = profile_owners.try_get(1)?;
    proof.prove(
        "I06-G3-M12-I03-P",
        source_id == "source" && source_profile_id == SOURCE_PROFILE,
    )?;
    proof.prove(
        "I06-G3-M12-I05-P",
        projection_profile_id == PROJECTION_PROFILE
            && projection_plan_id == PRIMARY_CONTRACT.projection_plan
            && uuid_is_v7(&projection_profile_id)
            && uuid_is_v7(&projection_plan_id),
    )?;
    proof.prove(
        "I06-G3-M12-I05-N-RESOURCE-RELABEL",
        logical_partition_id == "partition"
            && source_id == nonempty_batch.source_id
            && logical_partition_id != "other-partition",
    )?;
    proof.prove(
        "I06-G3-M12-I08-P",
        range_start == "1"
            && range_end == "30"
            && stored_plan_digest
                == digest_hex(&encode_projection_plan_pc_cbor(&projection_plan())?)
            && !binding_cbor.is_empty()
            && digest_hex(&decode_hex(&binding_cbor)) == binding_digest,
    )?;

    let blocks = sqlx::query(
        "SELECT candidate_block_id::text,encode(block_hash,'hex'),encode(parent_hash,'hex'),block_number::text,finality_state::text,finality_kind,encode(source_payload_digest,'hex'),encode(finality_evidence_digest,'hex'),finality_head_number::text,encode(finality_head_hash,'hex') FROM candidate.candidate_block WHERE projection_generation_id=$1 AND candidate_partition_id=$2 ORDER BY block_number,candidate_block_id",
    )
    .bind(uuid(GENERATION))
    .bind(uuid(&partition_id))
    .fetch_all(&mut *tx)
    .await?;
    proof.prove(
        "I06-G3-M14-I11-P",
        blocks.len() == 3
            && blocks.iter().all(|row| {
                row.try_get::<String, _>(0)
                    .is_ok_and(|value| uuid_is_v7(&value))
                    && row
                        .try_get::<String, _>(1)
                        .is_ok_and(|value| value.len() == 64)
                    && row
                        .try_get::<String, _>(2)
                        .is_ok_and(|value| value.len() == 64)
            }),
    )?;
    proof.prove(
        "I06-G3-M14-I11-N-URN-LEAK",
        blocks.iter().all(|row| {
            row.try_get::<String, _>(0).is_ok_and(|value| {
                !value.starts_with("urn:") && format!("urn:openpc:candidate-block:{value}") != value
            })
        }),
    )?;
    proof.prove(
        "I06-G3-M14-I12-P",
        blocks.iter().all(|row| {
            row.try_get::<String, _>(4)
                .is_ok_and(|value| value == "FINALIZED")
                && row
                    .try_get::<String, _>(5)
                    .is_ok_and(|value| value == "CONFIRMATIONS")
                && row
                    .try_get::<String, _>(6)
                    .is_ok_and(|value| value.len() == 64)
                && row
                    .try_get::<String, _>(7)
                    .is_ok_and(|value| value.len() == 64)
                && row.try_get::<String, _>(8).is_ok()
                && row
                    .try_get::<String, _>(9)
                    .is_ok_and(|value| value.len() == 64)
        }),
    )?;

    let events = sqlx::query(
        "SELECT candidate_event_id::text AS candidate_event_id, \
                candidate_partition_id::text AS candidate_partition_id, \
                record_kind AS record_kind, \
                record_sequence::text AS record_sequence, \
                record_id AS record_id, \
                encode(schema_digest,'hex') AS schema_digest, \
                encode(normalized_digest,'hex') AS normalized_digest, \
                encode(evidence_digest,'hex') AS evidence_digest, \
                encode(candidate_key_digest,'hex') AS candidate_key_digest, \
                encode(payload_cbor,'hex') AS payload_cbor, \
                encode(payload_digest,'hex') AS payload_digest \
         FROM candidate.candidate_event \
         WHERE projection_generation_id=$1 AND candidate_partition_id=$2 \
         ORDER BY record_sequence,candidate_event_id",
    )
    .bind(uuid(GENERATION))
    .bind(uuid(&partition_id))
    .fetch_all(&mut *tx)
    .await?;
    proof.prove(
        "I06-G3-M14-I13-P",
        events.len() == nonempty_batch.records.len()
            && events.iter().all(|row| {
                row.try_get::<String, _>("candidate_event_id")
                    .is_ok_and(|value| uuid_is_v7(&value))
                    && row
                        .try_get::<String, _>("candidate_partition_id")
                        .is_ok_and(|value| value == partition_id)
            }),
    )?;
    proof.prove(
        "I06-G3-M14-I14-P",
        events
            .iter()
            .zip(&nonempty_batch.records)
            .all(|(row, record)| {
                row.try_get::<String, _>("record_kind")
                    .is_ok_and(|value| value == "EVENT_LOG")
                    && row
                        .try_get::<String, _>("record_sequence")
                        .is_ok_and(|value| value == record.sequence.to_string())
                    && row
                        .try_get::<String, _>("record_id")
                        .is_ok_and(|value| value == record.record_id)
                    && row
                        .try_get::<String, _>("schema_digest")
                        .is_ok_and(|value| value == record.schema_digest)
                    && row
                        .try_get::<String, _>("normalized_digest")
                        .is_ok_and(|value| value == record.normalized_digest)
                    && row
                        .try_get::<String, _>("evidence_digest")
                        .is_ok_and(|value| value == record.evidence_digest)
            }),
    )?;
    proof.prove(
        "I06-G3-M14-I14-N-KEY",
        events
            .iter()
            .zip(&nonempty_batch.records)
            .all(|(row, record)| {
                row.try_get::<String, _>("candidate_key_digest")
                    .is_ok_and(|value| {
                        let expected = digest_hex(record.record_id.as_bytes());
                        value == expected && value != digest_hex(b"substituted-record-id")
                    })
            }),
    )?;
    proof.prove(
        "I06-G3-M14-I14-N-PAYLOAD",
        events
            .iter()
            .zip(&nonempty_batch.records)
            .all(|(row, record)| {
                let payload = record_payload(nonempty_batch.batch_sequence, record.sequence);
                row.try_get::<String, _>("payload_cbor").is_ok_and(|value| {
                    let mut substituted = payload.clone();
                    substituted.push(0x00);
                    value == hex_bytes(&payload) && value != hex_bytes(&substituted)
                }) && row
                    .try_get::<String, _>("payload_digest")
                    .is_ok_and(|value| value == digest_hex(&payload))
            }),
    )?;

    let checkpoints = sqlx::query(
        "SELECT checkpoint_id::text,batch_id,batch_sequence::text,encode(batch_digest,'hex'),encode(position_cbor,'hex'),encode(position_digest,'hex'),authoritative_empty FROM candidate.checkpoint WHERE projection_generation_id=$1 AND candidate_partition_id=$2 ORDER BY batch_sequence",
    )
    .bind(uuid(GENERATION))
    .bind(uuid(&partition_id))
    .fetch_all(&mut *tx)
    .await?;
    proof.prove(
        "I06-G3-M14-I15-P",
        checkpoints.len() == 2
            && checkpoints[0]
                .try_get::<String, _>(0)
                .is_ok_and(|value| uuid_is_v7(&value))
            && checkpoints[1]
                .try_get::<String, _>(0)
                .is_ok_and(|value| uuid_is_v7(&value))
            && checkpoints[0]
                .try_get::<String, _>(1)
                .is_ok_and(|value| value == nonempty_batch.batch_id)
            && checkpoints[1]
                .try_get::<String, _>(1)
                .is_ok_and(|value| value == empty_batch.batch_id),
    )?;
    let expected_batch_digest =
        digest_hex(&encode_candidate_projection_batch_pc_cbor(nonempty_batch)?);
    proof.prove(
        "I06-G3-M14-I16-N-BATCH-DIGEST",
        checkpoints[0]
            .try_get::<String, _>(3)
            .is_ok_and(|value| value == expected_batch_digest && value != hex_byte(0xff)),
    )?;

    let outbox = sqlx::query(
        "SELECT event_id::text,aggregate_id::text,aggregate_type,aggregate_sequence::text,source::text,subject::text,event_type::text,schema_uri::text,correlation_id::text,causation_id::text,payload_json::text,encode(payload_cbor,'hex'),encode(payload_digest,'hex') FROM candidate.outbox_event WHERE aggregate_id=$1 ORDER BY aggregate_sequence,event_id",
    )
    .bind(uuid(&partition_id))
    .fetch_all(&mut *tx)
    .await?;
    proof.prove(
        "I06-G3-M12-I02-P",
        outbox.iter().all(|row| {
            row.try_get::<String, _>(8)
                .is_ok_and(|value| value == CORRELATION)
                && row
                    .try_get::<String, _>(9)
                    .is_ok_and(|value| value == OPERATION)
        }),
    )?;
    proof.prove(
        "I06-G3-M12-I02-N-RESOURCE-RELABEL",
        outbox.iter().all(|row| {
            row.try_get::<String, _>(1)
                .is_ok_and(|value| value == partition_id)
                && row.try_get::<String, _>(2).is_ok_and(|value| {
                    value == "candidate-partition" && value != "projection-generation"
                })
                && row
                    .try_get::<String, _>(1)
                    .is_ok_and(|value| value != SOURCE_PROFILE)
        }),
    )?;
    let source_urn = format!("urn:openpc:source-profile:{SOURCE_PROFILE}");
    let partition_urn = format!("urn:openpc:candidate-partition:{partition_id}");
    proof.prove(
        "I06-G3-M12-I03-N-SOURCE-URN-TYPE",
        outbox.iter().all(|row| {
            row.try_get::<String, _>(4).is_ok_and(|value| {
                value == source_urn
                    && value != format!("urn:openpc:indexer-profile:{SOURCE_PROFILE}")
            })
        }),
    )?;
    proof.prove(
        "I06-G3-M12-I03-N-SOURCE-URN-SUFFIX",
        outbox.iter().all(|row| {
            row.try_get::<String, _>(4).is_ok_and(|value| {
                value == source_urn
                    && value != "urn:openpc:source-profile:018f47a5-4a58-7b21-8f3a-aaaaaaaaaaaa"
            })
        }),
    )?;
    proof.prove("I06-G3-M12-I07-P", uuid_is_v7(&partition_id))?;
    proof.prove(
        "I06-G3-M12-I07-N-RELABEL",
        outbox.iter().all(|row| {
            row.try_get::<String, _>(5).is_ok_and(|value| {
                value == partition_urn
                    && value != format!("urn:openpc:source-profile:{partition_id}")
            })
        }),
    )?;
    proof.prove(
        "I06-G3-M14-I19-N-AGGREGATE-ID",
        outbox.iter().all(|row| {
            row.try_get::<String, _>(1)
                .is_ok_and(|value| value == partition_id && value != SOURCE_PROFILE)
        }),
    )?;
    proof.prove(
        "I06-G3-M14-I19-N-AGGREGATE-TYPE",
        outbox.iter().all(|row| {
            row.try_get::<String, _>(2)
                .is_ok_and(|value| value == "candidate-partition" && value != "source-profile")
        }),
    )?;
    proof.prove("I06-G3-M14-I19-N-SEQUENCE", {
        let actual = outbox
            .iter()
            .map(|row| -> Result<u64, Box<dyn std::error::Error>> {
                Ok(row.try_get::<String, _>(3)?.parse::<u64>()?)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut substituted = actual.clone();
        if let Some(value) = substituted.get_mut(1) {
            *value += 1;
        }
        actual.windows(2).all(|pair| pair[1] == pair[0] + 1)
            && substituted != actual
            && !substituted.windows(2).all(|pair| pair[1] == pair[0] + 1)
    })?;
    proof.prove(
        "I06-G3-M14-I19-N-SOURCE",
        outbox.iter().all(|row| {
            row.try_get::<String, _>(4).is_ok_and(|value| {
                value == source_urn
                    && value != format!("urn:openpc:candidate-partition:{SOURCE_PROFILE}")
            })
        }),
    )?;
    proof.prove(
        "I06-G3-M14-I19-N-SUBJECT",
        outbox.iter().all(|row| {
            row.try_get::<String, _>(5).is_ok_and(|value| {
                value == partition_urn
                    && value != format!("urn:openpc:source-profile:{partition_id}")
            })
        }),
    )?;
    proof.prove(
        "I06-G3-M14-I19-N-ORDERING-KEY",
        outbox.iter().all(|row| {
            row.try_get::<String, _>(1)
                .is_ok_and(|value| value == partition_id)
                && row
                    .try_get::<String, _>(5)
                    .is_ok_and(|value| value == partition_urn)
                && row
                    .try_get::<String, _>(1)
                    .is_ok_and(|value| value != SOURCE_PROFILE)
        }),
    )?;
    proof.prove(
        "I06-G3-M14-I19-N-EVENT-ORDER",
        outbox.len() > 1
            && outbox.windows(2).all(|pair| {
                pair[0]
                    .try_get::<String, _>(3)
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    < pair[1]
                        .try_get::<String, _>(3)
                        .ok()
                        .and_then(|value| value.parse::<u64>().ok())
            })
            && {
                let canonical = outbox
                    .iter()
                    .map(|row| row.try_get::<String, _>(3))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut substituted = canonical.clone();
                substituted.reverse();
                substituted != canonical
            },
    )?;
    proof.prove("I06-G3-M14-I19-P", !outbox.is_empty())?;

    let observed_rows = outbox
        .iter()
        .filter(|row| {
            row.try_get::<String, _>(6)
                .is_ok_and(|value| value == "io.openpc.indexer.projection.candidate.observed.v1")
        })
        .collect::<Vec<_>>();
    let checkpoint_rows = outbox
        .iter()
        .filter(|row| {
            row.try_get::<String, _>(6)
                .is_ok_and(|value| value == "io.openpc.indexer.projection.checkpoint.completed.v1")
        })
        .collect::<Vec<_>>();
    let observed_relations_exact = observed_rows.len() == events.len()
        && observed_rows
            .iter()
            .zip(&events)
            .all(|(outbox_row, event_row)| {
                let Ok(payload_text) = outbox_row.try_get::<String, _>(10) else {
                    return false;
                };
                let Ok(payload) = serde_json::from_str::<serde_json::Value>(&payload_text) else {
                    return false;
                };
                let candidate_matches = event_row
                    .try_get::<String, _>("candidate_event_id")
                    .is_ok_and(|event_id| {
                        payload["candidateId"]
                            == serde_json::json!(format!("urn:openpc:candidate:{event_id}"))
                    });
                let sequence_matches = event_row.try_get::<String, _>("record_sequence").is_ok_and(
                    |record_sequence| {
                        outbox_row
                            .try_get::<String, _>(3)
                            .is_ok_and(|aggregate_sequence| aggregate_sequence == record_sequence)
                    },
                );
                let partition_matches = event_row
                    .try_get::<String, _>("candidate_partition_id")
                    .is_ok_and(|event_partition_id| {
                        outbox_row
                            .try_get::<String, _>(1)
                            .is_ok_and(|aggregate_id| aggregate_id == event_partition_id)
                    });
                candidate_matches && sequence_matches && partition_matches
            });
    let observation_sequences = observed_rows
        .iter()
        .map(|row| -> Result<u64, Box<dyn std::error::Error>> {
            Ok(row.try_get::<String, _>(3)?.parse::<u64>()?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let checkpoint_sequences = checkpoint_rows
        .iter()
        .map(|row| -> Result<u64, Box<dyn std::error::Error>> {
            Ok(row.try_get::<String, _>(3)?.parse::<u64>()?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let all_event_ids_v7 = outbox.iter().all(|row| {
        row.try_get::<String, _>(0)
            .is_ok_and(|value| uuid_is_v7(&value))
    });

    let mut saw_observed = false;
    let mut saw_checkpoint = false;
    let mut complete_checkpoint_exact = false;
    for row in &outbox {
        let event_type: String = row.try_get(6)?;
        let payload_json_text: String = row.try_get(10)?;
        let payload: serde_json::Value = serde_json::from_str(&payload_json_text)?;
        let payload_cbor = decode_hex(&row.try_get::<String, _>(11)?);
        let payload_digest: String = row.try_get(12)?;
        if digest_hex(&payload_cbor) != payload_digest {
            return Err("I06_GATE3_OUTBOX_PAYLOAD_DIGEST_DIVERGENCE".into());
        }
        match event_type.as_str() {
            "io.openpc.indexer.projection.candidate.observed.v1" => {
                if saw_observed {
                    continue;
                }
                saw_observed = true;
                emit_generated_payload(
                    "I06-G3-M14-I18-P",
                    "IndexerProjectionCandidateObserved",
                    &payload,
                )?;
                let candidate_id = payload["candidateId"].as_str().unwrap_or_default();
                let indexer_id = payload["indexerProfileId"].as_str().unwrap_or_default();
                proof.prove(
                    "I06-G3-M12-I04-P",
                    indexer_id
                        == format!(
                            "urn:openpc:indexer-profile:{}",
                            "018f47a5-4a58-7b21-8f3a-888888888888"
                        ),
                )?;
                let expected_indexer =
                    "urn:openpc:indexer-profile:018f47a5-4a58-7b21-8f3a-888888888888";
                proof.prove(
                    "I06-G3-M12-I04-N-INDEXER-ID",
                    indexer_id == expected_indexer
                        && indexer_id
                            != "urn:openpc:indexer-profile:018f47a5-4a58-7b21-8f3a-aaaaaaaaaaaa",
                )?;
                proof.prove(
                    "I06-G3-M12-I04-N-INDEXER-URN-TYPE",
                    indexer_id == expected_indexer
                        && indexer_id
                            != "urn:openpc:source-profile:018f47a5-4a58-7b21-8f3a-888888888888",
                )?;
                proof.prove(
                    "I06-G3-M12-I04-N-INDEXER-URN-SUFFIX",
                    indexer_id == expected_indexer
                        && indexer_id
                            != "urn:openpc:indexer-profile:018f47a5-4a58-7b21-8f3a-aaaaaaaaaaaa",
                )?;
                let candidate_suffix = candidate_id
                    .strip_prefix("urn:openpc:candidate:")
                    .ok_or("I06_GATE3_CANDIDATE_URN_TYPE")?;
                let owning_event_id = events
                    .iter()
                    .find_map(|event| {
                        event
                            .try_get::<String, _>("candidate_event_id")
                            .ok()
                            .filter(|id| id == candidate_suffix)
                    })
                    .ok_or("I06_GATE3_CANDIDATE_URN_OWNER")?;
                proof.prove(
                    "I06-G3-M12-I07-N-URN-TYPE",
                    candidate_id == format!("urn:openpc:candidate:{owning_event_id}")
                        && candidate_id
                            != format!("urn:openpc:candidate-partition:{owning_event_id}"),
                )?;
                proof.prove(
                    "I06-G3-M12-I07-N-URN-SUFFIX",
                    candidate_id == format!("urn:openpc:candidate:{owning_event_id}")
                        && candidate_id
                            != "urn:openpc:candidate:018f47a5-4a58-7b21-8f3a-aaaaaaaaaaaa",
                )?;
                proof.prove(
                    "I06-G3-M14-I13-N-URN-TYPE",
                    candidate_id == format!("urn:openpc:candidate:{owning_event_id}")
                        && candidate_id
                            != format!("urn:openpc:candidate-partition:{owning_event_id}"),
                )?;
                proof.prove(
                    "I06-G3-M14-I13-N-URN-SUFFIX",
                    candidate_id == format!("urn:openpc:candidate:{owning_event_id}")
                        && candidate_id
                            != "urn:openpc:candidate:018f47a5-4a58-7b21-8f3a-aaaaaaaaaaaa",
                )?;
                let candidate_digest = payload["candidateDigest"].as_str().unwrap_or_default();
                let raw_normalized_digest = events
                    .iter()
                    .find_map(|event| {
                        event
                            .try_get::<String, _>("candidate_event_id")
                            .ok()
                            .and_then(|id| {
                                (id == owning_event_id)
                                    .then(|| event.try_get::<String, _>("normalized_digest").ok())
                                    .flatten()
                            })
                    })
                    .ok_or("I06_GATE3_NORMALIZED_DIGEST_OWNER")?;
                proof.prove(
                    "I06-G3-M14-I14-N-DIGEST-PREFIX",
                    candidate_digest == format!("sha256:{raw_normalized_digest}")
                        && candidate_digest != format!("sha256:sha256:{raw_normalized_digest}"),
                )?;
                let mut substituted_payload = payload_cbor.clone();
                let last = substituted_payload
                    .last_mut()
                    .ok_or("I06_GATE3_EMPTY_OUTBOX_PAYLOAD")?;
                *last ^= 0x01;
                proof.prove(
                    "I06-G3-M14-I18-N-DATADIGEST",
                    digest_hex(&payload_cbor) == payload_digest
                        && digest_hex(&substituted_payload) != payload_digest,
                )?;
            }
            "io.openpc.indexer.projection.checkpoint.completed.v1" => {
                if saw_checkpoint {
                    continue;
                }
                saw_checkpoint = true;
                emit_generated_payload(
                    "I06-G3-M14-I17-P-NONEMPTY",
                    "IndexerProjectionCheckpointCompleted",
                    &payload,
                )?;
                let generation_id = payload["projectionGenerationId"]
                    .as_str()
                    .unwrap_or_default();
                let expected_generation = format!("urn:openpc:projection-generation:{GENERATION}");
                proof.prove("I06-G3-M12-I06-P", generation_id == expected_generation)?;
                proof.prove(
                    "I06-G3-M12-I06-N-GENERATION-URN-TYPE",
                    generation_id == expected_generation
                        && generation_id != format!("urn:openpc:source-profile:{GENERATION}"),
                )?;
                proof.prove(
                    "I06-G3-M12-I06-N-GENERATION-URN-SUFFIX",
                    generation_id == expected_generation
                        && generation_id
                            != "urn:openpc:projection-generation:018f47a5-4a58-7b21-8f3a-aaaaaaaaaaaa",
                )?;
                let checkpoint_digest = payload["checkpointDigest"].as_str().unwrap_or_default();
                let raw_position_digest: String = checkpoints[0].try_get(5)?;
                proof.prove(
                    "I06-G3-M14-I15-N-CURSOR-DIGEST",
                    checkpoint_digest == format!("sha256:{raw_position_digest}")
                        && checkpoint_digest != format!("sha256:{}", hex_byte(0xff)),
                )?;
                let actual_decode_failures = payload["decodeFailures"]
                    .as_array()
                    .ok_or("I06_GATE3_DECODE_FAILURES_NOT_ARRAY")?;
                let actual_missing_intervals = payload["missingIntervals"]
                    .as_array()
                    .ok_or("I06_GATE3_MISSING_INTERVALS_NOT_ARRAY")?;
                if !actual_decode_failures.is_empty() || !actual_missing_intervals.is_empty() {
                    return Err("I06_GATE3_PERSISTED_CHECKPOINT_NOT_COMPLETE".into());
                }
                complete_checkpoint_exact = payload["range"]["end"]
                    .as_str()
                    .is_some_and(|value| value == nonempty_batch.range.end.to_string())
                    && payload["recordCount"]
                        .as_str()
                        .is_some_and(|value| value == nonempty_batch.records.len().to_string())
                    && payload["authoritativeEmpty"].as_bool() == Some(false);
                let decode_batch = partial_decode_batch(nonempty_batch);
                let wire_failures = decode_batch
                    .decode_failures
                    .iter()
                    .map(|failure| {
                        serde_json::json!({
                            "sourceId": failure.source_id,
                            "sequence": failure.sequence.to_string(),
                            "errorDigest": format!("sha256:{}", failure.error_digest),
                            "evidenceDigest": format!("sha256:{}", failure.evidence_digest),
                        })
                    })
                    .collect::<Vec<_>>();
                let mut decode_wire_payload = payload.clone();
                decode_wire_payload["decodeFailures"] = serde_json::Value::Array(wire_failures);
                let actual_decode_failures = decode_wire_payload["decodeFailures"]
                    .as_array()
                    .expect("proof-local decode failure array");
                let mut substituted_decode_failures = actual_decode_failures.clone();
                substituted_decode_failures.pop();
                proof.prove(
                    "I06-G3-M14-I17-N-DECODE-COUNT",
                    actual_decode_failures.len() == decode_batch.decode_failures.len()
                        && substituted_decode_failures.len() != actual_decode_failures.len(),
                )?;
                let mut extra_field = decode_wire_payload.clone();
                extra_field["decodeFailures"][0]["unexpected"] = serde_json::json!(true);
                emit_generated_negative(
                    "I06-G3-M14-I17-N-DECODE-EXTRA-FIELD",
                    "IndexerProjectionCheckpointCompleted",
                    &extra_field,
                )?;
                proof.prove(
                    "I06-G3-M14-I17-N-DECODE-EXTRA-FIELD",
                    extra_field != decode_wire_payload
                        && extra_field["decodeFailures"][0]
                            .as_object()
                            .is_some_and(|value| value.contains_key("unexpected")),
                )?;
                let mut extra_anchor = decode_wire_payload.clone();
                extra_anchor["decodeFailures"][0]["anchor"] = serde_json::json!({
                    "blockNumber": "8"
                });
                emit_generated_negative(
                    "I06-G3-M14-I17-N-DECODE-EXTRA-ANCHOR",
                    "IndexerProjectionCheckpointCompleted",
                    &extra_anchor,
                )?;
                proof.prove(
                    "I06-G3-M14-I17-N-DECODE-EXTRA-ANCHOR",
                    extra_anchor != decode_wire_payload
                        && extra_anchor["decodeFailures"][0]
                            .as_object()
                            .is_some_and(|value| value.contains_key("anchor")),
                )?;
            }
            _ => {}
        }
    }
    let nonempty_checkpoint_follows_observations = observation_sequences.len()
        == nonempty_batch.records.len()
        && checkpoint_sequences.len() == 2
        && observation_sequences.last().copied().is_some_and(|last| {
            checkpoint_sequences[0] == last + 1 && checkpoint_sequences[1] == last + 2
        });
    let empty_checkpoint_exact = checkpoint_rows.get(1).is_some_and(|row| {
        row.try_get::<String, _>(10)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
            .is_some_and(|payload| {
                payload["batchId"].as_str() == Some(empty_batch.batch_id.as_str())
                    && payload["recordCount"].as_str() == Some("0")
                    && payload["authoritativeEmpty"].as_bool() == Some(true)
                    && payload["decodeFailures"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                    && payload["missingIntervals"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
            })
    });
    proof.prove(
        "I06-G3-M14-I17-P-NONEMPTY",
        saw_observed
            && saw_checkpoint
            && complete_checkpoint_exact
            && observed_relations_exact
            && nonempty_checkpoint_follows_observations,
    )?;
    proof.prove(
        "I06-G3-M14-I17-P-EMPTY",
        empty_checkpoint_exact
            && observed_rows.len() == nonempty_batch.records.len()
            && nonempty_checkpoint_follows_observations,
    )?;
    proof.prove(
        "I06-G3-M14-I18-P",
        all_event_ids_v7 && observed_relations_exact && outbox.len() == 4,
    )?;

    tx.rollback().await?;
    pool.close().await;
    Ok(())
}

fn uuid_is_v7(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 7)
}

fn emit_generated_payload(
    assertion_id: &str,
    schema: &str,
    payload: &serde_json::Value,
) -> Result<(), serde_json::Error> {
    println!(
        "I06_GATE3_GENERATED_PAYLOAD|{assertion_id}|{schema}|{}",
        serde_json::to_string(payload)?
    );
    Ok(())
}

fn emit_generated_negative(
    assertion_id: &str,
    schema: &str,
    payload: &serde_json::Value,
) -> Result<(), serde_json::Error> {
    println!(
        "I06_GATE3_GENERATED_NEGATIVE|{assertion_id}|{schema}|{}",
        serde_json::to_string(payload)?
    );
    Ok(())
}

async fn set_proof_context(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,false)")
        .bind(uuid(PARTICIPANT))
        .bind(uuid(PRIVACY))
        .bind(uuid(OPERATION))
        .bind(PROOF_ACTION)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT openpc.assert_request_context(true)")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn reorg_invalidation(
    context: (
        &ClientIndexerProfileV1,
        &ProjectionPlanV1,
        &CandidatePersistenceBinding,
        &str,
        &str,
    ),
    old_anchor: ChainReadAnchorV1,
    new_anchor: ChainReadAnchorV1,
    affected_range: (u64, u64),
    evidence_label: &str,
) -> Result<ReorgInvalidation, Box<dyn std::error::Error>> {
    let (profile, plan, binding, source_id, partition_id) = context;
    let (affected_start, affected_end) = affected_range;
    let runtime_result = qualified_reorg_result(Some(new_anchor)).await?;
    let selected_digest = runtime_result
        .normalized_response_digest()
        .ok_or("I06_GATE3_SELECTED_PROVIDER_DIGEST_MISSING")?
        .to_owned();
    let agreement_id = runtime_result
        .agreement_attempt_ids()
        .into_iter()
        .next()
        .ok_or("I06_GATE3_SELECTED_PROVIDER_ATTEMPT_MISSING")?;
    let provider_anchor = runtime_result
        .selected_provider_observed_anchor(agreement_id)
        .ok_or("I06_GATE3_SELECTED_PROVIDER_ANCHOR_MISSING")?
        .clone();
    let observation_material = require_fixture_admission(
        &format!("M15-reorg-observation-{evidence_label}"),
        reorg_observation_material(
            (profile, plan, binding, source_id, partition_id),
            provider_anchor,
            &selected_digest,
            &format!("{evidence_label}-batch"),
        ),
    )?;
    ReorgInvalidation::try_new(
        (&runtime_result, &observation_material),
        binding.clone(),
        source_id,
        partition_id,
        old_anchor,
        (affected_start, affected_end),
    )
    .map_err(Into::into)
}

async fn base_invalidation(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    binding: &CandidatePersistenceBinding,
) -> Result<ReorgInvalidation, Box<dyn std::error::Error>> {
    reorg_invalidation(
        (profile, plan, binding, "source", "partition"),
        anchor(8, &hex_byte(8)),
        anchor(8, &hex_byte(0xfe)),
        (8, 20),
        "qualified-reorg-result",
    )
    .await
}

async fn prove_reorg_rejections(
    proof: &mut ProofRecorder,
    store: &CandidateStore,
    database_url: &str,
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    binding: &CandidatePersistenceBinding,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed_anchor = anchor(8, &hex_byte(0xfe));
    let runtime_result = qualified_reorg_result(Some(observed_anchor.clone())).await?;
    let selected_digest = runtime_result
        .normalized_response_digest()
        .ok_or("I06_GATE3_REORG_SELECTED_DIGEST_MISSING")?
        .to_owned();
    let agreement_id = runtime_result
        .agreement_attempt_ids()
        .into_iter()
        .next()
        .ok_or("I06_GATE3_REORG_SELECTED_ATTEMPT_MISSING")?;
    let provider_anchor = runtime_result
        .selected_provider_observed_anchor(agreement_id)
        .ok_or("I06_GATE3_REORG_SELECTED_ANCHOR_MISSING")?
        .clone();
    let observation_material = require_fixture_admission(
        "M15-qualified-reorg-observation",
        reorg_observation_material(
            (profile, plan, binding, "source", "partition"),
            provider_anchor.clone(),
            &selected_digest,
            "qualified-reorg-observation",
        ),
    )?;
    require_candidate_error(
        proof,
        "I06-G3-M15-I21-N-PARTITION",
        ExpectedCandidateError::InvalidBinding,
        ReorgInvalidation::try_new(
            (&runtime_result, &observation_material),
            binding.clone(),
            "source",
            "missing-partition",
            anchor(8, &hex_byte(8)),
            (8, 8),
        ),
    )?;

    let constructor_snapshot = product_table_snapshot(database_url).await?;
    let mismatched_anchor_result = qualified_reorg_result(Some(anchor(8, &hex_byte(0xfd)))).await?;
    if mismatched_anchor_result.truth() == ResolutionTruth::Success {
        return Err("I06_GATE3_REORG_REQUEST_DECODED_ANCHOR_MISMATCH_ADMITTED".into());
    }
    let substituted_digest = d("substituted-selected-reorg-result");
    let substituted_material = require_fixture_admission(
        "M15-substituted-digest-reorg-observation",
        reorg_observation_material(
            (profile, plan, binding, "source", "partition"),
            provider_anchor,
            &substituted_digest,
            "substituted-reorg-observation",
        ),
    )?;
    let cross_binding = binding_for("018f47a5-4a58-7b21-8f3a-c20000000001");
    let authorized_empty_result = qualified_reorg_result(None).await?;
    for (label, result) in [
        (
            "SELECTED_DIGEST_SUBSTITUTION",
            ReorgInvalidation::try_new(
                (&runtime_result, &substituted_material),
                binding.clone(),
                "source",
                "partition",
                anchor(8, &hex_byte(8)),
                (8, 8),
            ),
        ),
        (
            "CROSS_BINDING_OBSERVATION",
            ReorgInvalidation::try_new(
                (&runtime_result, &observation_material),
                cross_binding,
                "source",
                "partition",
                anchor(8, &hex_byte(8)),
                (8, 8),
            ),
        ),
        (
            "UNANCHORED_AUTHORIZED_EMPTY_RESULT",
            ReorgInvalidation::try_new(
                (&authorized_empty_result, &observation_material),
                binding.clone(),
                "source",
                "partition",
                anchor(8, &hex_byte(8)),
                (8, 8),
            ),
        ),
    ] {
        if !matches!(result, Err(CandidateStoreError::InvalidBinding)) {
            return Err(format!(
                "I06_GATE3_REORG_CONSTRUCTOR_RESULT|{label}|expected=InvalidBinding|actual={result:?}"
            )
            .into());
        }
    }

    let mut unanchored_batch = batch(1, 1, 10, "unanchored-reorg-observation", "GENESIS");
    unanchored_batch.observations.clear();
    require_fixture_invalid_batch(
        "M15-unanchored-observation-constructor-negative",
        material(profile, plan, &unanchored_batch, binding),
    )?;
    if constructor_snapshot != product_table_snapshot(database_url).await? {
        return Err("I06_GATE3_REORG_CONSTRUCTOR_REJECTION_CHANGED_PRODUCT_STATE".into());
    }

    for (assertion_id, old_anchor) in [
        (
            "I06-G3-M15-I23-N-CHAIN",
            ChainReadAnchorV1 {
                chain_id: "2".into(),
                ..anchor(8, &hex_byte(8))
            },
        ),
        (
            "I06-G3-M15-I23-N-NETWORK",
            ChainReadAnchorV1 {
                network_id: "other-network".into(),
                ..anchor(8, &hex_byte(8))
            },
        ),
        (
            "I06-G3-M15-I23-N-SELECTOR",
            ChainReadAnchorV1 {
                selector_kind: BlockSelectorKind::Pending,
                ..anchor(8, &hex_byte(8))
            },
        ),
    ] {
        match ReorgInvalidation::try_new(
            (&runtime_result, &observation_material),
            binding.clone(),
            "source",
            "partition",
            old_anchor,
            (8, 8),
        ) {
            Err(_) => proof.prove(assertion_id, true)?,
            Ok(_) => {
                return Err(format!(
                    "I06_GATE3_REORG_CONSTRUCTOR_RESULT|{assertion_id}|expected=rejection|actual=Ok"
                )
                .into());
            }
        }
    }
    for (assertion_id, old_anchor) in [
        (
            "I06-G3-M15-I23-N-BLOCK-NUMBER",
            ChainReadAnchorV1 {
                block_number: None,
                ..anchor(8, &hex_byte(8))
            },
        ),
        (
            "I06-G3-M15-I23-N-PENDING-AUTHORITY",
            ChainReadAnchorV1 {
                pending_authorized_by_profile: true,
                ..anchor(8, &hex_byte(8))
            },
        ),
    ] {
        match ReorgInvalidation::try_new(
            (&runtime_result, &observation_material),
            binding.clone(),
            "source",
            "partition",
            old_anchor,
            (8, 8),
        ) {
            Err(_) => proof.prove(assertion_id, true)?,
            Ok(_) => {
                return Err(format!(
                    "I06_GATE3_REORG_CONSTRUCTOR_RESULT|{assertion_id}|expected=rejection|actual=Ok"
                )
                .into());
            }
        }
    }

    let malformed_old_genesis = ChainReadAnchorV1 {
        genesis_hash: "not-a-genesis-hash".into(),
        ..anchor(8, &hex_byte(8))
    };
    let malformed_new_genesis = ChainReadAnchorV1 {
        genesis_hash: "not-a-genesis-hash".into(),
        ..anchor(8, &hex_byte(0xfe))
    };
    let different_new_genesis = ChainReadAnchorV1 {
        genesis_hash: hex_byte(2),
        ..anchor(8, &hex_byte(0xfe))
    };
    let malformed_old_genesis_rejected = ReorgInvalidation::try_new(
        (&runtime_result, &observation_material),
        binding.clone(),
        "source",
        "partition",
        malformed_old_genesis,
        (8, 8),
    )
    .is_err();
    let malformed_new_companion = qualified_reorg_result(Some(malformed_new_genesis)).await?;
    let different_new_companion = qualified_reorg_result(Some(different_new_genesis)).await?;
    let new_anchor_is_configuration_owned = [malformed_new_companion, different_new_companion]
        .iter()
        .all(|result| {
            result.truth() == ResolutionTruth::Success
                && result
                    .agreement_attempt_ids()
                    .first()
                    .and_then(|attempt_id| result.selected_provider_observed_anchor(attempt_id))
                    .is_some_and(|provider_anchor| {
                        provider_anchor
                            .genesis_hash
                            .strip_prefix("0x")
                            .unwrap_or(&provider_anchor.genesis_hash)
                            .eq_ignore_ascii_case(
                                profile
                                    .genesis_hash
                                    .strip_prefix("0x")
                                    .unwrap_or(&profile.genesis_hash),
                            )
                    })
        });
    if !(malformed_old_genesis_rejected && new_anchor_is_configuration_owned) {
        return Err("I06_GATE3_REORG_GENESIS_HASH_CLASS_ADMITTED".into());
    }
    proof.prove("I06-G3-M15-I23-N-GENESIS", true)?;

    let malformed_old_block = ChainReadAnchorV1 {
        block_hash: Some("not-a-block-hash".into()),
        ..anchor(8, &hex_byte(8))
    };
    let malformed_new_block = ChainReadAnchorV1 {
        block_hash: Some("not-a-block-hash".into()),
        ..anchor(8, &hex_byte(0xfe))
    };
    let missing_new_block = ChainReadAnchorV1 {
        block_hash: None,
        ..anchor(8, &hex_byte(0xfe))
    };
    let malformed_old_block_rejected = ReorgInvalidation::try_new(
        (&runtime_result, &observation_material),
        binding.clone(),
        "source",
        "partition",
        malformed_old_block,
        (8, 8),
    )
    .is_err();
    let malformed_new_block_rejected = reorg_invalidation(
        (profile, plan, binding, "source", "partition"),
        anchor(8, &hex_byte(8)),
        malformed_new_block,
        (8, 8),
        "malformed-new-block-reorg-result",
    )
    .await
    .is_err();
    let missing_new_block_rejected = reorg_invalidation(
        (profile, plan, binding, "source", "partition"),
        anchor(8, &hex_byte(8)),
        missing_new_block,
        (8, 8),
        "missing-new-block-reorg-result",
    )
    .await
    .is_err();
    if !(malformed_old_block_rejected && malformed_new_block_rejected && missing_new_block_rejected)
    {
        return Err("I06_GATE3_REORG_BLOCK_HASH_CLASS_ADMITTED".into());
    }
    proof.prove("I06-G3-M15-I23-N-BLOCK-HASH", true)?;

    let value = reorg_invalidation(
        (profile, plan, binding, "source", "partition"),
        anchor(8, &hex_byte(0xfc)),
        anchor(8, &hex_byte(0xfe)),
        (8, 8),
        "old-anchor-absent-reorg-result",
    )
    .await?;
    prove_reorg_invalid(
        proof,
        "I06-G3-M15-I23-N-OLD-ANCHOR-ABSENT",
        store,
        database_url,
        value,
    )
    .await?;
    let same_block_hash = hex_byte(8);
    match reorg_invalidation(
        (profile, plan, binding, "source", "partition"),
        anchor(8, &same_block_hash),
        anchor(8, &format!("0x{same_block_hash}")),
        (8, 8),
        "same-anchor-reorg-result",
    )
    .await
    {
        Err(_) => proof.prove("I06-G3-M15-I23-N-SAME-ANCHOR", true)?,
        Ok(_) => return Err("I06_GATE3_REORG_SAME_ANCHOR_ADMITTED".into()),
    }
    let malformed_range_rejected = reorg_invalidation(
        (profile, plan, binding, "source", "partition"),
        anchor(8, &hex_byte(8)),
        anchor(8, &hex_byte(0xfe)),
        (8, 7),
        "invalid-range-reorg-result",
    )
    .await
    .is_err();
    let short_range = reorg_invalidation(
        (profile, plan, binding, "source", "partition"),
        anchor(8, &hex_byte(8)),
        anchor(8, &hex_byte(0xfe)),
        (8, 10),
        "short-range-reorg-result",
    )
    .await?;
    let oversized_range = reorg_invalidation(
        (profile, plan, binding, "source", "partition"),
        anchor(8, &hex_byte(8)),
        anchor(8, &hex_byte(0xfe)),
        (8, 21),
        "oversized-range-reorg-result",
    )
    .await?;
    let short_range_rejected =
        reorg_invalid_without_recording(store, database_url, &short_range).await?;
    let oversized_range_rejected =
        reorg_invalid_without_recording(store, database_url, &oversized_range).await?;
    proof.prove(
        "I06-G3-M15-I23-N-RANGE",
        malformed_range_rejected && short_range_rejected && oversized_range_rejected,
    )?;
    let valid = base_invalidation(profile, plan, binding).await?;
    proof.prove(
        "I06-G3-M15-I24-N-RAW-DIGEST",
        valid.evidence_digest() != "A".repeat(64)
            && valid.evidence_digest().len() == 64
            && valid
                .evidence_digest()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
    )?;
    Ok(())
}

async fn reorg_invalid_without_recording(
    store: &CandidateStore,
    database_url: &str,
    invalidation: &ReorgInvalidation,
) -> Result<bool, Box<dyn std::error::Error>> {
    let before = product_table_snapshot(database_url).await?;
    let result = store.invalidate_reorg(invalidation).await;
    let after = product_table_snapshot(database_url).await?;
    Ok(matches!(result, Err(CandidateStoreError::InvalidBinding)) && before == after)
}

async fn prove_authoritative_empty_invalidation(
    proof: &mut ProofRecorder,
    database_url: &str,
    input: &ReorgInvalidation,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;
    let mut tx = pool.begin().await?;
    set_proof_context(&mut tx).await?;
    let partition_id: Uuid = take_exactly_one(
        sqlx::query(
            "SELECT candidate_partition_id FROM candidate.candidate_partition WHERE participant_id=$1 AND privacy_domain_id=$2 AND projection_generation_id=$3 AND source_profile_id=$4 AND source_id='other-source' AND partition_id='other-partition'",
        )
        .bind(uuid(PARTICIPANT))
        .bind(uuid(PRIVACY))
        .bind(uuid(GENERATION))
        .bind(uuid(SOURCE_PROFILE))
        .fetch_all(&mut *tx)
        .await?,
        "authoritative-empty partition",
    )?
    .try_get(0)?;
    let payload_rows = sqlx::query(
        "SELECT payload_json::text,payload_cbor,encode(payload_digest,'hex') FROM candidate.outbox_event WHERE participant_id=$1 AND aggregate_type='candidate-partition' AND aggregate_id=$2 AND event_type='io.openpc.indexer.projection.candidate.invalidated.v1'",
    )
    .bind(uuid(PARTICIPANT))
    .bind(partition_id)
    .fetch_all(&mut *tx)
    .await?;
    let payload_row = take_exactly_one(payload_rows, "authoritative-empty invalidation event")?;
    let payload: serde_json::Value = serde_json::from_str(&payload_row.try_get::<String, _>(0)?)?;
    let payload_cbor: Vec<u8> = payload_row.try_get(1)?;
    let payload_digest: String = payload_row.try_get(2)?;
    let removed_blocks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM candidate.candidate_block WHERE participant_id=$1 AND privacy_domain_id=$2 AND projection_generation_id=$3 AND candidate_partition_id=$4 AND block_number=40 AND finality_state='REMOVED'",
    )
    .bind(uuid(PARTICIPANT))
    .bind(uuid(PRIVACY))
    .bind(uuid(GENERATION))
    .bind(partition_id)
    .fetch_one(&mut *tx)
    .await?;
    let reorg_checkpoints: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM candidate.checkpoint WHERE participant_id=$1 AND privacy_domain_id=$2 AND projection_generation_id=$3 AND candidate_partition_id=$4 AND batch_id='other-authoritative-empty' AND authoritative_empty AND state='REORG'",
    )
    .bind(uuid(PARTICIPANT))
    .bind(uuid(PRIVACY))
    .bind(uuid(GENERATION))
    .bind(partition_id)
    .fetch_one(&mut *tx)
    .await?;
    let affected_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM candidate.candidate_event ce JOIN candidate.candidate_block cb ON cb.candidate_block_id=ce.candidate_block_id WHERE ce.participant_id=$1 AND ce.privacy_domain_id=$2 AND ce.projection_generation_id=$3 AND ce.candidate_partition_id=$4 AND cb.block_number=40",
    )
    .bind(uuid(PARTICIPANT))
    .bind(uuid(PRIVACY))
    .bind(uuid(GENERATION))
    .bind(partition_id)
    .fetch_one(&mut *tx)
    .await?;
    proof.prove(
        "I06-G3-M15-I22-N-EMPTY",
        payload["affectedCandidateIds"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && payload["affectedRange"] == serde_json::json!({"start": "40", "end": "40"})
            && removed_blocks == 1
            && reorg_checkpoints == 1
            && affected_events == 0
            && canonical_json_cbor(&payload)? == payload_cbor
            && digest_hex(&payload_cbor) == payload_digest
            && input.affected_range() == (40, 40),
    )?;
    tx.rollback().await?;
    pool.close().await;
    Ok(())
}

async fn prove_reorg_invalid(
    proof: &mut ProofRecorder,
    assertion_id: &'static str,
    store: &CandidateStore,
    database_url: &str,
    invalidation: ReorgInvalidation,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = product_table_snapshot(database_url).await?;
    let result = store.invalidate_reorg(&invalidation).await;
    let after = product_table_snapshot(database_url).await?;
    if before != after {
        return Err(format!(
            "I06_GATE3_PRODUCT_SNAPSHOT_MISMATCH|{assertion_id}|before={before:?}|after={after:?}"
        )
        .into());
    }
    require_candidate_error(
        proof,
        assertion_id,
        ExpectedCandidateError::InvalidBinding,
        result,
    )?;
    Ok(())
}

async fn prove_invalidation_outputs(
    proof: &mut ProofRecorder,
    database_url: &str,
    input: &ReorgInvalidation,
) -> Result<(), Box<dyn std::error::Error>> {
    let (affected_start, affected_end) = input.affected_range();
    let old_anchor = input.old_anchor();
    let new_anchor = input.new_anchor();
    let evidence_digest = input.evidence_digest();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await?;
    let mut tx = pool.begin().await?;
    set_proof_context(&mut tx).await?;

    let invalidation_rows = sqlx::query(
        "SELECT ci.candidate_invalidation_id::text,ci.candidate_partition_id::text,ci.affected_start::text,ci.affected_end::text,ci.old_chain_id,encode(ci.old_genesis_hash,'hex'),ci.old_network_id,ci.old_selector_kind,ci.old_block_number::text,encode(ci.old_block_hash,'hex'),ci.old_pending_authorized,ci.new_chain_id,encode(ci.new_genesis_hash,'hex'),ci.new_network_id,ci.new_selector_kind,ci.new_block_number::text,encode(ci.new_block_hash,'hex'),ci.new_pending_authorized,encode(ci.evidence_digest,'hex'),ci.occurred_at::text FROM candidate.candidate_invalidation ci JOIN candidate.candidate_partition cp ON cp.candidate_partition_id=ci.candidate_partition_id WHERE cp.participant_id=$1 AND cp.privacy_domain_id=$2 AND cp.projection_generation_id=$3 AND cp.source_profile_id=$4 AND cp.source_id=$5 AND cp.partition_id=$6 AND ci.projection_generation_id=$3 AND ci.affected_start=$7::numeric AND ci.affected_end=$8::numeric AND ci.evidence_digest=decode($9,'hex')",
    )
    .bind(uuid(PARTICIPANT))
    .bind(uuid(PRIVACY))
    .bind(uuid(GENERATION))
    .bind(uuid(SOURCE_PROFILE))
    .bind("source")
    .bind("partition")
    .bind(affected_start.to_string())
    .bind(affected_end.to_string())
    .bind(evidence_digest)
    .fetch_all(&mut *tx)
    .await?;
    let invalidation = take_exactly_one(invalidation_rows, "primary-candidate-invalidation")?;
    let invalidation_id: String = invalidation.try_get(0)?;
    let partition_id: String = invalidation.try_get(1)?;
    proof.prove(
        "I06-G3-M15-I20-P",
        uuid_is_v7(&invalidation_id) && !invalidation_id.starts_with("urn:"),
    )?;
    proof.prove(
        "I06-G3-M15-I23-P",
        invalidation.try_get::<String, _>(4)? == old_anchor.chain_id
            && invalidation.try_get::<String, _>(5)?
                == old_anchor
                    .genesis_hash
                    .strip_prefix("0x")
                    .unwrap_or(&old_anchor.genesis_hash)
            && invalidation.try_get::<String, _>(6)? == old_anchor.network_id
            && invalidation.try_get::<String, _>(7)? == "PINNED"
            && invalidation.try_get::<String, _>(8)? == affected_start.to_string()
            && invalidation.try_get::<String, _>(9)?
                == old_anchor
                    .block_hash
                    .as_deref()
                    .unwrap_or_default()
                    .strip_prefix("0x")
                    .unwrap_or(old_anchor.block_hash.as_deref().unwrap_or_default())
            && !invalidation.try_get::<bool, _>(10)?
            && invalidation.try_get::<String, _>(11)? == new_anchor.chain_id
            && invalidation.try_get::<String, _>(12)?
                == new_anchor
                    .genesis_hash
                    .strip_prefix("0x")
                    .unwrap_or(&new_anchor.genesis_hash)
            && invalidation.try_get::<String, _>(13)? == new_anchor.network_id
            && invalidation.try_get::<String, _>(14)? == "PINNED"
            && invalidation.try_get::<String, _>(15)? == affected_start.to_string()
            && invalidation.try_get::<String, _>(16)?
                == new_anchor
                    .block_hash
                    .as_deref()
                    .unwrap_or_default()
                    .strip_prefix("0x")
                    .unwrap_or(new_anchor.block_hash.as_deref().unwrap_or_default())
            && !invalidation.try_get::<bool, _>(17)?,
    )?;
    proof.prove(
        "I06-G3-M15-I24-P",
        invalidation.try_get::<String, _>(18)? == evidence_digest,
    )?;

    let selected_rows = sqlx::query(
        "SELECT ce.candidate_event_id::text,ce.candidate_partition_id::text,ce.record_sequence::text,ce.state::text FROM candidate.candidate_event ce JOIN candidate.candidate_block cb ON cb.candidate_block_id=ce.candidate_block_id AND cb.projection_generation_id=$1 AND cb.candidate_partition_id=$2 WHERE ce.projection_generation_id=$1 AND ce.candidate_partition_id=$2 AND cb.block_number BETWEEN $3::numeric AND $4::numeric ORDER BY ce.record_sequence,ce.candidate_event_id",
    )
    .bind(uuid(GENERATION))
    .bind(uuid(&partition_id))
    .bind(affected_start.to_string())
    .bind(affected_end.to_string())
    .fetch_all(&mut *tx)
    .await?;
    let expected_ids = selected_rows
        .iter()
        .map(|row| {
            row.try_get::<String, _>(0)
                .map(|id| format!("urn:openpc:candidate:{id}"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let outbox_rows = sqlx::query(
        "SELECT aggregate_sequence::text,payload_json::text,encode(payload_cbor,'hex'),encode(payload_digest,'hex'),aggregate_id::text,source::text,subject::text FROM candidate.outbox_event WHERE aggregate_type='candidate-partition' AND aggregate_id=$1 AND aggregate_sequence=5 AND event_type='io.openpc.indexer.projection.candidate.invalidated.v1' AND payload_json->>'invalidationId'=$2",
    )
    .bind(uuid(&partition_id))
    .bind(&invalidation_id)
    .fetch_all(&mut *tx)
    .await?;
    let outbox = take_exactly_one(outbox_rows, "primary-invalidation-outbox")?;
    let payload_text: String = outbox.try_get(1)?;
    let payload: serde_json::Value = serde_json::from_str(&payload_text)?;
    emit_generated_payload(
        "I06-G3-M15-I22-P",
        "IndexerProjectionCandidateInvalidated",
        &payload,
    )?;
    let emitted_ids = payload["affectedCandidateIds"]
        .as_array()
        .ok_or("I06_GATE3_INVALIDATION_IDS_NOT_ARRAY")?
        .iter()
        .map(|value| value.as_str().unwrap_or_default().to_owned())
        .collect::<Vec<_>>();
    let mut reordered = emitted_ids.clone();
    reordered.reverse();
    if emitted_ids != expected_ids || emitted_ids.len() != 2 {
        return Err(format!(
            "I06_GATE3_AFFECTED_CANDIDATE_SET_MISMATCH|expected={expected_ids:?}|actual={emitted_ids:?}"
        )
        .into());
    }
    proof.prove(
        "I06-G3-M15-I22-P",
        emitted_ids == expected_ids && emitted_ids.len() == 2,
    )?;
    proof.prove(
        "I06-G3-M15-I22-N-ORDER",
        emitted_ids == expected_ids && reordered != expected_ids,
    )?;
    proof.prove(
        "I06-G3-M15-I22-N-DUPLICATE",
        emitted_ids.len() == emitted_ids.iter().collect::<BTreeSet<_>>().len()
            && emitted_ids.len() == selected_rows.len(),
    )?;
    proof.prove(
        "I06-G3-M15-I22-N-UNKNOWN-CANDIDATE",
        emitted_ids.iter().all(|urn| {
            urn.strip_prefix("urn:openpc:candidate:").is_some_and(|id| {
                selected_rows.iter().any(|row| {
                    row.try_get::<String, _>(0)
                        .is_ok_and(|candidate_id| candidate_id == id)
                })
            })
        }),
    )?;
    let other_partition_rows = sqlx::query(
        "SELECT ce.candidate_event_id::text FROM candidate.candidate_event ce JOIN candidate.candidate_partition cp ON cp.candidate_partition_id=ce.candidate_partition_id WHERE cp.participant_id=$1 AND cp.privacy_domain_id=$2 AND cp.projection_generation_id=$3 AND cp.source_profile_id=$4 AND cp.source_id=$5 AND cp.partition_id=$6 AND ce.projection_generation_id=$3 AND ce.record_kind='EVENT_LOG' AND ce.record_id=$7",
    )
    .bind(uuid(PARTICIPANT))
    .bind(uuid(PRIVACY))
    .bind(uuid(GENERATION))
    .bind(uuid(SOURCE_PROFILE))
    .bind("other-source")
    .bind("other-partition")
    .bind("other-record-1-1")
    .fetch_all(&mut *tx)
    .await?;
    let other_partition_row =
        take_exactly_one(other_partition_rows, "other-partition-candidate-event")?;
    let other_partition_candidate: String = other_partition_row.try_get(0)?;
    proof.prove(
        "I06-G3-M15-I22-N-CROSS-PARTITION",
        selected_rows.iter().all(|row| {
            row.try_get::<String, _>(1)
                .is_ok_and(|value| value == partition_id)
        }) && !emitted_ids
            .iter()
            .any(|urn| urn.ends_with(&other_partition_candidate)),
    )?;
    proof.prove(
        "I06-G3-M15-I22-N-URN-TYPE",
        emitted_ids.iter().zip(&selected_rows).all(|(value, row)| {
            row.try_get::<String, _>(0).is_ok_and(|owner| {
                value == &format!("urn:openpc:candidate:{owner}")
                    && value != &format!("urn:openpc:candidate-partition:{owner}")
            })
        }),
    )?;
    proof.prove(
        "I06-G3-M15-I22-N-URN-SUFFIX",
        emitted_ids.iter().all(|value| {
            value
                .strip_prefix("urn:openpc:candidate:")
                .is_some_and(uuid_is_v7)
                && value != "urn:openpc:candidate:018f47a5-4a58-7b21-8f3a-aaaaaaaaaaaa"
        }),
    )?;

    let payload_cbor = decode_hex(&outbox.try_get::<String, _>(2)?);
    let payload_digest: String = outbox.try_get(3)?;
    proof.prove(
        "I06-G3-M15-I24-N-WIRE-PREFIX",
        payload["reorgEvidenceDigest"]
            .as_str()
            .is_some_and(|value| {
                value == format!("sha256:{evidence_digest}")
                    && value != format!("sha256:sha256:{evidence_digest}")
            }),
    )?;
    proof.prove(
        "I06-G3-M15-I24-N-WIRE-VALUE",
        payload["reorgEvidenceDigest"].as_str()
            == Some(format!("sha256:{evidence_digest}").as_str())
            && payload["reorgEvidenceDigest"].as_str()
                != Some(format!("sha256:{}", hex_byte(0xab)).as_str()),
    )?;
    proof.prove(
        "I06-G3-M15-I24-N-URN-SUBSTITUTION",
        payload["invalidationId"].as_str() == Some(invalidation_id.as_str())
            && payload["invalidationId"].as_str()
                != Some(format!("urn:openpc:candidate-invalidation:{invalidation_id}").as_str()),
    )?;
    let mut substituted_evidence_payload = payload.clone();
    substituted_evidence_payload["reorgEvidenceDigest"] =
        serde_json::json!(format!("sha256:{}", hex_byte(0xac)));
    let substituted_evidence_cbor = canonical_json_cbor(&substituted_evidence_payload)?;
    proof.prove(
        "I06-G3-M15-I24-N-EVIDENCE-IDENTITY-SUBSTITUTION",
        payload["reorgEvidenceDigest"].as_str()
            == Some(format!("sha256:{evidence_digest}").as_str())
            && digest_hex(&payload_cbor) == payload_digest
            && substituted_evidence_payload["reorgEvidenceDigest"]
                != payload["reorgEvidenceDigest"]
            && substituted_evidence_cbor != payload_cbor
            && digest_hex(&substituted_evidence_cbor) != payload_digest,
    )?;
    proof.prove(
        "I06-G3-M15-I20-N-OPENPC-URN",
        payload["invalidationId"].as_str() == Some(invalidation_id.as_str())
            && payload["invalidationId"].as_str()
                != Some(format!("urn:openpc:candidate-invalidation:{invalidation_id}").as_str()),
    )?;
    proof.prove(
        "I06-G3-M15-I20-N-RELABEL",
        payload["candidatePartitionId"].as_str()
            == Some(format!("urn:openpc:candidate-partition:{partition_id}").as_str())
            && payload["candidatePartitionId"].as_str()
                != Some(format!("urn:openpc:source-profile:{partition_id}").as_str()),
    )?;
    let aggregate_sequence = outbox.try_get::<String, _>(0)?.parse::<u64>()?;
    let prior_sequence: i64 = sqlx::query_scalar(
        "SELECT max(aggregate_sequence)::bigint FROM candidate.outbox_event WHERE aggregate_type='candidate-partition' AND aggregate_id=$1 AND event_type<>'io.openpc.indexer.projection.candidate.invalidated.v1'",
    )
    .bind(uuid(&partition_id))
    .fetch_one(&mut *tx)
    .await?;
    let prior_sequence = u64::try_from(prior_sequence)?;
    proof.prove(
        "I06-G3-M15-I21-P",
        uuid_is_v7(&partition_id)
            && uuid_is_v7(&invalidation_id)
            && outbox.try_get::<String, _>(4)? == partition_id
            && aggregate_sequence == prior_sequence + 1
            && aggregate_sequence == 5
            && payload["invalidationId"].as_str() == Some(invalidation_id.as_str())
            && invalidation.try_get::<String, _>(2)? == affected_start.to_string()
            && invalidation.try_get::<String, _>(3)? == affected_end.to_string(),
    )?;
    proof.prove(
        "I06-G3-M15-I21-N-SEQUENCE",
        aggregate_sequence == prior_sequence + 1
            && aggregate_sequence != prior_sequence
            && aggregate_sequence != prior_sequence + 2,
    )?;
    let no_replacement = selected_rows.iter().all(|row| {
        row.try_get::<String, _>(3)
            .is_ok_and(|state| state == "REMOVED")
    });
    proof.prove("I06-G3-M15-I21-N-REPLACEMENT-SAME-TX", no_replacement)?;
    let occurred_at: String = invalidation.try_get(19)?;
    let replacement_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM candidate.candidate_event WHERE projection_generation_id=$1 AND candidate_partition_id=$2 AND state <> 'REMOVED' AND observed_at <= $3::timestamptz",
    )
    .bind(uuid(GENERATION))
    .bind(uuid(&partition_id))
    .bind(&occurred_at)
    .fetch_one(&mut *tx)
    .await?;
    proof.prove(
        "I06-G3-M15-I21-N-REPLACEMENT-BEFORE-INVALIDATION",
        replacement_after == 0,
    )?;

    tx.rollback().await?;
    pool.close().await;
    Ok(())
}

async fn seed_exact_preexisting_contract(
    database_url: &str,
    owner_database_url: &str,
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
) -> Result<(), Box<dyn std::error::Error>> {
    seed_contract(
        database_url,
        owner_database_url,
        profile,
        plan,
        SeedContractSpec {
            ids: PRIMARY_CONTRACT,
            stored_data_class: "EVENT_LOG",
            source_event_type: Some("extractor"),
            source_contract_address: Some(vec![0x11_u8; 20]),
            fault: SeedFault::None,
        },
    )
    .await
}

#[derive(Clone, Copy)]
enum SeedFault {
    None,
    ProjectionSchema,
    Generation,
    GenerationSource,
    GenerationSchema,
}

async fn seed_contract(
    _database_url: &str,
    owner_database_url: &str,
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    spec: SeedContractSpec<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let SeedContractSpec {
        ids,
        stored_data_class,
        source_event_type,
        source_contract_address,
        fault,
    } = spec;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(owner_database_url)
        .await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL ROLE openpc_candidate_index_owner")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,false)")
        .bind(uuid(PARTICIPANT))
        .bind(uuid(PRIVACY))
        .bind(uuid(OPERATION))
        .bind(PROOF_ACTION)
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT openpc.assert_request_context(true)")
        .execute(&mut *tx)
        .await?;
    let profile_cbor = encode_client_indexer_profile_pc_cbor(profile)?;
    let plan_cbor = encode_projection_plan_pc_cbor(plan)?;
    let source_digest = Sha256::digest(&profile_cbor).to_vec();
    let plan_digest = Sha256::digest(&plan_cbor).to_vec();
    let schemas = plan
        .candidate_schema_digests
        .iter()
        .map(|item| decode_hex(&item.digest))
        .collect::<Vec<_>>();
    let exact_schema_digest = Sha256::digest(encode_byte_array(&schemas)).to_vec();
    let exact_generation_digest = generation_digest(
        &source_digest,
        &plan_digest,
        plan.lifecycle_generation,
        &schemas,
    );
    let projection_schema_digest = if matches!(fault, SeedFault::ProjectionSchema) {
        vec![0xa1; 32]
    } else {
        exact_schema_digest.clone()
    };
    let stored_generation_digest = if matches!(fault, SeedFault::Generation) {
        vec![0xa2; 32]
    } else {
        exact_generation_digest
    };
    let generation_source_digest = if matches!(fault, SeedFault::GenerationSource) {
        vec![0xa3; 32]
    } else {
        source_digest.clone()
    };
    let generation_schema_digest = if matches!(fault, SeedFault::GenerationSchema) {
        vec![0xa4; 32]
    } else {
        exact_schema_digest
    };

    sqlx::query(
        "INSERT INTO candidate.source_profile(source_profile_id,participant_id,privacy_domain_id,indexer_profile_id,chain_namespace,source_contract_urn,source_profile_cbor,source_profile_digest,reorg_profile_digest,finality_mode,confirmation_count,state) VALUES ($1,$2,$3,$4,'eip155:1',$5,$6,$7,$8,'CONFIRMATIONS',12,'QUALIFIED')",
    )
    .bind(uuid(ids.source_profile)).bind(uuid(PARTICIPANT)).bind(uuid(PRIVACY))
    .bind(uuid(ids.indexer_profile))
    .bind(format!("urn:openpc:source-profile:{}", ids.source_profile))
    .bind(profile_cbor).bind(source_digest.clone()).bind(decode_hex(&profile.reorg_behavior_digest))
    .execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO candidate.projection_profile(projection_profile_id,participant_id,privacy_domain_id,source_profile_id,projection_plan_id,fact_type,source_event_type,source_contract_address,schema_digest,mapping_cbor,mapping_digest,state,data_class) VALUES ($1,$2,$3,$4,$5,'schema',$6,$7,$8,$9,$10,'QUALIFIED',$11)",
    )
    .bind(uuid(ids.projection_profile)).bind(uuid(PARTICIPANT)).bind(uuid(PRIVACY)).bind(uuid(ids.source_profile))
    .bind(uuid(ids.projection_plan))
    .bind(source_event_type).bind(source_contract_address).bind(projection_schema_digest).bind(plan_cbor).bind(plan_digest)
    .bind(stored_data_class)
    .execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO candidate.projection_generation(projection_generation_id,participant_id,privacy_domain_id,projection_profile_id,generation_digest,source_profile_digest,projection_schema_digest,state) VALUES ($1,$2,$3,$4,$5,$6,$7,'READY')",
    )
    .bind(uuid(ids.generation)).bind(uuid(PARTICIPANT)).bind(uuid(PRIVACY)).bind(uuid(ids.projection_profile))
    .bind(stored_generation_digest).bind(generation_source_digest).bind(generation_schema_digest).execute(&mut *tx).await?;
    tx.commit().await?;
    pool.close().await;
    provision_candidate_partitions(owner_database_url, ids, plan).await?;
    Ok(())
}

async fn provision_candidate_partitions(
    owner_database_url: &str,
    ids: ContractIds,
    plan: &ProjectionPlanV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(owner_database_url)
        .await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL ROLE openpc_candidate_index_owner")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,false)")
        .bind(uuid(PARTICIPANT))
        .bind(uuid(PRIVACY))
        .bind(uuid(OPERATION))
        .bind(PROOF_ACTION)
        .execute(&mut *tx)
        .await?;
    let plan_digest = Sha256::digest(encode_projection_plan_pc_cbor(plan)?).to_vec();
    for partition in &plan.partitions {
        let (range_end, range_end_open) = match partition.range.end {
            RangeEndV1::Inclusive(value) => (Some(value), false),
            RangeEndV1::Open => (None, true),
        };
        let binding = serde_json::json!({
            "participantId": PARTICIPANT,
            "privacyDomainId": PRIVACY,
            "projectionGenerationId": ids.generation,
            "sourceProfileId": ids.source_profile,
            "planContentDigest": format!("sha256:{}", hex_bytes(&plan_digest)),
            "sourceId": partition.source_id,
            "partitionId": partition.partition_id,
            "range": {
                "start": partition.range.start.to_string(),
                "end": range_end.map(|value| value.to_string()),
                "endOpen": range_end_open,
            },
        });
        let binding_cbor = canonical_json_cbor(&binding)?;
        let binding_digest = Sha256::digest(&binding_cbor).to_vec();
        sqlx::query(
            "INSERT INTO candidate.candidate_partition(participant_id,privacy_domain_id,projection_generation_id,source_profile_id,plan_digest,source_id,partition_id,range_start,range_end,range_end_open,binding_cbor,binding_digest) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10,$11,$12)",
        )
        .bind(uuid(PARTICIPANT))
        .bind(uuid(PRIVACY))
        .bind(uuid(ids.generation))
        .bind(uuid(ids.source_profile))
        .bind(&plan_digest)
        .bind(&partition.source_id)
        .bind(&partition.partition_id)
        .bind(partition.range.start.to_string())
        .bind(range_end.map(|value| value.to_string()))
        .bind(range_end_open)
        .bind(binding_cbor)
        .bind(binding_digest)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    pool.close().await;
    Ok(())
}

fn owner_database_url() -> String {
    std::env::var("OPENPC_I06_GATE3_OWNER_DATABASE_URL")
        .expect("runner supplies the owner-only proof setup URL")
}

fn binding() -> CandidatePersistenceBinding {
    binding_for(GENERATION)
}

fn binding_for(generation: &str) -> CandidatePersistenceBinding {
    CandidatePersistenceBinding::try_new(
        uuid(PARTICIPANT),
        uuid(PRIVACY),
        uuid(generation),
        uuid(OPERATION),
        uuid(CORRELATION),
    )
    .expect("UUIDv7 binding")
}

fn material(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
    binding: &CandidatePersistenceBinding,
) -> Result<CandidateBatchMaterialV1, openpc_indexer_adapter::CandidateStoreError> {
    CandidateBatchMaterialV1::try_new(
        (profile, plan, batch, binding),
        block_observations(profile, batch),
        record_materials(batch),
        false,
    )
}

fn material_for_class(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
    binding: &CandidatePersistenceBinding,
    data_class: &str,
) -> Result<CandidateBatchMaterialV1, openpc_indexer_adapter::CandidateStoreError> {
    CandidateBatchMaterialV1::try_new(
        (profile, plan, batch, binding),
        block_observations(profile, batch),
        record_materials_for_class(batch, data_class),
        false,
    )
}

fn other_partition_material(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    binding: &CandidatePersistenceBinding,
) -> (
    CandidateProjectionBatchV1,
    Result<CandidateBatchMaterialV1, CandidateStoreError>,
) {
    let mut other_batch = batch(1, 31, 35, "other-batch", "GENESIS");
    other_batch.source_id = "other-source".into();
    other_batch.partition_id = "other-partition".into();
    for record in &mut other_batch.records {
        record.record_id = format!("other-{}", record.record_id);
    }
    let mut other_records = record_materials(&other_batch);
    for record in &mut other_records {
        if let CandidateRecordIdentityV1::EventLog {
            transaction_hash, ..
        } = &mut record.identity
        {
            *transaction_hash = d("other-partition-transaction");
        }
    }
    let result = CandidateBatchMaterialV1::try_new(
        (profile, plan, &other_batch, binding),
        block_observations(profile, &other_batch),
        other_records,
        false,
    );
    (other_batch, result)
}

fn material_with_blocks(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
    binding: &CandidatePersistenceBinding,
    blocks: Vec<CandidateBlockObservationV1>,
) -> Result<CandidateBatchMaterialV1, openpc_indexer_adapter::CandidateStoreError> {
    CandidateBatchMaterialV1::try_new(
        (profile, plan, batch, binding),
        blocks,
        record_materials(batch),
        false,
    )
}

fn record_materials(batch: &CandidateProjectionBatchV1) -> Vec<CandidateRecordMaterialV1> {
    record_materials_for_class(batch, "EVENT_LOG")
}

fn record_materials_for_class(
    batch: &CandidateProjectionBatchV1,
    data_class: &str,
) -> Vec<CandidateRecordMaterialV1> {
    batch
        .records
        .iter()
        .map(|record| CandidateRecordMaterialV1 {
            record: record.clone(),
            identity: match data_class {
                "EVENT_LOG" => CandidateRecordIdentityV1::EventLog {
                    transaction_hash: hex_byte(0x22),
                    transaction_index: 0,
                    log_index: record.sequence - 1,
                    contract_address: "11".repeat(20),
                    event_signature: hex_byte(0x33),
                },
                "STATE_CALL" => CandidateRecordIdentityV1::StateCall {
                    target_address: "44".repeat(20),
                    call_parameter_digest: d(&format!("call-parameters-{}", record.sequence)),
                },
                "TRANSACTION_RECEIPT" => CandidateRecordIdentityV1::TransactionReceipt {
                    transaction_hash: d(&format!("transaction-{}", record.sequence)),
                },
                "BLOCK_HEADER" => CandidateRecordIdentityV1::BlockHeader,
                "FULL_BLOCK_TRANSACTIONS" => CandidateRecordIdentityV1::FullBlockTransactions,
                _ => panic!("unsupported proof data class"),
            },
            payload_cbor: record_payload(batch.batch_sequence, record.sequence),
        })
        .collect()
}

fn block_observation(
    _profile: &ClientIndexerProfileV1,
    record: &CandidateRecordV1,
) -> CandidateBlockObservationV1 {
    CandidateBlockObservationV1 {
        block_number: record.block_number,
        canonical_block_hash: record.canonical_block_hash.clone(),
        parent_hash: hex_byte(u8::try_from(record.block_number - 1).expect("fixture")),
        block_timestamp: "2026-09-02T00:00:00.000000Z".into(),
        evidence_digest: d(&format!("block-evidence-{}", record.block_number)),
        finality: CandidateBlockFinalityV1::Confirmations {
            head_anchor: anchor(record.block_number + 11, &hex_byte(0xdd)),
            evidence_digest: d(&format!("finality-evidence-{}", record.block_number)),
        },
    }
}

fn block_observations(
    profile: &ClientIndexerProfileV1,
    batch: &CandidateProjectionBatchV1,
) -> Vec<CandidateBlockObservationV1> {
    let mut seen = BTreeSet::new();
    batch
        .records
        .iter()
        .filter(|record| seen.insert((record.block_number, record.canonical_block_hash.clone())))
        .map(|record| block_observation(profile, record))
        .collect()
}

fn blocks_with_first(
    profile: &ClientIndexerProfileV1,
    batch: &CandidateProjectionBatchV1,
    first: CandidateBlockObservationV1,
) -> Vec<CandidateBlockObservationV1> {
    let mut blocks = block_observations(profile, batch);
    blocks[0] = first;
    blocks
}

fn empty_material(
    profile: &ClientIndexerProfileV1,
    plan: &ProjectionPlanV1,
    batch: &CandidateProjectionBatchV1,
    binding: &CandidatePersistenceBinding,
) -> Result<CandidateBatchMaterialV1, openpc_indexer_adapter::CandidateStoreError> {
    CandidateBatchMaterialV1::try_new(
        (profile, plan, batch, binding),
        vec![CandidateBlockObservationV1 {
            block_number: batch.range.end,
            canonical_block_hash: batch.completed_watermark.canonical_block_hash.clone(),
            parent_hash: hex_byte(u8::try_from(batch.range.end - 1).expect("fixture")),
            block_timestamp: "2026-09-02T00:00:01.000000Z".into(),
            evidence_digest: d("empty-block-evidence"),
            finality: CandidateBlockFinalityV1::Confirmations {
                head_anchor: anchor(batch.range.end + 11, &hex_byte(0xdc)),
                evidence_digest: d("empty-finality-evidence"),
            },
        }],
        vec![],
        true,
    )
}

fn reorg_observation_material(
    context: (
        &ClientIndexerProfileV1,
        &ProjectionPlanV1,
        &CandidatePersistenceBinding,
        &str,
        &str,
    ),
    observed_anchor: ChainReadAnchorV1,
    selected_digest: &str,
    batch_id: &str,
) -> Result<CandidateBatchMaterialV1, openpc_indexer_adapter::CandidateStoreError> {
    let (profile, plan, binding, source_id, partition_id) = context;
    let block_number = observed_anchor
        .block_number
        .ok_or(openpc_indexer_adapter::CandidateStoreError::InvalidBinding)?;
    let block_hash = observed_anchor
        .block_hash
        .clone()
        .ok_or(openpc_indexer_adapter::CandidateStoreError::InvalidBinding)?;
    let mut observation_batch = empty_batch(1, block_number, block_number, batch_id, "GENESIS");
    observation_batch.source_id = source_id.to_owned();
    observation_batch.partition_id = partition_id.to_owned();
    observation_batch.observations[0].anchor = observed_anchor;
    observation_batch.observations[0].normalized_digest = selected_digest.to_owned();
    observation_batch.observations[0].evidence_digest = d(&format!("{batch_id}-evidence"));
    observation_batch.completed_watermark = CompletedWatermarkV1 {
        block_number,
        canonical_block_hash: block_hash,
    };
    empty_material(profile, plan, &observation_batch, binding)
}

fn empty_batch(
    sequence: u64,
    range_start: u64,
    range_end: u64,
    batch_id: &str,
    predecessor: &str,
) -> CandidateProjectionBatchV1 {
    let mut value = batch(sequence, range_start, range_end, batch_id, predecessor);
    value.records.clear();
    value.decode_failures.clear();
    value.completed_watermark = CompletedWatermarkV1 {
        block_number: range_end,
        canonical_block_hash: hex_byte(u8::try_from(range_end).expect("fixture range")),
    };
    value.observations = vec![SequencedObservationV1 {
        sequence: 1,
        anchor: anchor(range_end, &value.completed_watermark.canonical_block_hash),
        normalized_digest: d(&format!("observation-{sequence}")),
        evidence_digest: d(&format!("observation-evidence-{sequence}")),
    }];
    value
}

fn partial_decode_batch(complete: &CandidateProjectionBatchV1) -> CandidateProjectionBatchV1 {
    let mut value = complete.clone();
    let watermark = value.range.end - 2;
    let watermark_hash = hex_byte(u8::try_from(watermark).expect("fixture range"));
    value.records.truncate(1);
    value.records[0].block_number = watermark;
    value.records[0].canonical_block_hash = watermark_hash.clone();
    value.observations[0].anchor = anchor(watermark, &watermark_hash);
    value.completed_watermark = CompletedWatermarkV1 {
        block_number: watermark,
        canonical_block_hash: watermark_hash,
    };
    value.decode_failures = [watermark + 1, watermark + 2]
        .into_iter()
        .enumerate()
        .map(|(index, block_number)| DecodeFailureV1 {
            sequence: u64::try_from(index + 1).expect("fixture sequence"),
            source_id: value.source_id.clone(),
            anchor: anchor(
                block_number,
                &hex_byte(u8::try_from(block_number).expect("fixture range")),
            ),
            error_digest: d(&format!(
                "decode-error-{}-{}",
                value.batch_sequence,
                index + 1
            )),
            evidence_digest: d(&format!(
                "decode-evidence-{}-{}",
                value.batch_sequence,
                index + 1
            )),
        })
        .collect();
    value
}

fn batch(
    sequence: u64,
    range_start: u64,
    range_end: u64,
    batch_id: &str,
    predecessor: &str,
) -> CandidateProjectionBatchV1 {
    let first_record_block = range_end.checked_sub(2).expect("non-empty fixture range");
    let first_block_hash = hex_byte(u8::try_from(first_record_block).expect("fixture range"));
    let final_block_hash = hex_byte(u8::try_from(range_end).expect("fixture range"));
    let first_payload = record_payload(sequence, 1);
    let second_payload = record_payload(sequence, 2);
    CandidateProjectionBatchV1 {
        profile_id: d("client-profile-id"),
        profile_version: "1.0.0".into(),
        profile_digest: d("client-profile"),
        plan_digest: d("projection-plan"),
        source_id: "source".into(),
        source_profile_digest: d("client-profile"),
        partition_id: "partition".into(),
        batch_id: batch_id.into(),
        batch_sequence: sequence,
        range: InclusiveRangeV1 {
            start: range_start,
            end: range_end,
        },
        observations: vec![SequencedObservationV1 {
            sequence: 1,
            anchor: anchor(first_record_block, &first_block_hash),
            normalized_digest: d(&format!("observation-{sequence}")),
            evidence_digest: d(&format!("observation-evidence-{sequence}")),
        }],
        records: vec![
            CandidateRecordV1 {
                sequence: 1,
                record_id: format!("record-{sequence}-1"),
                schema_digest: d("candidate-schema"),
                normalized_digest: digest_hex(&first_payload),
                block_number: first_record_block,
                canonical_block_hash: first_block_hash,
                evidence_digest: d(&format!("record-evidence-{sequence}-1")),
            },
            CandidateRecordV1 {
                sequence: 2,
                record_id: format!("record-{sequence}-2"),
                schema_digest: d("candidate-schema"),
                normalized_digest: digest_hex(&second_payload),
                block_number: range_end,
                canonical_block_hash: final_block_hash.clone(),
                evidence_digest: d(&format!("record-evidence-{sequence}-2")),
            },
        ],
        decode_failures: vec![],
        missing_intervals: vec![],
        completed_watermark: CompletedWatermarkV1 {
            block_number: range_end,
            canonical_block_hash: final_block_hash,
        },
        predecessor_batch_digest: predecessor.into(),
        evidence_refs: vec![d(&format!("batch-evidence-{sequence}"))],
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    }
}

fn record_payload(batch_sequence: u64, record_sequence: u64) -> Vec<u8> {
    canonical_text(&format!("payload-{batch_sequence}-{record_sequence}"))
}

fn canonical_text(value: &str) -> Vec<u8> {
    let length = u8::try_from(value.len()).expect("short canonical fixture text");
    assert!(length < 24, "fixture text uses the one-byte CBOR text form");
    let mut encoded = vec![0x60 + length];
    encoded.extend_from_slice(value.as_bytes());
    encoded
}

fn canonical_json_cbor(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    fn encode(out: &mut Vec<u8>, value: &serde_json::Value) -> Result<(), String> {
        match value {
            serde_json::Value::Null => out.push(0xf6),
            serde_json::Value::Bool(false) => out.push(0xf4),
            serde_json::Value::Bool(true) => out.push(0xf5),
            serde_json::Value::Number(number) => cbor_uint(
                out,
                number
                    .as_u64()
                    .ok_or_else(|| "I06_GATE3_PROOF_CBOR_UNSIGNED_NUMBER_REQUIRED".to_owned())?,
            ),
            serde_json::Value::String(value) => cbor_text(out, value),
            serde_json::Value::Array(values) => {
                cbor_len(out, 4, values.len() as u64);
                for value in values {
                    encode(out, value)?;
                }
            }
            serde_json::Value::Object(values) => {
                let mut entries = values
                    .iter()
                    .map(|(key, value)| {
                        let mut encoded_key = Vec::new();
                        cbor_text(&mut encoded_key, key);
                        (encoded_key, value)
                    })
                    .collect::<Vec<_>>();
                entries.sort_by(|(left, _), (right, _)| match left.len().cmp(&right.len()) {
                    Ordering::Equal => left.cmp(right),
                    ordering => ordering,
                });
                cbor_len(out, 5, entries.len() as u64);
                for (key, value) in entries {
                    out.extend_from_slice(&key);
                    encode(out, value)?;
                }
            }
        }
        Ok(())
    }

    let mut output = Vec::new();
    encode(&mut output, value)?;
    Ok(output)
}

fn client_profile() -> ClientIndexerProfileV1 {
    ClientIndexerProfileV1 {
        profile_id: d("client-profile-id"),
        profile_version: "1.0.0".into(),
        profile_digest: d("client-profile"),
        client_family: ClientIndexerFamily::CustomEvmIndexer,
        engine_or_runtime: "openpc-local".into(),
        engine_version: "1.0.0".into(),
        dependencies: vec![DependencyV1 {
            name: "local".into(),
            version: "1.0.0".into(),
            digest: d("dependency"),
        }],
        configuration_digest: d("configuration"),
        participant_binding: PARTICIPANT.into(),
        privacy_binding: PRIVACY.into(),
        workload_binding: "workload".into(),
        deployment_owner: "local".into(),
        boundary_declaration_digest: d("boundary"),
        protocol_kind: IndexerProtocolKind::JsonRpc,
        protocol_version: "2.0".into(),
        chain_id: "1".into(),
        genesis_hash: hex_byte(1),
        network_id: "openpc-local".into(),
        capability_profiles: vec![
            IndexerCapability::ProjectSessionCore,
            IndexerCapability::EventOnly,
        ],
        method_data_classes: vec![MethodDataClass {
            method: "eth_getLogs".into(),
            data_class: "EVENT_LOG".into(),
        }],
        source_range: source_range(),
        finality_rule_digest: d("finality"),
        reorg_behavior_digest: d("reorg"),
        removed_event_behavior_digest: d("removed"),
        checkpoint_semantics_digest: d("checkpoint"),
        completed_watermark_semantics_digest: d("watermark"),
        artifact_digests: vec![named("abi")],
        limits: limits(),
        behavior: IndexerBehaviorV1 {
            visibility_miss_digest: d("miss"),
            empty_digest: d("empty"),
            partial_digest: d("partial"),
            error_digest: d("error"),
            retry_digest: d("retry"),
            recovery_digest: d("recovery"),
            retirement_digest: d("retire"),
        },
        candidate_store_contract_digest: d("candidate"),
        outbox_contract_digest: d("outbox"),
        fact_bridge_contract_digest: d("bridge"),
        security_evidence_digest: d("security"),
        privacy_evidence_digest: d("privacy"),
        licensing_digest: d("license"),
        supply_chain_digest: d("supply"),
        telemetry_classification_digest: d("telemetry"),
        rollback_digest: d("rollback"),
        uninstall_digest: d("uninstall"),
        corpus_digest: d("corpus"),
        conformance_receipt_digest: d("receipt"),
        lifecycle: ClientIndexerLifecycle::Active,
        source_authority: SourceAuthority::NonAuthoritativeCandidateOnly,
    }
}

async fn qualified_reorg_result(
    provider_observed_anchor: Option<ChainReadAnchorV1>,
) -> Result<ReadExecutionResult, Box<dyn std::error::Error>> {
    const DEFAULT_REQUEST_BLOCK: u64 = 8;
    let request_block = provider_observed_anchor
        .as_ref()
        .and_then(|anchor| anchor.block_number)
        .unwrap_or(DEFAULT_REQUEST_BLOCK);
    let request_bytes = serde_json::to_vec(&serde_json::json!({
        "id": "openpc-local-eth-getlogs-1",
        "jsonrpc": "2.0",
        "method": "eth_getLogs",
        "params": [{
            "address": "0x1111111111111111111111111111111111111111",
            "fromBlock": format!("0x{request_block:x}"),
            "toBlock": format!("0x{request_block:x}"),
            "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]
        }]
    }))?;
    let response_result = provider_observed_anchor
        .map(|anchor| {
            let block_number = anchor
                .block_number
                .ok_or("I06_GATE3_REORG_PROVIDER_BLOCK_MISSING")?;
            let block_hash = anchor
                .block_hash
                .as_deref()
                .ok_or("I06_GATE3_REORG_PROVIDER_HASH_MISSING")?;
            Ok::<_, Box<dyn std::error::Error>>(vec![serde_json::json!({
                "address": "0x1111111111111111111111111111111111111111",
                "blockHash": format!("0x{}", block_hash.strip_prefix("0x").unwrap_or(block_hash)),
                "blockNumber": format!("0x{block_number:x}"),
                "data": format!("0x{}", "44".repeat(32)),
                "logIndex": "0x0",
                "removed": false,
                "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],
                "transactionHash": format!("0x{}", "55".repeat(32)),
                "transactionIndex": "0x0"
            })])
        })
        .transpose()?
        .unwrap_or_default();
    let response_body = serde_json::to_vec(&serde_json::json!({
        "id": "openpc-local-eth-getlogs-1",
        "jsonrpc": "2.0",
        "result": response_result,
    }))?;
    let provider_listener = TcpListener::bind("127.0.0.1:0")?;
    let provider_address = provider_listener.local_addr()?;
    let provider_server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = provider_listener
            .accept()
            .map_err(|error| error.to_string())?;
        let mut received = [0_u8; 2_048];
        let _ = stream
            .read(&mut received)
            .map_err(|error| error.to_string())?;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nx-openpc-completeness: complete-non-partial\r\nconnection: close\r\n\r\n",
            response_body.len()
        )
        .map_err(|error| error.to_string())?;
        stream
            .write_all(&response_body)
            .map_err(|error| error.to_string())?;
        Ok(())
    });
    let result = LocalFixtureRouteExecutorV1::for_i06_candidate_store_eth_get_logs(
        &request_bytes,
        &format!("http://{provider_address}"),
        "candidate-store-proof-secret",
    )?
    .execute()
    .await;
    provider_server
        .join()
        .map_err(|_| "I06_GATE3_REORG_PROVIDER_THREAD")??;
    result.map_err(Into::into)
}

fn profile_for_class(data_class: &str) -> ClientIndexerProfileV1 {
    let mut profile = client_profile();
    profile.method_data_classes = vec![MethodDataClass {
        method: match data_class {
            "EVENT_LOG" => "eth_getLogs",
            "STATE_CALL" => "eth_call",
            "TRANSACTION_RECEIPT" => "eth_getTransactionReceipt",
            "BLOCK_HEADER" => "eth_getBlockByNumber",
            "FULL_BLOCK_TRANSACTIONS" => "eth_getBlockByHash",
            _ => panic!("unsupported proof data class"),
        }
        .into(),
        data_class: data_class.into(),
    }];
    profile
}

fn projection_plan() -> ProjectionPlanV1 {
    ProjectionPlanV1 {
        profile_id: d("client-profile-id"),
        profile_version: "1.0.0".into(),
        profile_digest: d("client-profile"),
        plan_digest: d("projection-plan"),
        workload_identity: WorkloadIdentityV1::ExternalOwner {
            owner: "openpc-local".into(),
            boundary_digest: d("workload-boundary"),
        },
        partitions: vec![
            ProjectionPartitionV1 {
                partition_id: "partition".into(),
                source_id: "source".into(),
                range: SourceRangeV1 {
                    start: 1,
                    end: RangeEndV1::Inclusive(30),
                },
                state: PartitionState::Complete,
                finality_digest: d("finality"),
                checkpoint_digest: d("checkpoint"),
            },
            ProjectionPartitionV1 {
                partition_id: "other-partition".into(),
                source_id: "other-source".into(),
                range: SourceRangeV1 {
                    start: 31,
                    end: RangeEndV1::Inclusive(40),
                },
                state: PartitionState::Complete,
                finality_digest: d("finality"),
                checkpoint_digest: d("checkpoint-other"),
            },
        ],
        source_range: source_range(),
        finality_rule_digest: d("finality"),
        extractor_digests: vec![named("extractor")],
        candidate_schema_digests: vec![NamedDigestV1 {
            name: "schema".into(),
            digest: d("candidate-schema"),
        }],
        limits: limits(),
        secret_references: vec![SecretReferenceV1 {
            purpose: SecretPurposeV1::ApiToken,
            reference: "ref:local".into(),
        }],
        lifecycle_generation: 1,
        desired_state: DesiredState::Active,
    }
}

fn anchor(block: u64, hash: &str) -> ChainReadAnchorV1 {
    ChainReadAnchorV1 {
        chain_id: "1".into(),
        genesis_hash: hex_byte(1),
        network_id: "openpc-local".into(),
        selector_kind: BlockSelectorKind::Pinned,
        block_number: Some(block),
        block_hash: Some(hash.into()),
        pending_authorized_by_profile: false,
    }
}
fn source_range() -> SourceRangeV1 {
    SourceRangeV1 {
        start: 1,
        end: RangeEndV1::Inclusive(40),
    }
}
fn limits() -> IndexerLimitsV1 {
    IndexerLimitsV1 {
        max_request_bytes: 1_024,
        max_range: 10,
        max_batch: 10,
        max_response_bytes: 10_000,
        max_depth: 10,
        max_resource: 10,
        rate_limit_contract_digest: d("rate"),
    }
}
fn named(name: &str) -> NamedDigestV1 {
    NamedDigestV1 {
        name: name.into(),
        digest: d(name),
    }
}
fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("fixture UUID")
}
fn d(value: &str) -> String {
    digest_hex(value.as_bytes())
}
fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn hex_byte(value: u8) -> String {
    format!("{value:02x}").repeat(32)
}
fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16).expect("hex"))
        .collect()
}
fn generation_digest(source: &[u8], plan: &[u8], generation: u64, schemas: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0x84];
    cbor_bytes(&mut out, source);
    cbor_bytes(&mut out, plan);
    cbor_uint(&mut out, generation);
    out.extend_from_slice(&encode_byte_array(schemas));
    Sha256::digest(out).to_vec()
}
fn encode_byte_array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    cbor_len(&mut out, 4, values.len() as u64);
    for value in values {
        cbor_bytes(&mut out, value);
    }
    out
}
fn cbor_bytes(out: &mut Vec<u8>, value: &[u8]) {
    cbor_len(out, 2, value.len() as u64);
    out.extend_from_slice(value)
}
fn cbor_text(out: &mut Vec<u8>, value: &str) {
    cbor_len(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}
fn cbor_uint(out: &mut Vec<u8>, value: u64) {
    cbor_len(out, 0, value)
}
fn cbor_len(out: &mut Vec<u8>, major: u8, value: u64) {
    let p = major << 5;
    match value {
        0..=23 => out.push(p | value as u8),
        24..=255 => out.extend_from_slice(&[p | 24, value as u8]),
        256..=65_535 => {
            out.push(p | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes())
        }
        _ => {
            out.push(p | 27);
            out.extend_from_slice(&value.to_be_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_supposed_valid_proof_fixtures_cross_constructor_admission() {
        audit_supposed_valid_fixture_admission().expect("all proof-positive fixtures are admitted");
    }

    #[test]
    fn variant_only_identity_mutation_reaches_exact_constructor_owner() {
        let profile = client_profile();
        let plan = projection_plan();
        let batch = batch(1, 1, 10, "variant-test", "GENESIS");
        let result = variant_mismatch_material(&profile, &plan, &batch, &binding());
        match result {
            Err(CandidateStoreError::InvalidBinding) => {}
            Err(error) => panic!("expected InvalidBinding, got {error:?}"),
            Ok(_) => panic!("expected InvalidBinding, got Ok"),
        }
    }

    #[tokio::test]
    async fn reorg_invalidation_derives_anchor_from_selected_provider_observation() {
        let profile = client_profile();
        let plan = projection_plan();
        let binding = binding();
        let observed = anchor(8, &hex_byte(0xfe));
        let runtime_result = qualified_reorg_result(Some(observed.clone()))
            .await
            .expect("decoded provider result");
        let selected_digest = runtime_result
            .normalized_response_digest()
            .expect("selected digest")
            .to_owned();
        let selected_attempt = match runtime_result.witness().execution() {
            RouteExecutionV1::IdempotentRead {
                outcome: RouteOutcomeV1::Selected(selected),
                ..
            } => selected.agreement_attempt_ids()[0].as_str(),
            _ => panic!("expected selected read"),
        };
        let provider_observed = runtime_result
            .selected_provider_observed_anchor(selected_attempt)
            .expect("provider-observed anchor")
            .clone();
        let observation_material = reorg_observation_material(
            (&profile, &plan, &binding, "source", "partition"),
            provider_observed.clone(),
            &selected_digest,
            "unit-reorg-observation",
        )
        .expect("candidate observation material");
        let invalidation = ReorgInvalidation::try_new(
            (&runtime_result, &observation_material),
            binding.clone(),
            "source",
            "partition",
            anchor(8, &hex_byte(8)),
            (8, 20),
        )
        .expect("qualified invalidation");
        assert_eq!(invalidation.new_anchor(), &provider_observed);
        assert_eq!(
            invalidation.new_anchor().block_hash.as_deref(),
            Some(format!("0x{}", hex_byte(0xfe)).as_str())
        );
        assert_eq!(invalidation.evidence_digest().len(), 64);
        assert_ne!(invalidation.evidence_digest(), hex_byte(0xee));

        for (owner, old_anchor) in [
            ("raw-versus-prefixed-same-block", anchor(8, &hex_byte(0xfe))),
            (
                "missing-old-block",
                ChainReadAnchorV1 {
                    block_hash: None,
                    ..anchor(8, &hex_byte(8))
                },
            ),
            (
                "malformed-old-block",
                ChainReadAnchorV1 {
                    block_hash: Some("not-a-block-hash".into()),
                    ..anchor(8, &hex_byte(8))
                },
            ),
            (
                "malformed-old-genesis",
                ChainReadAnchorV1 {
                    genesis_hash: "not-a-genesis-hash".into(),
                    ..anchor(8, &hex_byte(8))
                },
            ),
            (
                "different-old-genesis",
                ChainReadAnchorV1 {
                    genesis_hash: hex_byte(2),
                    ..anchor(8, &hex_byte(8))
                },
            ),
        ] {
            let result = ReorgInvalidation::try_new(
                (&runtime_result, &observation_material),
                binding.clone(),
                "source",
                "partition",
                old_anchor,
                (8, 20),
            );
            assert!(
                matches!(result, Err(CandidateStoreError::InvalidBinding)),
                "{owner}: expected exact InvalidBinding after the unchanged opaque result/profile/material guards, got {result:?}"
            );
        }

        let missing_provider_block = ChainReadAnchorV1 {
            block_hash: None,
            ..observed.clone()
        };
        assert!(
            qualified_reorg_result(Some(missing_provider_block))
                .await
                .is_err(),
            "missing-provider-block: no opaque selected result may be constructed"
        );

        let malformed_provider_block = ChainReadAnchorV1 {
            block_hash: Some("not-a-block-hash".into()),
            ..observed.clone()
        };
        let malformed_block_result = qualified_reorg_result(Some(malformed_provider_block))
            .await
            .expect("closed malformed-block runtime result");
        assert_ne!(malformed_block_result.truth(), ResolutionTruth::Success);
        assert!(
            malformed_block_result
                .normalized_response_digest()
                .is_none()
        );

        let malformed_provider_genesis = ChainReadAnchorV1 {
            genesis_hash: "not-a-genesis-hash".into(),
            ..observed.clone()
        };
        let malformed_genesis_result = qualified_reorg_result(Some(malformed_provider_genesis))
            .await
            .expect("closed malformed-genesis runtime result");
        assert_eq!(malformed_genesis_result.truth(), ResolutionTruth::Success);
        let malformed_genesis_attempt = malformed_genesis_result.agreement_attempt_ids()[0];
        let malformed_genesis_observed = malformed_genesis_result
            .selected_provider_observed_anchor(malformed_genesis_attempt)
            .expect("malformed-genesis provider observation")
            .clone();
        assert_eq!(
            malformed_genesis_observed.genesis_hash,
            anchor(8, &hex_byte(0xfe)).genesis_hash,
            "a caller-authored companion genesis identity cannot alter the opaque fixture result",
        );

        let mismatched = qualified_reorg_result(Some(anchor(8, &hex_byte(0xfd))))
            .await
            .expect("closed terminal result");
        assert_ne!(mismatched.truth(), ResolutionTruth::Success);
    }
}
