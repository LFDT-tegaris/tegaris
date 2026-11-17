use super::state::{AnchoredStateValueV1, StateAnchorV1};
use super::*;
use std::cell::Cell;

#[test]
fn state_value_projection_requires_exact_canonical_chain_block_finality_and_typed_payload() {
    let hash = Digest::parse("11".repeat(32)).unwrap();
    let value = AnchoredStateValueV1 {
        schema_version: "1.0".into(),
        state_anchor: StateAnchorV1 {
            chain_id: "0x1".into(),
            block_hash: format!("0x{}", hash.as_str()),
            block_number: "0x10".into(),
            require_canonical: true,
        },
        value: ArgumentValue::Uint([255; 32]),
    };
    let bytes = value.to_fact_payload().unwrap();
    assert_eq!(
        AnchoredStateValueV1::read_at_anchor(&bytes, 1, 16, &hash, &[0x11; 32]).unwrap(),
        value.value
    );
    for (chain, block, anchor) in [
        (2, 16, [0x11; 32]),
        (1, 17, [0x11; 32]),
        (1, 16, [0x22; 32]),
    ] {
        assert!(
            AnchoredStateValueV1::read_at_anchor(&bytes, chain, block, &hash, &anchor).is_err()
        );
    }
    for (pointer, replacement) in [
        ("/schemaVersion", serde_json::json!("2.0")),
        ("/stateAnchor/chainId", serde_json::json!("0x01")),
        ("/stateAnchor/blockNumber", serde_json::json!("0x010")),
        ("/stateAnchor/requireCanonical", serde_json::json!(false)),
        (
            "/stateAnchor/blockHash",
            serde_json::json!(format!("0x{}", "22".repeat(32))),
        ),
    ] {
        let mut changed = serde_json::to_value(&value).unwrap();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            AnchoredStateValueV1::read_at_anchor(
                &crate::pc_cbor_1(&changed),
                1,
                16,
                &hash,
                &[0x11; 32]
            )
            .is_err()
        );
    }
    let mut extra = serde_json::to_value(&value).unwrap();
    extra["ready"] = serde_json::json!(true);
    assert!(
        AnchoredStateValueV1::read_at_anchor(&crate::pc_cbor_1(&extra), 1, 16, &hash, &[0x11; 32])
            .is_err()
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(AnchoredStateValueV1::read_at_anchor(&trailing, 1, 16, &hash, &[0x11; 32]).is_err());
}

struct Evidence {
    reads: Cell<usize>,
    value: Option<ArgumentValue>,
}
impl CurrentStateEvidence for Evidence {
    fn read(&self, _: &StateValueReference) -> RuntimeResult<ArgumentValue> {
        self.reads.set(self.reads.get() + 1);
        self.value.clone().ok_or(RuntimeError::RuntimeUnavailable)
    }
}
fn definition(primitives: Vec<Primitive>) -> CiglProgramV1 {
    CiglProgramV1 {
        program_id: "cigl.test/v1".into(),
        version: 1,
        primitives,
        max_steps: 1024,
        max_stack_depth: 64,
        max_evidence_reads: 16,
        result_type: ResultType::AllowDenyIndeterminate,
    }
}
fn evaluate(primitives: Vec<Primitive>) -> ProgramResult {
    ValidatedCiglProgram::try_new(definition(primitives), &[])
        .unwrap()
        .evaluate(
            &[],
            &Evidence {
                reads: Cell::new(0),
                value: None,
            },
        )
}
fn reference() -> StateValueReference {
    StateValueReference {
        fact: FactReference {
            candidate_id: "canonical-state".into(),
            generation_id: "generation-1".into(),
            fact_digest: format!("sha256:{}", Digest::of("fact").as_str()),
        },
        value_type: AbiType::Bool,
    }
}

#[test]
fn typed_comparisons_keep_full_width_signedness_and_no_implicit_coercion() {
    for (primitive, left, right, expected) in [
        (
            Primitive::Eq(()),
            ArgumentValue::Uint([255; 32]),
            ArgumentValue::Uint([255; 32]),
            true,
        ),
        (
            Primitive::Neq(()),
            ArgumentValue::uint(1),
            ArgumentValue::uint(2),
            true,
        ),
        (
            Primitive::Lt(()),
            ArgumentValue::int(-1),
            ArgumentValue::int(0),
            true,
        ),
        (
            Primitive::Lte(()),
            ArgumentValue::int(-2),
            ArgumentValue::int(-1),
            true,
        ),
        (
            Primitive::Gt(()),
            ArgumentValue::Uint([255; 32]),
            ArgumentValue::uint(u128::MAX),
            true,
        ),
        (
            Primitive::Gte(()),
            ArgumentValue::int(-1),
            ArgumentValue::int(-2),
            true,
        ),
        (
            Primitive::Eq(()),
            ArgumentValue::Address([1; 20]),
            ArgumentValue::Address([2; 20]),
            false,
        ),
    ] {
        assert_eq!(
            evaluate(vec![
                Primitive::PushConst(left),
                Primitive::PushConst(right),
                primitive,
                Primitive::Return(())
            ]),
            if expected {
                ProgramResult::Allow
            } else {
                ProgramResult::Deny
            }
        );
    }
    for primitive in [Primitive::Eq(()), Primitive::Neq(()), Primitive::Lt(())] {
        assert!(
            ValidatedCiglProgram::try_new(
                definition(vec![
                    Primitive::PushConst(ArgumentValue::int(1)),
                    Primitive::PushConst(ArgumentValue::uint(1)),
                    primitive,
                    Primitive::Return(())
                ]),
                &[]
            )
            .is_err()
        );
    }
}

#[test]
fn boolean_operators_require_is_terminal_and_opaque_state_errors_never_allow() {
    for (operator, expected) in [(Primitive::And(()), false), (Primitive::Or(()), true)] {
        assert_eq!(
            evaluate(vec![
                Primitive::PushConst(ArgumentValue::Bool(true)),
                Primitive::PushConst(ArgumentValue::Bool(false)),
                operator,
                Primitive::Not(()),
                Primitive::Return(())
            ]),
            if expected {
                ProgramResult::Deny
            } else {
                ProgramResult::Allow
            }
        );
    }
    let evidence = Evidence {
        reads: Cell::new(0),
        value: None,
    };
    let program = ValidatedCiglProgram::try_new(
        definition(vec![
            Primitive::PushConst(ArgumentValue::Bool(false)),
            Primitive::Require(()),
            Primitive::LoadStateEvidence(reference()),
            Primitive::Return(()),
        ]),
        &[],
    )
    .unwrap();
    assert_eq!(program.evaluate(&[], &evidence), ProgramResult::Deny);
    assert_eq!(evidence.reads.get(), 0);
    let program = ValidatedCiglProgram::try_new(
        definition(vec![
            Primitive::LoadStateEvidence(reference()),
            Primitive::Return(()),
        ]),
        &[],
    )
    .unwrap();
    assert_eq!(
        program.evaluate(&[], &evidence),
        ProgramResult::Indeterminate(IndeterminateReason::StateUnavailable)
    );
    assert_eq!(
        program.evaluate(
            &[],
            &Evidence {
                reads: Cell::new(0),
                value: Some(ArgumentValue::uint(0))
            }
        ),
        ProgramResult::Indeterminate(IndeterminateReason::TypeMismatch)
    );
    assert_eq!(
        program.evaluate(
            &[],
            &Evidence {
                reads: Cell::new(0),
                value: Some(ArgumentValue::Bool(true))
            }
        ),
        ProgramResult::Allow
    );
}

#[test]
fn typed_argument_paths_reuse_abi_rules_and_never_substitute_missing_values() {
    let program = ValidatedCiglProgram::try_new(
        definition(vec![
            Primitive::LoadArgument(vec![
                PathSegment::Input(0),
                PathSegment::Field(0),
                PathSegment::Index(0),
            ]),
            Primitive::PushConst(ArgumentValue::uint(5)),
            Primitive::Lte(()),
            Primitive::Return(()),
        ]),
        &[AbiType::Tuple(vec![AbiType::Array {
            element: Box::new(AbiType::Uint(8)),
            length: None,
        }])],
    )
    .unwrap();
    let evidence = Evidence {
        reads: Cell::new(0),
        value: None,
    };
    let input = |value| {
        vec![ArgumentValue::Tuple(vec![ArgumentValue::Array(vec![
            value,
        ])])]
    };
    assert_eq!(
        program.evaluate(&input(ArgumentValue::uint(4)), &evidence),
        ProgramResult::Allow
    );
    assert_eq!(
        program.evaluate(&input(ArgumentValue::uint(6)), &evidence),
        ProgramResult::Deny
    );
    assert_eq!(
        program.evaluate(&input(ArgumentValue::uint(256)), &evidence),
        ProgramResult::Indeterminate(IndeterminateReason::TypeMismatch)
    );
    assert_eq!(
        program.evaluate(&[], &evidence),
        ProgramResult::Indeterminate(IndeterminateReason::ArgumentUnavailable)
    );
}

#[test]
fn admission_rejects_unknown_instructions_operands_versions_and_unbounded_or_unterminated_stacks() {
    for wire in [
        r#"{"opcode":"EQ"}"#,
        r#"{"opcode":"EQ","operand":1}"#,
        r#"{"opcode":"NETWORK","operand":null}"#,
        r#"{"opcode":"RETURN","operand":null,"extra":true}"#,
    ] {
        assert!(serde_json::from_str::<Primitive>(wire).is_err(), "{wire}");
    }
    let valid = definition(vec![
        Primitive::PushConst(ArgumentValue::Bool(true)),
        Primitive::Return(()),
    ]);
    let encoded = serde_json::to_value(&valid).unwrap();
    assert_eq!(
        encoded["primitives"][1],
        serde_json::json!({"opcode":"RETURN","operand":null})
    );
    for changed in [
        CiglProgramV1 {
            version: 2,
            ..valid.clone()
        },
        CiglProgramV1 {
            max_steps: 1,
            ..valid.clone()
        },
        CiglProgramV1 {
            max_stack_depth: 0,
            ..valid.clone()
        },
        CiglProgramV1 {
            max_stack_depth: 65,
            ..valid.clone()
        },
        CiglProgramV1 {
            max_evidence_reads: 17,
            ..valid.clone()
        },
        CiglProgramV1 {
            program_id: "1bad".into(),
            ..valid.clone()
        },
        CiglProgramV1 {
            primitives: vec![Primitive::Return(())],
            ..valid.clone()
        },
        CiglProgramV1 {
            primitives: vec![Primitive::PushConst(ArgumentValue::Bool(true))],
            ..valid.clone()
        },
        CiglProgramV1 {
            primitives: vec![
                Primitive::PushConst(ArgumentValue::Bool(true)),
                Primitive::Return(()),
                Primitive::Return(()),
            ],
            ..valid.clone()
        },
        CiglProgramV1 {
            primitives: vec![
                Primitive::PushConst(ArgumentValue::String("a".repeat(32_769))),
                Primitive::PushConst(ArgumentValue::String("a".into())),
                Primitive::Eq(()),
                Primitive::Return(()),
            ],
            ..valid.clone()
        },
        CiglProgramV1 {
            primitives: vec![
                Primitive::LoadStateEvidence(reference()),
                Primitive::Return(()),
            ],
            max_evidence_reads: 0,
            ..valid.clone()
        },
    ] {
        assert!(ValidatedCiglProgram::try_new(changed, &[]).is_err());
    }
    assert!(
        ValidatedCiglProgram::try_new(
            definition(vec![Primitive::PushConst(ArgumentValue::Bool(true)); 257]),
            &[]
        )
        .is_err()
    );
    let mut over = valid.clone();
    over.primitives = vec![Primitive::PushConst(ArgumentValue::Bool(true)); 65];
    over.primitives.extend(vec![Primitive::And(()); 64]);
    over.primitives.push(Primitive::Return(()));
    assert!(ValidatedCiglProgram::try_new(over, &[]).is_err());
}
