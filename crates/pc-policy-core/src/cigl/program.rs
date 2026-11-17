//! WSP08B CiglProgramV1: finite straight-line typed instructions. No expression
//! engine, I/O, time or randomness. State values belong to a retained owner.
use crate::{
    invocation::{
        AbiType, ArgumentValue, PathSegment, abi_at_path, numeric_cmp, value_at, value_matches_abi,
    },
    semantics::{FactReference, validate_fact_references},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult, canonical_bytes};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, cmp::Ordering};
pub mod state;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateValueReference {
    pub fact: FactReference,
    pub value_type: AbiType,
}

/// Reuse the Argument Guard's typed literal and path models. Operators without
/// operands still require explicit null, matching the closed primitive schema.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "opcode",
    content = "operand",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum Primitive {
    PushConst(ArgumentValue),
    LoadArgument(Vec<PathSegment>),
    LoadStateEvidence(StateValueReference),
    Eq(()),
    Neq(()),
    Lt(()),
    Lte(()),
    Gt(()),
    Gte(()),
    And(()),
    Or(()),
    Not(()),
    Require(()),
    Return(()),
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultType {
    AllowDenyIndeterminate,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CiglProgramV1 {
    pub program_id: String,
    pub version: u64,
    pub primitives: Vec<Primitive>,
    pub max_steps: u16,
    pub max_stack_depth: u8,
    pub max_evidence_reads: u8,
    pub result_type: ResultType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndeterminateReason {
    ArgumentUnavailable,
    StateUnavailable,
    TypeMismatch,
    BudgetExhausted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(
    tag = "result",
    content = "reason",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum ProgramResult {
    Allow,
    Deny,
    Indeterminate(IndeterminateReason),
}

/// Implement at the actual state/fact owner. Reads must already be bounded,
/// local, exact-reference/tenant/anchor bound and current under the held lease.
/// Unavailable or incompatible evidence is never a fabricated zero/false value.
pub trait CurrentStateEvidence {
    fn read(&self, reference: &StateValueReference) -> RuntimeResult<ArgumentValue>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Address,
    Bool,
    Uint,
    Int,
    Bytes,
    String,
}
fn kind(abi: &AbiType) -> RuntimeResult<Kind> {
    match abi {
        AbiType::Address => Ok(Kind::Address),
        AbiType::Bool => Ok(Kind::Bool),
        AbiType::Uint(bits) if (8..=256).contains(bits) && bits % 8 == 0 => Ok(Kind::Uint),
        AbiType::Int(bits) if (8..=256).contains(bits) && bits % 8 == 0 => Ok(Kind::Int),
        AbiType::FixedBytes(length) if (1..=32).contains(length) => Ok(Kind::Bytes),
        AbiType::Bytes => Ok(Kind::Bytes),
        AbiType::String => Ok(Kind::String),
        _ => Err(RuntimeError::InvalidInput),
    }
}
fn value_kind(value: &ArgumentValue) -> RuntimeResult<Kind> {
    match value {
        ArgumentValue::Address(_) => Ok(Kind::Address),
        ArgumentValue::Bool(_) => Ok(Kind::Bool),
        ArgumentValue::Uint(_) => Ok(Kind::Uint),
        ArgumentValue::Int(_) => Ok(Kind::Int),
        ArgumentValue::Bytes(value) if value.len() <= 32_768 => Ok(Kind::Bytes),
        ArgumentValue::String(value) if value.len() <= 32_768 => Ok(Kind::String),
        // A path may select a scalar inside arrays/tuples; a whole collection
        // is not an implicit expression, numeric cast or unbounded operand.
        _ => Err(RuntimeError::InvalidInput),
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedCiglProgram {
    definition: CiglProgramV1,
    digest: Digest,
    argument_types: Vec<AbiType>,
}
impl ValidatedCiglProgram {
    pub fn evaluate_invocation(
        &self,
        invocation: &pc_runtime_types::ContractInvocation,
        policy: &crate::invocation::ValidatedInvocationPolicy,
        evidence: &impl CurrentStateEvidence,
    ) -> ProgramResult {
        match crate::invocation::decode_call(invocation, policy.artifact()) {
            Ok(arguments) => self.evaluate(&arguments, evidence),
            Err(_) => ProgramResult::Indeterminate(IndeterminateReason::ArgumentUnavailable),
        }
    }
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
    pub fn state_references(&self) -> impl Iterator<Item = &StateValueReference> {
        self.definition.primitives.iter().filter_map(|primitive| {
            if let Primitive::LoadStateEvidence(reference) = primitive {
                Some(reference)
            } else {
                None
            }
        })
    }
    pub fn try_new(definition: CiglProgramV1, arguments: &[AbiType]) -> RuntimeResult<Self> {
        let id = definition.program_id.as_bytes();
        if !(2..=192).contains(&id.len())
            || !id[0].is_ascii_alphabetic()
            || !id[1..]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:@/-".contains(b))
            || definition.version != 1
            || !(1..=256).contains(&definition.primitives.len())
            || !(1..=1024).contains(&definition.max_steps)
            || definition.primitives.len() > usize::from(definition.max_steps)
            || !(1..=64).contains(&definition.max_stack_depth)
            || definition.max_evidence_reads > 16
        {
            return Err(RuntimeError::InvalidInput);
        }
        let mut stack = Vec::new();
        let mut evidence_reads = 0;
        for (index, primitive) in definition.primitives.iter().enumerate() {
            match primitive {
                Primitive::PushConst(value) => stack.push(value_kind(value)?),
                Primitive::LoadArgument(path) => {
                    if path.is_empty()
                        || path.len() > 17
                        || path.iter().any(|p| match p {
                            PathSegment::Input(n)
                            | PathSegment::Index(n)
                            | PathSegment::Field(n) => *n >= 4096,
                        })
                    {
                        return Err(RuntimeError::InvalidInput);
                    }
                    stack.push(kind(abi_at_path(arguments, path)?)?);
                }
                Primitive::LoadStateEvidence(reference) => {
                    validate_fact_references(std::slice::from_ref(&reference.fact))
                        .map_err(|_| RuntimeError::InvalidInput)?;
                    evidence_reads += 1;
                    if evidence_reads > definition.max_evidence_reads {
                        return Err(RuntimeError::InvalidInput);
                    }
                    stack.push(kind(&reference.value_type)?);
                }
                Primitive::Not(()) | Primitive::Require(()) | Primitive::Return(()) => {
                    if stack.pop() != Some(Kind::Bool) {
                        return Err(RuntimeError::InvalidInput);
                    }
                    if matches!(primitive, Primitive::Not(())) {
                        stack.push(Kind::Bool);
                    }
                    if matches!(primitive, Primitive::Return(()))
                        && (index + 1 != definition.primitives.len() || !stack.is_empty())
                    {
                        return Err(RuntimeError::InvalidInput);
                    }
                }
                _ => {
                    let right = stack.pop().ok_or(RuntimeError::InvalidInput)?;
                    let left = stack.pop().ok_or(RuntimeError::InvalidInput)?;
                    if left != right
                        || (matches!(primitive, Primitive::And(()) | Primitive::Or(()))
                            && left != Kind::Bool)
                        || (matches!(
                            primitive,
                            Primitive::Lt(())
                                | Primitive::Lte(())
                                | Primitive::Gt(())
                                | Primitive::Gte(())
                        ) && !matches!(left, Kind::Int | Kind::Uint))
                    {
                        return Err(RuntimeError::InvalidInput);
                    }
                    stack.push(Kind::Bool);
                }
            }
            if stack.len() > usize::from(definition.max_stack_depth) {
                return Err(RuntimeError::InvalidInput);
            }
        }
        if !matches!(definition.primitives.last(), Some(Primitive::Return(()))) || !stack.is_empty()
        {
            return Err(RuntimeError::InvalidInput);
        }
        let digest = Digest::of(canonical_bytes(
            &serde_json::to_value(&definition).map_err(|_| RuntimeError::InvalidInput)?,
        )?);
        Ok(Self {
            definition,
            digest,
            argument_types: arguments.to_vec(),
        })
    }

    pub fn evaluate(
        &self,
        arguments: &[ArgumentValue],
        evidence: &impl CurrentStateEvidence,
    ) -> ProgramResult {
        self.evaluate_inner(arguments, evidence)
            .unwrap_or_else(ProgramResult::Indeterminate)
    }
    fn evaluate_inner(
        &self,
        arguments: &[ArgumentValue],
        evidence: &impl CurrentStateEvidence,
    ) -> Result<ProgramResult, IndeterminateReason> {
        use IndeterminateReason as Reason;
        let mut stack: Vec<Cow<'_, ArgumentValue>> =
            Vec::with_capacity(usize::from(self.definition.max_stack_depth));
        let mut evidence_reads = 0;
        for (step, primitive) in self.definition.primitives.iter().enumerate() {
            if step >= usize::from(self.definition.max_steps) {
                return Err(Reason::BudgetExhausted);
            }
            match primitive {
                Primitive::PushConst(value) => stack.push(Cow::Borrowed(value)),
                Primitive::LoadArgument(path) => {
                    let value =
                        value_at(arguments, path).map_err(|_| Reason::ArgumentUnavailable)?;
                    let expected = abi_at_path(&self.argument_types, path)
                        .map_err(|_| Reason::TypeMismatch)?;
                    if !value_matches_abi(value, expected) {
                        return Err(Reason::TypeMismatch);
                    }
                    value_kind(value).map_err(|_| Reason::TypeMismatch)?;
                    stack.push(Cow::Borrowed(value));
                }
                Primitive::LoadStateEvidence(reference) => {
                    evidence_reads += 1;
                    if evidence_reads > self.definition.max_evidence_reads {
                        return Err(Reason::BudgetExhausted);
                    }
                    let value = evidence
                        .read(reference)
                        .map_err(|_| Reason::StateUnavailable)?;
                    if value_kind(&value).is_err()
                        || !value_matches_abi(&value, &reference.value_type)
                    {
                        return Err(Reason::TypeMismatch);
                    }
                    stack.push(Cow::Owned(value));
                }
                Primitive::Not(()) | Primitive::Require(()) | Primitive::Return(()) => {
                    let value = stack.pop().ok_or(Reason::TypeMismatch)?;
                    let ArgumentValue::Bool(value) = value.as_ref() else {
                        return Err(Reason::TypeMismatch);
                    };
                    match primitive {
                        Primitive::Not(()) => stack.push(Cow::Owned(ArgumentValue::Bool(!value))),
                        Primitive::Require(()) if !value => return Ok(ProgramResult::Deny),
                        Primitive::Return(()) => {
                            return if stack.is_empty() {
                                Ok(if *value {
                                    ProgramResult::Allow
                                } else {
                                    ProgramResult::Deny
                                })
                            } else {
                                Err(Reason::TypeMismatch)
                            };
                        }
                        _ => {}
                    }
                }
                _ => {
                    let right = stack.pop().ok_or(Reason::TypeMismatch)?;
                    let left = stack.pop().ok_or(Reason::TypeMismatch)?;
                    if value_kind(&left).map_err(|_| Reason::TypeMismatch)?
                        != value_kind(&right).map_err(|_| Reason::TypeMismatch)?
                    {
                        return Err(Reason::TypeMismatch);
                    }
                    let result = match primitive {
                        Primitive::Eq(()) => left == right,
                        Primitive::Neq(()) => left != right,
                        Primitive::And(()) | Primitive::Or(()) => {
                            let (ArgumentValue::Bool(a), ArgumentValue::Bool(b)) =
                                (left.as_ref(), right.as_ref())
                            else {
                                return Err(Reason::TypeMismatch);
                            };
                            if matches!(primitive, Primitive::And(())) {
                                *a && *b
                            } else {
                                *a || *b
                            }
                        }
                        Primitive::Lt(())
                        | Primitive::Lte(())
                        | Primitive::Gt(())
                        | Primitive::Gte(()) => {
                            let order = numeric_cmp(&left, &right).ok_or(Reason::TypeMismatch)?;
                            matches!(
                                (primitive, order),
                                (Primitive::Lt(()), Ordering::Less)
                                    | (Primitive::Lte(()), Ordering::Less | Ordering::Equal)
                                    | (Primitive::Gt(()), Ordering::Greater)
                                    | (Primitive::Gte(()), Ordering::Greater | Ordering::Equal)
                            )
                        }
                        _ => return Err(Reason::TypeMismatch),
                    };
                    stack.push(Cow::Owned(ArgumentValue::Bool(result)));
                }
            }
            if stack.len() > usize::from(self.definition.max_stack_depth) {
                return Err(Reason::BudgetExhausted);
            }
        }
        Err(Reason::TypeMismatch)
    }
}

#[cfg(test)]
mod tests;
