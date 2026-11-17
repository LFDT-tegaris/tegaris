//! Immutable local values admitted off path from the signed manifest and all
//! signed records. Lookup has no database, network, mutation or enumeration API.
use super::*;
use pc_facts_core::{FactObject, FactRecord, FactSubject, RelationshipResult};
use pc_policy_core::fact_condition::FactCondition;
use pc_runtime_types::Digest;
use std::collections::BTreeMap;

pub struct LocalFactContext<'a> {
    pub participant_id: &'a str,
    pub privacy_domain_id: &'a str,
    pub workload_id: &'a str,
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: &'a Digest,
}

pub struct VerifiedLocalFacts {
    shard: VerifiedShard,
    records: Vec<FactRecord>,
    by_digest: BTreeMap<String, usize>,
    relationships: BTreeMap<Vec<u8>, Vec<usize>>,
    empty_blocks: BTreeMap<u64, (String, String)>,
}

fn relationship_key(subject: &FactSubject) -> Result<Option<Vec<u8>>, FactSigningError> {
    let FactSubject::Relationship {
        namespace,
        entity_key_digest,
        subject_key_digest,
        relationship_kind,
        role_predicates,
        profile_digest,
        ..
    } = subject
    else {
        return Ok(None);
    };
    Ok(Some(crate::state_value::canonical(&(
        namespace,
        entity_key_digest,
        subject_key_digest,
        relationship_kind,
        role_predicates,
        profile_digest,
    ))?))
}

impl FactSignatureVerifier {
    pub fn verify_local_facts(
        &self,
        shard: &VerifiedShard,
        content: &[u8],
    ) -> Result<VerifiedLocalFacts, FactSigningError> {
        if content.len() > 64 * 1024 * 1024 || sha256(content) != *shard.shard_digest() {
            return Err(FactSigningError::Verification);
        }
        let manifest = shard
            .manifest
            .as_ref()
            .ok_or(FactSigningError::Verification)?;
        let Value::Array(mut container) = decode_value(content)? else {
            return Err(FactSigningError::InvalidCose);
        };
        let entries = if container.len() == 2
            && container[0] == Value::Text("openpc:fact-shard-content:v1".into())
        {
            let Value::Array(entries) = container.remove(1) else {
                return Err(FactSigningError::InvalidCose);
            };
            entries
        } else {
            vec![Value::Bytes(content.to_vec())]
        };
        if entries.is_empty() || entries.len() > 1_000_000 {
            return Err(FactSigningError::Verification);
        }
        let mut records = Vec::with_capacity(entries.len());
        let mut by_digest = BTreeMap::new();
        let mut relationships: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
        for entry in entries {
            let Value::Bytes(cose) = entry else {
                return Err(FactSigningError::InvalidCose);
            };
            // Parse only to select the registered purpose; no value is used until verified.
            let Value::Array(fields) = decode_value(&cose)? else {
                return Err(FactSigningError::InvalidCose);
            };
            let Some(Value::Bytes(payload)) = fields.get(2) else {
                return Err(FactSigningError::InvalidCose);
            };
            let untrusted = FactRecord::from_cbor(payload)?;
            let claims = self.verified_stored_claims(untrusted.identity.fact_schema_id, &cose)?;
            let record = FactRecord::from_cbor(&encode_pc_cbor(claims)?)?;
            if by_digest
                .insert(record.identity.local_fact_digest.clone(), records.len())
                .is_some()
            {
                return Err(FactSigningError::Verification);
            }
            if let Some(key) = relationship_key(&record.identity.typed_subject)? {
                let members = relationships.entry(key).or_default();
                members.push(records.len());
                if members.len() > 64 {
                    return Err(FactSigningError::Verification);
                }
            }
            records.push(record);
        }
        if !manifest.matches(&records, content) {
            return Err(FactSigningError::Verification);
        }
        let mut local = VerifiedLocalFacts {
            shard: shard.clone(),
            records,
            by_digest,
            relationships,
            empty_blocks: BTreeMap::new(),
        };
        self.extend_relationship_checkpoints(
            &mut local,
            shard.checkpoint_proofs.iter().map(Vec::as_slice),
        )?;
        Ok(local)
    }
    /// Apply only signed empty intervals contiguous with this exact published
    /// relationship shard. Unrelated artifact bytes cannot change its state.
    pub fn extend_relationship_checkpoints<'a>(
        &self,
        local: &mut VerifiedLocalFacts,
        proofs: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Vec<Digest>, FactSigningError> {
        let Some(base) = local.shard.manifest.as_ref() else {
            return Ok(Vec::new());
        };
        if base.relationship_profile_digest.is_none() {
            return Ok(Vec::new());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| FactSigningError::Verification)?;
        let now = pc_facts_core::fact_timestamp_from_ms(
            i64::try_from(now.as_millis()).map_err(|_| FactSigningError::Verification)?,
        )?;
        let mut intervals = BTreeMap::new();
        for proof in proofs {
            let Ok(verified) = self.verify_shard_cose(proof) else {
                continue;
            };
            let Some(manifest) = verified.manifest.as_ref() else {
                continue;
            };
            if manifest.entry_count != 0
                || manifest.participant_id != base.participant_id
                || manifest.privacy_domain_id != base.privacy_domain_id
                || manifest.fact_profile_id != base.fact_profile_id
                || manifest.relationship_profile_digest != base.relationship_profile_digest
                || manifest.canonical_range.partition_id != base.canonical_range.partition_id
            {
                continue;
            }
            if now < manifest.not_before || now >= manifest.expires_at {
                return Err(FactSigningError::Verification);
            }
            let start = manifest.canonical_range.range_start;
            let digest = Digest::of(proof);
            if let Some(prior) = intervals.insert(start, verified.clone())
                && prior != verified
            {
                return Err(FactSigningError::Verification);
            }
            if intervals.len() > 64 || digest == Digest::of([]) {
                return Err(FactSigningError::Verification);
            }
        }
        let mut watermark = base.canonical_range.range_end;
        let mut generation = base.canonical_generation;
        let mut previous = shard::digest_text(&sha256(local.shard.cose_sign1()));
        let mut used = Vec::new();
        while let Some(start) = watermark.checked_add(1) {
            let Some(proof) = intervals.remove(&start) else {
                break;
            };
            let manifest = proof
                .manifest
                .as_ref()
                .ok_or(FactSigningError::Verification)?;
            if manifest.predecessor_shard_digest.as_deref() != Some(previous.as_str())
                || generation.checked_add(1) != Some(manifest.canonical_generation)
            {
                return Err(FactSigningError::Verification);
            }
            for (number, hash) in &manifest.canonical_blocks {
                local
                    .empty_blocks
                    .insert(*number, (hash.clone(), manifest.expires_at.clone()));
            }
            watermark = manifest.canonical_range.range_end;
            generation = manifest.canonical_generation;
            let digest = Digest::of(proof.cose_sign1());
            previous = format!("sha256:{}", digest.as_str());
            used.push(digest);
        }
        Ok(used)
    }
}

impl VerifiedLocalFacts {
    pub(crate) fn empty_checkpoint_scope(&self) -> Option<(uuid::Uuid, u64)> {
        let record = self.records.first()?;
        if !matches!(
            record.identity.typed_subject,
            FactSubject::Relationship { .. }
        ) {
            return None;
        }
        Some((
            uuid::Uuid::parse_str(
                record
                    .completeness_scope
                    .partition_id
                    .strip_prefix("urn:openpc:candidate-partition:")?,
            )
            .ok()?,
            record.completeness_scope.range_end,
        ))
    }

    /// Off-path simulation predicts at the selected immutable fact's own anchor.
    /// Runtime requests still call `evaluate` with their independently pinned anchor.
    pub fn evaluate_at_snapshot_anchor(
        &self,
        condition: &FactCondition,
        workload_id: &str,
    ) -> RelationshipResult {
        let Some(index) = self.by_digest.get(&condition.fact().fact_digest) else {
            return RelationshipResult::Unresolved;
        };
        let anchor = &self.records[*index].identity.chain_anchor;
        let Ok(chain_id) = anchor.chain_id.parse() else {
            return RelationshipResult::Unresolved;
        };
        // A relationship reference selects its key, not a historical evaluation
        // time. Simulation must include later removal and signed empty coverage.
        let (block_number, block_hash) = if matches!(condition, FactCondition::Relationship { .. })
        {
            if let Some((height, (hash, _))) = self.empty_blocks.last_key_value() {
                (*height, hash.as_str())
            } else {
                let Some(manifest) = self.shard.manifest.as_ref() else {
                    return RelationshipResult::Unresolved;
                };
                let height = manifest.canonical_range.range_end;
                let Some((_, hash)) = manifest
                    .canonical_blocks
                    .iter()
                    .find(|(number, _)| *number == height)
                else {
                    return RelationshipResult::Unresolved;
                };
                (height, hash.as_str())
            }
        } else {
            (
                anchor.block_height,
                anchor.block_hash.trim_start_matches("0x"),
            )
        };
        let Ok(block_hash) = Digest::parse(block_hash) else {
            return RelationshipResult::Unresolved;
        };
        self.evaluate(
            condition,
            &LocalFactContext {
                participant_id: self.shard.participant_id(),
                privacy_domain_id: self.shard.privacy_domain_id(),
                workload_id,
                chain_id,
                block_number,
                block_hash: &block_hash,
            },
        )
    }

    /// A condition can only reject an already authorized operation. The actual
    /// runtime owns the current capsule/Identity/fact invalidation fences.
    pub fn permits_condition(
        &self,
        condition: &FactCondition,
        context: &LocalFactContext<'_>,
    ) -> bool {
        self.evaluate(condition, context) == RelationshipResult::MemberConfirmed
    }
    pub fn evaluate(
        &self,
        condition: &FactCondition,
        context: &LocalFactContext<'_>,
    ) -> RelationshipResult {
        self.evaluate_ordered(condition, context, None)
    }

    /// An event observes only transitions strictly before its exact occurrence.
    /// End-of-block membership cannot grant visibility to an earlier log.
    pub fn permits_condition_at_occurrence(
        &self,
        condition: &FactCondition,
        context: &LocalFactContext<'_>,
        transaction_index: u64,
        log_index: u64,
    ) -> bool {
        self.evaluate_at_occurrence(condition, context, transaction_index, log_index)
            == RelationshipResult::MemberConfirmed
    }

    pub fn evaluate_at_occurrence(
        &self,
        condition: &FactCondition,
        context: &LocalFactContext<'_>,
        transaction_index: u64,
        log_index: u64,
    ) -> RelationshipResult {
        self.evaluate_ordered(condition, context, Some((transaction_index, log_index)))
    }

    /// Candidate acquisition may proceed if this complete anchored block has a
    /// permitted interval. Release still evaluates each exact returned log;
    /// an end-of-block revocation must not erase earlier permitted occurrences.
    pub fn permits_any_occurrence(
        &self,
        condition: &FactCondition,
        context: &LocalFactContext<'_>,
    ) -> bool {
        if self.permits_condition_at_occurrence(condition, context, 0, 0) {
            return true;
        }
        let Some(record) = self
            .by_digest
            .get(&condition.fact().fact_digest)
            .map(|index| &self.records[*index])
        else {
            return false;
        };
        let Ok(Some(key)) = relationship_key(&record.identity.typed_subject) else {
            return false;
        };
        self.relationships.get(&key).is_some_and(|records| {
            records.iter().any(|index| {
                let record = &self.records[*index];
                let anchor = &record.identity.chain_anchor;
                if anchor.block_height != context.block_number {
                    return false;
                }
                match (
                    anchor.transaction_index,
                    anchor.log_index.and_then(|log| log.checked_add(1)),
                ) {
                    (Some(transaction), Some(log)) => {
                        self.permits_condition_at_occurrence(condition, context, transaction, log)
                    }
                    _ => false,
                }
            })
        })
    }

    fn evaluate_ordered(
        &self,
        condition: &FactCondition,
        context: &LocalFactContext<'_>,
        occurrence: Option<(u64, u64)>,
    ) -> RelationshipResult {
        use RelationshipResult as R;
        if condition.validate().is_err()
            || context.participant_id != self.shard.participant_id()
            || context.privacy_domain_id != self.shard.privacy_domain_id()
            || condition.fact().generation_id != self.shard.generation_id()
        {
            return R::Denied;
        }
        let Some(index) = self.by_digest.get(&condition.fact().fact_digest) else {
            return R::Unresolved;
        };
        let record = &self.records[*index];
        let identity = &record.identity;
        let anchor = &identity.chain_anchor;
        let now = match std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|now| i64::try_from(now.as_millis()).ok())
            .and_then(|now| pc_facts_core::fact_timestamp_from_ms(now).ok())
        {
            Some(now) => now,
            None => return R::Unavailable,
        };
        if now < record.not_before || now >= record.expires_at {
            return R::Stale;
        }
        if record.gap_state != pc_facts_core::FactGapState::Complete {
            return R::Partial;
        }
        if anchor.chain_id != context.chain_id.to_string() {
            return R::Unresolved;
        }
        let relationship = matches!(condition, FactCondition::Relationship { .. });
        let anchored = if relationship {
            self.shard.manifest.as_ref().is_some_and(|m| {
                m.canonical_blocks.iter().any(|(height, hash)| {
                    *height == context.block_number && hash == context.block_hash.as_str()
                })
            }) || self.records.iter().any(|r| {
                r.identity.chain_anchor.block_height == context.block_number
                    && r.identity.chain_anchor.block_hash
                        == format!("0x{}", context.block_hash.as_str())
            }) || self
                .empty_blocks
                .get(&context.block_number)
                .is_some_and(|(hash, expiry)| {
                    hash == context.block_hash.as_str() && now.as_str() < expiry.as_str()
                })
        } else {
            anchor.block_height == context.block_number
                && anchor.block_hash == format!("0x{}", context.block_hash.as_str())
        };
        if !anchored {
            return R::Unresolved;
        }
        if context.block_number < record.completeness_scope.range_start
            || (context.block_number > record.completeness_scope.range_end
                && !self.empty_blocks.contains_key(&context.block_number))
        {
            return R::NotCaughtUp;
        }
        match condition {
            FactCondition::ExternalObservation {
                provider_id,
                provider_version,
                provider_configuration_digest,
                request_digest,
                condition,
                ..
            } => match (&identity.typed_subject, &identity.typed_object) {
                (
                    FactSubject::ExternalDecision {
                        provider_id: actual_provider,
                        provider_version: actual_version,
                        configuration_digest,
                        request_digest: actual_request,
                        condition: actual_condition,
                        ..
                    },
                    FactObject::ExternalObservation {
                        satisfied: true, ..
                    },
                ) if provider_id == actual_provider
                    && provider_version == actual_version
                    && configuration_digest
                        == &format!("sha256:{}", provider_configuration_digest.as_str())
                    && actual_request == &format!("sha256:{}", request_digest.as_str())
                    && condition == actual_condition =>
                {
                    R::MemberConfirmed
                }
                _ => R::Denied,
            },
            FactCondition::Relationship {
                fact_profile_id,
                profile_digest,
                namespace,
                entity_key_digest,
                relationship_kind,
                role_predicate,
                ..
            } => {
                let Ok(workload) = uuid::Uuid::parse_str(
                    context
                        .workload_id
                        .strip_prefix("urn:openpc:workload:")
                        .unwrap_or(context.workload_id),
                ) else {
                    return R::Denied;
                };
                if workload.get_version_num() != 7 {
                    return R::Denied;
                }
                let mut key = [0u8; 32];
                key[16..].copy_from_slice(workload.as_bytes());
                let Ok(projected) = crate::state_value::canonical(&serde_json::json!([
                    "openpc:rgra-scoped-key:v1",
                    context.participant_id,
                    context.privacy_domain_id,
                    "subject",
                    key.to_vec()
                ])) else {
                    return R::Denied;
                };
                let expected_subject = shard::digest_text(&sha256(&projected));
                let FactSubject::Relationship {
                    namespace: actual_namespace,
                    entity_key_digest: actual_entity,
                    subject_key_digest,
                    relationship_kind: actual_kind,
                    role_predicates,
                    profile_digest: actual_profile,
                    ..
                } = &identity.typed_subject
                else {
                    return R::Denied;
                };
                if identity.fact_profile_id != format!("urn:openpc:fact-profile:{fact_profile_id}")
                    || actual_namespace != namespace
                    || actual_entity != &format!("sha256:{}", entity_key_digest.as_str())
                    || subject_key_digest != &expected_subject
                    || actual_kind != relationship_kind
                    || actual_profile != &format!("sha256:{}", profile_digest.as_str())
                    || !role_predicates.contains(role_predicate)
                {
                    return R::Denied;
                }
                let Ok(Some(key)) = relationship_key(&identity.typed_subject) else {
                    return R::Denied;
                };
                let Some(matching) = self.relationships.get(&key) else {
                    return R::Unresolved;
                };
                let mut current = None;
                for index in matching {
                    let next = &self.records[*index];
                    let next_anchor = &next.identity.chain_anchor;
                    if occurrence.is_some()
                        && (next_anchor.transaction_index.is_none()
                            || next_anchor.log_index.is_none())
                    {
                        return R::Partial;
                    }
                    let precedes = if let Some((transaction, log)) = occurrence {
                        (
                            next_anchor.block_height,
                            next_anchor.transaction_index,
                            next_anchor.log_index,
                        ) < (context.block_number, Some(transaction), Some(log))
                    } else {
                        next_anchor.block_height <= context.block_number
                    };
                    if precedes {
                        if current.is_some_and(|prior: &FactRecord| {
                            (
                                &prior.identity.chain_anchor.block_height,
                                &prior.identity.chain_anchor.transaction_index,
                                &prior.identity.chain_anchor.log_index,
                            ) >= (
                                &next.identity.chain_anchor.block_height,
                                &next.identity.chain_anchor.transaction_index,
                                &next.identity.chain_anchor.log_index,
                            )
                        }) {
                            return R::Partial;
                        }
                        current = Some(next);
                    }
                }
                let Some(current) = current else {
                    return R::Unresolved;
                };
                let FactObject::RelationshipInterval {
                    transition,
                    effective_from_block,
                    effective_through_block,
                    completed_watermark,
                    successful_execution,
                    ..
                } = &current.value
                else {
                    return R::Denied;
                };
                if !successful_execution {
                    return R::Denied;
                }
                if occurrence.is_some() && transition == "CLOSE" {
                    return R::NonMemberConfirmed;
                }
                if context.block_number > *completed_watermark
                    && !self.empty_blocks.contains_key(&context.block_number)
                {
                    return R::NotCaughtUp;
                }
                if now < current.not_before || now >= current.expires_at {
                    return R::Stale;
                }
                if context.block_number < *effective_from_block
                    || effective_through_block.is_some_and(|end| context.block_number > end)
                {
                    R::NonMemberConfirmed
                } else {
                    R::MemberConfirmed
                }
            }
        }
    }
}
