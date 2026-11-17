//! RGRA maps only the registered event after independent canonical block, code,
//! complete log response and successful transaction receipt verification.
use super::*;
use openpc_indexer_adapter::acquisition::{
    RGRA_EVENT_NAME, RGRA_EVENT_SIGNATURE, relationship_candidate,
};
use pc_facts_core::{FactObject, FactSubject};
use pc_policy_core::fact_profile::StateFactMapping;

pub(super) fn validate_abi(abi: &Value) -> Result<()> {
    let events: Vec<_> = abi
        .as_array()
        .ok_or(SourceAuthorityError::Binding)?
        .iter()
        .filter(|value| value["type"] == "event" && value["name"] == RGRA_EVENT_NAME)
        .collect();
    if events.len() != 1 || events[0]["anonymous"] != false {
        return Err(SourceAuthorityError::Binding);
    }
    let inputs = events[0]["inputs"]
        .as_array()
        .ok_or(SourceAuthorityError::Binding)?;
    let expected = [
        ("bytes32", true),
        ("bytes32", true),
        ("uint8", false),
        ("uint64", false),
        ("uint64", false),
    ];
    if inputs.len() != expected.len()
        || inputs
            .iter()
            .zip(expected)
            .any(|(input, (kind, indexed))| input["type"] != kind || input["indexed"] != indexed)
    {
        return Err(SourceAuthorityError::Binding);
    }
    Ok(())
}

impl CurrentFactContract<'_> {
    pub(crate) fn relationship_checkpoint_profile(&self) -> Result<(String, String)> {
        if self.event_signature.is_none() {
            return Err(SourceAuthorityError::Binding);
        }
        Ok((
            format!(
                "urn:openpc:fact-profile:{}",
                self.admission_profile.fact_profile_id
            ),
            format!(
                "sha256:{}",
                Digest::of(
                    self.admission_profile
                        .to_cbor()
                        .map_err(|_| SourceAuthorityError::Binding)?
                )
                .as_str()
            ),
        ))
    }

    pub(crate) fn verify_empty_event_block(
        &self,
        observations: &[BoundFactObservation],
        head: u64,
        hash: &[u8],
    ) -> Result<Vec<Digest>> {
        self.assert_fresh()?;
        let signature = self
            .event_signature
            .as_ref()
            .ok_or(SourceAuthorityError::Binding)?;
        if observations.len() != self.providers().len() || observations.is_empty() {
            return Err(SourceAuthorityError::Binding);
        }
        observations
            .iter()
            .map(|bound| {
                let observation = &bound.observation;
                observation
                    .validate_event(
                        &self.query,
                        signature,
                        observation.connection(),
                        now_ns()? / 1_000_000,
                    )
                    .map_err(|_| SourceAuthorityError::Binding)?;
                let logs: Value = serde_json::from_slice(observation.result())
                    .map_err(|_| SourceAuthorityError::Binding)?;
                if logs != serde_json::json!([])
                    || observation.head_number() != head
                    || observation.head_hash().as_str() != hex(hash)
                    || bound.publication_digest != self.source.publication_digest
                {
                    return Err(SourceAuthorityError::Binding);
                }
                observation
                    .digest()
                    .map_err(|_| SourceAuthorityError::Binding)
            })
            .collect()
    }

    pub(crate) fn verify_complete_event_block(
        &self,
        materials: &[&CandidateMaterial],
        observations: &[BoundFactObservation],
    ) -> Result<()> {
        if self.event_signature.is_none() {
            return Ok(());
        }
        if materials.is_empty() || materials.len() > 64 {
            return Err(SourceAuthorityError::Binding);
        }
        for observation in observations {
            let logs: Value = serde_json::from_slice(observation.observation.result())
                .map_err(|_| SourceAuthorityError::Binding)?;
            if logs
                .as_array()
                .is_none_or(|logs| logs.len() != materials.len())
            {
                return Err(SourceAuthorityError::Binding);
            }
            for material in materials {
                self.project_relationship(material, observation)?;
            }
        }
        Ok(())
    }
    pub(super) fn project_relationship(
        &self,
        material: &CandidateMaterial,
        bound: &BoundFactObservation,
    ) -> Result<TypedStateProjection> {
        let StateFactMapping::RgraEventRelationshipV1 {
            namespace,
            relationship_kind,
            role_predicates,
        } = &self.admission_profile.mapping
        else {
            return Err(SourceAuthorityError::Binding);
        };
        let signature = self
            .event_signature
            .as_ref()
            .ok_or(SourceAuthorityError::Binding)?;
        bound
            .observation
            .validate_event(
                &self.query,
                signature,
                bound.observation.connection(),
                now_ns()? / 1_000_000,
            )
            .map_err(|_| SourceAuthorityError::Binding)?;
        let logs: Value = serde_json::from_slice(bound.observation.result())
            .map_err(|_| SourceAuthorityError::Binding)?;
        let transaction = format!(
            "0x{}",
            hex(material
                .transaction_hash
                .as_deref()
                .ok_or(SourceAuthorityError::Binding)?)
        );
        let tx_index = material
            .transaction_index
            .ok_or(SourceAuthorityError::Binding)?;
        let log_index = material.log_index.ok_or(SourceAuthorityError::Binding)?;
        let matching: Vec<_> = logs
            .as_array()
            .ok_or(SourceAuthorityError::Binding)?
            .iter()
            .filter(|log| {
                log["transactionHash"] == transaction
                    && log["transactionIndex"] == format!("0x{tx_index:x}")
                    && log["logIndex"] == format!("0x{log_index:x}")
            })
            .collect();
        if matching.len() != 1 {
            return Err(SourceAuthorityError::Binding);
        }
        let (_, payload) = relationship_candidate(
            matching[0],
            &self.source.participant.to_string(),
            &self.source.privacy.to_string(),
            &format!("0x{}", hex(&self.query.target)),
            RGRA_EVENT_SIGNATURE,
            material.block_number,
            self.query.block_hash.as_str(),
        )
        .map_err(|_| SourceAuthorityError::Binding)?;
        if payload != material.payload_cbor {
            return Err(SourceAuthorityError::Binding);
        }
        let value: Value = ciborium::de::from_reader(payload.as_slice())
            .map_err(|_| SourceAuthorityError::Binding)?;
        let string = |name: &str| {
            value[name]
                .as_str()
                .map(str::to_owned)
                .ok_or(SourceAuthorityError::Binding)
        };
        let from = string("effectiveFromBlock")?
            .parse()
            .map_err(|_| SourceAuthorityError::Binding)?;
        let through = value["effectiveThroughBlock"]
            .as_str()
            .map(str::parse)
            .transpose()
            .map_err(|_| SourceAuthorityError::Binding)?;
        let subject = FactSubject::Relationship {
            namespace: namespace.clone(),
            entity_key_digest: string("entityKeyDigest")?,
            subject_key_digest: string("subjectKeyDigest")?,
            relationship_kind: relationship_kind.clone(),
            role_predicates: role_predicates.clone(),
            profile_digest: format!(
                "sha256:{}",
                Digest::of(
                    self.admission_profile
                        .to_cbor()
                        .map_err(|_| SourceAuthorityError::Binding)?
                )
                .as_str()
            ),
            transaction_hash: transaction,
        };
        let object = FactObject::RelationshipInterval {
            transition: string("transition")?,
            effective_from_block: from,
            effective_through_block: through,
            completed_watermark: material.range_end,
            successful_execution: true,
        };
        Ok(TypedStateProjection {
            runtime_binding_id: self.binding_id,
            binding_revision: self.binding_revision,
            abi_digest: self.abi_digest.clone(),
            canonical_signature: self.signature.clone(),
            arguments: Vec::new(),
            result: Vec::new(),
            observation_digest: bound
                .observation
                .digest()
                .map_err(|_| SourceAuthorityError::Binding)?,
            specialization: Some((subject, object)),
        })
    }
}
