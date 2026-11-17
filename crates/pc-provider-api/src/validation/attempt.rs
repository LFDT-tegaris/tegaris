use super::*;

pub(super) fn lifecycle_start_millis(lifecycle: &AttemptLifecycleV1) -> Option<u64> {
    match lifecycle {
        AttemptLifecycleV1::Started(start)
        | AttemptLifecycleV1::ResponseObserved { start, .. }
        | AttemptLifecycleV1::Resolved { start, .. }
        | AttemptLifecycleV1::Unknown { start, .. }
        | AttemptLifecycleV1::FailedAfterStart { start, .. } => Some(start.started_at_millis),
        AttemptLifecycleV1::Prepared | AttemptLifecycleV1::FailedPreStart { .. } => None,
    }
}

pub(super) fn terminal_completion(attempt: &RouteAttemptV1) -> Option<u64> {
    match attempt.envelope().lifecycle() {
        AttemptLifecycleV1::Resolved {
            completed_at_millis,
            ..
        }
        | AttemptLifecycleV1::Unknown {
            completed_at_millis,
            ..
        }
        | AttemptLifecycleV1::FailedPreStart {
            completed_at_millis,
            ..
        }
        | AttemptLifecycleV1::FailedAfterStart {
            completed_at_millis,
            ..
        } => Some(*completed_at_millis),
        AttemptLifecycleV1::Prepared
        | AttemptLifecycleV1::Started(_)
        | AttemptLifecycleV1::ResponseObserved { .. } => None,
    }
}

impl TryFrom<AttemptEnvelopeDraftV1> for AttemptEnvelopeV1 {
    type Error = ProviderContractError;

    fn try_from(value: AttemptEnvelopeDraftV1) -> Result<Self, Self::Error> {
        validate_chain_anchor(&value.anchor)?;
        if value.ordinal == 0 || value.deadline_millis == 0 {
            return Err(invalid("attempt ordinal or deadline"));
        }
        let identity = AttemptIdentityV1 {
            attempt_id: AttemptId::new(value.attempt_id).map_err(|_| invalid("attempt id"))?,
            request_id: RequestId::new(value.request_id).map_err(|_| invalid("request id"))?,
            authority_context_digest: AuthorityContextDigest::new(value.authority_context_digest)
                .map_err(|_| invalid("authority"))?,
            capability_profile_digest: CapabilityProfileDigest::new(
                value.capability_profile_digest,
            )
            .map_err(|_| invalid("capability profile"))?,
            provider: provider_key(value.profile_digest, value.provider_instance_id)?,
            immutable_request_digest: RequestDigest::new(value.immutable_request_digest)
                .map_err(|_| invalid("request digest"))?,
            anchor: value.anchor,
            ordinal: value.ordinal,
            deadline_millis: value.deadline_millis,
            correlation_id: CorrelationId::new(value.correlation_id)
                .map_err(|_| invalid("correlation"))?,
            causation_id: CausationId::new(value.causation_id).map_err(|_| invalid("causation"))?,
        };

        let no_start = value.bytes_started_evidence_digest.is_none()
            && value.started_at_millis.is_none()
            && value.response_observed_evidence_digest.is_none()
            && value.observed_at_millis.is_none();
        let no_completion = value.completed_at_millis.is_none();
        let no_prestart_evidence = value.no_bytes_sent_evidence_digest.is_none();
        let start = || -> Result<StartEvidenceV1, ProviderContractError> {
            let start = StartEvidenceV1 {
                bytes_started_evidence_digest: EvidenceDigest::new(
                    value
                        .bytes_started_evidence_digest
                        .clone()
                        .ok_or_else(|| invalid("bytes-started evidence"))?,
                )
                .map_err(|_| invalid("bytes-started evidence"))?,
                started_at_millis: value
                    .started_at_millis
                    .ok_or_else(|| invalid("started time"))?,
            };
            if start.started_at_millis > identity.deadline_millis {
                return Err(invalid("attempt started after deadline"));
            }
            Ok(start)
        };
        let lifecycle = match value.state {
            AttemptState::Prepared if no_start && no_completion && no_prestart_evidence => {
                AttemptLifecycleV1::Prepared
            }
            AttemptState::Started
                if value.response_observed_evidence_digest.is_none()
                    && value.observed_at_millis.is_none()
                    && no_completion
                    && no_prestart_evidence =>
            {
                AttemptLifecycleV1::Started(start()?)
            }
            AttemptState::ResponseObserved if no_completion && no_prestart_evidence => {
                let start = start()?;
                let observed_at_millis = value
                    .observed_at_millis
                    .ok_or_else(|| invalid("response-observed time"))?;
                if observed_at_millis < start.started_at_millis {
                    return Err(invalid("response-observed ordering"));
                }
                AttemptLifecycleV1::ResponseObserved {
                    start,
                    response_observed_evidence_digest: EvidenceDigest::new(
                        value
                            .response_observed_evidence_digest
                            .ok_or_else(|| invalid("response-observed evidence"))?,
                    )
                    .map_err(|_| invalid("response-observed evidence"))?,
                    observed_at_millis,
                }
            }
            AttemptState::Resolved | AttemptState::Unknown
                if value.response_observed_evidence_digest.is_none()
                    && value.observed_at_millis.is_none()
                    && no_prestart_evidence =>
            {
                let start = start()?;
                let completed_at_millis = value
                    .completed_at_millis
                    .ok_or_else(|| invalid("completed time"))?;
                if completed_at_millis < start.started_at_millis {
                    return Err(invalid("completion ordering"));
                }
                if value.state == AttemptState::Resolved {
                    AttemptLifecycleV1::Resolved {
                        start,
                        completed_at_millis,
                    }
                } else {
                    AttemptLifecycleV1::Unknown {
                        start,
                        completed_at_millis,
                    }
                }
            }
            AttemptState::Failed
                if no_start
                    && value.completed_at_millis.is_some()
                    && value.no_bytes_sent_evidence_digest.is_some() =>
            {
                AttemptLifecycleV1::FailedPreStart {
                    completed_at_millis: value.completed_at_millis.expect("checked"),
                    no_bytes_sent_evidence_digest: EvidenceDigest::new(
                        value.no_bytes_sent_evidence_digest.expect("checked"),
                    )
                    .map_err(|_| invalid("no-bytes-sent evidence"))?,
                }
            }
            AttemptState::Failed
                if value.no_bytes_sent_evidence_digest.is_none()
                    && value.response_observed_evidence_digest.is_none()
                    && value.observed_at_millis.is_none() =>
            {
                let start = start()?;
                let completed_at_millis = value
                    .completed_at_millis
                    .ok_or_else(|| invalid("completed time"))?;
                if completed_at_millis < start.started_at_millis {
                    return Err(invalid("completion ordering"));
                }
                AttemptLifecycleV1::FailedAfterStart {
                    start,
                    completed_at_millis,
                }
            }
            _ => return Err(invalid("contradictory attempt lifecycle evidence")),
        };
        Ok(Self {
            identity,
            lifecycle,
        })
    }
}

impl TryFrom<AttemptResolutionDraftV2> for AttemptResolutionV2 {
    type Error = ProviderContractError;

    fn try_from(value: AttemptResolutionDraftV2) -> Result<Self, Self::Error> {
        validate_chain_anchor(&value.observed_anchor)?;
        let provider = provider_key(value.profile_digest, value.provider_instance_id)?;
        let capability_profile_digest =
            CapabilityProfileDigest::new(value.capability_profile_digest)
                .map_err(|_| invalid("capability profile"))?;
        let evidence_refs = evidence(value.evidence_refs)?;
        match value.truth {
            ResolutionTruth::Success | ResolutionTruth::AuthorizedEmpty => {
                if value.error_digest.is_some()
                    || value.recovery_eligibility != RecoveryEligibilityV1::None
                {
                    return Err(invalid("successful resolution error digest"));
                }
                let success = SuccessfulResolutionV2 {
                    normalized_response_digest: NormalizedResponseDigest::new(
                        value
                            .normalized_response_digest
                            .ok_or_else(|| invalid("normalized response digest"))?,
                    )
                    .map_err(|_| invalid("normalized response digest"))?,
                    response_digest: ResponseDigest::new(
                        value
                            .response_digest
                            .ok_or_else(|| invalid("response digest"))?,
                    )
                    .map_err(|_| invalid("response digest"))?,
                    status_digest: StatusDigest::new(
                        value
                            .status_digest
                            .ok_or_else(|| invalid("status digest"))?,
                    )
                    .map_err(|_| invalid("status digest"))?,
                    observed_anchor: value.observed_anchor,
                    capability_profile_digest,
                    provider,
                    evidence_refs,
                };
                if value.truth == ResolutionTruth::Success {
                    Ok(Self::Success(success))
                } else {
                    Ok(Self::AuthorizedEmpty(success))
                }
            }
            truth => {
                if value.normalized_response_digest.is_some() || value.response_digest.is_some() {
                    return Err(invalid("failure cannot claim normalized response"));
                }
                let failure = FailureResolutionV2 {
                    truth,
                    status_digest: value
                        .status_digest
                        .map(StatusDigest::new)
                        .transpose()
                        .map_err(|_| invalid("status digest"))?,
                    error_digest: ErrorDigest::new(
                        value.error_digest.ok_or_else(|| invalid("error digest"))?,
                    )
                    .map_err(|_| invalid("error digest"))?,
                    observed_anchor: value.observed_anchor,
                    capability_profile_digest,
                    provider,
                    recovery_eligibility: value.recovery_eligibility,
                    evidence_refs,
                };
                match truth {
                    ResolutionTruth::Unavailable
                    | ResolutionTruth::RateLimited
                    | ResolutionTruth::Timeout => Ok(Self::ReadFailure(failure)),
                    ResolutionTruth::Divergent
                    | ResolutionTruth::Invalid
                    | ResolutionTruth::WriteAmbiguity
                    | ResolutionTruth::Reorg
                    | ResolutionTruth::Partial
                    | ResolutionTruth::Denied => {
                        if value.recovery_eligibility != RecoveryEligibilityV1::None {
                            Err(invalid("terminal truth cannot be recoverable"))
                        } else {
                            Ok(Self::TerminalFailure(failure))
                        }
                    }
                    ResolutionTruth::Success | ResolutionTruth::AuthorizedEmpty => unreachable!(),
                }
            }
        }
    }
}

impl TryFrom<RouteAttemptDraftV1> for RouteAttemptV1 {
    type Error = ProviderContractError;

    fn try_from(value: RouteAttemptDraftV1) -> Result<Self, Self::Error> {
        let envelope = AttemptEnvelopeV1::try_from(value.envelope)?;
        let terminal = matches!(
            envelope.lifecycle,
            AttemptLifecycleV1::Resolved { .. }
                | AttemptLifecycleV1::Unknown { .. }
                | AttemptLifecycleV1::FailedPreStart { .. }
                | AttemptLifecycleV1::FailedAfterStart { .. }
        );
        let resolution = value
            .resolution
            .map(AttemptResolutionV2::try_from)
            .transpose()?;
        if terminal != resolution.is_some() {
            return Err(invalid(
                "terminal lifecycle requires exactly one resolution",
            ));
        }
        if let Some(resolution) = &resolution {
            match &envelope.lifecycle {
                AttemptLifecycleV1::Resolved { .. }
                    if matches!(
                        resolution.truth(),
                        ResolutionTruth::WriteAmbiguity | ResolutionTruth::Reorg
                    ) =>
                {
                    return Err(invalid("resolved lifecycle truth"));
                }
                AttemptLifecycleV1::Unknown { .. }
                    if !matches!(
                        resolution.truth(),
                        ResolutionTruth::WriteAmbiguity | ResolutionTruth::Reorg
                    ) =>
                {
                    return Err(invalid("unknown lifecycle truth"));
                }
                AttemptLifecycleV1::FailedPreStart { .. }
                | AttemptLifecycleV1::FailedAfterStart { .. }
                    if matches!(
                        resolution.truth(),
                        ResolutionTruth::Success | ResolutionTruth::AuthorizedEmpty
                    ) =>
                {
                    return Err(invalid("failed lifecycle truth"));
                }
                _ => {}
            }
        }
        match resolution {
            Some(resolution) => Ok(Self::Terminal(Box::new(TerminalRouteAttemptV1 {
                envelope,
                resolution,
            }))),
            None => Ok(Self::InFlight(Box::new(InFlightRouteAttemptV1 {
                envelope,
            }))),
        }
    }
}
