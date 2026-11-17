use super::*;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum DerivedTerminalRouteState {
    Selected {
        truth: ResolutionTruth,
        digest: NormalizedResponseDigest,
        agreement_attempt_ids: Vec<AttemptId>,
    },
    Divergent {
        evidence_refs: Vec<EvidenceDigest>,
    },
    Partial {
        evidence_refs: Vec<EvidenceDigest>,
    },
    Failed {
        truth: ResolutionTruth,
        evidence_refs: Vec<EvidenceDigest>,
    },
}

#[derive(Debug)]
struct TimelySuccessGroup {
    truth: ResolutionTruth,
    digest: NormalizedResponseDigest,
    attempt_ids: Vec<AttemptId>,
    providers: BTreeSet<ProviderKeyV1>,
    evidence_refs: Vec<EvidenceDigest>,
}

pub(super) struct ReadTemporalEvaluation {
    pub(super) terminal_state: DerivedTerminalRouteState,
}

pub(super) struct ReadTemporalPolicy<'a> {
    request_deadline_millis: u64,
    attempts: &'a [RouteAttemptV1],
    attempts_by_id: &'a BTreeMap<AttemptId, &'a RouteAttemptV1>,
}

pub(crate) fn derive_terminal_outcome_draft(
    request: &RouteRequestV1,
    route_plan: &RoutePlanV1,
    attempt_drafts: &[RouteAttemptDraftV1],
    primary_values: &[String],
    hedge_values: &[String],
) -> Result<RouteOutcomeDraftV1, ProviderContractError> {
    let attempts = attempt_drafts
        .iter()
        .cloned()
        .map(super::witness::close_terminal_attempt)
        .collect::<Result<Vec<_>, _>>()?;
    let mut attempts_by_id = BTreeMap::new();
    for attempt in &attempts {
        if attempts_by_id
            .insert(attempt.envelope().identity.attempt_id.clone(), attempt)
            .is_some()
        {
            return Err(invalid("duplicate attempt id"));
        }
    }
    let primary_ids = super::read::typed_attempt_ids(
        primary_values.to_vec(),
        &attempts_by_id,
        "primary ownership",
    )?;
    let hedge_ids =
        super::read::typed_attempt_ids(hedge_values.to_vec(), &attempts_by_id, "hedge ownership")?;
    let policy = ReadTemporalPolicy {
        request_deadline_millis: request.request_deadline_millis,
        attempts: &attempts,
        attempts_by_id: &attempts_by_id,
    };
    let state = policy
        .evaluate(route_plan, &primary_ids, &hedge_ids)?
        .terminal_state;
    Ok(match state {
        DerivedTerminalRouteState::Selected {
            truth,
            digest,
            agreement_attempt_ids,
        } => RouteOutcomeDraftV1::Selected {
            truth,
            selected_result_digest: digest.as_str().to_owned(),
            agreement_attempt_ids: agreement_attempt_ids
                .into_iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
        },
        DerivedTerminalRouteState::Divergent { evidence_refs } => RouteOutcomeDraftV1::Divergent {
            evidence_refs: evidence_refs
                .into_iter()
                .map(|digest| digest.as_str().to_owned())
                .collect(),
        },
        DerivedTerminalRouteState::Partial { evidence_refs } => RouteOutcomeDraftV1::Partial {
            evidence_refs: evidence_refs
                .into_iter()
                .map(|digest| digest.as_str().to_owned())
                .collect(),
        },
        DerivedTerminalRouteState::Failed {
            truth,
            evidence_refs,
        } => RouteOutcomeDraftV1::Failed {
            truth,
            evidence_refs: evidence_refs
                .into_iter()
                .map(|digest| digest.as_str().to_owned())
                .collect(),
        },
    })
}

impl<'a> ReadTemporalPolicy<'a> {
    pub(super) fn new(context: &'a WitnessValidationContext<'a>) -> Self {
        Self {
            request_deadline_millis: context.request.request_deadline_millis,
            attempts: context.attempts,
            attempts_by_id: context.attempts_by_id,
        }
    }

    pub(super) fn evaluate(
        &self,
        route_plan: &RoutePlanV1,
        primary_ids: &[AttemptId],
        hedge_ids: &[AttemptId],
    ) -> Result<ReadTemporalEvaluation, ProviderContractError> {
        if self.attempts.is_empty() {
            return Err(invalid("empty attempt set"));
        }
        self.validate_hedge_admission(route_plan, primary_ids, hedge_ids)?;

        let mut timely_groups: Vec<TimelySuccessGroup> = Vec::new();
        let mut late_valid_result = false;
        let mut terminal_failures = Vec::new();
        let mut all_terminal_evidence = Vec::new();
        for attempt in self.attempts {
            let resolution = attempt
                .resolution()
                .ok_or_else(|| invalid("terminal outcome with nonterminal attempt"))?;
            extend_unique_evidence(&mut all_terminal_evidence, resolution.evidence_refs());
            if let Some(digest) = resolution.normalized_response_digest() {
                let completed = terminal_completion(attempt)
                    .ok_or_else(|| invalid("valid read result requires terminal completion"))?;
                if completed > self.effective_deadline(attempt) {
                    late_valid_result = true;
                    continue;
                }
                let truth = resolution.truth();
                if let Some(group) = timely_groups
                    .iter_mut()
                    .find(|group| group.truth == truth && &group.digest == digest)
                {
                    if !group
                        .providers
                        .insert(attempt.envelope().identity.provider.clone())
                    {
                        return Err(invalid("duplicate provider success support"));
                    }
                    group
                        .attempt_ids
                        .push(attempt.envelope().identity.attempt_id.clone());
                    extend_unique_evidence(&mut group.evidence_refs, resolution.evidence_refs());
                } else {
                    timely_groups.push(TimelySuccessGroup {
                        truth,
                        digest: digest.clone(),
                        attempt_ids: vec![attempt.envelope().identity.attempt_id.clone()],
                        providers: BTreeSet::from([attempt.envelope().identity.provider.clone()]),
                        evidence_refs: resolution.evidence_refs().to_vec(),
                    });
                }
            } else {
                let completed = terminal_completion(attempt)
                    .ok_or_else(|| invalid("terminal failure completion"))?;
                terminal_failures.push((
                    completed,
                    attempt.envelope().identity.ordinal,
                    resolution.truth(),
                ));
            }
        }

        let terminal_state = self.derive_terminal_state(
            route_plan,
            timely_groups,
            late_valid_result,
            terminal_failures,
            all_terminal_evidence,
        )?;
        Ok(ReadTemporalEvaluation { terminal_state })
    }

    pub(super) fn validate_recovery_transition(
        &self,
        prior: &RouteAttemptV1,
        next: &RouteAttemptV1,
    ) -> Result<(), ProviderContractError> {
        let prior_completed = terminal_completion(prior)
            .ok_or_else(|| invalid("recovery prior terminal completion"))?;
        let next_started = lifecycle_start_millis(next.envelope().lifecycle())
            .ok_or_else(|| invalid("recovery next start evidence"))?;
        if next_started <= prior_completed || next_started >= self.effective_deadline(next) {
            return Err(invalid("recovery temporal policy"));
        }
        Ok(())
    }

    fn effective_deadline(&self, attempt: &RouteAttemptV1) -> u64 {
        attempt
            .envelope()
            .identity
            .deadline_millis
            .min(self.request_deadline_millis)
    }

    fn derive_terminal_state(
        &self,
        route_plan: &RoutePlanV1,
        mut timely_groups: Vec<TimelySuccessGroup>,
        late_valid_result: bool,
        terminal_failures: Vec<(u64, u8, ResolutionTruth)>,
        all_terminal_evidence: Vec<EvidenceDigest>,
    ) -> Result<DerivedTerminalRouteState, ProviderContractError> {
        if timely_groups.is_empty() {
            if late_valid_result
                && matches!(
                    route_plan,
                    RoutePlanV1::QuorumIdentical { .. } | RoutePlanV1::HedgedQuorumIdentical { .. }
                )
            {
                return Ok(DerivedTerminalRouteState::Partial {
                    evidence_refs: all_terminal_evidence,
                });
            }
            if let Some((_, _, truth)) = terminal_failures
                .iter()
                .min_by_key(|(completed, ordinal, _)| (*completed, *ordinal))
                .copied()
                .filter(|(_, _, truth)| {
                    !matches!(truth, ResolutionTruth::Divergent | ResolutionTruth::Partial)
                })
            {
                return Ok(DerivedTerminalRouteState::Failed {
                    truth,
                    evidence_refs: all_terminal_evidence,
                });
            }
            if terminal_failures.is_empty() {
                if matches!(
                    route_plan,
                    RoutePlanV1::QuorumIdentical { .. } | RoutePlanV1::HedgedQuorumIdentical { .. }
                ) {
                    return Ok(DerivedTerminalRouteState::Partial {
                        evidence_refs: all_terminal_evidence,
                    });
                }
                return Ok(DerivedTerminalRouteState::Failed {
                    truth: ResolutionTruth::Timeout,
                    evidence_refs: all_terminal_evidence,
                });
            }
            return Ok(DerivedTerminalRouteState::Failed {
                truth: terminal_failures
                    .iter()
                    .min_by_key(|(completed, ordinal, _)| (*completed, *ordinal))
                    .map(|(_, _, truth)| *truth)
                    .expect("nonempty terminal failures"),
                evidence_refs: all_terminal_evidence,
            });
        }

        match route_plan {
            RoutePlanV1::HedgedSingle { .. } => {
                if self.earliest_timely_result_conflicts()? {
                    return Ok(DerivedTerminalRouteState::Divergent {
                        evidence_refs: all_terminal_evidence,
                    });
                }
                let (truth, digest, attempt_id) = self.unique_earliest_timely_result()?;
                Ok(DerivedTerminalRouteState::Selected {
                    truth,
                    digest,
                    agreement_attempt_ids: vec![attempt_id],
                })
            }
            RoutePlanV1::SingleExact => {
                if timely_groups.len() != 1 {
                    return Err(invalid("contradictory single-exact results"));
                }
                let group = timely_groups.pop().expect("one group checked");
                Ok(DerivedTerminalRouteState::Selected {
                    truth: group.truth,
                    digest: group.digest,
                    agreement_attempt_ids: group.attempt_ids,
                })
            }
            RoutePlanV1::QuorumIdentical { .. } | RoutePlanV1::HedgedQuorumIdentical { .. } => {
                let threshold = route_plan.required_agreement();
                let winners = timely_groups
                    .iter()
                    .filter(|group| group.attempt_ids.len() >= threshold)
                    .collect::<Vec<_>>();
                if winners.len() > 1 {
                    let mut evidence_refs = Vec::new();
                    for group in &timely_groups {
                        extend_unique_evidence(&mut evidence_refs, &group.evidence_refs);
                    }
                    return Ok(DerivedTerminalRouteState::Divergent { evidence_refs });
                }
                if let Some(group) = winners.first() {
                    return Ok(DerivedTerminalRouteState::Selected {
                        truth: group.truth,
                        digest: group.digest.clone(),
                        agreement_attempt_ids: group.attempt_ids.clone(),
                    });
                }
                if timely_groups.len() >= 2 {
                    let mut evidence_refs = Vec::new();
                    for group in &timely_groups {
                        extend_unique_evidence(&mut evidence_refs, &group.evidence_refs);
                    }
                    return Ok(DerivedTerminalRouteState::Divergent { evidence_refs });
                }
                Ok(DerivedTerminalRouteState::Partial {
                    evidence_refs: all_terminal_evidence,
                })
            }
        }
    }

    fn unique_earliest_timely_result(
        &self,
    ) -> Result<(ResolutionTruth, NormalizedResponseDigest, AttemptId), ProviderContractError> {
        let mut winner: Option<(
            u64,
            u8,
            ResolutionTruth,
            NormalizedResponseDigest,
            AttemptId,
        )> = None;
        for attempt in self.attempts {
            let Some(resolution) = attempt.resolution() else {
                continue;
            };
            let Some(digest) = resolution.normalized_response_digest() else {
                continue;
            };
            let completed = terminal_completion(attempt)
                .ok_or_else(|| invalid("valid hedge result requires resolved completion"))?;
            if completed > self.effective_deadline(attempt) {
                continue;
            }
            let candidate = (
                completed,
                attempt.envelope().identity.ordinal,
                resolution.truth(),
                digest.clone(),
                attempt.envelope().identity.attempt_id.clone(),
            );
            match &winner {
                Some((earliest, ordinal, ..))
                    if (completed, attempt.envelope().identity.ordinal)
                        >= (*earliest, *ordinal) => {}
                _ => winner = Some(candidate),
            }
        }
        winner
            .map(|(_, _, truth, digest, attempt_id)| (truth, digest, attempt_id))
            .ok_or_else(|| invalid("hedged selection support"))
    }

    fn earliest_timely_result_conflicts(&self) -> Result<bool, ProviderContractError> {
        let earliest_completion = self
            .attempts
            .iter()
            .filter_map(|attempt| {
                let resolution = attempt.resolution()?;
                resolution.normalized_response_digest()?;
                let completed = terminal_completion(attempt)?;
                (completed <= self.effective_deadline(attempt)).then_some(completed)
            })
            .min()
            .ok_or_else(|| invalid("hedged selection support"))?;
        let mut identity: Option<(ResolutionTruth, NormalizedResponseDigest)> = None;
        for attempt in self.attempts {
            let Some(resolution) = attempt.resolution() else {
                continue;
            };
            let Some(digest) = resolution.normalized_response_digest() else {
                continue;
            };
            if terminal_completion(attempt) != Some(earliest_completion)
                || earliest_completion > self.effective_deadline(attempt)
            {
                continue;
            }
            let candidate = (resolution.truth(), digest.clone());
            if identity.as_ref().is_some_and(|value| value != &candidate) {
                return Ok(true);
            }
            identity.get_or_insert(candidate);
        }
        Ok(false)
    }

    fn validate_hedge_admission(
        &self,
        route_plan: &RoutePlanV1,
        primary_ids: &[AttemptId],
        hedge_ids: &[AttemptId],
    ) -> Result<(), ProviderContractError> {
        let (threshold, agreement, max_hedges) = match route_plan {
            RoutePlanV1::HedgedSingle {
                hedge_threshold_millis,
            } => (*hedge_threshold_millis, 1, 1),
            RoutePlanV1::HedgedQuorumIdentical {
                required_agreement,
                hedge_threshold_millis,
                max_hedge_attempts,
            } => (
                *hedge_threshold_millis,
                usize::from(*required_agreement),
                usize::from(*max_hedge_attempts),
            ),
            RoutePlanV1::SingleExact | RoutePlanV1::QuorumIdentical { .. } => {
                return if hedge_ids.is_empty() {
                    Ok(())
                } else {
                    Err(invalid("hedge attempts on non-hedged route"))
                };
            }
        };
        if primary_ids.is_empty() || hedge_ids.len() > max_hedges {
            return Err(invalid("bounded hedge ownership"));
        }
        if hedge_ids.is_empty() {
            return Ok(());
        }
        let primary_start = primary_ids
            .iter()
            .filter_map(|id| lifecycle_start_millis(self.attempts_by_id[id].envelope().lifecycle()))
            .min()
            .ok_or_else(|| invalid("hedge requires primary start evidence"))?;
        let qualified_at = primary_start
            .checked_add(threshold)
            .ok_or_else(|| invalid("hedge qualification overflow"))?;
        for (hedge_index, hedge_id) in hedge_ids.iter().enumerate() {
            let hedge = self.attempts_by_id[hedge_id];
            let hedge_time = lifecycle_start_millis(hedge.envelope().lifecycle())
                .or_else(|| terminal_completion(hedge))
                .ok_or_else(|| invalid("hedge timing evidence"))?;
            if hedge_time < qualified_at || hedge_time > self.effective_deadline(hedge) {
                return Err(invalid("hedge threshold or deadline"));
            }
            let prior_ids = primary_ids.iter().chain(hedge_ids[..hedge_index].iter());
            if self.has_timely_agreement_before(prior_ids, agreement, hedge_time)? {
                return Err(invalid("hedge started after canonical result"));
            }
        }
        Ok(())
    }

    fn has_timely_agreement_before<'b>(
        &self,
        attempt_ids: impl Iterator<Item = &'b AttemptId>,
        agreement: usize,
        boundary: u64,
    ) -> Result<bool, ProviderContractError> {
        let mut groups: Vec<(ResolutionTruth, NormalizedResponseDigest, usize)> = Vec::new();
        for id in attempt_ids {
            let attempt = self.attempts_by_id[id];
            let Some(resolution) = attempt.resolution() else {
                continue;
            };
            let Some(digest) = resolution.normalized_response_digest() else {
                continue;
            };
            let completed = terminal_completion(attempt)
                .ok_or_else(|| invalid("canonical result completion"))?;
            if completed > boundary || completed > self.effective_deadline(attempt) {
                continue;
            }
            if let Some((_, _, count)) = groups.iter_mut().find(|(truth, group_digest, _)| {
                *truth == resolution.truth() && group_digest == digest
            }) {
                *count += 1;
            } else {
                groups.push((resolution.truth(), digest.clone(), 1));
            }
        }
        Ok(groups.iter().any(|(_, _, count)| *count >= agreement))
    }
}

fn extend_unique_evidence(target: &mut Vec<EvidenceDigest>, source: &[EvidenceDigest]) {
    for item in source {
        if !target.contains(item) {
            target.push(item.clone());
        }
    }
}
