import {
  assertPrivacyExplorerEvidence,
  type PrivacyExplorerEvidenceDigestRecordV1,
} from '../contracts/privacy-explorer-adapter.js';
import { immutableJsonCopy } from './immutable.js';
import { safeProblemForCondition, type SafeProblem } from './problems.js';
import {
  requirePublicResponseCandidate,
  type CandidateDelivery,
  type CandidateOutcome,
  type PublicResponseCandidate,
} from './result-candidate.js';

type EvidenceIdentity = Readonly<{
  occurrenceId: string;
  correlationId: string;
  requestDigest: string;
  profileDigest: string;
  queryDigest: string;
  authorizationDigest: string;
  contextDigest: string;
  scopeDigest: string;
  responseDigest: string;
  validationDigest: string;
  redactionDigest: string;
  resultDigest: string;
  outcome: CandidateOutcome;
  truthState: string;
  delivery: CandidateDelivery;
}>;
export type AdapterContribution = Readonly<EvidenceIdentity & { revision: number }>;
export type CompletionContribution = Readonly<EvidenceIdentity & { revision: number }>;
export type RawStateWitness = Readonly<{
  occurrenceId: string;
  correlationId: string;
  rawState: 'NEVER_CREATED' | 'DISPOSED';
  revision: number;
}>;
export type EvidenceAssembly = Readonly<{
  adapter: readonly AdapterContribution[];
  completion: readonly CompletionContribution[];
  rawState: readonly RawStateWitness[];
}>;

export type EvidenceLifecycleOwner = Readonly<{
  adapterContribution(candidate: PublicResponseCandidate, revision: number): AdapterContribution;
  completionContribution(
    candidate: PublicResponseCandidate,
    revision: number,
  ): CompletionContribution;
  rawStateWitness(
    candidate: PublicResponseCandidate,
    rawState: 'NEVER_CREATED' | 'DISPOSED',
    revision: number,
  ): RawStateWitness;
  assemble(input: EvidenceAssembly): PrivacyExplorerEvidenceDigestRecordV1 | SafeProblem;
}>;

const integerRevision = (revision: number) => {
  if (!Number.isSafeInteger(revision) || revision < 0) throw new Error('invalid evidence revision');
  return revision;
};
const identityFrom = (candidate: PublicResponseCandidate): EvidenceIdentity => {
  const admitted = requirePublicResponseCandidate(candidate);
  return immutableJsonCopy({
    occurrenceId: admitted.occurrenceId,
    correlationId: admitted.correlationId,
    requestDigest: admitted.requestDigest,
    profileDigest: admitted.profileDigest,
    queryDigest: admitted.queryDigest,
    authorizationDigest: admitted.authorizationDigest,
    contextDigest: admitted.contextDigest,
    scopeDigest: admitted.scopeDigest,
    responseDigest: admitted.responseDigest,
    validationDigest: admitted.validationDigest,
    redactionDigest: admitted.redactionDigest,
    resultDigest: admitted.resultDigest,
    outcome: admitted.outcome,
    truthState: admitted.truthState,
    delivery: admitted.delivery,
  });
};
const sameIdentity = (left: EvidenceIdentity, right: EvidenceIdentity) =>
  left.occurrenceId === right.occurrenceId &&
  left.correlationId === right.correlationId &&
  left.requestDigest === right.requestDigest &&
  left.profileDigest === right.profileDigest &&
  left.queryDigest === right.queryDigest &&
  left.authorizationDigest === right.authorizationDigest &&
  left.contextDigest === right.contextDigest &&
  left.scopeDigest === right.scopeDigest &&
  left.responseDigest === right.responseDigest &&
  left.validationDigest === right.validationDigest &&
  left.redactionDigest === right.redactionDigest &&
  left.resultDigest === right.resultDigest &&
  left.outcome === right.outcome &&
  left.truthState === right.truthState &&
  left.delivery === right.delivery;

export const createEvidenceLifecycleOwner = (): EvidenceLifecycleOwner => {
  const adapterOwners = new WeakSet<AdapterContribution>();
  const completionOwners = new WeakSet<CompletionContribution>();
  const rawOwners = new WeakSet<RawStateWitness>();
  const sealedOccurrences = new Map<string, string>();

  const owner: EvidenceLifecycleOwner = Object.freeze({
    adapterContribution(candidate, revision) {
      const contribution = immutableJsonCopy({
        ...identityFrom(candidate),
        revision: integerRevision(revision),
      });
      adapterOwners.add(contribution);
      return contribution;
    },
    completionContribution(candidate, revision) {
      const contribution = immutableJsonCopy({
        ...identityFrom(candidate),
        revision: integerRevision(revision),
      });
      completionOwners.add(contribution);
      return contribution;
    },
    rawStateWitness(candidate, rawState, revision) {
      const admitted = requirePublicResponseCandidate(candidate);
      if (rawState !== 'NEVER_CREATED' && rawState !== 'DISPOSED')
        throw new Error('unproven raw state');
      const witness = immutableJsonCopy({
        occurrenceId: admitted.occurrenceId,
        correlationId: admitted.correlationId,
        rawState,
        revision: integerRevision(revision),
      });
      rawOwners.add(witness);
      return witness;
    },
    assemble(input) {
      if (
        input.adapter.length === 0 ||
        input.completion.length === 0 ||
        input.rawState.length === 0
      )
        return safeProblemForCondition('EXP-EVIDENCE');
      if (
        input.adapter.length !== 1 ||
        input.completion.length !== 1 ||
        input.rawState.length !== 1
      )
        return safeProblemForCondition('EXP-REPLAY');
      const adapter = input.adapter[0]!;
      const completion = input.completion[0]!;
      const raw = input.rawState[0]!;
      if (
        !adapterOwners.has(adapter) ||
        !completionOwners.has(completion) ||
        !rawOwners.has(raw) ||
        !sameIdentity(adapter, completion) ||
        raw.occurrenceId !== adapter.occurrenceId ||
        raw.correlationId !== adapter.correlationId ||
        completion.revision !== adapter.revision + 1 ||
        raw.revision !== completion.revision + 1
      )
        return safeProblemForCondition('EXP-EVIDENCE');
      const replayKey = `${adapter.occurrenceId}\u0000${adapter.resultDigest}`;
      const prior = sealedOccurrences.get(adapter.occurrenceId);
      if (prior !== undefined) return safeProblemForCondition('EXP-REPLAY');
      const record = assertPrivacyExplorerEvidence(
        immutableJsonCopy({
          occurrenceId: adapter.occurrenceId,
          correlationId: adapter.correlationId,
          authorizationDigest: adapter.authorizationDigest,
          contextDigest: adapter.contextDigest,
          scopeDigest: adapter.scopeDigest,
          requestDigest: adapter.requestDigest,
          profileDigest: adapter.profileDigest,
          queryDigest: adapter.queryDigest,
          responseDigest: adapter.responseDigest,
          validationDigest: adapter.validationDigest,
          redactionDigest: adapter.redactionDigest,
          outcome: adapter.outcome,
          resultDigest: adapter.resultDigest,
          rawState: raw.rawState,
        }),
      );
      sealedOccurrences.set(adapter.occurrenceId, replayKey);
      return record;
    },
  });
  return owner;
};
