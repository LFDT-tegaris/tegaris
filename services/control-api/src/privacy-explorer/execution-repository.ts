import type { PrivacyExplorerEvidenceDigestRecordV1 } from '../contracts/privacy-explorer-adapter.js';
import { executionRegistry } from '../contracts/privacy-explorer-adapter.js';
import { immutableJsonCopy } from './immutable.js';
import { sha256CanonicalJson } from './narrowing.js';
import { reducePrivacyExplorerTransition, type ReducerInput } from './reducer.js';
import {
  requirePublicResponseCandidate,
  type CandidateOutcome,
  type PublicResponseCandidate,
} from './result-candidate.js';
import { requireGovernedProjectionBoundary, type GovernedProjectionBoundary } from './request.js';

type ExecutionState = (typeof executionRegistry.states)[number];
type RawState = (typeof executionRegistry.rawStates)[number];
type DeliveryState = (typeof executionRegistry.deliveryStates)[number];
type RawTransitionEffect = 'NEVER_CREATED_TO_LIVE' | 'LIVE_TO_DISPOSED';

export type ExecutionHandle = Readonly<Record<never, never>>;
export type ExecutionSnapshot = Readonly<{
  occurrenceId: string;
  correlationId: string;
  requestDigest: string;
  profileDigest: string;
  queryDigest: string;
  state: ExecutionState;
  rawState: RawState;
  delivery: DeliveryState;
  revision: number;
  adapterEffectId: string;
  retainedFactId: string;
  outcome?: CandidateOutcome;
  resultDigest?: string;
  evidenceResultDigest?: string;
}>;
export type RawTransitionPermit = Readonly<Record<never, never>>;

type TransitionCommit = Readonly<{
  candidate?: PublicResponseCandidate;
  evidence?: PrivacyExplorerEvidenceDigestRecordV1;
  rawPermit?: RawTransitionPermit;
}>;

type StoredExecution = {
  boundary: GovernedProjectionBoundary;
  boundaryIdentityDigest: string;
  snapshot: ExecutionSnapshot;
  candidate?: PublicResponseCandidate;
  evidence?: PrivacyExplorerEvidenceDigestRecordV1;
};

export type ExecutionRepository = Readonly<{
  create(boundary: GovernedProjectionBoundary): ExecutionHandle;
  inspect(handle: ExecutionHandle): ExecutionSnapshot;
  candidate(handle: ExecutionHandle): PublicResponseCandidate | undefined;
  evidence(handle: ExecutionHandle): PrivacyExplorerEvidenceDigestRecordV1 | undefined;
  requireOwnedSnapshot(snapshot: ExecutionSnapshot): ExecutionSnapshot;
  issueRawPermit(snapshot: ExecutionSnapshot, effect: RawTransitionEffect): RawTransitionPermit;
  transition(
    handle: ExecutionHandle,
    expectedRevision: number,
    input: ReducerInput,
    commit?: TransitionCommit,
  ): ExecutionSnapshot;
}>;

const snapshotOwners = new WeakMap<ExecutionSnapshot, object>();

export const requireExecutionSnapshot = (value: unknown): ExecutionSnapshot => {
  if (!value || typeof value !== 'object' || !snapshotOwners.has(value as ExecutionSnapshot))
    throw new Error('unowned execution snapshot');
  return value as ExecutionSnapshot;
};

const sameCandidateIdentity = (snapshot: ExecutionSnapshot, candidate: PublicResponseCandidate) =>
  snapshot.occurrenceId === candidate.occurrenceId &&
  snapshot.correlationId === candidate.correlationId &&
  snapshot.requestDigest === candidate.requestDigest &&
  snapshot.profileDigest === candidate.profileDigest &&
  snapshot.queryDigest === candidate.queryDigest;

const nextRawState = (current: RawState, effect: string, permitValid: boolean): RawState => {
  switch (effect) {
    case 'UNCHANGED':
      return current;
    case 'NEVER_CREATED':
      if (current !== 'NEVER_CREATED') throw new Error('raw state relation rejected');
      return current;
    case 'NEVER_CREATED_TO_LIVE':
      if (current !== 'NEVER_CREATED' || !permitValid)
        throw new Error('raw capture authority rejected');
      return 'LIVE';
    case 'LIVE':
      if (current !== 'LIVE') throw new Error('raw state relation rejected');
      return current;
    case 'LIVE_TO_DISPOSED':
      if (current !== 'LIVE' || !permitValid) throw new Error('raw disposal authority rejected');
      return 'DISPOSED';
    case 'DISPOSED':
      if (current !== 'DISPOSED') throw new Error('raw state relation rejected');
      return current;
    case 'REQUIRES_NEVER_CREATED_OR_DISPOSED':
      if (current !== 'NEVER_CREATED' && current !== 'DISPOSED')
        throw new Error('safe raw state required');
      return current;
    default:
      throw new Error('unknown raw state effect');
  }
};

const nextDelivery = (current: DeliveryState, effect: string): DeliveryState => {
  switch (effect) {
    case 'UNCHANGED':
      return current;
    case 'SUPPRESSED':
      if (current === 'RELEASED') throw new Error('immutable delivery rejected');
      return 'SUPPRESSED';
    case 'RELEASED':
      if (current !== 'PENDING') throw new Error('delivery is not releasable');
      return 'RELEASED';
    default:
      throw new Error('unknown delivery effect');
  }
};

const immutableSnapshot = (value: ExecutionSnapshot, owner: object): ExecutionSnapshot => {
  const snapshot = immutableJsonCopy(value);
  snapshotOwners.set(snapshot, owner);
  return snapshot;
};

export const createExecutionRepository = (): ExecutionRepository => {
  const repositoryId = Object.freeze({});
  const handles = new WeakMap<ExecutionHandle, typeof repositoryId>();
  const executions = new WeakMap<ExecutionHandle, StoredExecution>();
  const occurrences = new Map<string, ExecutionHandle>();
  const permits = new WeakMap<
    RawTransitionPermit,
    Readonly<{ occurrenceId: string; revision: number; effect: RawTransitionEffect }>
  >();

  const requireStored = (handle: ExecutionHandle) => {
    if (handles.get(handle) !== repositoryId) throw new Error('unknown execution handle');
    const stored = executions.get(handle);
    if (!stored) throw new Error('unknown execution handle');
    return stored;
  };
  const requireOwnedSnapshot = (snapshot: ExecutionSnapshot) => {
    const admitted = requireExecutionSnapshot(snapshot);
    if (snapshotOwners.get(admitted) !== repositoryId)
      throw new Error('foreign execution snapshot');
    return admitted;
  };

  return Object.freeze({
    create(boundary) {
      const admitted = requireGovernedProjectionBoundary(boundary);
      const occurrenceId = admitted.request.occurrence.requestId;
      const boundaryIdentityDigest = sha256CanonicalJson({
        request: admitted.request,
        context: admitted.context,
        requestDigest: admitted.requestDigest,
      });
      const existing = occurrences.get(occurrenceId);
      if (existing) {
        const stored = requireStored(existing);
        if (stored.boundaryIdentityDigest === boundaryIdentityDigest) return existing;
        throw new Error('conflicting execution occurrence');
      }
      const handle = Object.freeze({});
      const snapshot = immutableSnapshot(
        {
          occurrenceId,
          correlationId: admitted.request.occurrence.correlationId,
          requestDigest: admitted.requestDigest,
          profileDigest: admitted.request.exportProfile.digest,
          queryDigest: admitted.request.queryDigest,
          state: executionRegistry.states[0],
          rawState: 'NEVER_CREATED',
          delivery: 'PENDING',
          revision: 0,
          adapterEffectId: 'NONE',
          retainedFactId: 'OPEN',
        },
        repositoryId,
      );
      handles.set(handle, repositoryId);
      executions.set(handle, { boundary: admitted, boundaryIdentityDigest, snapshot });
      occurrences.set(occurrenceId, handle);
      return handle;
    },
    inspect(handle) {
      return requireStored(handle).snapshot;
    },
    candidate(handle) {
      return requireStored(handle).candidate;
    },
    evidence(handle) {
      return requireStored(handle).evidence;
    },
    requireOwnedSnapshot,
    issueRawPermit(snapshot, effect) {
      const admitted = requireOwnedSnapshot(snapshot);
      if (
        (effect === 'NEVER_CREATED_TO_LIVE' && admitted.rawState !== 'NEVER_CREATED') ||
        (effect === 'LIVE_TO_DISPOSED' && admitted.rawState !== 'LIVE')
      )
        throw new Error('raw transition source rejected');
      const permit = Object.freeze({});
      permits.set(permit, {
        occurrenceId: admitted.occurrenceId,
        revision: admitted.revision,
        effect,
      });
      return permit;
    },
    transition(handle, expectedRevision, input, commit = {}) {
      const stored = requireStored(handle);
      const current = stored.snapshot;
      if (!Number.isSafeInteger(expectedRevision) || expectedRevision !== current.revision)
        throw new Error('stale execution revision');
      if (input.state !== current.state) throw new Error('caller-selected source state rejected');
      const reduced = reducePrivacyExplorerTransition(input);
      const permitFacts = commit.rawPermit ? permits.get(commit.rawPermit) : undefined;
      const permitValid =
        permitFacts?.occurrenceId === current.occurrenceId &&
        permitFacts.revision === current.revision &&
        permitFacts.effect === reduced.rawStateEffectId;
      const rawState = nextRawState(current.rawState, reduced.rawStateEffectId, permitValid);
      const delivery = nextDelivery(current.delivery, reduced.deliveryEffectId);
      const candidate = commit.candidate
        ? requirePublicResponseCandidate(commit.candidate)
        : stored.candidate;
      if (candidate && !sameCandidateIdentity(current, candidate))
        throw new Error('cross-occurrence candidate rejected');
      if (reduced.state === 'RELEASED') {
        if (!candidate || candidate.delivery !== 'PENDING' || candidate.response === null)
          throw new Error('missing releasable response candidate');
      }
      if (
        reduced.state === 'CANCELLED_CLOSED' &&
        (!candidate || candidate.delivery !== 'SUPPRESSED')
      )
        throw new Error('missing suppressed response candidate');
      if (reduced.state === 'EVIDENCE_SEALED' && !commit.evidence && !stored.evidence)
        throw new Error('missing evidence result');
      const noEffect =
        reduced.state === current.state &&
        reduced.rawStateEffectId !== 'NEVER_CREATED_TO_LIVE' &&
        reduced.rawStateEffectId !== 'LIVE_TO_DISPOSED' &&
        rawState === current.rawState &&
        delivery === current.delivery &&
        reduced.adapterEffectId === 'NONE';
      if (noEffect) return current;

      const next = immutableSnapshot(
        {
          occurrenceId: current.occurrenceId,
          correlationId: current.correlationId,
          requestDigest: current.requestDigest,
          profileDigest: current.profileDigest,
          queryDigest: current.queryDigest,
          state: reduced.state as ExecutionState,
          rawState,
          delivery,
          revision: current.revision + 1,
          adapterEffectId: reduced.adapterEffectId,
          retainedFactId: reduced.retainedFactId,
          ...(candidate
            ? { outcome: candidate.outcome, resultDigest: candidate.resultDigest }
            : {}),
          ...(commit.evidence ? { evidenceResultDigest: commit.evidence.resultDigest } : {}),
        },
        repositoryId,
      );
      if (commit.rawPermit) permits.delete(commit.rawPermit);
      executions.set(handle, {
        boundary: stored.boundary,
        boundaryIdentityDigest: stored.boundaryIdentityDigest,
        snapshot: next,
        ...(candidate ? { candidate } : {}),
        ...(commit.evidence
          ? { evidence: commit.evidence }
          : stored.evidence
            ? { evidence: stored.evidence }
            : {}),
      });
      return next;
    },
  });
};
