import type {
  PrivacyExplorerEvidenceDigestRecordV1,
  PrivacyExplorerResultV1,
} from '../contracts/privacy-explorer-adapter.js';
import { executionRegistry } from '../contracts/privacy-explorer-adapter.js';
import { createCompletionOwner } from './completion-owner.js';
import { createEvidenceLifecycleOwner } from './evidence.js';
import { createExecutionOwner } from './execution-owner.js';
import {
  createExecutionRepository,
  type ExecutionHandle,
  type ExecutionSnapshot,
} from './execution-repository.js';
import { canonicalSafeProblem, safeProblemForCondition, type SafeProblem } from './problems.js';
import { reducePrivacyExplorerTransition } from './reducer.js';
import {
  buildSafeProblemCandidate,
  buildSuppressedCandidate,
  requirePublicResponseCandidate,
  type PublicResponseCandidate,
} from './result-candidate.js';
import { requireGovernedProjectionBoundary, type GovernedProjectionBoundary } from './request.js';

type Application =
  | (typeof executionRegistry.lifecycleApplications)[number]
  | (typeof executionRegistry.conditionApplications)[number]
  | (typeof executionRegistry.cancellationApplications)[number]
  | (typeof executionRegistry.contributionApplications)[number];
export type ExecutionEventId = Application['eventId'];
export type OraclePayload = Readonly<{ candidate?: PublicResponseCandidate }>;
export type OracleResult = Readonly<{
  snapshot: ExecutionSnapshot;
  released?: PrivacyExplorerResultV1 | SafeProblem;
  problem?: SafeProblem;
  evidence?: PrivacyExplorerEvidenceDigestRecordV1;
}>;
export type PrivacyExplorerExecutionOracle = Readonly<{
  create(boundary: GovernedProjectionBoundary): ExecutionHandle;
  inspect(handle: ExecutionHandle): ExecutionSnapshot;
  apply(
    handle: ExecutionHandle,
    expectedRevision: number,
    eventId: ExecutionEventId,
    payload?: OraclePayload,
  ): OracleResult;
}>;

const applications = [
  ...executionRegistry.lifecycleApplications,
  ...executionRegistry.conditionApplications,
  ...executionRegistry.cancellationApplications,
  ...executionRegistry.contributionApplications,
] as const;

const conditionId = (row: Application) => {
  const disposition = row.disposition as Record<string, unknown>;
  return disposition.kind === 'CONDITION'
    ? (disposition.conditionDefinitionId as string)
    : undefined;
};

const cancellationOutcome = (eventId: string) => {
  if (eventId === 'CANCEL_BEFORE_DISPATCH') return 'CANCELLED_BEFORE_DISPATCH' as const;
  if (eventId === 'RECONCILE_NO_BYTES' || eventId === 'CANCEL_AFTER_NO_RAW_READY')
    return 'CANCELLED_AFTER_DISPATCH_NO_RAW' as const;
  if (
    eventId === 'CAPTURE_LATE_BYTES' ||
    eventId === 'CANCEL_AFTER_BYTES' ||
    eventId === 'CANCEL_AFTER_VALIDATION' ||
    eventId === 'CANCEL_AFTER_REDACTION' ||
    eventId === 'CANCEL_AFTER_OUTCOME_SELECTION' ||
    eventId === 'CANCEL_AFTER_DISPOSAL'
  )
    return 'CANCELLED_AFTER_RAW' as const;
  return undefined;
};

export const createPrivacyExplorerExecutionOracle = (): PrivacyExplorerExecutionOracle => {
  const repository = createExecutionRepository();
  const evidenceOwner = createEvidenceLifecycleOwner();
  const executionOwner = createExecutionOwner(repository, evidenceOwner);
  const completionOwner = createCompletionOwner(repository, evidenceOwner);
  const boundaries = new WeakMap<ExecutionHandle, GovernedProjectionBoundary>();

  return Object.freeze({
    create(boundary) {
      const admitted = requireGovernedProjectionBoundary(boundary);
      const handle = repository.create(admitted);
      boundaries.set(handle, admitted);
      return handle;
    },
    inspect(handle) {
      return repository.inspect(handle);
    },
    apply(handle, expectedRevision, eventId, payload = {}) {
      const before = repository.inspect(handle);
      const boundary = boundaries.get(handle);
      if (!boundary) throw new Error('unknown execution boundary');
      if (!Number.isSafeInteger(expectedRevision) || expectedRevision !== before.revision)
        throw new Error('stale execution revision');
      if (typeof eventId !== 'string') throw new Error('invalid execution event');
      if (!payload || typeof payload !== 'object' || Array.isArray(payload))
        throw new Error('invalid execution event payload');
      const payloadKeys = Reflect.ownKeys(payload);
      const payloadPrototype = Object.getPrototypeOf(payload);
      const candidateEvent =
        eventId.startsWith('SELECT_') || eventId === 'REGISTERED_SAFE_PROBLEM_RETURNED';
      if (
        (payloadPrototype !== Object.prototype && payloadPrototype !== null) ||
        payloadKeys.length > 1 ||
        payloadKeys.some((key) => key !== 'candidate') ||
        (payloadKeys.length === 1 && !candidateEvent)
      )
        throw new Error('invalid execution event payload');
      const candidateDescriptor = Object.getOwnPropertyDescriptor(payload, 'candidate');
      if (
        candidateDescriptor &&
        (!candidateDescriptor.enumerable || !('value' in candidateDescriptor))
      )
        throw new Error('invalid execution event payload');
      const suppliedCandidate = candidateDescriptor
        ? requirePublicResponseCandidate(candidateDescriptor.value)
        : undefined;
      const matches = applications.filter(
        (row) => row.fromStateId === before.state && row.eventId === eventId,
      );
      if (matches.length !== 1) throw new Error('undeclared execution event');
      const row = matches[0] as Application;
      const guardSatisfied =
        row.guardId === 'EXACT_SOURCE_STATE' ||
        (row.guardId === 'EXACT_REGISTERED_SAFE_PROBLEM' &&
          suppliedCandidate?.delivery === 'PENDING' &&
          canonicalSafeProblem(suppliedCandidate.response) !== undefined) ||
        row.guardId.startsWith('CLASSIFIED_AS_') ||
        (row.guardId === 'DELIVERY_PENDING' && before.delivery === 'PENDING') ||
        (row.guardId === 'DELIVERY_SUPPRESSED' && before.delivery === 'SUPPRESSED') ||
        (row.guardId === 'DISPATCH_STARTED_NO_BYTES' &&
          before.rawState === 'NEVER_CREATED' &&
          before.adapterEffectId === 'DISPATCH_STARTED') ||
        (row.guardId === 'RAW_OWNER_LIVE' && before.rawState === 'LIVE') ||
        (row.guardId === 'IMMUTABLE_RELEASE_EXISTS' && before.delivery === 'RELEASED') ||
        (row.guardId === 'IMMUTABLE_EVIDENCE_EXISTS' &&
          repository.evidence(handle) !== undefined) ||
        (row.guardId === 'IDENTITY_OCCURRENCE_DIGESTS_REVISION_AND_UNIQUENESS_MATCH' &&
          (before.rawState === 'NEVER_CREATED' || before.rawState === 'DISPOSED'));
      if (!guardSatisfied) throw new Error('execution event guard rejected');
      const rowConditionId = conditionId(row);
      const reducerInput = {
        state: before.state,
        operationId: row.operationId,
        eventId: row.eventId,
        guardId: row.guardId,
        ...(rowConditionId ? { conditionDefinitionId: rowConditionId } : {}),
      };
      // Evaluate the authoritative reducer before constructing any effect payload.
      const reduced = reducePrivacyExplorerTransition(reducerInput);
      let candidate = suppliedCandidate ?? repository.candidate(handle);
      let problem: SafeProblem | undefined;

      if (rowConditionId) {
        problem = safeProblemForCondition(rowConditionId);
        if (row.toStateId !== row.fromStateId)
          candidate = buildSafeProblemCandidate(boundary, problem);
      }
      const cancelled = cancellationOutcome(eventId);
      if (cancelled) candidate = buildSuppressedCandidate(boundary, cancelled);
      if (eventId.startsWith('SELECT_')) {
        if (!candidate || candidate.outcome !== row.retainedFactId)
          throw new Error('selected outcome candidate mismatch');
      }

      let rawPermit;
      if (reduced.rawStateEffectId === 'NEVER_CREATED_TO_LIVE')
        rawPermit = executionOwner.authorizeCapture(before);
      if (reduced.rawStateEffectId === 'LIVE_TO_DISPOSED')
        rawPermit = executionOwner.authorizeDisposal(before);

      let evidence: PrivacyExplorerEvidenceDigestRecordV1 | undefined;
      if (eventId === 'MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS') {
        if (!candidate) throw new Error('missing evidence candidate');
        const adapter = executionOwner.adapterContribution(before, candidate);
        const completion = completionOwner.contribution(before, candidate);
        const rawState = executionOwner.rawStateWitness(before, candidate);
        const assembled = evidenceOwner.assemble({
          adapter: [adapter],
          completion: [completion],
          rawState: [rawState],
        });
        if ('code' in assembled) throw new Error(assembled.code);
        evidence = assembled;
      }

      const snapshot = repository.transition(handle, expectedRevision, reducerInput, {
        ...(candidate ? { candidate } : {}),
        ...(evidence ? { evidence } : {}),
        ...(rawPermit ? { rawPermit } : {}),
      });
      if (eventId === 'RELEASE') {
        const released = repository.candidate(handle)?.response;
        if (!released) throw new Error('release produced no response');
        return Object.freeze({ snapshot, released });
      }
      return Object.freeze({
        snapshot,
        ...(problem ? { problem } : {}),
        ...(evidence ? { evidence } : {}),
      });
    },
  });
};
