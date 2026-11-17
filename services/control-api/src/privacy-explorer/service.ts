import type {
  PrivacyExplorerEvidenceDigestRecordV1,
  PrivacyExplorerResultV1,
} from '../contracts/privacy-explorer-adapter.js';
import {
  readGovernedProjection,
  requireGovernedProjectionConsumer,
  type GovernedProjectionConsumerPort,
} from './consumer-port.js';
import {
  createPersistedExecutionOracle,
  type ExecutionPersistence,
} from './execution-persistence.js';
import type { ExecutionHandle } from './execution-repository.js';
import type { NarrowingInput } from './narrowing.js';
import { narrowIntent } from './narrowing.js';
import { canonicalSafeProblem, type SafeProblem } from './problems.js';
import { type RegisteredPurposeAction, preauthorize } from './preauthorization.js';
import type { RegisteredExplorerProfile } from './profile-registration.js';
import { redactProjection, type RedactedProjection } from './redaction.js';
import { buildProjectionCandidate, buildSafeProblemCandidate } from './result-candidate.js';
import {
  createProjectionRequest,
  type CallContextSeed,
  type GovernedProjectionBoundary,
} from './request.js';
import {
  requireValidatedProjection,
  validateProjection,
  type ValidatedProjection,
  assertContinuationBoundary,
  bindValidatedContinuation,
} from './validation.js';
import type { PrivacyExplorerLocalContext } from './context.js';

export type PrivacyExplorerReadInput = Readonly<{
  context: PrivacyExplorerLocalContext;
  purposeAction: RegisteredPurposeAction;
  profile: RegisteredExplorerProfile;
  query: NarrowingInput;
  seed: CallContextSeed;
  signal?: AbortSignal;
}>;

export type PrivacyExplorerReadResult =
  | Readonly<{
      disposition: 'RELEASED';
      response: PrivacyExplorerResultV1 | SafeProblem;
      evidence: PrivacyExplorerEvidenceDigestRecordV1;
    }>
  | Readonly<{
      disposition: 'SUPPRESSED';
      response?: never;
      evidence: PrivacyExplorerEvidenceDigestRecordV1;
    }>;

export type PrivacyExplorerService = Readonly<{
  read(input: PrivacyExplorerReadInput): Promise<PrivacyExplorerReadResult>;
}>;

export type PrivacyExplorerAuthenticReadResultFacts = Readonly<{
  disposition: PrivacyExplorerReadResult['disposition'];
  response?: PrivacyExplorerResultV1 | SafeProblem;
  evidence: PrivacyExplorerEvidenceDigestRecordV1;
}>;
const authenticReadResults = new WeakMap<
  PrivacyExplorerReadResult,
  PrivacyExplorerAuthenticReadResultFacts
>();

export const requirePrivacyExplorerAuthenticReadResult = (value: PrivacyExplorerReadResult) => {
  const facts = authenticReadResults.get(value);
  if (!facts) throw new Error('unauthentic Privacy Explorer service result');
  const keys = Reflect.ownKeys(value);
  const expected =
    facts.disposition === 'RELEASED'
      ? ['disposition', 'response', 'evidence']
      : ['disposition', 'evidence'];
  if (
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) ||
    keys.length !== expected.length ||
    expected.some((key) => !keys.includes(key)) ||
    keys.some((key) => typeof key !== 'string') ||
    expected.some((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return !descriptor || !descriptor.enumerable || !('value' in descriptor);
    }) ||
    value.disposition !== facts.disposition ||
    value.evidence !== facts.evidence ||
    (facts.disposition === 'RELEASED' && value.response !== facts.response)
  )
    throw new Error('tampered Privacy Explorer service result');
  return facts;
};

type SettledRead =
  | Readonly<{ kind: 'VALUE'; value: unknown | SafeProblem }>
  | Readonly<{ kind: 'NO_BYTES' }>
  | Readonly<{ kind: 'DEADLINE' }>
  | Readonly<{ kind: 'CANCELLED' }>;

const requireReadInput = (value: PrivacyExplorerReadInput): PrivacyExplorerReadInput => {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('invalid Privacy Explorer service input');
  const prototype = Object.getPrototypeOf(value);
  const keys = Reflect.ownKeys(value);
  const required = ['context', 'purposeAction', 'profile', 'query', 'seed'] as const;
  const allowed: readonly PropertyKey[] = [...required, 'signal'];
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length < required.length ||
    keys.length > required.length + 1 ||
    required.some((key) => !keys.includes(key)) ||
    keys.some((key) => typeof key !== 'string' || !allowed.includes(key))
  )
    throw new Error('invalid Privacy Explorer service input');
  const admitted = {} as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor))
      throw new Error('invalid Privacy Explorer service input');
    admitted[key as string] = descriptor.value;
  }
  if (Object.hasOwn(admitted, 'signal') && !(admitted.signal instanceof AbortSignal))
    throw new Error('invalid Privacy Explorer cancellation signal');
  return Object.freeze(admitted) as PrivacyExplorerReadInput;
};

const rawProblemEvent = (problem: SafeProblem) => {
  switch (problem.code) {
    case 'PC-OPS-9004':
      return 'ORDER_PARTIAL' as const;
    case 'PC-FACT-4001':
      return 'ABSENCE_WITHOUT_COMPLETE_PROOF' as const;
    case 'PC-FACT-4002':
      return 'STALE_OBSERVATION' as const;
    case 'PC-FACT-4003':
      return 'REORG_OBSERVATION' as const;
    case 'PC-RUNTIME-3011':
      return 'CONFLICTING_OBSERVATIONS' as const;
    default:
      return 'RESPONSE_SCHEMA_INVALID' as const;
  }
};

const settleWithinControl = async (
  invocation: () => Promise<unknown | SafeProblem>,
  deadlineAt: string,
  signal: AbortSignal | undefined,
): Promise<SettledRead> => {
  if (signal?.aborted) return Object.freeze({ kind: 'CANCELLED' });
  const absoluteDeadline = Date.parse(deadlineAt);
  if (Date.now() >= absoluteDeadline) return Object.freeze({ kind: 'DEADLINE' });

  let timer: ReturnType<typeof setTimeout> | undefined;
  let cancel = () => {};
  let scheduleDeadline!: () => void;
  const deadline = new Promise<SettledRead>((resolve) => {
    scheduleDeadline = () => {
      const remaining = absoluteDeadline - Date.now();
      if (remaining <= 0) {
        resolve(Object.freeze({ kind: 'DEADLINE' }));
        return;
      }
      timer = setTimeout(scheduleDeadline, Math.min(remaining, 2_147_483_647));
    };
    scheduleDeadline();
  });
  const cancellation = new Promise<SettledRead>((resolve) => {
    if (!signal) return;
    cancel = () => resolve(Object.freeze({ kind: 'CANCELLED' }));
    signal.addEventListener('abort', cancel, { once: true });
    if (signal.aborted) cancel();
  });
  const invoked = Promise.resolve()
    .then(invocation)
    .then(
      (value) => Object.freeze({ kind: 'VALUE' as const, value }),
      () => Object.freeze({ kind: 'NO_BYTES' as const }),
    );
  const settled = await Promise.race([invoked, deadline, cancellation]);
  if (timer) clearTimeout(timer);
  signal?.removeEventListener('abort', cancel);
  return settled;
};

const waitForRetry = async (
  delayMilliseconds: number,
  deadlineAt: string,
  signal: AbortSignal | undefined,
): Promise<'READY' | 'DEADLINE' | 'CANCELLED'> => {
  if (delayMilliseconds === 0)
    return signal?.aborted
      ? 'CANCELLED'
      : Date.now() >= Date.parse(deadlineAt)
        ? 'DEADLINE'
        : 'READY';
  let delayTimer: ReturnType<typeof setTimeout> | undefined;
  const settled = await settleWithinControl(
    () =>
      new Promise((resolve) => {
        delayTimer = setTimeout(() => resolve('READY'), delayMilliseconds);
      }),
    deadlineAt,
    signal,
  );
  if (delayTimer) clearTimeout(delayTimer);
  return settled.kind === 'VALUE'
    ? 'READY'
    : settled.kind === 'CANCELLED'
      ? 'CANCELLED'
      : 'DEADLINE';
};

export const createPrivacyExplorerService = (
  consumer: GovernedProjectionConsumerPort,
  persistence?: ExecutionPersistence,
  redact?: (projection: ValidatedProjection) => Promise<RedactedProjection>,
  sourceBoundary?: GovernedProjectionBoundary,
): PrivacyExplorerService => {
  if (!redact && process.env.NODE_ENV !== 'test')
    throw new Error('local disclosure visibility required');
  const oracle = createPersistedExecutionOracle(persistence);

  const apply = (
    handle: ExecutionHandle,
    eventId: Parameters<typeof oracle.apply>[2],
    payload?: Parameters<typeof oracle.apply>[3],
  ) => oracle.apply(handle, oracle.inspect(handle).revision, eventId, payload);

  const sealReleased = async (
    handle: ExecutionHandle,
    response: PrivacyExplorerResultV1 | SafeProblem,
  ): Promise<PrivacyExplorerReadResult> => {
    const evidenceResult = await apply(handle, 'MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS');
    if (!evidenceResult.evidence) throw new Error('missing Privacy Explorer evidence');
    const result = Object.freeze({
      disposition: 'RELEASED' as const,
      response,
      evidence: evidenceResult.evidence,
    });
    authenticReadResults.set(
      result,
      Object.freeze({
        disposition: result.disposition,
        response,
        evidence: evidenceResult.evidence,
      }),
    );
    return result;
  };

  const release = async (handle: ExecutionHandle): Promise<PrivacyExplorerReadResult> => {
    const releaseResult = await apply(handle, 'RELEASE');
    if (!releaseResult.released) throw new Error('missing Privacy Explorer response');
    return sealReleased(handle, releaseResult.released);
  };

  const closeCancelled = async (handle: ExecutionHandle): Promise<PrivacyExplorerReadResult> => {
    await apply(handle, 'CLOSE_CANCELLED');
    const evidenceResult = await apply(handle, 'MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS');
    if (!evidenceResult.evidence) throw new Error('missing cancellation evidence');
    const result = Object.freeze({
      disposition: 'SUPPRESSED' as const,
      evidence: evidenceResult.evidence,
    });
    authenticReadResults.set(
      result,
      Object.freeze({ disposition: result.disposition, evidence: evidenceResult.evidence }),
    );
    return result;
  };

  const applyB2Admission = (
    input: PrivacyExplorerReadInput,
  ): Readonly<{
    boundary: ReturnType<typeof createProjectionRequest>;
  }> => {
    const intent = preauthorize(input.context, input.purposeAction);
    const narrowed = narrowIntent(intent, input.profile, input.query);
    return Object.freeze({
      boundary: createProjectionRequest(narrowed, input.seed),
    });
  };

  return Object.freeze({
    async read(input) {
      const serviceInput = requireReadInput(input);
      const admitted = applyB2Admission(serviceInput);
      if (sourceBoundary) assertContinuationBoundary(admitted.boundary, sourceBoundary);
      const handle = await oracle.create(admitted.boundary);

      await apply(handle, 'BIND_LOCAL_CONTEXT');
      await apply(handle, 'PREAUTHORIZE');
      await apply(handle, 'NARROW_INTENT');
      await apply(handle, 'CREATE_REQUEST');
      requireGovernedProjectionConsumer(consumer, admitted.boundary);

      if (serviceInput.signal?.aborted) {
        await apply(handle, 'CANCEL_BEFORE_DISPATCH');
        return closeCancelled(handle);
      }

      await apply(handle, 'START_READ');
      let first: SettledRead = Object.freeze({ kind: 'NO_BYTES' });
      const consumerControl = Object.freeze(
        serviceInput.signal ? { signal: serviceInput.signal } : {},
      );
      for (let attempt = 0; attempt < serviceInput.profile.maximumReadAttempts; attempt += 1) {
        first = await settleWithinControl(
          () => readGovernedProjection(consumer, admitted.boundary, consumerControl),
          admitted.boundary.context.deadlineAt,
          serviceInput.signal,
        );
        if (serviceInput.signal?.aborted) {
          first = Object.freeze({ kind: 'CANCELLED' });
          break;
        }
        if (first.kind === 'CANCELLED' || first.kind === 'DEADLINE') break;
        const problem = first.kind === 'VALUE' ? canonicalSafeProblem(first.value) : undefined;
        const retryable = first.kind === 'NO_BYTES' || problem?.code === 'PC-INTEGRATION-5001';
        if (!retryable || attempt + 1 >= serviceInput.profile.maximumReadAttempts) break;
        const retry = await waitForRetry(
          serviceInput.profile.retryBackoffMilliseconds[attempt]!,
          admitted.boundary.context.deadlineAt,
          serviceInput.signal,
        );
        if (serviceInput.signal?.aborted) {
          first = Object.freeze({ kind: 'CANCELLED' });
          break;
        }
        if (retry !== 'READY') {
          first = Object.freeze({ kind: retry });
          break;
        }
      }

      if (first.kind === 'CANCELLED') {
        await apply(handle, 'CANCEL_DURING_READ');
        await apply(handle, 'RECONCILE_NO_BYTES');
        return closeCancelled(handle);
      }

      if (first.kind === 'DEADLINE') {
        await apply(handle, 'DEADLINE_EXPIRED');
        return release(handle);
      }

      if (first.kind === 'NO_BYTES') {
        await apply(handle, 'SOURCE_UNAVAILABLE');
        return release(handle);
      }

      if (serviceInput.signal?.aborted) {
        await apply(handle, 'CANCEL_DURING_READ');
        await apply(handle, 'RECONCILE_NO_BYTES');
        return closeCancelled(handle);
      }

      const directProblem = canonicalSafeProblem(first.value);
      if (directProblem) {
        await apply(handle, 'REGISTERED_SAFE_PROBLEM_RETURNED', {
          candidate: buildSafeProblemCandidate(admitted.boundary, directProblem),
        });
        return release(handle);
      }

      await apply(handle, 'CAPTURE_BYTES');
      if (serviceInput.signal?.aborted) {
        await apply(handle, 'CANCEL_AFTER_BYTES');
        await apply(handle, 'DISPOSE_RAW');
        return closeCancelled(handle);
      }

      const validated = validateProjection(sourceBoundary ?? admitted.boundary, first.value);
      const validationProblem = canonicalSafeProblem(validated);
      if (validationProblem) {
        await apply(handle, rawProblemEvent(validationProblem));
        await apply(handle, 'DISPOSE_RAW');
        return release(handle);
      }

      await apply(handle, 'VALIDATE_PROJECTION');
      if (serviceInput.signal?.aborted) {
        await apply(handle, 'CANCEL_AFTER_VALIDATION');
        await apply(handle, 'DISPOSE_RAW');
        return closeCancelled(handle);
      }

      const projection = bindValidatedContinuation(
        requireValidatedProjection(validated as ValidatedProjection),
        admitted.boundary,
      );
      const redacted = redact ? await redact(projection) : redactProjection(projection);
      await apply(handle, 'REDACT_PROJECTION');
      if (serviceInput.signal?.aborted) {
        await apply(handle, 'CANCEL_AFTER_REDACTION');
        await apply(handle, 'DISPOSE_RAW');
        return closeCancelled(handle);
      }

      const candidate = buildProjectionCandidate(redacted);
      await apply(handle, `SELECT_${redacted.outcome}`, { candidate });
      if (serviceInput.signal?.aborted) {
        await apply(handle, 'CANCEL_AFTER_OUTCOME_SELECTION');
        await apply(handle, 'DISPOSE_RAW');
        return closeCancelled(handle);
      }

      await apply(handle, 'DISPOSE_RAW');
      return release(handle);
    },
  });
};
