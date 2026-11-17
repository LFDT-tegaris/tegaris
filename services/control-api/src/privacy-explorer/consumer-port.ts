import {
  assertAdapterCallContext,
  assertEvidenceReference,
  assertEvidenceVerificationResult,
  type AdapterCallContextV1,
  type EvidenceReferenceV1,
  type EvidenceVerificationResultV1,
  type ExplorerProjectionRequestV1,
  type ExplorerProjectionResultV1,
} from '../contracts/privacy-explorer-adapter.js';
import { sha256CanonicalJson } from './canonical.js';
import { immutableJsonCopy } from './immutable.js';
import {
  requirePreauthorizedIntent,
  type PrivacyExplorerPreauthorizedIntent,
} from './preauthorization.js';
import { canonicalSafeProblem, safeProblemForCondition, type SafeProblem } from './problems.js';
import {
  registeredProfileId,
  requireRegisteredExplorerProfile,
  type RegisteredExplorerProfile,
  validDateTime,
} from './profile-registration.js';
import {
  governedBoundaryRegistrationId,
  requireGovernedProjectionBoundary,
  type GovernedProjectionBoundary,
} from './request.js';

export interface GovernedProjectionConsumerImplementation {
  readGovernedProjection(
    request: ExplorerProjectionRequestV1,
    context: AdapterCallContextV1,
    control?: GovernedProjectionExecutionControl,
  ): Promise<ExplorerProjectionResultV1 | SafeProblem>;
  verifyEvidenceReference(
    request: EvidenceReferenceV1,
    context: AdapterCallContextV1,
    control?: GovernedProjectionExecutionControl,
  ): Promise<EvidenceVerificationResultV1 | SafeProblem>;
}

export type GovernedProjectionExecutionControl = Readonly<{
  signal?: AbortSignal;
}>;

const requireGovernedProjectionExecutionControl = (
  value: GovernedProjectionExecutionControl,
): GovernedProjectionExecutionControl => {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('invalid governed projection execution control');
  const prototype = Object.getPrototypeOf(value);
  const keys = Reflect.ownKeys(value);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length > 1 ||
    keys.some((key) => key !== 'signal')
  )
    throw new Error('invalid governed projection execution control');
  const signal = Object.getOwnPropertyDescriptor(value, 'signal');
  if (
    signal &&
    (!signal.enumerable || !('value' in signal) || !(signal.value instanceof AbortSignal))
  )
    throw new Error('invalid governed projection execution control');
  return Object.freeze(signal ? { signal: signal.value } : {});
};

class GovernedProjectionCancellationError extends Error {
  readonly occurrenceId: string;

  constructor(occurrenceId: string) {
    super('Privacy Explorer consumer cancelled');
    this.name = 'AbortError';
    this.occurrenceId = occurrenceId;
    Object.freeze(this);
  }
}

export type GovernedProjectionConsumerPort = Readonly<Record<never, never>>;
type BoundConsumer = Readonly<{
  registrationId: string;
  profileDigest: string;
  read: GovernedProjectionConsumerImplementation['readGovernedProjection'];
  verify: GovernedProjectionConsumerImplementation['verifyEvidenceReference'];
}>;
const consumers = new WeakMap<GovernedProjectionConsumerPort, BoundConsumer>();

export type GovernedEvidenceVerificationBoundary = Readonly<{
  reference: EvidenceReferenceV1;
  context: AdapterCallContextV1;
}>;
const evidenceVerificationBoundaries = new WeakMap<GovernedEvidenceVerificationBoundary, string>();

export const requireGovernedProjectionConsumer = (
  port: GovernedProjectionConsumerPort,
  boundary: GovernedProjectionBoundary,
): BoundConsumer => {
  const admitted = requireGovernedProjectionBoundary(boundary);
  const bound = consumers.get(port);
  if (!bound || bound.registrationId !== governedBoundaryRegistrationId(admitted))
    throw new Error('projection consumer registration mismatch');
  return bound;
};

export const bindGovernedProjectionConsumer = (
  profile: RegisteredExplorerProfile,
  implementation: GovernedProjectionConsumerImplementation,
): GovernedProjectionConsumerPort => {
  const registered = requireRegisteredExplorerProfile(profile);
  const read = implementation?.readGovernedProjection;
  const verify = implementation?.verifyEvidenceReference;
  if (typeof read !== 'function' || typeof verify !== 'function')
    throw new Error('invalid governed projection consumer');
  const port = Object.freeze({});
  consumers.set(
    port,
    Object.freeze({
      registrationId: registeredProfileId(registered),
      profileDigest: registered.digest,
      read: read.bind(implementation),
      verify: verify.bind(implementation),
    }),
  );
  return port;
};

export const readGovernedProjection = async (
  port: GovernedProjectionConsumerPort,
  boundary: GovernedProjectionBoundary,
  control: GovernedProjectionExecutionControl = {},
): Promise<ExplorerProjectionResultV1 | SafeProblem> => {
  const admitted = requireGovernedProjectionBoundary(boundary);
  const admittedControl = requireGovernedProjectionExecutionControl(control);
  const bound = requireGovernedProjectionConsumer(port, admitted);
  if (admittedControl.signal?.aborted)
    throw new GovernedProjectionCancellationError(admitted.context.occurrenceId);
  const response = await bound.read(admitted.request, admitted.context, admittedControl);
  if (admittedControl.signal?.aborted)
    throw new GovernedProjectionCancellationError(admitted.context.occurrenceId);
  return canonicalSafeProblem(response) ?? response;
};

export const createEvidenceVerificationBoundary = (
  intent: PrivacyExplorerPreauthorizedIntent,
  profile: RegisteredExplorerProfile,
  reference: EvidenceReferenceV1,
  deadlineAt: string,
): GovernedEvidenceVerificationBoundary => {
  const admittedIntent = requirePreauthorizedIntent(intent);
  const admittedProfile = requireRegisteredExplorerProfile(profile);
  const admittedReference = immutableJsonCopy(
    assertEvidenceReference(immutableJsonCopy(reference)),
  );
  const expectedReferenceDigest = sha256CanonicalJson({
    schemaVersion: admittedReference.schemaVersion,
    evidenceDigest: admittedReference.evidenceDigest,
    occurrenceId: admittedReference.occurrenceId,
    profileDigest: admittedReference.profileDigest,
  });
  if (
    admittedReference.referenceDigest !== expectedReferenceDigest ||
    admittedReference.profileDigest !== admittedProfile.digest ||
    admittedReference.occurrenceId !== admittedIntent.context.occurrenceId
  )
    throw new Error('invalid evidence reference boundary');
  const deadline = Date.parse(validDateTime(deadlineAt, 'evidence verification deadline'));
  if (
    deadline > Date.parse(admittedProfile.maximumDeadlineAt) ||
    deadline > Date.parse(admittedIntent.context.deadlineAt)
  )
    throw new Error('invalid evidence reference boundary');
  const context = immutableJsonCopy(
    assertAdapterCallContext({
      authorizationDigest: admittedIntent.context.authorizationDigest,
      profileDigest: admittedProfile.digest,
      authorizationContextId: admittedIntent.context.authorizationContextId,
      authorizationContextEpoch: admittedIntent.context.authorizationContextEpoch,
      accessClassIds: admittedIntent.context.accessClassIds,
      scopeDigest: sha256CanonicalJson({
        participantId: admittedIntent.context.participantId,
        privacyDomainId: admittedIntent.context.privacyDomainId,
        platformId: admittedIntent.context.platformId,
        workloadId: admittedIntent.context.workloadId,
        action: admittedIntent.action,
      }),
      deadlineAt,
      idempotencyDigest: admittedReference.referenceDigest,
      occurrenceId: admittedReference.occurrenceId,
      auditCorrelationId: admittedIntent.context.auditCorrelationId,
      cancellation: {
        mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION',
        occurrenceId: admittedReference.occurrenceId,
      },
      reconciliation: {
        mode: 'EXACT_OCCURRENCE',
        occurrenceId: admittedReference.occurrenceId,
      },
    }),
  );
  const boundary = Object.freeze({ reference: admittedReference, context });
  evidenceVerificationBoundaries.set(boundary, registeredProfileId(admittedProfile));
  return boundary;
};

export const requireEvidenceVerificationBoundary = (
  value: unknown,
): GovernedEvidenceVerificationBoundary => {
  if (
    !value ||
    typeof value !== 'object' ||
    !evidenceVerificationBoundaries.has(value as GovernedEvidenceVerificationBoundary)
  )
    throw new Error('invalid evidence reference boundary');
  return value as GovernedEvidenceVerificationBoundary;
};

export const verifyEvidenceReference = async (
  port: GovernedProjectionConsumerPort,
  evidenceBoundary: GovernedEvidenceVerificationBoundary,
  control: GovernedProjectionExecutionControl = {},
): Promise<EvidenceVerificationResultV1 | SafeProblem> => {
  const boundary = requireEvidenceVerificationBoundary(evidenceBoundary);
  const admittedControl = requireGovernedProjectionExecutionControl(control);
  const bound = consumers.get(port);
  if (
    !bound ||
    bound.profileDigest !== boundary.reference.profileDigest ||
    bound.registrationId !== evidenceVerificationBoundaries.get(boundary)
  )
    throw new Error('projection consumer registration mismatch');
  const remaining = Date.parse(boundary.context.deadlineAt) - Date.now();
  if (remaining <= 0) return safeProblemForCondition('EXP-DEADLINE');
  if (admittedControl.signal?.aborted)
    throw new GovernedProjectionCancellationError(boundary.reference.occurrenceId);

  let timeout: ReturnType<typeof setTimeout> | undefined;
  let cancel = () => {};
  let scheduleDeadline!: () => void;
  const deadline = new Promise<'DEADLINE'>((resolve) => {
    const absoluteDeadline = Date.parse(boundary.context.deadlineAt);
    scheduleDeadline = () => {
      const remainingChunk = absoluteDeadline - Date.now();
      if (remainingChunk <= 0) {
        resolve('DEADLINE');
        return;
      }
      timeout = setTimeout(scheduleDeadline, Math.min(remainingChunk, 2_147_483_647));
    };
    scheduleDeadline();
  });
  const cancellation = new Promise<'CANCELLED'>((resolve) => {
    if (!admittedControl.signal) return;
    cancel = () => resolve('CANCELLED');
    admittedControl.signal.addEventListener('abort', cancel, { once: true });
    if (admittedControl.signal.aborted) cancel();
  });
  const invoked = Promise.resolve()
    .then(() => bound.verify(boundary.reference, boundary.context, admittedControl))
    .then(
      (value) => Object.freeze({ kind: 'VALUE' as const, value }),
      () => Object.freeze({ kind: 'NO_BYTES' as const }),
    );
  const settled = await Promise.race([invoked, deadline, cancellation]);
  if (timeout) clearTimeout(timeout);
  admittedControl.signal?.removeEventListener('abort', cancel);
  if (settled === 'CANCELLED')
    throw new GovernedProjectionCancellationError(boundary.reference.occurrenceId);
  if (admittedControl.signal?.aborted)
    throw new GovernedProjectionCancellationError(boundary.reference.occurrenceId);
  if (settled === 'DEADLINE' || settled.kind === 'NO_BYTES')
    return safeProblemForCondition(settled === 'DEADLINE' ? 'EXP-DEADLINE' : 'EXP-COND-004');
  const problem = canonicalSafeProblem(settled.value);
  if (problem) return problem;
  let result: EvidenceVerificationResultV1;
  try {
    result = immutableJsonCopy(assertEvidenceVerificationResult(immutableJsonCopy(settled.value)));
  } catch {
    return safeProblemForCondition('EXP-EVIDENCE');
  }
  if (
    result.referenceDigest !== boundary.reference.referenceDigest ||
    result.evidenceDigest !== boundary.reference.evidenceDigest ||
    result.verificationDigest !==
      sha256CanonicalJson({
        schemaVersion: result.schemaVersion,
        referenceDigest: result.referenceDigest,
        evidenceDigest: result.evidenceDigest,
        verified: result.verified,
      })
  )
    return safeProblemForCondition('EXP-EVIDENCE');
  return result;
};
