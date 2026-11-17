import {
  assertAdapterCallContext,
  assertEvidenceReference,
  assertExplorerProjectionRequest,
  type AdapterCallContextV1,
  type EvidenceReferenceV1,
  type EvidenceVerificationResultV1,
  type ExplorerProjectionRequestV1,
  type ExplorerProjectionResultV1,
} from '../contracts/privacy-explorer-adapter.js';
import { canonicalJson } from './canonical.js';
import type {
  GovernedProjectionConsumerImplementation,
  GovernedProjectionExecutionControl,
} from './consumer-port.js';
import { immutableJsonCopy } from './immutable.js';
import { canonicalSafeProblem, safeProblemForCondition, type SafeProblem } from './problems.js';
import { parseStrictJsonBytes } from './strict-json.js';
import {
  requirePrivacyExplorerTransportProfile,
  type PrivacyExplorerTransportOperation,
  type PrivacyExplorerTransportProfile,
} from './transport-profile.js';
import type { TlsDispatchResponse } from './tls-client-binding.js';

const transportAbortMarker = Symbol('transport-abort');

const raceTransportAbort = <T>(
  promise: Promise<T>,
  signal: AbortSignal,
): Promise<T | typeof transportAbortMarker> => {
  if (signal.aborted) return Promise.resolve(transportAbortMarker);
  return new Promise((resolve, reject) => {
    const abort = () => resolve(transportAbortMarker);
    signal.addEventListener('abort', abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', abort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', abort);
        reject(error);
      },
    );
  });
};

const readBoundedBody = async (
  response: TlsDispatchResponse,
  maximumBytes: number,
  signal: AbortSignal,
): Promise<Uint8Array | typeof transportAbortMarker> => {
  const iterator = response.body[Symbol.asyncIterator]();
  const chunks: Uint8Array[] = [];
  let length = 0;
  let complete = false;
  try {
    while (true) {
      const next = await raceTransportAbort(Promise.resolve(iterator.next()), signal);
      if (next === transportAbortMarker) return transportAbortMarker;
      if (next.done) {
        complete = true;
        break;
      }
      if (!(next.value instanceof Uint8Array)) throw new Error('invalid response chunk');
      length += next.value.byteLength;
      if (length > maximumBytes) throw new Error('response body limit exceeded');
      chunks.push(Buffer.from(next.value));
    }
    return Buffer.concat(chunks, length);
  } finally {
    if (!complete && iterator.return) await iterator.return().catch(() => undefined);
  }
};

class GovernedProjectionTransportCancellationError extends Error {
  constructor() {
    super('Privacy Explorer transport cancelled');
    this.name = 'AbortError';
  }
}

const invoke = async (
  profileToken: PrivacyExplorerTransportProfile,
  operation: PrivacyExplorerTransportOperation,
  requestValue: unknown,
  contextValue: unknown,
  control: GovernedProjectionExecutionControl,
): Promise<unknown | SafeProblem> => {
  const profile = requirePrivacyExplorerTransportProfile(profileToken);
  let request: ExplorerProjectionRequestV1 | EvidenceReferenceV1;
  let context: AdapterCallContextV1;
  let requestBytes: Uint8Array;
  try {
    request =
      operation === 'READ_PROJECTION'
        ? assertExplorerProjectionRequest(immutableJsonCopy(requestValue))
        : assertEvidenceReference(immutableJsonCopy(requestValue));
    context = assertAdapterCallContext(immutableJsonCopy(contextValue));
    const requestProfileDigest =
      operation === 'READ_PROJECTION'
        ? (request as ExplorerProjectionRequestV1).exportProfile.digest
        : (request as EvidenceReferenceV1).profileDigest;
    if (
      requestProfileDigest !== profile.exportProfileDigest ||
      context.profileDigest !== profile.exportProfileDigest
    )
      return safeProblemForCondition('EXP-ENVELOPE');
    requestBytes = Buffer.from(canonicalJson({ context, request }), 'utf8');
  } catch {
    return safeProblemForCondition('EXP-ENVELOPE');
  }
  if (requestBytes.byteLength > profile.requestByteLimit)
    return safeProblemForCondition('EXP-ENVELOPE');

  const deadlineAt = Date.parse(context.deadlineAt);
  const remaining = deadlineAt - Date.now();
  if (control.signal?.aborted) throw new GovernedProjectionTransportCancellationError();
  if (!Number.isFinite(deadlineAt) || remaining <= 0)
    return safeProblemForCondition('EXP-DEADLINE');
  const controller = new AbortController();
  let termination: 'CALLER' | 'DEADLINE' | undefined;
  const abortForCaller = () => {
    if (!termination) termination = 'CALLER';
    controller.abort();
  };
  control.signal?.addEventListener('abort', abortForCaller, { once: true });
  if (control.signal?.aborted) abortForCaller();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const scheduleDeadline = () => {
    const remainingChunk = deadlineAt - Date.now();
    if (remainingChunk <= 0) {
      if (!termination) termination = 'DEADLINE';
      controller.abort();
      return;
    }
    timer = setTimeout(scheduleDeadline, Math.min(remainingChunk, 2_147_483_647));
  };
  scheduleDeadline();
  let response: TlsDispatchResponse | undefined;
  try {
    const pendingResponse = profile.dispatch(operation, {
      body: requestBytes,
      signal: controller.signal,
    });
    const dispatched = await raceTransportAbort(pendingResponse, controller.signal);
    if (dispatched === transportAbortMarker) {
      void pendingResponse.then(
        (late) => late.dispose(),
        () => undefined,
      );
      if (termination === 'CALLER' || control.signal?.aborted)
        throw new GovernedProjectionTransportCancellationError();
      return safeProblemForCondition('EXP-DEADLINE');
    }
    response = dispatched;
    if (control.signal?.aborted) throw new GovernedProjectionTransportCancellationError();
    if (
      response.locationPresent ||
      response.contentType !== 'application/json' ||
      !Number.isSafeInteger(response.statusCode) ||
      response.statusCode < 100 ||
      response.statusCode > 599
    )
      return safeProblemForCondition('EXP-COND-004');
    const bytes = await readBoundedBody(response, profile.responseByteLimit, controller.signal);
    if (bytes === transportAbortMarker) {
      if (termination === 'CALLER' || control.signal?.aborted)
        throw new GovernedProjectionTransportCancellationError();
      return safeProblemForCondition('EXP-DEADLINE');
    }
    if (control.signal?.aborted) throw new GovernedProjectionTransportCancellationError();
    let decoded: unknown;
    try {
      decoded = parseStrictJsonBytes(bytes, { maximumDepth: profile.maximumJsonDepth });
    } catch {
      return safeProblemForCondition('EXP-PARSE');
    }
    const problem = canonicalSafeProblem(decoded);
    if (response.statusCode === 200)
      return problem ? safeProblemForCondition('EXP-COND-004') : decoded;
    return problem?.httpStatus === response.statusCode
      ? problem
      : safeProblemForCondition('EXP-COND-004');
  } catch (error) {
    if (termination === 'CALLER' || control.signal?.aborted)
      throw error instanceof GovernedProjectionTransportCancellationError
        ? error
        : new GovernedProjectionTransportCancellationError();
    return controller.signal.aborted
      ? safeProblemForCondition('EXP-DEADLINE')
      : safeProblemForCondition('EXP-COND-004');
  } finally {
    if (timer) clearTimeout(timer);
    control.signal?.removeEventListener('abort', abortForCaller);
    response?.dispose();
  }
};

export const createHttpGovernedProjectionConsumer = (
  profile: PrivacyExplorerTransportProfile,
): GovernedProjectionConsumerImplementation => {
  requirePrivacyExplorerTransportProfile(profile);
  return Object.freeze({
    readGovernedProjection(
      request: ExplorerProjectionRequestV1,
      context: AdapterCallContextV1,
      control: GovernedProjectionExecutionControl = {},
    ) {
      return invoke(profile, 'READ_PROJECTION', request, context, control) as Promise<
        ExplorerProjectionResultV1 | SafeProblem
      >;
    },
    verifyEvidenceReference(
      request: EvidenceReferenceV1,
      context: AdapterCallContextV1,
      control: GovernedProjectionExecutionControl = {},
    ) {
      return invoke(profile, 'VERIFY_EVIDENCE', request, context, control) as Promise<
        EvidenceVerificationResultV1 | SafeProblem
      >;
    },
  });
};
