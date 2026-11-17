import type { FastifyReply, FastifyRequest } from 'fastify';

import {
  assertExplorerProjectionRequest,
  type ExplorerProjectionRequestV1,
} from '../contracts/privacy-explorer-adapter.js';
import { canonicalJson, sha256CanonicalJson } from './canonical.js';
import {
  bindLocalContext,
  requireLocalContext,
  type TerminalAuthorizationVerifier,
} from './context.js';
import { narrowIntent, type NarrowingInput } from './narrowing.js';
import { preauthorize } from './preauthorization.js';
import {
  requireRegisteredExplorerProfile,
  validDateTime,
  type RegisteredExplorerProfile,
} from './profile-registration.js';
import { safeProblemForCondition, type SafeProblem } from './problems.js';
import { createProjectionRequest } from './request.js';
import type { PrivacyExplorerReadInput } from './service.js';
import { requireExactOwnData } from './server-input.js';
import { parseStrictJsonBytes } from './strict-json.js';

const sessionCookieName = '__Host-openpc_session';
const unauthorizedProblem = Object.freeze({
  code: 'PC-AUTH-0001',
  httpStatus: 401,
  jsonRpcCode: -32041,
  grpcStatus: 'UNAUTHENTICATED',
  truthState: 'DENIED',
  retryable: false,
  disclosure: 'NON_LEAKING_INVARIANT',
  publicTitle: 'Resource is unavailable',
});
const invalidCookieValue = (value: string) =>
  [...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 0x20 || code === 0x7f || character === ';';
  });

export type PrivacyExplorerHttpReadAdmission = Readonly<Record<never, never>>;
export type PrivacyExplorerHttpAdmissionOutcome =
  | Readonly<{ kind: 'ADMITTED'; admission: PrivacyExplorerHttpReadAdmission }>
  | Readonly<{ kind: 'REJECTED'; problem: SafeProblem }>;

type AdmissionLimits = Readonly<{
  resolveSession(session: string): unknown | Promise<unknown>;
  clock(): Date;
  maximumRequestBytes: number;
  maximumJsonDepth: number;
}>;
export type PrivacyExplorerHttpAdmissionDependencies = AdmissionLimits &
  (
    | Readonly<{
        terminalAuthorizationVerifier: TerminalAuthorizationVerifier;
        profile: RegisteredExplorerProfile;
        serverMaximumDeadlineAt: string;
      }>
    | Readonly<{
        resolveRequest(
          session: string,
          intent: ExplorerProjectionRequestV1,
          signal: AbortSignal,
        ): Promise<{
          context: ReturnType<typeof bindLocalContext>;
          profile: RegisteredExplorerProfile;
          serverMaximumDeadlineAt: string;
        }>;
      }>
  );

export type PrivacyExplorerHttpAdmission = Readonly<{
  onRequest(
    request: FastifyRequest,
    reply: FastifyReply,
    signal: AbortSignal,
    finalizeRejection: (problem: SafeProblem) => Promise<void>,
  ): Promise<'REJECTED' | undefined>;
  parseBody(request: FastifyRequest, payload: AsyncIterable<Uint8Array>): Promise<undefined>;
  consume(request: FastifyRequest): PrivacyExplorerHttpAdmissionOutcome;
}>;

type PendingAdmission = Readonly<{
  session: string;
  context?: ReturnType<typeof bindLocalContext>;
  signal: AbortSignal;
  cleanup(): void;
}>;

const resolveSessionWhileConnected = async (
  resolveSession: PrivacyExplorerHttpAdmissionDependencies['resolveSession'],
  session: string,
  signal: AbortSignal,
) => {
  const resolved = Promise.resolve()
    .then(() => resolveSession(session))
    .then(
      (value) => Object.freeze({ kind: 'VALUE' as const, value }),
      () => Object.freeze({ kind: 'FAILED' as const }),
    );
  let onAbort = () => {};
  const disconnected = new Promise<Readonly<{ kind: 'ABORTED' }>>((resolve) => {
    if (signal.aborted) {
      resolve(Object.freeze({ kind: 'ABORTED' }));
      return;
    }
    onAbort = () => resolve(Object.freeze({ kind: 'ABORTED' }));
    signal.addEventListener('abort', onAbort, { once: true });
  });
  const outcome = await Promise.race([resolved, disconnected]);
  signal.removeEventListener('abort', onAbort);
  return outcome;
};

const admissions = new WeakMap<
  PrivacyExplorerHttpReadAdmission,
  Readonly<{ input: PrivacyExplorerReadInput; cleanup(): void }>
>();

const exactDependencies = (
  value: PrivacyExplorerHttpAdmissionDependencies,
): PrivacyExplorerHttpAdmissionDependencies => {
  const live = !!value && typeof value === 'object' && Object.hasOwn(value, 'resolveRequest');
  const expected = [
    'resolveSession',
    'clock',
    'maximumRequestBytes',
    'maximumJsonDepth',
    ...(live
      ? ['resolveRequest']
      : ['terminalAuthorizationVerifier', 'profile', 'serverMaximumDeadlineAt']),
  ];
  const admitted = requireExactOwnData(
    value,
    expected,
    'Privacy Explorer HTTP admission dependencies',
  );
  const maximumRequestBytes = admitted.maximumRequestBytes;
  const maximumJsonDepth = admitted.maximumJsonDepth;
  if (
    typeof admitted.resolveSession !== 'function' ||
    (live
      ? typeof admitted.resolveRequest !== 'function'
      : !admitted.terminalAuthorizationVerifier ||
        typeof (admitted.terminalAuthorizationVerifier as TerminalAuthorizationVerifier).verify !==
          'function') ||
    typeof admitted.clock !== 'function' ||
    typeof maximumRequestBytes !== 'number' ||
    !Number.isSafeInteger(maximumRequestBytes) ||
    maximumRequestBytes < 1 ||
    maximumRequestBytes > 1_048_576 ||
    typeof maximumJsonDepth !== 'number' ||
    !Number.isSafeInteger(maximumJsonDepth) ||
    maximumJsonDepth < 1 ||
    maximumJsonDepth > 64
  )
    throw new Error('invalid Privacy Explorer HTTP admission dependencies');
  const common = {
    resolveSession:
      admitted.resolveSession as PrivacyExplorerHttpAdmissionDependencies['resolveSession'],
    clock: admitted.clock as PrivacyExplorerHttpAdmissionDependencies['clock'],
    maximumRequestBytes,
    maximumJsonDepth,
  };
  if (live)
    return Object.freeze({
      ...common,
      resolveRequest: admitted.resolveRequest as Extract<
        PrivacyExplorerHttpAdmissionDependencies,
        { resolveRequest: unknown }
      >['resolveRequest'],
    });
  return Object.freeze({
    ...common,
    terminalAuthorizationVerifier:
      admitted.terminalAuthorizationVerifier as TerminalAuthorizationVerifier,
    profile: requireRegisteredExplorerProfile(admitted.profile),
    serverMaximumDeadlineAt: validDateTime(admitted.serverMaximumDeadlineAt, 'server deadline'),
  });
};

export const readSessionCookie = (request: FastifyRequest): string | undefined => {
  const headers = request.raw.rawHeaders;
  const values: string[] = [];
  for (let index = 0; index < headers.length; index += 2) {
    if (headers[index]?.toLowerCase() === 'cookie') values.push(headers[index + 1] ?? '');
  }
  const cookieHeader = values[0];
  if (values.length !== 1 || !cookieHeader) return undefined;
  let session: string | undefined;
  for (const part of cookieHeader.split(';')) {
    const separator = part.indexOf('=');
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1);
    if (
      separator < 1 ||
      !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name) ||
      value.length === 0 ||
      invalidCookieValue(value)
    )
      return undefined;
    if (name === sessionCookieName) {
      if (session !== undefined) return undefined;
      session = value;
    }
  }
  return session;
};

const readBody = async (payload: AsyncIterable<Uint8Array>, maximumBytes: number) => {
  const chunks: Uint8Array[] = [];
  let length = 0;
  for await (const chunk of payload) {
    if (!(chunk instanceof Uint8Array)) throw new Error('invalid request bytes');
    length += chunk.byteLength;
    if (length > maximumBytes) throw new Error('request body limit exceeded');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks, length);
};

const earliestDeadline = (values: readonly string[]) =>
  new Date(Math.min(...values.map((value) => Date.parse(value)))).toISOString();

const requestInput = (
  candidate: ExplorerProjectionRequestV1,
  pending: PendingAdmission,
  profile: RegisteredExplorerProfile,
  now: Date,
  serverMaximumDeadlineAt: string,
): PrivacyExplorerReadInput => {
  const context = requireLocalContext(pending.context);
  const trustedNow = now.getTime();
  const issuedAt = Date.parse(validDateTime(candidate.issuedAt, 'issued at'));
  if (
    !Number.isFinite(trustedNow) ||
    issuedAt > trustedNow ||
    trustedNow - issuedAt > profile.maximumFreshnessAgeMilliseconds
  )
    throw new Error('unfresh request');
  const deadlineAt = earliestDeadline([
    context.deadlineAt,
    profile.maximumDeadlineAt,
    serverMaximumDeadlineAt,
  ]);
  if (Date.parse(deadlineAt) <= trustedNow) throw new Error('expired request');
  const intent = preauthorize(context, {
    purpose: candidate.purpose,
    action: candidate.action,
    resource: context.resource,
  });
  const narrowed = narrowIntent(intent, profile, {
    operationId: candidate.operationId,
    semanticOperationVersion: candidate.semanticOperationVersion,
    dataClassId: candidate.dataClassId,
    filters: candidate.filters,
    projectionFields: candidate.projectionFields,
    page: candidate.page,
  } satisfies NarrowingInput);
  const boundary = createProjectionRequest(narrowed, {
    now: candidate.issuedAt,
    deadlineAt,
    occurrenceId: context.occurrenceId,
    auditCorrelationId: context.auditCorrelationId,
    cancellationOccurrenceId: context.occurrenceId,
    reconciliationOccurrenceId: context.occurrenceId,
  });
  if (
    canonicalJson(boundary.request) !== canonicalJson(candidate) ||
    boundary.requestDigest !== sha256CanonicalJson(candidate)
  )
    throw new Error('untrusted request assertion mismatch');
  return Object.freeze({
    context: context,
    purposeAction: Object.freeze({
      purpose: candidate.purpose,
      action: candidate.action,
      resource: context.resource,
    }),
    profile,
    query: Object.freeze({
      operationId: candidate.operationId,
      semanticOperationVersion: candidate.semanticOperationVersion,
      dataClassId: candidate.dataClassId,
      filters: candidate.filters,
      projectionFields: candidate.projectionFields,
      page: candidate.page,
    }),
    seed: Object.freeze({
      now: candidate.issuedAt,
      deadlineAt,
      occurrenceId: context.occurrenceId,
      auditCorrelationId: context.auditCorrelationId,
      cancellationOccurrenceId: context.occurrenceId,
      reconciliationOccurrenceId: context.occurrenceId,
    }),
    signal: pending.signal,
  });
};

export const createPrivacyExplorerHttpAdmission = (
  input: PrivacyExplorerHttpAdmissionDependencies,
): PrivacyExplorerHttpAdmission => {
  const dependencies = exactDependencies(input);
  const states = new WeakMap<
    FastifyRequest,
    PendingAdmission | PrivacyExplorerHttpAdmissionOutcome
  >();
  const reject = (request: FastifyRequest, problem: SafeProblem) => {
    const prior = states.get(request);
    if (prior && 'cleanup' in prior) prior.cleanup();
    states.set(request, Object.freeze({ kind: 'REJECTED', problem }));
  };
  return Object.freeze({
    async onRequest(request, _reply, signal, finalizeRejection) {
      const session = readSessionCookie(request);
      if (!session) {
        reject(request, unauthorizedProblem);
        await finalizeRejection(unauthorizedProblem);
        return 'REJECTED';
      }
      if (!(signal instanceof AbortSignal)) throw new Error('missing route attempt signal');
      const cleanup = () => {};
      let context: ReturnType<typeof bindLocalContext> | undefined;
      try {
        const resolved = await resolveSessionWhileConnected(
          dependencies.resolveSession,
          session,
          signal,
        );
        if (resolved.kind === 'ABORTED') {
          return;
        }
        if (resolved.kind !== 'VALUE') throw new Error('session resolution failed');
        if ('resolveRequest' in dependencies) {
          if (!resolved.value) throw new Error('session resolution failed');
        } else
          context = bindLocalContext(resolved.value, dependencies.terminalAuthorizationVerifier);
      } catch {
        cleanup();
        if (signal.aborted) return;
        reject(request, unauthorizedProblem);
        await finalizeRejection(unauthorizedProblem);
        return 'REJECTED';
      }
      if (request.headers['content-type'] !== 'application/json') {
        cleanup();
        const problem = safeProblemForCondition('EXP-ENVELOPE');
        reject(request, problem);
        await finalizeRejection(problem);
        return 'REJECTED';
      }
      states.set(
        request,
        Object.freeze({
          session,
          ...(context ? { context } : {}),
          signal,
          cleanup,
        }),
      );
    },
    async parseBody(request, payload) {
      const pending = states.get(request);
      if (!pending || !('cleanup' in pending)) return undefined;
      let decoded: unknown;
      try {
        const bytes = await readBody(payload, dependencies.maximumRequestBytes);
        decoded = parseStrictJsonBytes(bytes, { maximumDepth: dependencies.maximumJsonDepth });
      } catch {
        reject(request, safeProblemForCondition('EXP-PARSE'));
        return undefined;
      }
      try {
        const candidate = assertExplorerProjectionRequest(decoded);
        const current =
          'resolveRequest' in dependencies
            ? await dependencies.resolveRequest(pending.session, candidate, pending.signal)
            : {
                context: requireLocalContext(pending.context),
                profile: dependencies.profile,
                serverMaximumDeadlineAt: dependencies.serverMaximumDeadlineAt,
              };
        const capturedNow = dependencies.clock();
        if (!(capturedNow instanceof Date)) throw new Error('invalid trusted clock');
        const readInput = requestInput(
          candidate,
          { ...pending, context: current.context },
          current.profile,
          new Date(capturedNow.getTime()),
          current.serverMaximumDeadlineAt,
        );
        const admission = Object.freeze({});
        admissions.set(admission, Object.freeze({ input: readInput, cleanup: pending.cleanup }));
        states.set(request, Object.freeze({ kind: 'ADMITTED', admission }));
      } catch {
        reject(request, safeProblemForCondition('EXP-ENVELOPE'));
      }
      return undefined;
    },
    consume(request) {
      const outcome = states.get(request);
      states.delete(request);
      if (!outcome || 'cleanup' in outcome)
        return Object.freeze({
          kind: 'REJECTED',
          problem: safeProblemForCondition('EXP-ENVELOPE'),
        });
      return outcome;
    },
  });
};

export const requirePrivacyExplorerHttpReadAdmission = (
  admission: PrivacyExplorerHttpReadAdmission,
): PrivacyExplorerReadInput => {
  const admitted = admissions.get(admission);
  if (!admitted) throw new Error('unadmitted Privacy Explorer HTTP read');
  return admitted.input;
};

export const disposePrivacyExplorerHttpReadAdmission = (
  admission: PrivacyExplorerHttpReadAdmission,
) => {
  const admitted = admissions.get(admission);
  if (!admitted) throw new Error('unadmitted Privacy Explorer HTTP read');
  admissions.delete(admission);
  admitted.cleanup();
};
