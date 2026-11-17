import { randomUUID } from 'node:crypto';
import { IncomingMessage } from 'node:http';

import Fastify, {
  LogController,
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
  type FastifyServerOptions,
} from 'fastify';

import {
  assertPrivacyExplorerProblem,
  assertPrivacyExplorerResult,
  type PrivacyExplorerResultV1,
} from '../contracts/privacy-explorer-adapter.js';
import {
  appendPrivacyExplorerEvidence,
  appendPrivacyExplorerRouteAudit,
  requirePrivacyExplorerEvidenceReceipt,
  requirePrivacyExplorerEvidenceSink,
  requirePrivacyExplorerOperationalEventSink,
  requirePrivacyExplorerRouteAuditSink,
  type PrivacyExplorerEvidenceSink,
  type PrivacyExplorerOperationalEvent,
  type PrivacyExplorerOperationalEventSink,
  type PrivacyExplorerRouteAuditSink,
} from './evidence-sink.js';
import { sha256CanonicalJson } from './canonical.js';
import {
  createPrivacyExplorerHttpAdmission,
  disposePrivacyExplorerHttpReadAdmission,
  requirePrivacyExplorerHttpReadAdmission,
  type PrivacyExplorerHttpAdmissionDependencies,
} from './http-admission.js';
import { isSafeProblem, safeProblemForCondition, type SafeProblem } from './problems.js';
import { narrowIntent } from './narrowing.js';
import { preauthorize } from './preauthorization.js';
import { createProjectionRequest } from './request.js';
import { requireExactOwnData } from './server-input.js';
import type {
  PrivacyExplorerReadInput,
  PrivacyExplorerReadResult,
  PrivacyExplorerService,
} from './service.js';
import { requirePrivacyExplorerAuthenticReadResult } from './service.js';

const routePath = '/v1/privacy-explorer/projections:read';

type Delivery =
  | Readonly<{ kind: 'RELEASE'; response: PrivacyExplorerResultV1 | SafeProblem }>
  | Readonly<{ kind: 'SUPPRESS' }>
  | Readonly<{ kind: 'CONFLICT' }>
  | Readonly<{ kind: 'EVIDENCE_FAILURE' }>;

export type PrivacyExplorerHttpDeliveryDependencies = Readonly<{
  evidenceSink: PrivacyExplorerEvidenceSink;
  auditSink: PrivacyExplorerRouteAuditSink;
  eventSink: PrivacyExplorerOperationalEventSink;
  maximumSinkWaitMilliseconds: number;
}>;

export type PrivacyExplorerPreparedExecution = Readonly<{
  service: PrivacyExplorerService;
  evidenceSink: PrivacyExplorerEvidenceSink;
  release(result: PrivacyExplorerReadResult, enqueue: () => void): Promise<void>;
  close?(): Promise<void>;
}>;

export type PrivacyExplorerHttpRouteDependencies = Readonly<{
  admission: PrivacyExplorerHttpAdmissionDependencies;
  auditSink: PrivacyExplorerRouteAuditSink;
  eventSink: PrivacyExplorerOperationalEventSink;
  maximumSinkWaitMilliseconds: number;
}> &
  (
    | Readonly<{ service: PrivacyExplorerService; evidenceSink: PrivacyExplorerEvidenceSink }>
    | Readonly<{
        prepare(input: PrivacyExplorerReadInput): Promise<PrivacyExplorerPreparedExecution>;
      }>
  );

export type PrivacyExplorerHttpDelivery = Readonly<{
  complete(
    identity: PrivacyExplorerCompletionIdentity,
    result: PrivacyExplorerReadResult,
  ): Promise<Delivery>;
  auditAdmissionRejection(attempt: PrivacyExplorerRouteAttempt): Promise<void>;
  auditAdmissionSuppression(attempt: PrivacyExplorerRouteAttempt): Promise<void>;
  auditExecutionRejection(
    attempt: PrivacyExplorerRouteAttempt,
    identity: PrivacyExplorerCompletionIdentity,
  ): Promise<void>;
}>;

export type PrivacyExplorerCompletionIdentity = Readonly<Record<never, never>>;
export type PrivacyExplorerRouteAttempt = Readonly<Record<never, never>>;

type CompletionExpectation = Readonly<{
  occurrenceId: string;
  correlationId: string;
  requestDigest: string;
  profileDigest: string;
  queryDigest: string;
  authorizationDigest: string;
  contextDigest: string;
  scopeDigest: string;
  deadlineAt: string;
  signal: AbortSignal;
}>;

type AttemptExpectation = {
  attemptId: string;
  startedAt: number;
  signal: AbortSignal;
  deadlineAt: string;
  state: 'ACTIVE' | 'DELIVERY_CLAIMED' | 'FINISHED' | 'SUPPRESSED';
  cleaned: boolean;
  cleanup(): void;
};

const completionIdentities = new WeakMap<
  PrivacyExplorerCompletionIdentity,
  CompletionExpectation
>();
const routeAttempts = new WeakMap<PrivacyExplorerRouteAttempt, AttemptExpectation>();

const exactService = (value: unknown): PrivacyExplorerService => {
  const admitted = requireExactOwnData(value, ['read'], 'Privacy Explorer service');
  if (typeof admitted.read !== 'function') throw new Error('invalid Privacy Explorer service');
  return Object.freeze({ read: admitted.read as PrivacyExplorerService['read'] });
};

const exactDeliveryDependencies = (value: unknown): PrivacyExplorerHttpDeliveryDependencies => {
  const admitted = requireExactOwnData(
    value,
    ['evidenceSink', 'auditSink', 'eventSink', 'maximumSinkWaitMilliseconds'],
    'Privacy Explorer HTTP delivery dependencies',
  );
  if (
    typeof admitted.maximumSinkWaitMilliseconds !== 'number' ||
    !Number.isSafeInteger(admitted.maximumSinkWaitMilliseconds) ||
    admitted.maximumSinkWaitMilliseconds < 1 ||
    admitted.maximumSinkWaitMilliseconds > 60_000
  )
    throw new Error('invalid Privacy Explorer sink wait limit');
  return Object.freeze({
    evidenceSink: requirePrivacyExplorerEvidenceSink(admitted.evidenceSink),
    auditSink: requirePrivacyExplorerRouteAuditSink(admitted.auditSink),
    eventSink: requirePrivacyExplorerOperationalEventSink(admitted.eventSink),
    maximumSinkWaitMilliseconds: admitted.maximumSinkWaitMilliseconds,
  });
};

export const createPrivacyExplorerCompletionIdentity = (
  input: PrivacyExplorerReadInput,
): PrivacyExplorerCompletionIdentity => {
  const intent = preauthorize(input.context, input.purposeAction);
  const narrowed = narrowIntent(intent, input.profile, input.query);
  const boundary = createProjectionRequest(narrowed, input.seed);
  const identity = Object.freeze({});
  completionIdentities.set(
    identity,
    Object.freeze({
      occurrenceId: boundary.request.occurrence.requestId,
      correlationId: boundary.request.occurrence.correlationId,
      requestDigest: boundary.requestDigest,
      profileDigest: boundary.request.exportProfile.digest,
      queryDigest: boundary.request.queryDigest,
      authorizationDigest: boundary.context.authorizationDigest,
      contextDigest: sha256CanonicalJson(boundary.context),
      scopeDigest: boundary.context.scopeDigest,
      deadlineAt: boundary.context.deadlineAt,
      signal: input.signal ?? new AbortController().signal,
    }),
  );
  return identity;
};

const requireCompletionIdentity = (value: PrivacyExplorerCompletionIdentity) => {
  const identity = completionIdentities.get(value);
  if (!identity) throw new Error('invalid Privacy Explorer completion identity');
  return identity;
};

const createRouteAttempt = (
  request: FastifyRequest,
  reply: FastifyReply,
  maximumWait: number,
  removeOwner: () => void,
) => {
  const controller = new AbortController();
  const abortIncompleteRequest = () => {
    if (request.raw instanceof IncomingMessage && !request.raw.complete) controller.abort();
  };
  const attempt = Object.freeze({});
  request.raw.once('aborted', abortIncompleteRequest);
  const finish = () => {
    const owner = routeAttempts.get(attempt);
    if (owner && owner.state === 'DELIVERY_CLAIMED') owner.state = 'FINISHED';
    disposeRouteAttempt(attempt);
  };
  const close = () => {
    if (!(request.raw instanceof IncomingMessage)) return;
    const owner = routeAttempts.get(attempt);
    if (!owner) return;
    if (!reply.raw.writableFinished) {
      controller.abort();
      if (owner.state !== 'DELIVERY_CLAIMED') return;
      owner.state = 'SUPPRESSED';
    } else if (owner.state === 'DELIVERY_CLAIMED') owner.state = 'FINISHED';
    disposeRouteAttempt(attempt);
  };
  reply.raw.once('finish', finish);
  reply.raw.once('close', close);
  routeAttempts.set(attempt, {
    attemptId: randomUUID(),
    startedAt: Date.now(),
    signal: controller.signal,
    deadlineAt: new Date(Date.now() + maximumWait).toISOString(),
    state: 'ACTIVE',
    cleaned: false,
    cleanup: () => {
      request.raw.removeListener('aborted', abortIncompleteRequest);
      reply.raw.removeListener('finish', finish);
      reply.raw.removeListener('close', close);
      removeOwner();
    },
  });
  return attempt;
};

const requireRouteAttempt = (value: PrivacyExplorerRouteAttempt) => {
  const attempt = routeAttempts.get(value);
  if (!attempt) throw new Error('invalid Privacy Explorer route attempt');
  return attempt;
};

const disposeRouteAttempt = (value: PrivacyExplorerRouteAttempt) => {
  const attempt = routeAttempts.get(value);
  if (!attempt || attempt.cleaned) return;
  attempt.cleaned = true;
  attempt.cleanup();
  routeAttempts.delete(value);
};

const emitAttemptEvent = (
  sink: PrivacyExplorerOperationalEventSink,
  attempt: PrivacyExplorerRouteAttempt,
  profileState: PrivacyExplorerOperationalEvent['profileState'],
  outcomeClass: PrivacyExplorerOperationalEvent['outcomeClass'],
  errorClass: PrivacyExplorerOperationalEvent['errorClass'],
  maximumWaitMilliseconds: number,
  correlationId?: string,
) => {
  const expected = requireRouteAttempt(attempt);
  emitOperationalEvent(sink, {
    ...(correlationId ? { correlationId } : {}),
    profileState,
    outcomeClass,
    durationMilliseconds: Math.min(
      maximumWaitMilliseconds,
      Math.max(0, Date.now() - expected.startedAt),
    ),
    errorClass,
  });
};

type BoundedSettlement<T> =
  | Readonly<{ kind: 'VALUE'; value: T }>
  | Readonly<{ kind: 'ABORTED' }>
  | Readonly<{ kind: 'TIMED_OUT' }>
  | Readonly<{ kind: 'FAILED' }>;

const settleBounded = async <T>(
  operation: () => Promise<T>,
  deadlineAt: string,
  maximumWaitMilliseconds: number | undefined,
  signal: AbortSignal,
  cancelOnAbort: boolean,
): Promise<BoundedSettlement<T>> => {
  const deadline = Math.min(
    Date.parse(deadlineAt),
    maximumWaitMilliseconds === undefined
      ? Number.POSITIVE_INFINITY
      : Date.now() + maximumWaitMilliseconds,
  );
  if (!Number.isFinite(deadline) || deadline <= Date.now())
    return Object.freeze({ kind: 'TIMED_OUT' });
  if (cancelOnAbort && signal.aborted) return Object.freeze({ kind: 'ABORTED' });
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abort = () => {};
  const completion = Promise.resolve()
    .then(operation)
    .then(
      (value) => Object.freeze({ kind: 'VALUE' as const, value }),
      () => Object.freeze({ kind: 'FAILED' as const }),
    );
  const timeout = new Promise<BoundedSettlement<T>>((resolve) => {
    const schedule = () => {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        resolve(Object.freeze({ kind: 'TIMED_OUT' }));
        return;
      }
      timer = setTimeout(schedule, Math.min(remaining, 2_147_483_647));
    };
    schedule();
  });
  const cancellation = new Promise<BoundedSettlement<T>>((resolve) => {
    if (!cancelOnAbort) return;
    abort = () => resolve(Object.freeze({ kind: 'ABORTED' }));
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
  });
  const settled = await Promise.race([completion, timeout, cancellation]);
  if (settled.kind === 'ABORTED') {
    const grace = await Promise.race([
      completion,
      new Promise<BoundedSettlement<T>>((resolve) =>
        setTimeout(() => resolve(Object.freeze({ kind: 'ABORTED' })), 0),
      ),
    ]);
    if (grace.kind === 'VALUE') {
      if (timer) clearTimeout(timer);
      signal.removeEventListener('abort', abort);
      return grace;
    }
  }
  if (timer) clearTimeout(timer);
  signal.removeEventListener('abort', abort);
  return settled;
};

const matchesExpectation = (identity: CompletionExpectation, result: PrivacyExplorerReadResult) => {
  const evidence = result.evidence;
  if (
    evidence.occurrenceId !== identity.occurrenceId ||
    evidence.correlationId !== identity.correlationId ||
    evidence.requestDigest !== identity.requestDigest ||
    evidence.profileDigest !== identity.profileDigest ||
    evidence.queryDigest !== identity.queryDigest ||
    evidence.authorizationDigest !== identity.authorizationDigest ||
    evidence.contextDigest !== identity.contextDigest ||
    evidence.scopeDigest !== identity.scopeDigest
  )
    return false;
  if (result.disposition === 'SUPPRESSED') return true;
  if (isSafeProblem(result.response))
    return sha256CanonicalJson(result.response) === evidence.resultDigest;
  const { resultDigest, ...preimage } = result.response;
  return sha256CanonicalJson(preimage) === resultDigest && resultDigest === evidence.resultDigest;
};

const emitOperationalEvent = (
  sink: PrivacyExplorerOperationalEventSink,
  event: PrivacyExplorerOperationalEvent,
) => {
  void Promise.resolve()
    .then(() => sink.emit(Object.freeze(event)))
    .catch(() => {});
};

const validateResponse = (response: unknown): PrivacyExplorerResultV1 | SafeProblem => {
  if (isSafeProblem(response)) return assertPrivacyExplorerProblem(response) as SafeProblem;
  return assertPrivacyExplorerResult(response);
};

const release = (reply: FastifyReply, response: PrivacyExplorerResultV1 | SafeProblem) => {
  const admitted = validateResponse(response);
  if (isSafeProblem(admitted))
    return reply.code(admitted.httpStatus).type('application/problem+json').send(admitted);
  return reply.code(200).type('application/json').send(admitted);
};

const suppress = (reply: FastifyReply) => {
  reply.hijack();
  if (!reply.raw.destroyed) reply.raw.destroy();
};

const releaseAttempt = (
  attempt: PrivacyExplorerRouteAttempt,
  reply: FastifyReply,
  response: PrivacyExplorerResultV1 | SafeProblem,
  cleanup: () => void,
) => {
  const admitted = validateResponse(response);
  const expected = requireRouteAttempt(attempt);
  if (expected.state !== 'ACTIVE' || expected.signal.aborted) {
    return suppressAttempt(attempt, reply, cleanup);
  }
  expected.state = 'DELIVERY_CLAIMED';
  return release(reply, admitted);
};

const releaseAdmissionProblemAttempt = (
  attempt: PrivacyExplorerRouteAttempt,
  reply: FastifyReply,
  problem: SafeProblem,
  cleanup: () => void,
) => {
  const expected = requireRouteAttempt(attempt);
  if (expected.state !== 'ACTIVE' || expected.signal.aborted)
    return suppressAttempt(attempt, reply, cleanup);
  expected.state = 'DELIVERY_CLAIMED';
  return reply.code(problem.httpStatus).type('application/problem+json').send(problem);
};

const suppressAttempt = (
  attempt: PrivacyExplorerRouteAttempt,
  reply: FastifyReply,
  cleanup: () => void,
) => {
  const expected = requireRouteAttempt(attempt);
  if (expected.state === 'ACTIVE') expected.state = 'SUPPRESSED';
  suppress(reply);
  cleanup();
};

export const createPrivacyExplorerHttpDelivery = (
  input: PrivacyExplorerHttpDeliveryDependencies,
): PrivacyExplorerHttpDelivery => {
  const dependencies = exactDeliveryDependencies(input);
  return Object.freeze({
    async complete(identity, result) {
      const expectation = requireCompletionIdentity(identity);
      let authentic;
      try {
        authentic = requirePrivacyExplorerAuthenticReadResult(result);
      } catch {
        return Object.freeze({ kind: 'EVIDENCE_FAILURE' });
      }
      if (
        authentic.disposition !== result.disposition ||
        authentic.evidence !== result.evidence ||
        (result.disposition === 'RELEASED' && authentic.response !== result.response)
      )
        return Object.freeze({ kind: 'EVIDENCE_FAILURE' });
      if (!matchesExpectation(expectation, result))
        return Object.freeze({ kind: 'EVIDENCE_FAILURE' });
      try {
        const settled = await settleBounded(
          () => appendPrivacyExplorerEvidence(dependencies.evidenceSink, result.evidence),
          expectation.deadlineAt,
          dependencies.maximumSinkWaitMilliseconds,
          expectation.signal,
          result.disposition !== 'SUPPRESSED',
        );
        if (settled.kind === 'ABORTED') return Object.freeze({ kind: 'SUPPRESS' });
        if (settled.kind !== 'VALUE')
          return Object.freeze({
            kind: result.disposition === 'SUPPRESSED' ? 'SUPPRESS' : 'EVIDENCE_FAILURE',
          });
        const receipt = settled.value;
        if (receipt === 'CONFLICT')
          return Object.freeze({
            kind: result.disposition === 'SUPPRESSED' ? 'SUPPRESS' : 'CONFLICT',
          });
        requirePrivacyExplorerEvidenceReceipt(receipt, dependencies.evidenceSink, result.evidence);
        if (result.disposition === 'SUPPRESSED' || expectation.signal.aborted)
          return Object.freeze({ kind: 'SUPPRESS' });
        return Object.freeze({ kind: 'RELEASE', response: validateResponse(result.response) });
      } catch {
        return Object.freeze({
          kind: result.disposition === 'SUPPRESSED' ? 'SUPPRESS' : 'EVIDENCE_FAILURE',
        });
      }
    },
    async auditAdmissionRejection(attempt) {
      const expected = requireRouteAttempt(attempt);
      const settled = await settleBounded(
        () =>
          appendPrivacyExplorerRouteAudit(
            dependencies.auditSink,
            Object.freeze({ phase: 'ADMISSION_REJECTED', attemptId: expected.attemptId }),
          ),
        expected.deadlineAt,
        dependencies.maximumSinkWaitMilliseconds,
        expected.signal,
        true,
      );
      if (settled.kind !== 'VALUE')
        throw new Error('Privacy Explorer admission audit was not accepted');
    },
    async auditAdmissionSuppression(attempt) {
      const expected = requireRouteAttempt(attempt);
      const settled = await settleBounded(
        () =>
          appendPrivacyExplorerRouteAudit(
            dependencies.auditSink,
            Object.freeze({ phase: 'ADMISSION_SUPPRESSED', attemptId: expected.attemptId }),
          ),
        expected.deadlineAt,
        dependencies.maximumSinkWaitMilliseconds,
        expected.signal,
        false,
      );
      if (settled.kind !== 'VALUE')
        throw new Error('Privacy Explorer admission suppression audit was not accepted');
    },
    async auditExecutionRejection(attempt, identity) {
      const expected = requireRouteAttempt(attempt);
      const completion = requireCompletionIdentity(identity);
      const settled = await settleBounded(
        () =>
          appendPrivacyExplorerRouteAudit(
            dependencies.auditSink,
            Object.freeze({
              phase: 'EXECUTION_REJECTED',
              attemptId: expected.attemptId,
              occurrenceId: completion.occurrenceId,
              correlationId: completion.correlationId,
            }),
          ),
        completion.deadlineAt,
        dependencies.maximumSinkWaitMilliseconds,
        completion.signal,
        true,
      );
      if (settled.kind !== 'VALUE')
        throw new Error('Privacy Explorer execution audit was not accepted');
    },
  });
};

const exactRouteDependencies = (value: unknown): PrivacyExplorerHttpRouteDependencies => {
  const live = !!value && typeof value === 'object' && Object.hasOwn(value, 'prepare');
  const admitted = requireExactOwnData(
    value,
    [
      'admission',
      ...(live ? ['prepare'] : ['service', 'evidenceSink']),
      'auditSink',
      'eventSink',
      'maximumSinkWaitMilliseconds',
    ],
    'Privacy Explorer HTTP route dependencies',
  );
  const common = {
    admission: admitted.admission as PrivacyExplorerHttpAdmissionDependencies,
    auditSink: requirePrivacyExplorerRouteAuditSink(admitted.auditSink),
    eventSink: requirePrivacyExplorerOperationalEventSink(admitted.eventSink),
    maximumSinkWaitMilliseconds: admitted.maximumSinkWaitMilliseconds as number,
  };
  if (live) {
    if (typeof admitted.prepare !== 'function')
      throw new Error('invalid Privacy Explorer execution owner');
    return Object.freeze({
      ...common,
      prepare: admitted.prepare as Extract<
        PrivacyExplorerHttpRouteDependencies,
        { prepare: unknown }
      >['prepare'],
    });
  }
  if (process.env.NODE_ENV !== 'test')
    throw new Error('Privacy Explorer live release owner required');
  return Object.freeze({
    ...common,
    service: exactService(admitted.service),
    evidenceSink: requirePrivacyExplorerEvidenceSink(admitted.evidenceSink),
  });
};

export const registerPrivacyExplorerHttpReadRoute = (
  app: FastifyInstance,
  input: PrivacyExplorerHttpRouteDependencies,
) => {
  const dependencies = exactRouteDependencies(input);
  const admission = createPrivacyExplorerHttpAdmission(dependencies.admission);
  const delivery = createPrivacyExplorerHttpDelivery({
    evidenceSink:
      'evidenceSink' in dependencies
        ? dependencies.evidenceSink
        : {
            append: async () => {
              throw new Error('request-bound evidence sink required');
            },
          },
    auditSink: dependencies.auditSink,
    eventSink: dependencies.eventSink,
    maximumSinkWaitMilliseconds: dependencies.maximumSinkWaitMilliseconds,
  });
  const handled = new WeakSet<FastifyRequest>();
  const earlyReplies = new WeakSet<FastifyRequest>();
  const auditedAdmissionRejections = new WeakSet<FastifyRequest>();
  const attempts = new WeakMap<FastifyRequest, PrivacyExplorerRouteAttempt>();
  const cleanupAttempt = (request: FastifyRequest) => {
    const attempt = attempts.get(request);
    if (!attempt) return;
    disposeRouteAttempt(attempt);
    attempts.delete(request);
  };
  app.addContentTypeParser('application/json', (request, payload, done) => {
    admission.parseBody(request, payload).then(
      () => done(null, undefined),
      () => done(null, undefined),
    );
  });
  app.post(
    routePath,
    {
      logLevel: 'silent',
      onRequest: async (request, reply) => {
        reply.header('cache-control', 'no-store');
        attempts.set(
          request,
          createRouteAttempt(request, reply, dependencies.maximumSinkWaitMilliseconds, () =>
            attempts.delete(request),
          ),
        );
        const attempt = attempts.get(request);
        if (!attempt) throw new Error('missing Privacy Explorer route attempt');
        let rejectionFinalized = false;
        const admissionOutcome = await admission.onRequest(
          request,
          reply,
          requireRouteAttempt(attempt).signal,
          async (problem) => {
            rejectionFinalized = true;
            auditedAdmissionRejections.add(request);
            try {
              await delivery.auditAdmissionRejection(attempt);
              emitAttemptEvent(
                dependencies.eventSink,
                attempt,
                'NOT_ADMITTED',
                'SAFE_PROBLEM',
                'NONE',
                dependencies.maximumSinkWaitMilliseconds,
              );
              releaseAdmissionProblemAttempt(attempt, reply, problem, () =>
                cleanupAttempt(request),
              );
            } catch {
              emitAttemptEvent(
                dependencies.eventSink,
                attempt,
                'NOT_ADMITTED',
                'AUDIT_FAILURE',
                'AUDIT_FAILURE',
                dependencies.maximumSinkWaitMilliseconds,
              );
              releaseAttempt(attempt, reply, safeProblemForCondition('EXP-EVIDENCE'), () =>
                cleanupAttempt(request),
              );
            }
          },
        );
        if (admissionOutcome === 'REJECTED' || rejectionFinalized) {
          earlyReplies.add(request);
          return reply;
        }
        if (reply.sent) {
          earlyReplies.add(request);
          return;
        }
        if (!routeAttempts.has(attempt)) return;
        if (requireRouteAttempt(attempt).signal.aborted) {
          try {
            await delivery.auditAdmissionSuppression(attempt);
            emitAttemptEvent(
              dependencies.eventSink,
              attempt,
              'NOT_ADMITTED',
              'SUPPRESSED',
              'NONE',
              dependencies.maximumSinkWaitMilliseconds,
            );
          } catch {
            emitAttemptEvent(
              dependencies.eventSink,
              attempt,
              'NOT_ADMITTED',
              'AUDIT_FAILURE',
              'AUDIT_FAILURE',
              dependencies.maximumSinkWaitMilliseconds,
            );
          }
          suppressAttempt(attempt, reply, () => cleanupAttempt(request));
          earlyReplies.add(request);
          return;
        }
      },
      onResponse: async (request) => cleanupAttempt(request),
      onError: async (request) => cleanupAttempt(request),
      onSend: async (request, reply, payload) => {
        if (handled.has(request) || auditedAdmissionRejections.has(request)) return payload;
        auditedAdmissionRejections.add(request);
        const attempt = attempts.get(request);
        if (!attempt) return payload;
        const terminal = requireRouteAttempt(attempt);
        if (terminal.state !== 'ACTIVE' || terminal.signal.aborted) {
          suppressAttempt(attempt, reply, () => cleanupAttempt(request));
          return payload;
        }
        try {
          await delivery.auditAdmissionRejection(attempt);
          emitAttemptEvent(
            dependencies.eventSink,
            attempt,
            'NOT_ADMITTED',
            'SAFE_PROBLEM',
            'NONE',
            dependencies.maximumSinkWaitMilliseconds,
          );
          terminal.state = 'DELIVERY_CLAIMED';
          return payload;
        } catch {
          emitAttemptEvent(
            dependencies.eventSink,
            attempt,
            'NOT_ADMITTED',
            'AUDIT_FAILURE',
            'AUDIT_FAILURE',
            dependencies.maximumSinkWaitMilliseconds,
          );
          const problem = safeProblemForCondition('EXP-EVIDENCE');
          if (requireRouteAttempt(attempt).signal.aborted) {
            suppressAttempt(attempt, reply, () => cleanupAttempt(request));
            return payload;
          }
          terminal.state = 'DELIVERY_CLAIMED';
          reply.code(problem.httpStatus).type('application/problem+json');
          return JSON.stringify(problem);
        }
      },
    },
    async (request, reply) => {
      const attempt = attempts.get(request);
      if (!attempt || reply.sent || earlyReplies.has(request)) return;
      handled.add(request);
      const outcome = admission.consume(request);
      if (outcome.kind === 'REJECTED') {
        if (auditedAdmissionRejections.has(request)) {
          disposeRouteAttempt(attempt);
          attempts.delete(request);
          return;
        }
        auditedAdmissionRejections.add(request);
        try {
          await delivery.auditAdmissionRejection(attempt);
          emitAttemptEvent(
            dependencies.eventSink,
            attempt,
            'NOT_ADMITTED',
            'SAFE_PROBLEM',
            'NONE',
            dependencies.maximumSinkWaitMilliseconds,
          );
          return releaseAttempt(attempt, reply, outcome.problem, () => cleanupAttempt(request));
        } catch {
          emitAttemptEvent(
            dependencies.eventSink,
            attempt,
            'NOT_ADMITTED',
            'AUDIT_FAILURE',
            'AUDIT_FAILURE',
            dependencies.maximumSinkWaitMilliseconds,
          );
          return releaseAttempt(attempt, reply, safeProblemForCondition('EXP-EVIDENCE'), () =>
            cleanupAttempt(request),
          );
        }
      }
      const input = requirePrivacyExplorerHttpReadAdmission(outcome.admission);
      const identity = createPrivacyExplorerCompletionIdentity(input);
      let prepared: PrivacyExplorerPreparedExecution | undefined;
      try {
        prepared = 'prepare' in dependencies ? await dependencies.prepare(input) : undefined;
        const service =
          prepared?.service ?? ('service' in dependencies ? dependencies.service : undefined);
        if (!service) throw new Error('Privacy Explorer execution owner unavailable');
        const requestDelivery = prepared
          ? createPrivacyExplorerHttpDelivery({
              evidenceSink: prepared.evidenceSink,
              auditSink: dependencies.auditSink,
              eventSink: dependencies.eventSink,
              maximumSinkWaitMilliseconds: dependencies.maximumSinkWaitMilliseconds,
            })
          : delivery;
        const serviceSettled = await settleBounded(
          () => service.read(input),
          input.seed.deadlineAt,
          undefined,
          input.signal ?? new AbortController().signal,
          true,
        );
        if (!routeAttempts.has(attempt)) return;
        if (serviceSettled.kind !== 'VALUE') {
          if (serviceSettled.kind === 'ABORTED') {
            emitAttemptEvent(
              dependencies.eventSink,
              attempt,
              'ADMITTED',
              'SUPPRESSED',
              'NONE',
              dependencies.maximumSinkWaitMilliseconds,
              input.seed.auditCorrelationId,
            );
            return suppressAttempt(attempt, reply, () => cleanupAttempt(request));
          }
          try {
            await delivery.auditExecutionRejection(attempt, identity);
          } catch {
            emitAttemptEvent(
              dependencies.eventSink,
              attempt,
              'ADMITTED',
              'AUDIT_FAILURE',
              'AUDIT_FAILURE',
              dependencies.maximumSinkWaitMilliseconds,
              input.seed.auditCorrelationId,
            );
            return releaseAttempt(attempt, reply, safeProblemForCondition('EXP-EVIDENCE'), () =>
              cleanupAttempt(request),
            );
          }
          emitAttemptEvent(
            dependencies.eventSink,
            attempt,
            'ADMITTED',
            'SAFE_PROBLEM',
            'SERVICE_FAILURE',
            dependencies.maximumSinkWaitMilliseconds,
            input.seed.auditCorrelationId,
          );
          return releaseAttempt(attempt, reply, safeProblemForCondition('EXP-EVIDENCE'), () =>
            cleanupAttempt(request),
          );
        }
        const result = serviceSettled.value;
        const completed = await requestDelivery.complete(identity, result);
        if (!routeAttempts.has(attempt)) return;
        if (completed.kind === 'SUPPRESS') {
          emitAttemptEvent(
            dependencies.eventSink,
            attempt,
            'ADMITTED',
            'SUPPRESSED',
            'NONE',
            dependencies.maximumSinkWaitMilliseconds,
            input.seed.auditCorrelationId,
          );
          return suppressAttempt(attempt, reply, () => cleanupAttempt(request));
        }
        if (completed.kind === 'CONFLICT') {
          emitAttemptEvent(
            dependencies.eventSink,
            attempt,
            'ADMITTED',
            'EVIDENCE_FAILURE',
            'EVIDENCE_FAILURE',
            dependencies.maximumSinkWaitMilliseconds,
            input.seed.auditCorrelationId,
          );
          return releaseAttempt(attempt, reply, safeProblemForCondition('EXP-REPLAY'), () =>
            cleanupAttempt(request),
          );
        }
        if (completed.kind === 'EVIDENCE_FAILURE') {
          emitAttemptEvent(
            dependencies.eventSink,
            attempt,
            'ADMITTED',
            'EVIDENCE_FAILURE',
            'EVIDENCE_FAILURE',
            dependencies.maximumSinkWaitMilliseconds,
            input.seed.auditCorrelationId,
          );
          return releaseAttempt(attempt, reply, safeProblemForCondition('EXP-EVIDENCE'), () =>
            cleanupAttempt(request),
          );
        }
        if (prepared) {
          // Serialize before acquiring final fences. The live path enqueues
          // directly so no asynchronous Fastify hook can reopen the release gap.
          const response = validateResponse(completed.response);
          const bytes = Buffer.from(JSON.stringify(response));
          const status = isSafeProblem(response) ? response.httpStatus : 200;
          const type = isSafeProblem(response) ? 'application/problem+json' : 'application/json';
          await prepared.release(result, () => {
            const terminal = requireRouteAttempt(attempt);
            if (
              terminal.state !== 'ACTIVE' ||
              terminal.signal.aborted ||
              reply.raw.destroyed ||
              Date.now() >= Date.parse(input.seed.deadlineAt)
            ) {
              suppressAttempt(attempt, reply, () => cleanupAttempt(request));
              return;
            }
            terminal.state = 'DELIVERY_CLAIMED';
            reply.hijack();
            reply.raw.writeHead(status, {
              'content-type': type,
              'cache-control': 'no-store',
              'content-length': bytes.length,
            });
            reply.raw.end(bytes);
            emitAttemptEvent(
              dependencies.eventSink,
              attempt,
              'ADMITTED',
              isSafeProblem(response) ? 'SAFE_PROBLEM' : 'RELEASED',
              'NONE',
              dependencies.maximumSinkWaitMilliseconds,
              input.seed.auditCorrelationId,
            );
          });
          return reply;
        }
        emitAttemptEvent(
          dependencies.eventSink,
          attempt,
          'ADMITTED',
          isSafeProblem(completed.response) ? 'SAFE_PROBLEM' : 'RELEASED',
          'NONE',
          dependencies.maximumSinkWaitMilliseconds,
          input.seed.auditCorrelationId,
        );
        return releaseAttempt(attempt, reply, completed.response, () => cleanupAttempt(request));
      } catch {
        if (reply.sent) return reply;
        if (!routeAttempts.has(attempt)) return;
        try {
          await delivery.auditExecutionRejection(attempt, identity);
        } catch {
          // The public closure is identical; no raw operational detail is retained here.
        }
        emitAttemptEvent(
          dependencies.eventSink,
          attempt,
          'ADMITTED',
          'SAFE_PROBLEM',
          'SERVICE_FAILURE',
          dependencies.maximumSinkWaitMilliseconds,
          input.seed.auditCorrelationId,
        );
        return releaseAttempt(attempt, reply, safeProblemForCondition('EXP-EVIDENCE'), () =>
          cleanupAttempt(request),
        );
      } finally {
        await prepared?.close?.().catch(() => undefined);
        disposePrivacyExplorerHttpReadAdmission(outcome.admission);
      }
    },
  );
};

export type PrivacyExplorerHttpApplicationOptions = Readonly<{
  logger?: FastifyServerOptions['logger'];
}>;

export const createPrivacyExplorerHttpApplication = (
  dependencies: PrivacyExplorerHttpRouteDependencies,
  options: PrivacyExplorerHttpApplicationOptions = {},
): FastifyInstance => {
  const app = Fastify({
    logger: options.logger ?? false,
    logController: new LogController({ disableRequestLogging: true }),
  });
  app.setNotFoundHandler((_request, reply) => {
    const problem = safeProblemForCondition('EXP-BROWSER');
    return reply.code(problem.httpStatus).type('application/problem+json').send(problem);
  });
  app.setErrorHandler((_error, _request, reply) => {
    const problem = safeProblemForCondition('EXP-EVIDENCE');
    return reply.code(problem.httpStatus).type('application/problem+json').send(problem);
  });
  registerPrivacyExplorerHttpReadRoute(app, dependencies);
  return app;
};

export { routePath as privacyExplorerHttpReadRoutePath };
