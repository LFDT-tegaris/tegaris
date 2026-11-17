import { createHash, X509Certificate } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { join } from 'node:path';

import { afterAll, describe, expect, it as vitestIt } from 'vitest';

import { createPrivacyExplorerClient } from '../../../packages/api-client/src/privacy-explorer.js';
import type { EvidenceReferenceV1 } from '../../../services/control-api/src/contracts/privacy-explorer-adapter.js';
import {
  bindGovernedProjectionConsumer,
  createEvidenceVerificationBoundary,
  createHttpGovernedProjectionConsumer,
  createPrivacyExplorerHttpApplication,
  createPrivacyExplorerService,
  createPrivacyExplorerTransportProfile,
  createProjectionRequest,
  createTlsClientBinding,
  narrowIntent,
  preauthorize,
  verifyEvidenceReference,
} from '../../../services/control-api/src/privacy-explorer/index.js';
import { buildB5Harness } from '../../privacy/i07-gate2-b5-test-support.js';
import {
  createGate3ConformantEndpoint,
  gate3EndpointPaths,
  type Gate3ConformantEndpoint,
  type Gate3ResponseMode,
  type Gate3WireVector,
} from '../../privacy/i07-gate3-conformant-endpoint.js';
// @ts-expect-error This executable JavaScript registry is intentionally shared with node:test.
import {
  canonicalAtomicCases,
  registerGate3AtomicCases,
} from '../../privacy/i07-gate3-denominator.mjs';

const canonicalJson = (value: unknown): string => {
  if (value === null || ['boolean', 'number', 'string'].includes(typeof value))
    return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(',')}}`;
};
const independentDigest = (value: unknown) =>
  `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;

const independentProjection = (
  request: ReturnType<typeof createProjectionRequest>['request'],
  outcome: 'COMPLETE' | 'PARTIAL' | 'UNKNOWN' | 'UNAVAILABLE' = 'COMPLETE',
) => {
  const requestDigest = independentDigest(request);
  const preimage = {
    schemaVersion: '1.0' as const,
    requestDigest,
    profileDigest: request.exportProfile.digest,
    provenanceDigest: independentDigest({
      profileDigest: request.exportProfile.digest,
      requestDigest,
      provenanceProfileDigest: request.exportProfile.provenanceProfileDigest,
    }),
    observedAt: request.issuedAt,
    records:
      outcome === 'UNKNOWN' || outcome === 'UNAVAILABLE'
        ? []
        : [
            {
              id: 'record-a',
              fields: [
                { fieldId: 'PEF-A', value: 7 },
                { fieldId: 'PEF-B', value: 'visible' },
              ],
            },
          ],
    page: { cursor: outcome === 'PARTIAL' ? 'next' : null, gapFree: outcome === 'COMPLETE' },
    completeness: outcome,
    freshness: outcome === 'UNKNOWN' || outcome === 'UNAVAILABLE' ? 'UNKNOWN' : 'FRESH',
    conflict: 'NONE' as const,
  };
  return { ...preimage, responseDigest: independentDigest(preimage) };
};

const withQueryDigest = (request: ReturnType<typeof createProjectionRequest>['request']) => ({
  ...request,
  queryDigest: independentDigest({
    purpose: request.purpose,
    subject: request.subject,
    resource: request.resource,
    action: request.action,
    scope: request.scope,
    operationId: request.operationId,
    semanticOperationVersion: request.semanticOperationVersion,
    dataClassId: request.dataClassId,
    filters: request.filters,
    page: { limit: request.page.limit },
    projectionFields: request.projectionFields,
    exportProfileDigest: request.exportProfile.digest,
  }),
});

const resources: {
  endpoint?: Gate3ConformantEndpoint;
  app?: ReturnType<typeof createPrivacyExplorerHttpApplication>;
  evidenceSnapshot?: () => readonly unknown[];
  auditSnapshot?: () => readonly unknown[];
  eventSnapshot?: () => readonly unknown[];
  publicSnapshot?: () => readonly unknown[];
  orderSnapshot?: () => readonly string[];
}[] = [];

type Outcome = 'COMPLETE' | 'PARTIAL' | 'UNKNOWN' | 'UNAVAILABLE';
type SinkFailure = 'NONE' | 'REJECT' | 'TIMEOUT' | 'MALFORMED' | 'FORGED' | 'CONFLICT';
type AuditFailure = 'NONE' | 'REJECT' | 'TIMEOUT' | 'MALFORMED';
type PhaseGate = 'BEFORE_DISPATCH' | 'AFTER_VALIDATION' | 'DURING_EVIDENCE';
type SystemOptions = Readonly<{
  outcome?: Outcome;
  readBody?: Uint8Array;
  readStatusCode?: number;
  readContentType?: string;
  readLocation?: string;
  responseByteLimit?: number;
  responseMode?: Gate3ResponseMode;
  delayMilliseconds?: number;
  responseChunkBytes?: number;
  maximumSinkWaitMilliseconds?: number;
  evidenceFailure?: SinkFailure;
  auditFailurePhase?: string;
  auditFailure?: AuditFailure;
  operationIndex?: number;
  clientSignal?: AbortSignal;
  verifyBody?: Uint8Array;
  verifyStatusCode?: number;
  verifyContentType?: string;
  verifyResponseMode?: Gate3ResponseMode;
  sessionMode?: 'NORMAL' | 'NEVER_SETTLE';
  sessionFailure?: boolean;
  terminalVerifierDenial?: boolean;
  serverMaximumDeadlineAt?: string;
  serviceFailure?: boolean;
  phaseGate?: PhaseGate;
  onEvidenceAccepted?: () => void;
  waitForAbortAfterEvidenceAccepted?: boolean;
  eventFailure?: 'NONE' | 'SYNCHRONOUS' | 'ASYNCHRONOUS';
}>;

const createAppendOnceEvidenceSink = (failure: SinkFailure = 'NONE') => {
  const byOccurrence = new Map<
    string,
    Readonly<{ canonical: string; record: unknown; receipt: Readonly<Record<string, string>> }>
  >();
  const durableWrites: unknown[] = [];
  const port = Object.freeze({
    append: async (record: Record<string, unknown>) => {
      if (failure === 'REJECT') throw new Error('local evidence rejection');
      if (failure === 'TIMEOUT') return await new Promise<never>(() => undefined);
      if (failure === 'MALFORMED') return Object.freeze({ outcome: 'ACCEPTED' });
      const canonical = canonicalJson(record);
      const occurrenceId = String(record.occurrenceId);
      const existing = byOccurrence.get(occurrenceId);
      if (existing) {
        if (existing.canonical === canonical) return existing.receipt;
        return Object.freeze({
          ...existing.receipt,
          outcome: 'CONFLICT',
          scopeDigest: String(record.scopeDigest),
          resultDigest: String(record.resultDigest),
          recordDigest: independentDigest(record),
        });
      }
      const receipt = Object.freeze({
        outcome: failure === 'CONFLICT' ? 'CONFLICT' : 'ACCEPTED',
        occurrenceId,
        scopeDigest: failure === 'FORGED' ? `sha256:${'f'.repeat(64)}` : String(record.scopeDigest),
        resultDigest: String(record.resultDigest),
        recordDigest: independentDigest(record),
      });
      if (failure === 'FORGED' || failure === 'CONFLICT') return receipt;
      const durable = structuredClone(record);
      durableWrites.push(durable);
      byOccurrence.set(occurrenceId, Object.freeze({ canonical, record: durable, receipt }));
      return receipt;
    },
  });
  return Object.freeze({
    port,
    snapshot: () => Object.freeze(structuredClone(durableWrites)),
  });
};

const createPhaseAuditSink = (
  failurePhase?: string,
  failure: AuditFailure = failurePhase ? 'REJECT' : 'NONE',
) => {
  const durableWrites: unknown[] = [];
  const port = Object.freeze({
    append: async (fact: Record<string, unknown>) => {
      if (fact.phase === failurePhase) {
        if (failure === 'REJECT') throw new Error('local audit rejection');
        if (failure === 'TIMEOUT') return await new Promise<never>(() => undefined);
        if (failure === 'MALFORMED') return Object.freeze({ outcome: 'ACCEPTED' });
      }
      const durable = structuredClone(fact);
      durableWrites.push(durable);
      return Object.freeze({
        outcome: 'ACCEPTED',
        attemptId: String(fact.attemptId),
        auditDigest: independentDigest(fact),
      });
    },
  });
  return Object.freeze({
    port,
    snapshot: () => Object.freeze(structuredClone(durableWrites)),
  });
};

const boundaryFixture = (outcome: Outcome = 'COMPLETE', operationIndex = 0) => {
  const generatedHarness = buildB5Harness({
    implementation: { readGovernedProjection: async () => ({}) },
  });
  const harness = Object.freeze({
    ...generatedHarness,
    input: Object.freeze({
      ...generatedHarness.input,
      seed: Object.freeze({
        ...generatedHarness.input.seed,
        now: '2099-01-01T00:00:00.000Z',
        deadlineAt: '2099-01-01T00:01:00.000Z',
      }),
    }),
  });
  const intent = preauthorize(harness.input.context, harness.input.purposeAction);
  const operation = harness.input.profile.operationVersions[operationIndex];
  if (!operation) throw new Error('invalid operation fixture index');
  const narrowed = narrowIntent(intent, harness.input.profile, {
    ...harness.input.query,
    operationId: operation.operationId,
    semanticOperationVersion: operation.version,
    dataClassId: operation.acceptedDataClassIds[0]!,
  });
  const boundary = createProjectionRequest(narrowed, harness.input.seed);
  const referencePreimage = {
    schemaVersion: '1.0' as const,
    evidenceDigest: `sha256:${'e'.repeat(64)}`,
    occurrenceId: boundary.context.occurrenceId,
    profileDigest: boundary.context.profileDigest,
  };
  const reference: EvidenceReferenceV1 = {
    ...referencePreimage,
    referenceDigest: independentDigest(referencePreimage),
  };
  const verificationPreimage = {
    schemaVersion: '1.0' as const,
    referenceDigest: reference.referenceDigest,
    evidenceDigest: reference.evidenceDigest,
    verified: true,
  };
  const verificationBoundary = createEvidenceVerificationBoundary(
    intent,
    harness.input.profile,
    reference,
    boundary.context.deadlineAt,
  );
  return {
    harness,
    boundary,
    reference,
    verificationBoundary,
    projection: independentProjection(boundary.request, outcome),
    verification: {
      ...verificationPreimage,
      verificationDigest: independentDigest(verificationPreimage),
    },
  };
};

const createPhaseGate = () => {
  let markEntered!: () => void;
  let release!: () => void;
  const entered = new Promise<void>((resolve) => {
    markEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  let enteredOnce = false;
  return Object.freeze({
    entered,
    release,
    async hold() {
      if (!enteredOnce) {
        enteredOnce = true;
        markEntered();
      }
      await released;
    },
  });
};

const systemFixture = async (options: SystemOptions = {}) => {
  const fixture = boundaryFixture(options.outcome, options.operationIndex);
  const phaseGate = createPhaseGate();
  const endpoint = await createGate3ConformantEndpoint([
    {
      path: gate3EndpointPaths.read,
      expectedBody: Buffer.from(
        canonicalJson({
          context: {
            ...fixture.boundary.context,
            deadlineAt: '9999-12-31T23:59:59.000Z',
          },
          request: fixture.boundary.request,
        }),
      ),
      statusCode: options.readStatusCode ?? 200,
      contentType: options.readContentType ?? 'application/json',
      body: options.readBody ?? Buffer.from(JSON.stringify(fixture.projection)),
      maximumCalls: 3,
      ...(options.responseMode ? { responseMode: options.responseMode } : {}),
      ...(options.delayMilliseconds === undefined
        ? {}
        : { delayMilliseconds: options.delayMilliseconds }),
      ...(options.responseChunkBytes === undefined
        ? {}
        : { responseChunkBytes: options.responseChunkBytes }),
      ...(options.readLocation ? { location: options.readLocation } : {}),
    },
    {
      path: gate3EndpointPaths.verify,
      expectedBody: Buffer.from(
        canonicalJson({
          context: fixture.verificationBoundary.context,
          request: fixture.verificationBoundary.reference,
        }),
      ),
      statusCode: options.verifyStatusCode ?? 200,
      contentType: options.verifyContentType ?? 'application/json',
      body: options.verifyBody ?? Buffer.from(JSON.stringify(fixture.verification)),
      maximumCalls: 1,
      ...(options.verifyResponseMode ? { responseMode: options.verifyResponseMode } : {}),
    },
  ]);
  const resource: (typeof resources)[number] = { endpoint };
  const binding = createTlsClientBinding({
    transportClass: 'LOCAL_DEVELOPMENT',
    trustAnchorId: 'openpc-i07-gate3-root@v1',
    clientIdentityId: 'openpc-i07-gate3-client@v1',
    trustAnchorPem: endpoint.trustAnchorPem,
    clientCertificatePem: endpoint.acceptedClientCertificatePem,
    clientPrivateKeyPem: endpoint.acceptedClientPrivateKeyPem,
  });
  const profile = createPrivacyExplorerTransportProfile({
    transportClass: 'LOCAL_DEVELOPMENT',
    origin: endpoint.origin,
    exportProfileDigest: fixture.boundary.request.exportProfile.digest,
    transportProfileId: 'openpc-i07-gate3-transport@v1',
    egressPolicyId: 'openpc-i07-gate3-egress@v1',
    requestByteLimit: 65_536,
    responseByteLimit: options.responseByteLimit ?? 65_536,
    maximumJsonDepth: 16,
    tlsClientBinding: binding,
  });
  const consumer = createHttpGovernedProjectionConsumer(profile);
  const port = bindGovernedProjectionConsumer(fixture.harness.profile, consumer);
  const evidenceSink = createAppendOnceEvidenceSink(options.evidenceFailure);
  const auditSink = createPhaseAuditSink(options.auditFailurePhase, options.auditFailure);
  const events: unknown[] = [];
  const eventSnapshot = () => Object.freeze(structuredClone(events));
  const publicResponses: unknown[] = [];
  const publicSnapshot = () => Object.freeze(structuredClone(publicResponses));
  const order: string[] = [];
  const actualService = createPrivacyExplorerService(port);
  let markAbortObserved!: () => void;
  const abortObserved = new Promise<void>((resolve) => {
    markAbortObserved = resolve;
  });
  let monitoredSignal: AbortSignal | undefined;
  const observeSignal = (signal: AbortSignal | undefined) => {
    if (!signal || signal === monitoredSignal) return;
    monitoredSignal = signal;
    if (signal.aborted) markAbortObserved();
    else signal.addEventListener('abort', markAbortObserved, { once: true });
  };
  const monitoredService = Object.freeze({
    read: async (...arguments_: Parameters<typeof actualService.read>) => {
      observeSignal(arguments_[0].signal);
      return actualService.read(...arguments_);
    },
  });
  const routeService = options.serviceFailure
    ? { read: async () => Promise.reject(new Error('SERVICE_SECRET_CANARY')) }
    : options.phaseGate === 'BEFORE_DISPATCH'
      ? {
          read: async (...arguments_: Parameters<typeof monitoredService.read>) => {
            observeSignal(arguments_[0].signal);
            await phaseGate.hold();
            return monitoredService.read(...arguments_);
          },
        }
      : options.phaseGate === 'AFTER_VALIDATION'
        ? {
            read: async (...arguments_: Parameters<typeof monitoredService.read>) => {
              const value = await monitoredService.read(...arguments_);
              await phaseGate.hold();
              return value;
            },
          }
        : monitoredService;
  const app = createPrivacyExplorerHttpApplication({
    admission: {
      resolveSession: (session) =>
        options.sessionFailure
          ? Promise.reject(new Error('SESSION_SECRET_CANARY'))
          : options.sessionMode === 'NEVER_SETTLE'
            ? new Promise<never>(() => undefined)
            : session === 'session-a'
              ? fixture.harness.input.context
              : undefined,
      terminalAuthorizationVerifier: {
        verify: (candidate) =>
          !options.terminalVerifierDenial && candidate === fixture.harness.input.context
            ? fixture.harness.input.context
            : undefined,
      },
      profile: fixture.harness.input.profile,
      clock: () => new Date(Date.parse(fixture.harness.input.seed.now) + 1),
      maximumRequestBytes: 65_536,
      maximumJsonDepth: 16,
      serverMaximumDeadlineAt: options.serverMaximumDeadlineAt ?? '9999-12-31T23:59:59.000Z',
    },
    service: routeService,
    evidenceSink: {
      append: async (record) => {
        if (options.phaseGate === 'DURING_EVIDENCE') await phaseGate.hold();
        const receipt = await evidenceSink.port.append(record);
        if (receipt.outcome === 'ACCEPTED') {
          order.push('EVIDENCE_ACCEPTED');
          options.onEvidenceAccepted?.();
          if (options.waitForAbortAfterEvidenceAccepted) await abortObserved;
        }
        return receipt;
      },
    },
    auditSink: auditSink.port,
    eventSink: {
      emit: async (event) => {
        events.push(structuredClone(event));
        if (options.eventFailure === 'SYNCHRONOUS') throw new Error('event sink failure');
        if (options.eventFailure === 'ASYNCHRONOUS')
          return await Promise.reject(new Error('event sink failure'));
      },
    },
    maximumSinkWaitMilliseconds: options.maximumSinkWaitMilliseconds ?? 1_000,
  });
  resource.app = app;
  resource.evidenceSnapshot = evidenceSink.snapshot;
  resource.auditSnapshot = auditSink.snapshot;
  resource.eventSnapshot = eventSnapshot;
  resource.publicSnapshot = publicSnapshot;
  resource.orderSnapshot = () => Object.freeze([...order]);
  resources.push(resource);
  app.addHook('onSend', async (_request, reply, payload) => {
    const serialized =
      typeof payload === 'string' ? payload : Buffer.from(payload).toString('utf8');
    let body: unknown;
    try {
      body = JSON.parse(serialized);
    } catch {
      body = 'NON_JSON_BODY';
    }
    publicResponses.push(
      Object.freeze({
        statusCode: reply.statusCode,
        contentType: reply.getHeader('content-type') ?? 'ABSENT',
        body,
      }),
    );
    return payload;
  });
  await app.listen({ host: '127.0.0.1', port: 0 });
  const address = app.server.address();
  if (!address || typeof address === 'string') throw new Error('missing Control API address');
  const client = createPrivacyExplorerClient({
    baseUrl: `http://127.0.0.1:${address.port}`,
    headers: { cookie: '__Host-openpc_session=session-a' },
    fetch: async (request) => {
      const response = await globalThis.fetch(request, { signal: options.clientSignal });
      order.push('CONTROL_API_RESPONSE');
      return response;
    },
  });
  return {
    ...fixture,
    endpoint,
    consumer,
    port,
    evidence: evidenceSink.snapshot,
    evidenceSink,
    audit: auditSink.snapshot,
    events: eventSnapshot,
    order,
    baseUrl: `http://127.0.0.1:${address.port}`,
    client,
    app,
    phaseEntered: phaseGate.entered,
    releasePhase: phaseGate.release,
    abortObserved,
  };
};

const directRequest = (
  endpoint: Gate3ConformantEndpoint,
  options: Readonly<{
    path: string;
    method?: string;
    useAcceptedClient?: boolean;
    omitAccept?: boolean;
    extraHeaders?: Readonly<Record<string, string>>;
  }>,
) =>
  new Promise<number>((resolve, reject) => {
    const url = new URL(endpoint.origin);
    const request = httpsRequest(
      {
        host: url.hostname,
        port: url.port,
        path: options.path,
        method: options.method ?? 'POST',
        ca: endpoint.trustAnchorPem,
        ...(options.useAcceptedClient === false
          ? {}
          : {
              cert: endpoint.acceptedClientCertificatePem,
              key: endpoint.acceptedClientPrivateKeyPem,
            }),
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        rejectUnauthorized: true,
        servername: '',
        headers: {
          ...(options.omitAccept ? {} : { accept: 'application/json' }),
          'content-type': 'application/json',
          'content-length': '2',
          ...options.extraHeaders,
        },
      },
      (response) => {
        response.resume();
        response.once('end', () => resolve(response.statusCode ?? 0));
      },
    );
    request.once('error', reject);
    request.end('{}');
  });

const rejectedTlsRequest = (
  endpoint: Gate3ConformantEndpoint,
  options: Readonly<{
    certificate?: Uint8Array;
    privateKey?: Uint8Array;
    servername?: string;
    maximumVersion?: 'TLSv1.2' | 'TLSv1.3';
  }> = {},
) =>
  new Promise<void>((resolve, reject) => {
    const url = new URL(endpoint.origin);
    const request = httpsRequest(
      {
        host: url.hostname,
        port: url.port,
        path: gate3EndpointPaths.read,
        method: 'POST',
        ca: endpoint.trustAnchorPem,
        cert: options.certificate ?? endpoint.acceptedClientCertificatePem,
        key: options.privateKey ?? endpoint.acceptedClientPrivateKeyPem,
        ...(options.servername ? { servername: options.servername } : {}),
        minVersion: options.maximumVersion === 'TLSv1.2' ? 'TLSv1.2' : 'TLSv1.3',
        maxVersion: options.maximumVersion ?? 'TLSv1.3',
        rejectUnauthorized: true,
        headers: { 'content-type': 'application/json', 'content-length': '2' },
      },
      (response) => {
        response.resume();
        response.once('end', () => resolve());
      },
    );
    request.once('error', reject);
    request.end('{}');
  });

const waitUntil = async (predicate: () => boolean, message: string) => {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error(message);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
};

const disconnectDuringSessionResolution = async (
  fixture: Awaited<ReturnType<typeof systemFixture>>,
) => {
  const payload = JSON.stringify(fixture.boundary.request);
  await new Promise<void>((resolve) => {
    const url = new URL(fixture.baseUrl);
    const client = httpRequest({
      host: url.hostname,
      port: url.port,
      path: '/v1/privacy-explorer/projections:read',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
        'content-length': Buffer.byteLength(payload),
      },
    });
    client.once('error', () => resolve());
    client.once('close', () => resolve());
    client.once('finish', () => client.destroy());
    client.end(payload);
  });
};

const startPublicSocketRead = (
  fixture: Awaited<ReturnType<typeof systemFixture>>,
  cookie = '__Host-openpc_session=session-a',
) => {
  const payload = JSON.stringify(fixture.boundary.request);
  let firstByte!: () => void;
  const firstByteReceived = new Promise<void>((resolve) => {
    firstByte = resolve;
  });
  let settled!: () => void;
  const completed = new Promise<void>((resolve) => {
    settled = resolve;
  });
  const url = new URL(fixture.baseUrl);
  const request = httpRequest(
    {
      host: url.hostname,
      port: url.port,
      path: '/v1/privacy-explorer/projections:read',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie,
        'content-length': Buffer.byteLength(payload),
      },
    },
    (response) => {
      response.once('data', () => firstByte());
      response.once('error', settled);
      response.once('end', settled);
      response.once('close', settled);
      response.resume();
    },
  );
  request.once('error', settled);
  request.once('close', settled);
  request.end(payload);
  return Object.freeze({ request, completed, firstByteReceived });
};

type AtomicBody = () => void | Promise<void>;
const atomicBodies = new Map<string, AtomicBody>();
let declaredBodyIndex = 0;
const registerAtomicBody = (title: string, body: AtomicBody, _timeout?: number) => {
  const atomicCase = canonicalAtomicCases[declaredBodyIndex++];
  if (!atomicCase || atomicCase.title !== title)
    throw new Error(`Gate 3 atomic body order/title mismatch at ${declaredBodyIndex}`);
  if (atomicBodies.has(atomicCase.id))
    throw new Error(`duplicate Gate 3 atomic body: ${atomicCase.id}`);
  atomicBodies.set(atomicCase.id, body);
};
const it = Object.assign(registerAtomicBody, {
  each:
    <T>(table: readonly T[]) =>
    (titleTemplate: string, body: (...values: never[]) => void | Promise<void>) => {
      for (const row of table) {
        const values = (Array.isArray(row) ? row : [row]) as never[];
        let title = titleTemplate;
        for (const value of values) title = title.replace('%s', String(value));
        registerAtomicBody(title, () => body(...values));
      }
    },
});

const executeAtomicBody = async (id: string) => {
  const body = atomicBodies.get(id);
  if (!body) throw new Error(`missing Gate 3 atomic body: ${id}`);
  const resourceOffset = resources.length;
  let bodyFailure: unknown;
  try {
    await body();
  } catch (error) {
    bodyFailure = error;
  }
  const owned = resources.splice(resourceOffset);
  const endpointCalls = owned.flatMap((resource) => resource.endpoint?.calls() ?? []);
  const evidence = owned.flatMap((resource) => resource.evidenceSnapshot?.() ?? []);
  const audit = owned.flatMap((resource) => resource.auditSnapshot?.() ?? []);
  const events = owned.flatMap((resource) => resource.eventSnapshot?.() ?? []);
  const publicResponses = owned.flatMap((resource) => resource.publicSnapshot?.() ?? []);
  const order = owned.flatMap((resource) => resource.orderSnapshot?.() ?? []);
  let closedApps = 0;
  let closedEndpoints = 0;
  for (const resource of owned.reverse()) {
    await resource.app?.close();
    if (resource.app) closedApps += 1;
    await resource.endpoint?.close();
    if (resource.endpoint) closedEndpoints += 1;
    expect(resource.endpoint?.pendingTimerCount() ?? 0).toBe(0);
    expect(resource.endpoint?.openSocketCount() ?? 0).toBe(0);
  }
  if (bodyFailure) throw bodyFailure;
  const stableAudit = audit.map((fact) => {
    const value = fact as Record<string, unknown>;
    expect(value.attemptId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    return Object.freeze({ ...value, attemptId: 'VALID_UUID_V4' });
  });
  const stableEvents = events.map((event) => {
    const value = event as Record<string, unknown>;
    expect(value.durationMilliseconds).toEqual(expect.any(Number));
    expect(value.durationMilliseconds).toBeGreaterThanOrEqual(0);
    return Object.freeze({ ...value, durationMilliseconds: 'NON_NEGATIVE_INTEGER' });
  });
  const measured = Object.freeze({
    calls: Object.freeze(
      endpointCalls.map((call) =>
        Object.freeze({
          path: call.path,
          method: call.method,
          contentType: call.contentType,
          tlsProtocol: call.tlsProtocol,
          clientCommonName: call.clientCommonName,
          bodyDigest: independentDigest(call.body),
        }),
      ),
    ),
    retries: owned.reduce(
      (count, resource) => count + Math.max(0, (resource.endpoint?.calls().length ?? 0) - 1),
      0,
    ),
    evidence: Object.freeze({
      count: evidence.length,
      digest: independentDigest(evidence),
      identities: Object.freeze(
        evidence.map((record) => {
          const value = record as Record<string, unknown>;
          return Object.freeze({
            occurrenceId: value.occurrenceId,
            outcome: value.outcome,
            resultDigest: value.resultDigest,
            recordDigest: independentDigest(value),
          });
        }),
      ),
    }),
    audit: Object.freeze(stableAudit),
    events: Object.freeze(stableEvents),
    publicResponses: Object.freeze(
      publicResponses.map((response) => {
        const value = response as {
          statusCode: number;
          contentType: unknown;
          body: Record<string, unknown>;
        };
        return Object.freeze({
          statusCode: value.statusCode,
          contentType: value.contentType,
          bodyDigest: independentDigest(value.body),
          ...(typeof value.body.outcome === 'string' ? { outcome: value.body.outcome } : {}),
          ...(typeof value.body.code === 'string' ? { code: value.body.code } : {}),
        });
      }),
    ),
    order: Object.freeze(order),
    cleanup: Object.freeze({
      apps: closedApps,
      endpoints: closedEndpoints,
      timers: owned.reduce(
        (count, resource) => count + (resource.endpoint?.pendingTimerCount() ?? 0),
        0,
      ),
      sockets: owned.reduce(
        (count, resource) => count + (resource.endpoint?.openSocketCount() ?? 0),
        0,
      ),
    }),
  });
  return measured;
};

describe('I07 Gate 3 real boundary composition', () => {
  it('uses the API client through Control API, real mTLS transport, and evidence-before-delivery', async () => {
    const fixture = await systemFixture();
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result.data).toMatchObject({ outcome: 'COMPLETE', truthState: 'TRUE' });
    expect(fixture.evidence()).toHaveLength(1);
    expect(fixture.order).toEqual(['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE']);
    const [call] = fixture.endpoint.calls();
    expect(call).toMatchObject({
      path: gate3EndpointPaths.read,
      method: 'POST',
      contentType: 'application/json',
      tlsProtocol: 'TLSv1.3',
      clientCommonName: 'openpc-i07-gate3-client',
    });
    expect(JSON.parse(Buffer.from(call!.body).toString('utf8'))).toEqual({
      context: {
        ...fixture.boundary.context,
        deadlineAt: '9999-12-31T23:59:59.000Z',
      },
      request: fixture.boundary.request,
    });
    expect(JSON.stringify(result)).not.toContain(fixture.endpoint.origin);
  });

  it('executes evidence verification once on its distinct fixed path without retry', async () => {
    const fixture = await systemFixture();
    await expect(
      fixture.consumer.verifyEvidenceReference(
        fixture.reference,
        fixture.verificationBoundary.context,
      ),
    ).resolves.toEqual(fixture.verification);
    expect(fixture.endpoint.calls()).toHaveLength(1);
    expect(fixture.endpoint.calls()[0]?.path).toBe(gate3EndpointPaths.verify);
  });

  it('rejects an invalid evidence verification response without retry', async () => {
    const fixture = await systemFixture({ verifyBody: Buffer.from('{') });
    const result = await fixture.consumer.verifyEvidenceReference(
      fixture.reference,
      fixture.verificationBoundary.context,
    );
    expect(result).toMatchObject({
      code: expect.any(String),
      disclosure: 'NON_LEAKING_INVARIANT',
    });
    expect(fixture.endpoint.calls()).toHaveLength(1);
    expect(fixture.endpoint.calls()[0]?.path).toBe(gate3EndpointPaths.verify);
  });

  it.each(['COMPLETE', 'PARTIAL', 'UNKNOWN', 'UNAVAILABLE'] as const)(
    'preserves the explicit %s outcome through the actual API client',
    async (outcome) => {
      const fixture = await systemFixture({ outcome });
      const result = await fixture.client.read(fixture.boundary.request);
      expect(result.data).toMatchObject({ outcome });
      expect(fixture.endpoint.calls()).toHaveLength(1);
      expect(JSON.stringify(result)).not.toContain(fixture.endpoint.origin);
    },
  );

  it.each([
    ['malformed JSON', { readBody: Buffer.from('{') }],
    [
      'duplicate member',
      { readBody: Buffer.from('{"schemaVersion":"1.0","schemaVersion":"1.0"}') },
    ],
    ['invalid UTF-8', { readBody: Uint8Array.from([0xc3, 0x28]) }],
    ['empty body', { readBody: new Uint8Array() }],
    ['wrong content type', { readContentType: 'text/plain' }],
    ['undeclared success status', { readStatusCode: 201 }],
    ['redirect', { readStatusCode: 302, readLocation: 'https://outside.invalid/escape' }],
    ['oversized body', { readBody: Buffer.alloc(65_537, 0x20), responseByteLimit: 65_536 }],
  ] as const)(
    'contains the %s Explorer response as a non-leaking registered problem',
    async (_name, options) => {
      const fixture = await systemFixture(options);
      const result = await fixture.client.read(fixture.boundary.request);
      expect(result.problem).toMatchObject({
        httpStatus: expect.any(Number),
        disclosure: 'NON_LEAKING_INVARIANT',
      });
      expect(fixture.endpoint.calls()).toHaveLength(
        ['wrong content type', 'undeclared success status', 'redirect', 'oversized body'].includes(
          _name,
        )
          ? 2
          : 1,
      );
      expect(JSON.stringify(result)).not.toContain(fixture.endpoint.origin);
      expect(JSON.stringify(result)).not.toContain('outside.invalid');
    },
  );

  it('preserves an exact registered Explorer problem without retry or raw detail', async () => {
    const registered = {
      code: 'PC-INTEGRATION-5001',
      httpStatus: 503,
      jsonRpcCode: -32051,
      grpcStatus: 'UNAVAILABLE',
      truthState: 'UNAVAILABLE',
      retryable: true,
      disclosure: 'NON_LEAKING_INVARIANT',
      publicTitle: 'The service is unavailable',
    };
    const fixture = await systemFixture({
      readBody: Buffer.from(JSON.stringify(registered)),
      readStatusCode: 503,
    });
    await expect(fixture.client.read(fixture.boundary.request)).resolves.toEqual({
      problem: registered,
    });
    expect(fixture.endpoint.calls()).toHaveLength(2);
  });

  it('rejects an unauthenticated public request before egress', async () => {
    const fixture = await systemFixture();
    const unauthenticated = await fetch(`${fixture.baseUrl}/v1/privacy-explorer/projections:read`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(fixture.boundary.request),
    });
    expect(unauthenticated.status).toBe(401);
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it.each(['hidden-subject', 'nonexistent-subject'] as const)(
    'rejects server-context-mismatched subject %s before egress',
    async (subject) => {
      const fixture = await systemFixture();
      const request = structuredClone(fixture.boundary.request);
      request.subject = subject;
      const result = await fixture.client.read(withQueryDigest(request));
      expect(result.problem).toMatchObject({ httpStatus: 400 });
      expect(fixture.endpoint.calls()).toHaveLength(0);
    },
  );

  it.each([
    [
      'issuedAt',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.issuedAt = '9999-12-31T23:59:58.000Z';
      },
    ],
    [
      'scope.chainId',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.scope.chainId = 'chain-mutated';
      },
    ],
    [
      'queryDigest',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.queryDigest = `sha256:${'f'.repeat(64)}`;
      },
    ],
    [
      'occurrenceId',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.occurrenceId = '123e4567-e89b-42d3-a456-426614174199';
      },
    ],
  ] as const)('rejects the field-isolated %s mutation with zero fetch', async (_name, mutate) => {
    const fixture = await systemFixture();
    const request = structuredClone(fixture.boundary.request);
    mutate(request);
    await fixture.client.read(request).then(
      (result) => expect(result.problem).toMatchObject({ disclosure: 'NON_LEAKING_INVARIANT' }),
      (error: unknown) => expect(String(error)).toContain('invalid Privacy Explorer request'),
    );
    expect(fixture.endpoint.calls()).toHaveLength(0);
    expect(fixture.evidence()).toHaveLength(0);
  });

  it.each([
    ['root schemaVersion', (value: string) => value.replace('{', '{"schemaVersion":"1.0",')],
    [
      'subject',
      (value: string) =>
        value.replace('"subject":"subject-a"', '"subject":"subject-a","subject":"other"'),
    ],
    [
      'scope participantId',
      (value: string) =>
        value.replace(
          '"participantId":"participant-a"',
          '"participantId":"participant-a","participantId":"other"',
        ),
    ],
  ] as const)('rejects the nested duplicate %s member with zero fetch', async (_name, mutate) => {
    const fixture = await systemFixture();
    const serialized = JSON.stringify(fixture.boundary.request);
    const body = mutate(serialized);
    expect(body).not.toBe(serialized);
    const response = await fetch(`${fixture.baseUrl}/v1/privacy-explorer/projections:read`, {
      method: 'POST',
      headers: {
        'cookie': '__Host-openpc_session=session-a',
        'content-type': 'application/json',
      },
      body,
    });
    expect(response.status).toBe(400);
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('keeps the exact nine-operation registry structural', async () => {
    const fixture = await systemFixture();
    const operations = fixture.boundary.request.exportProfile.operationVersions;
    expect(operations).toHaveLength(9);
    expect(operations.map(({ operationId }) => operationId)).toEqual(
      [...operations.map(({ operationId }) => operationId)].sort(),
    );
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it.each([
    [
      'duplicate operation',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.exportProfile.operationVersions[1] = structuredClone(
          request.exportProfile.operationVersions[0]!,
        );
      },
    ],
    [
      'missing operation',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.exportProfile.operationVersions.pop();
      },
    ],
    [
      'wrong operation version',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.semanticOperationVersion = '999.0.0';
      },
    ],
    [
      'wrong data class',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.dataClassId = 'UNREGISTERED-DATA-CLASS';
      },
    ],
  ] as const)('rejects the %s registry mutation before fetch', async (_name, mutate) => {
    const fixture = await systemFixture();
    const request = structuredClone(fixture.boundary.request);
    mutate(request);
    await expect(fixture.client.read(request)).rejects.toThrow('invalid Privacy Explorer request');
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it.each([
    ['/unknown', 'POST'],
    [`${gate3EndpointPaths.read}?escape=1`, 'POST'],
    [gate3EndpointPaths.verify, 'GET'],
  ] as const)(
    'rejects undeclared method/path %s without consuming a vector',
    async (path, method) => {
      const fixture = await systemFixture();
      await expect(directRequest(fixture.endpoint, { path, method })).resolves.toBe(404);
      expect(fixture.endpoint.calls()).toHaveLength(0);
      await expect(fixture.client.read(fixture.boundary.request)).resolves.toMatchObject({
        data: { outcome: 'COMPLETE' },
      });
      expect(fixture.endpoint.calls()).toHaveLength(1);
    },
  );

  it('rejects an absent client certificate before endpoint application handling', async () => {
    const fixture = await systemFixture();
    await expect(
      directRequest(fixture.endpoint, {
        path: gate3EndpointPaths.read,
        useAcceptedClient: false,
      }),
    ).rejects.toThrow();
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('rejects an undeclared envelope without consuming the declared read vector', async () => {
    const fixture = await systemFixture();
    await expect(directRequest(fixture.endpoint, { path: gate3EndpointPaths.read })).resolves.toBe(
      400,
    );
    expect(fixture.endpoint.calls()).toHaveLength(0);
    await expect(fixture.client.read(fixture.boundary.request)).resolves.toMatchObject({
      data: { outcome: 'COMPLETE' },
    });
    expect(fixture.endpoint.calls()).toHaveLength(1);
  });

  it('rejects a CA-signed but unadmitted client identity before HTTP handling', async () => {
    const fixture = await systemFixture();
    await expect(
      rejectedTlsRequest(fixture.endpoint, {
        certificate: fixture.endpoint.wrongClientCertificatePem,
        privateKey: fixture.endpoint.wrongClientPrivateKeyPem,
      }),
    ).rejects.toThrow();
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('rejects a CA-signed same-CN certificate with a different key before HTTP handling', async () => {
    const fixture = await systemFixture();
    await expect(
      rejectedTlsRequest(fixture.endpoint, {
        certificate: fixture.endpoint.sameNameWrongClientCertificatePem,
        privateKey: fixture.endpoint.sameNameWrongClientPrivateKeyPem,
      }),
    ).rejects.toThrow();
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it.each([
    [
      'untrusted client CA',
      (endpoint: Gate3ConformantEndpoint) => ({
        certificate: endpoint.untrustedClientCertificatePem,
        privateKey: endpoint.untrustedClientPrivateKeyPem,
      }),
    ],
    ['TLS downgrade', () => ({ maximumVersion: 'TLSv1.2' as const })],
    ['wrong server SAN', () => ({ servername: 'localhost' })],
  ] as const)('rejects %s before vector consumption', async (_name, select) => {
    const fixture = await systemFixture();
    await expect(rejectedTlsRequest(fixture.endpoint, select(fixture.endpoint))).rejects.toThrow();
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('rejects plain HTTP before endpoint vector consumption', async () => {
    const fixture = await systemFixture();
    const url = new URL(fixture.endpoint.origin);
    await expect(
      new Promise<void>((resolve, reject) => {
        const request = httpRequest(
          {
            host: url.hostname,
            port: url.port,
            path: gate3EndpointPaths.read,
            method: 'POST',
          },
          (response) => {
            response.resume();
            response.once('end', resolve);
          },
        );
        request.once('error', reject);
        request.end('{}');
      }),
    ).rejects.toThrow();
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('exposes only the exact loopback server SAN', async () => {
    const fixture = await systemFixture();
    expect(new X509Certificate(fixture.endpoint.serverCertificatePem).subjectAltName).toBe(
      'IP Address:127.0.0.1',
    );
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  const validVector = (path: string): Gate3WireVector => ({
    path,
    expectedBody: Buffer.from('{}'),
    statusCode: 204,
    contentType: 'application/json',
    body: Buffer.from('{}'),
    maximumCalls: 1,
  });

  it('rejects a proxied endpoint vector without invoking its traps', async () => {
    let traps = 0;
    const proxy = new Proxy(validVector(gate3EndpointPaths.read), {
      get() {
        traps += 1;
        throw new Error('proxy get trap invoked');
      },
      ownKeys() {
        traps += 1;
        throw new Error('proxy ownKeys trap invoked');
      },
    });
    await expect(
      createGate3ConformantEndpoint([proxy, validVector(gate3EndpointPaths.verify)]),
    ).rejects.toThrow('non-proxy');
    expect(traps).toBe(0);
  });

  it('rejects an accessor endpoint vector before reading the accessor', async () => {
    const accessor = validVector(gate3EndpointPaths.read) as Record<string, unknown>;
    Object.defineProperty(accessor, 'statusCode', {
      get: () => {
        throw new Error('accessor invoked');
      },
      enumerable: true,
    });
    await expect(
      createGate3ConformantEndpoint([
        accessor as Gate3WireVector,
        validVector(gate3EndpointPaths.verify),
      ]),
    ).rejects.toThrow('own data');
  });

  it('rejects a hostile endpoint vector prototype', async () => {
    const hostile = Object.assign(
      Object.create({ hidden: true }),
      validVector(gate3EndpointPaths.read),
    );
    await expect(
      createGate3ConformantEndpoint([hostile, validVector(gate3EndpointPaths.verify)]),
    ).rejects.toThrow('prototype');
  });

  it('rejects an extra endpoint vector field', async () => {
    await expect(
      createGate3ConformantEndpoint([
        { ...validVector(gate3EndpointPaths.read), extra: true } as never,
        validVector(gate3EndpointPaths.verify),
      ]),
    ).rejects.toThrow('fields');
  });

  it('rejects an omitted endpoint vector field', async () => {
    const missing = { ...validVector(gate3EndpointPaths.read) } as Record<string, unknown>;
    delete missing.body;
    await expect(
      createGate3ConformantEndpoint([
        missing as Gate3WireVector,
        validVector(gate3EndpointPaths.verify),
      ]),
    ).rejects.toThrow('fields');
  });

  it('rejects a proxied byte vector without invoking its traps', async () => {
    let traps = 0;
    const byteProxy = new Proxy(Buffer.from('{}'), {
      get() {
        traps += 1;
        throw new Error('byte proxy get trap invoked');
      },
      getPrototypeOf() {
        traps += 1;
        throw new Error('byte proxy prototype trap invoked');
      },
      ownKeys() {
        traps += 1;
        throw new Error('byte proxy ownKeys trap invoked');
      },
    });
    await expect(
      createGate3ConformantEndpoint([
        { ...validVector(gate3EndpointPaths.read), body: byteProxy },
        validVector(gate3EndpointPaths.verify),
      ]),
    ).rejects.toThrow('exact built-in byte array');
    expect(traps).toBe(0);
  });

  it('rejects a byte-array subclass before invoking its iterator', async () => {
    class HostileBytes extends Uint8Array {
      override [Symbol.iterator](): ArrayIterator<number> {
        throw new Error('hostile iterator invoked');
      }
    }
    await expect(
      createGate3ConformantEndpoint([
        { ...validVector(gate3EndpointPaths.read), body: new HostileBytes([1, 2]) },
        validVector(gate3EndpointPaths.verify),
      ]),
    ).rejects.toThrow('exact built-in byte array');
  });

  it('rejects an own symbol on endpoint byte vectors', async () => {
    const symbolBytes = Buffer.from('{}') as Uint8Array & { [key: symbol]: boolean };
    symbolBytes[Symbol('hidden')] = true;
    await expect(
      createGate3ConformantEndpoint([
        { ...validVector(gate3EndpointPaths.read), body: symbolBytes },
        validVector(gate3EndpointPaths.verify),
      ]),
    ).rejects.toThrow('overrides are forbidden');
  });

  it('rejects an own byte-vector iterator before invoking it', async () => {
    const iteratorBytes = Buffer.from('{}');
    Object.defineProperty(iteratorBytes, Symbol.iterator, {
      value: () => {
        throw new Error('own iterator invoked');
      },
    });
    await expect(
      createGate3ConformantEndpoint([
        { ...validVector(gate3EndpointPaths.read), body: iteratorBytes },
        validVector(gate3EndpointPaths.verify),
      ]),
    ).rejects.toThrow('overrides are forbidden');
  });

  it('rejects an absent B01 Accept header without consuming the vector', async () => {
    const endpoint = await createGate3ConformantEndpoint([
      validVector(gate3EndpointPaths.read),
      validVector(gate3EndpointPaths.verify),
    ]);
    resources.push({ endpoint });
    await expect(
      directRequest(endpoint, { path: gate3EndpointPaths.read, omitAccept: true }),
    ).resolves.toBe(400);
    expect(endpoint.calls()).toHaveLength(0);
  });

  it('rejects a forbidden authorization header without consuming the vector', async () => {
    const endpoint = await createGate3ConformantEndpoint([
      validVector(gate3EndpointPaths.read),
      validVector(gate3EndpointPaths.verify),
    ]);
    resources.push({ endpoint });
    await expect(
      directRequest(endpoint, {
        path: gate3EndpointPaths.read,
        extraHeaders: { authorization: 'Bearer forbidden' },
      }),
    ).resolves.toBe(400);
    expect(endpoint.calls()).toHaveLength(0);
  });

  it('copies request and response bytes before caller mutation', async () => {
    const requestBytes = Buffer.from('{}');
    const responseBytes = Buffer.from('{}');
    const readVector = {
      ...validVector(gate3EndpointPaths.read),
      expectedBody: requestBytes,
      body: responseBytes,
    };
    const endpoint = await createGate3ConformantEndpoint([
      readVector,
      validVector(gate3EndpointPaths.verify),
    ]);
    resources.push({ endpoint });
    requestBytes.fill(0x78);
    responseBytes.fill(0x78);
    readVector.statusCode = 500;
    readVector.contentType = 'text/plain';
    expect(await directRequest(endpoint, { path: gate3EndpointPaths.read })).toBe(204);
    expect(endpoint.calls()).toHaveLength(1);
  });
  it('returns the original append-once evidence receipt on exact sink replay', async () => {
    const sink = createAppendOnceEvidenceSink();
    const record = {
      occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
      scopeDigest: `sha256:${'a'.repeat(64)}`,
      resultDigest: `sha256:${'b'.repeat(64)}`,
    };
    const firstReceipt = await sink.port.append(record);
    const replayReceipt = await sink.port.append(structuredClone(record));
    expect(replayReceipt).toBe(firstReceipt);
    expect(sink.snapshot()).toHaveLength(1);
  });

  it('suppresses an exact public replay after one accepted evidence write', async () => {
    const fixture = await systemFixture();
    const first = await fixture.client.read(fixture.boundary.request);
    const second = await fixture.client.read(fixture.boundary.request);
    expect(first).toHaveProperty('data');
    expect(second.problem).toMatchObject({ code: 'PC-RUNTIME-3010' });
    expect(fixture.evidence()).toHaveLength(1);
    expect(fixture.endpoint.calls()).toHaveLength(1);
  });

  it('retains the first occurrence and returns conflict for different evidence', async () => {
    const sink = createAppendOnceEvidenceSink();
    const record = {
      occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
      scopeDigest: `sha256:${'a'.repeat(64)}`,
      resultDigest: `sha256:${'b'.repeat(64)}`,
    };
    const first = await sink.port.append(record);
    const conflict = await sink.port.append({
      ...record,
      resultDigest: `sha256:${'c'.repeat(64)}`,
    });
    expect(first).toMatchObject({ outcome: 'ACCEPTED' });
    expect(conflict).toMatchObject({ outcome: 'CONFLICT' });
    expect(sink.snapshot()).toEqual([record]);
  });

  it.each(['REJECT', 'TIMEOUT', 'MALFORMED'] as const)(
    'fails closed when the evidence sink mode is %s',
    async (evidenceFailure) => {
      const fixture = await systemFixture({
        evidenceFailure,
        maximumSinkWaitMilliseconds: 20,
      });
      const result = await fixture.client.read(fixture.boundary.request);
      expect(result.problem).toMatchObject({ disclosure: 'NON_LEAKING_INVARIANT' });
      expect(fixture.evidence()).toHaveLength(0);
    },
  );

  it('fails closed when the admission audit rejects', async () => {
    const fixture = await systemFixture({ auditFailurePhase: 'ADMISSION_REJECTED' });
    const response = await fetch(`${fixture.baseUrl}/v1/privacy-explorer/projections:read`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(response.status).toBe(503);
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('fails closed when the execution audit rejects after a malformed provider response', async () => {
    const fixture = await systemFixture({
      auditFailurePhase: 'EXECUTION_REJECTED',
    });
    await fixture.endpoint.close();
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result.problem).toMatchObject({
      httpStatus: 503,
      disclosure: 'NON_LEAKING_INVARIANT',
    });
    expect(fixture.endpoint.calls()).toHaveLength(0);
    expect(fixture.evidence()).toHaveLength(1);
  });

  it.each(['DELAYED', 'LATE_CHUNKS'] as const)(
    'owns and completes the %s response timer/stream mode',
    async (responseMode) => {
      const fixture = await systemFixture({ responseMode, delayMilliseconds: 10 });
      await expect(fixture.client.read(fixture.boundary.request)).resolves.toMatchObject({
        data: { outcome: 'COMPLETE' },
      });
      expect(fixture.endpoint.calls()).toHaveLength(1);
      expect(fixture.endpoint.pendingTimerCount()).toBe(0);
    },
  );

  it.each([
    [
      'STALE',
      502,
      'PC-RUNTIME-3009',
      -32009,
      'FAILED_PRECONDITION',
      'FAILED',
      'The service is unavailable',
    ],
    [
      'REORG',
      502,
      'PC-RUNTIME-3009',
      -32009,
      'FAILED_PRECONDITION',
      'FAILED',
      'The service is unavailable',
    ],
    [
      'CONFLICT',
      409,
      'PC-RUNTIME-3011',
      -32011,
      'FAILED_PRECONDITION',
      'CONFLICTING',
      'The request conflicts with current state',
    ],
  ] as const)(
    'preserves the registered %s wire outcome',
    async (_name, status, code, jsonRpcCode, grpcStatus, truthState, publicTitle) => {
      const problem = {
        code,
        httpStatus: status,
        jsonRpcCode,
        grpcStatus,
        truthState,
        retryable: false,
        disclosure: 'NON_LEAKING_INVARIANT',
        publicTitle,
      };
      const fixture = await systemFixture({
        readStatusCode: status,
        readBody: Buffer.from(JSON.stringify(problem)),
      });
      const result = await fixture.client.read(fixture.boundary.request);
      expect(result.problem).toMatchObject({ code, httpStatus: status });
    },
  );

  it('cancels a never-settling endpoint and owns every pending timer and socket', async () => {
    const controller = new AbortController();
    const fixture = await systemFixture({
      responseMode: 'NEVER_SETTLE',
      clientSignal: controller.signal,
    });
    const pending = fixture.client.read(fixture.boundary.request);
    setTimeout(() => controller.abort(), 20);
    await expect(pending).rejects.toThrow();
    expect(fixture.endpoint.calls()).toHaveLength(1);
    await fixture.app?.close?.();
    await fixture.endpoint.close();
    expect(fixture.endpoint.pendingTimerCount()).toBe(0);
    expect(fixture.endpoint.openSocketCount()).toBe(0);
  });

  it.each(Array.from({ length: 9 }, (_, operationIndex) => [operationIndex] as const))(
    'executes registered operation index %s through the public client and mTLS boundary',
    async (operationIndex) => {
      const fixture = await systemFixture({ operationIndex });
      await expect(fixture.client.read(fixture.boundary.request)).resolves.toMatchObject({
        data: { outcome: 'COMPLETE' },
      });
      expect(fixture.endpoint.calls()).toHaveLength(1);
      await fixture.app.close();
      await fixture.endpoint.close();
    },
  );

  it('closes immutable predecessor, claim-ceiling, telemetry, and full-gate joins', () => {
    const publicCanary = 'OPENPC-G3-RAW-CANARY-DO-NOT-RELEASE';
    const publicSources = [
      createPrivacyExplorerClient.toString(),
      gate3EndpointPaths.read,
      gate3EndpointPaths.verify,
    ].join('\n');
    expect(publicSources).not.toContain(publicCanary);
    const immutable = {
      'services/control-api/src/privacy-explorer/http-consumer.ts':
        'ee171c3ecff038f4db4010bb79dd9fd6c45addac0608088dcebffc10164c56cf',
      'services/control-api/src/privacy-explorer/http-admission.ts':
        'f66577de878851486cb5f9994290be3166e2f2dd76b71425e51676ae90461c84',
      'services/control-api/src/privacy-explorer/http-delivery.ts':
        '3a8be3afab5fb0dd2c257f46d9e4957d64dbb88bc8014a8f44e3b77898da6da7',
      'services/control-api/src/privacy-explorer/evidence-sink.ts':
        'a72c1ad643095d35bc4b329ca286b42dc96d2ad9036461559d53a84559a070d2',
      'services/control-api/src/privacy-explorer/service.ts':
        'c4a121d52bf10282cf5d60ea267d1b631bbd4ee4129bbba08dabdf7d43b53503',
      'packages/api-client/src/privacy-explorer.ts':
        '6545074d2b845f7691d816d7228fdc06ccf51b2e94d92cf335a7b1298fc78a0b',
    };
    return Promise.all(
      Object.entries(immutable).map(async ([path, digest]) =>
        expect(
          createHash('sha256')
            .update(await readFile(path))
            .digest('hex'),
        ).toBe(digest),
      ),
    ).then(() => undefined);
  });

  it('keeps the private-material root external with mode 0700', async () => {
    const fixture = await systemFixture();
    expect(fixture.endpoint.privateMaterialRoot.startsWith(process.env.OPENPC_PNC_TMP_ROOT!)).toBe(
      true,
    );
    expect((await stat(fixture.endpoint.privateMaterialRoot)).mode & 0o777).toBe(0o700);
  });

  it('keeps every private key file at mode 0600', async () => {
    const fixture = await systemFixture();
    for (const name of [
      'ca.key',
      'server.key',
      'client.key',
      'wrong-client.key',
      'same-name-wrong-client.key',
      'untrusted-client.key',
    ]) {
      expect((await stat(join(fixture.endpoint.privateMaterialRoot, name))).mode & 0o777).toBe(
        0o600,
      );
    }
  });

  it('zeroes every exposed private-key byte on close', async () => {
    const fixture = await systemFixture();
    const exposedPrivateKeys = [
      fixture.endpoint.acceptedClientPrivateKeyPem,
      fixture.endpoint.wrongClientPrivateKeyPem,
      fixture.endpoint.sameNameWrongClientPrivateKeyPem,
      fixture.endpoint.untrustedClientPrivateKeyPem,
    ];
    await fixture.endpoint.close();
    expect(exposedPrivateKeys.every((key) => key.every((byte) => byte === 0))).toBe(true);
  });

  it('removes the private root and all endpoint timers and sockets on close', async () => {
    const fixture = await systemFixture();
    await fixture.endpoint.close();
    await expect(stat(fixture.endpoint.privateMaterialRoot)).rejects.toMatchObject({
      code: 'ENOENT',
    });
    expect(fixture.endpoint.pendingTimerCount()).toBe(0);
    expect(fixture.endpoint.openSocketCount()).toBe(0);
  });

  it('audits and emits admission suppression when the client disconnects during session resolution', async () => {
    const fixture = await systemFixture({ sessionMode: 'NEVER_SETTLE' });
    await disconnectDuringSessionResolution(fixture);
    await waitUntil(() => fixture.audit().length === 1, 'admission suppression audit missing');
    await waitUntil(() => fixture.events().length === 1, 'admission suppression event missing');
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('emits audit failure and no response when admission-suppression audit rejects', async () => {
    const fixture = await systemFixture({
      sessionMode: 'NEVER_SETTLE',
      auditFailurePhase: 'ADMISSION_SUPPRESSED',
    });
    await disconnectDuringSessionResolution(fixture);
    await waitUntil(() => fixture.events().length === 1, 'audit failure event missing');
    expect(fixture.audit()).toHaveLength(0);
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('audits and emits an exact service failure without provider egress', async () => {
    const fixture = await systemFixture({ serviceFailure: true });
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result.problem).toMatchObject({ httpStatus: 503, disclosure: 'NON_LEAKING_INVARIANT' });
    expect(fixture.audit()).toHaveLength(1);
    expect(fixture.events()).toHaveLength(1);
    expect(fixture.evidence()).toHaveLength(0);
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it.each(['SYNCHRONOUS', 'ASYNCHRONOUS'] as const)(
    'contains an %s event-sink failure after an accepted public result',
    async (eventFailure) => {
      const fixture = await systemFixture({ eventFailure });
      await expect(fixture.client.read(fixture.boundary.request)).resolves.toMatchObject({
        data: { outcome: 'COMPLETE' },
      });
      expect(fixture.evidence()).toHaveLength(1);
      expect(fixture.events()).toHaveLength(1);
    },
  );

  it('contains trailing JSON bytes as an exact non-leaking problem', async () => {
    const prepared = boundaryFixture();
    const fixture = await systemFixture({
      readBody: Buffer.from(`${JSON.stringify(prepared.projection)}{}`),
    });
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result.problem).toMatchObject({ code: 'PC-DATA-6001' });
  });

  it('contains an unknown top-level provider member as an exact non-leaking problem', async () => {
    const prepared = boundaryFixture();
    const readBody = Buffer.from(JSON.stringify({ ...prepared.projection, unknown: true }));
    const fixture = await systemFixture({ readBody });
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result.problem).toMatchObject({ disclosure: 'NON_LEAKING_INVARIANT' });
  });

  it('contains a poisonous provider key as an exact non-leaking problem', async () => {
    const fixture = await systemFixture({
      readBody: Buffer.from('{"__proto__":{"polluted":true}}'),
    });
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result.problem).toMatchObject({ disclosure: 'NON_LEAKING_INVARIANT' });
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
  });

  it('keeps a forbidden provider-field canary out of every retained and public sink', async () => {
    const canary = 'OPENPC-G3-FORBIDDEN-FIELD-CANARY';
    const prepared = boundaryFixture();
    const preimage = {
      ...prepared.projection,
      records: [{ id: 'record-a', fields: [{ fieldId: 'PEF-HIDDEN', value: canary }] }],
    } as Record<string, unknown>;
    delete preimage.responseDigest;
    const readBody = Buffer.from(
      JSON.stringify({ ...preimage, responseDigest: independentDigest(preimage) }),
    );
    const fixture = await systemFixture({ readBody });
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result.problem).toMatchObject({ disclosure: 'NON_LEAKING_INVARIANT' });
    expect(
      JSON.stringify({
        result,
        evidence: fixture.evidence(),
        audit: fixture.audit(),
        events: fixture.events(),
      }),
    ).not.toContain(canary);
  });

  it('accepts a valid Explorer response at the exact response-byte cap', async () => {
    const prepared = boundaryFixture();
    const readBody = Buffer.from(JSON.stringify(prepared.projection));
    const fixture = await systemFixture({ readBody, responseByteLimit: readBody.byteLength });
    await expect(fixture.client.read(fixture.boundary.request)).resolves.toMatchObject({
      data: { outcome: 'COMPLETE' },
    });
    expect(fixture.endpoint.calls()).toHaveLength(1);
  });

  it('contains a controlled many-chunk response-byte overflow without partial release', async () => {
    const prepared = boundaryFixture();
    const validPrefix = Buffer.from(JSON.stringify(prepared.projection));
    const readBody = Buffer.concat([validPrefix, Buffer.alloc(4_096, 0x20)]);
    const fixture = await systemFixture({
      readBody,
      responseByteLimit: validPrefix.byteLength + 127,
      responseMode: 'MANY_CHUNKS',
      responseChunkBytes: 64,
    });
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result.problem).toMatchObject({ disclosure: 'NON_LEAKING_INVARIANT' });
    expect(result).not.toHaveProperty('data');
  });

  it.each([
    [
      'filter',
      (value: string) =>
        value.replace(
          '"fieldId":"PEF-A","filterId":"PEFILTER-A"',
          '"fieldId":"PEF-A","fieldId":"OTHER","filterId":"PEFILTER-A"',
        ),
    ],
    ['page', (value: string) => value.replace('"page":{"limit":2', '"page":{"limit":2,"limit":3')],
    [
      'exportProfile',
      (value: string) =>
        value.replace(
          '"exportProfile":{"id":"local-qualified-profile"',
          '"exportProfile":{"id":"local-qualified-profile","id":"other"',
        ),
    ],
    [
      'operation version entry',
      (value: string) =>
        value.replace(
          '"operationVersions":[{"operationId":"OP-01"',
          '"operationVersions":[{"operationId":"OP-01","operationId":"OP-X"',
        ),
    ],
    [
      'occurrence',
      (value: string) =>
        value.replace(
          '"occurrence":{"requestId":"123e4567-e89b-42d3-a456-426614174101"',
          '"occurrence":{"requestId":"123e4567-e89b-42d3-a456-426614174101","requestId":"123e4567-e89b-42d3-a456-426614174199"',
        ),
    ],
  ] as const)(
    'rejects a duplicate member in the inbound %s object before fetch',
    async (_name, mutate) => {
      const fixture = await systemFixture();
      const serialized = JSON.stringify(fixture.boundary.request);
      const body = mutate(serialized);
      expect(body).not.toBe(serialized);
      const response = await fetch(`${fixture.baseUrl}/v1/privacy-explorer/projections:read`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'cookie': '__Host-openpc_session=session-a',
        },
        body,
      });
      expect(response.status).toBe(400);
      expect(fixture.endpoint.calls()).toHaveLength(0);
    },
  );

  it.each([
    [
      'record',
      (value: string) =>
        value.replace('"records":[{"id":"record-a"', '"records":[{"id":"record-a","id":"other"'),
    ],
    [
      'field',
      (value: string) =>
        value.replace(
          '"fields":[{"fieldId":"PEF-A"',
          '"fields":[{"fieldId":"PEF-A","fieldId":"PEF-B"',
        ),
    ],
    [
      'page',
      (value: string) =>
        value.replace('"page":{"cursor":null', '"page":{"cursor":null,"cursor":"other"'),
    ],
  ] as const)('rejects a duplicate member in the outbound %s object', async (_name, mutate) => {
    const prepared = boundaryFixture();
    const serialized = JSON.stringify(prepared.projection);
    const readBody = Buffer.from(mutate(serialized));
    expect(readBody.toString('utf8')).not.toBe(serialized);
    const fixture = await systemFixture({ readBody });
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result.problem).toMatchObject({ disclosure: 'NON_LEAKING_INVARIANT' });
  });

  it.each([
    ['empty session', '__Host-openpc_session='],
    ['duplicate session', '__Host-openpc_session=session-a; __Host-openpc_session=session-b'],
    ['malformed session', '__Host-openpc_session=session a'],
    ['invalid session', '__Host-openpc_session=unknown'],
  ] as const)('rejects %s before parsing or provider fetch', async (_name, cookie) => {
    const fixture = await systemFixture();
    const exchange = startPublicSocketRead(fixture, cookie);
    await exchange.completed;
    expect(fixture.endpoint.calls()).toHaveLength(0);
    expect(fixture.evidence()).toHaveLength(0);
  });

  it('contains a session resolver failure before parsing or provider fetch', async () => {
    const fixture = await systemFixture({ sessionFailure: true });
    const response = await fetch(`${fixture.baseUrl}/v1/privacy-explorer/projections:read`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
      },
      body: JSON.stringify(fixture.boundary.request),
    });
    expect(response.status).toBe(401);
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('contains a terminal verifier denial before parsing or provider fetch', async () => {
    const fixture = await systemFixture({ terminalVerifierDenial: true });
    const response = await fetch(`${fixture.baseUrl}/v1/privacy-explorer/projections:read`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
      },
      body: JSON.stringify(fixture.boundary.request),
    });
    expect(response.status).toBe(401);
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it.each([
    [
      'resource',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.resource = 'other-resource';
      },
    ],
    [
      'scope.participantId',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.scope.participantId = 'other-participant';
      },
    ],
    [
      'scope.privacyDomainId',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.scope.privacyDomainId = 'other-privacy-domain';
      },
    ],
    [
      'scope.platformId',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.scope.platformId = 'other-platform';
      },
    ],
    [
      'scope.workloadId',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.scope.workloadId = 'other-workload';
      },
    ],
    [
      'scope.action',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.scope.action = 'write';
      },
    ],
    [
      'exportProfile.digest',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.exportProfile.digest = `sha256:${'f'.repeat(64)}`;
      },
    ],
    [
      'occurrence.correlationId',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.occurrence.correlationId = '123e4567-e89b-42d3-a456-426614174199';
      },
    ],
  ] as const)(
    'rejects the remaining isolated %s assertion with zero fetch',
    async (_name, mutate) => {
      const fixture = await systemFixture();
      const request = structuredClone(fixture.boundary.request);
      mutate(request);
      await fixture.client.read(withQueryDigest(request)).then(
        (result) => expect(result.problem).toMatchObject({ disclosure: 'NON_LEAKING_INVARIANT' }),
        (error: unknown) => expect(String(error)).toContain('invalid Privacy Explorer request'),
      );
      expect(fixture.endpoint.calls()).toHaveLength(0);
      expect(fixture.evidence()).toHaveLength(0);
    },
  );

  it.each([
    [
      'future issuedAt',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.issuedAt = '2099-01-01T00:00:00.002Z';
      },
      undefined,
    ],
    [
      'stale issuedAt',
      (request: ReturnType<typeof boundaryFixture>['boundary']['request']) => {
        request.issuedAt = '2098-12-31T23:58:59.999Z';
      },
      undefined,
    ],
    [
      'expired server deadline',
      (_request: ReturnType<typeof boundaryFixture>['boundary']['request']) => undefined,
      '2099-01-01T00:00:00.000Z',
    ],
  ] as const)(
    'rejects the trusted-time %s boundary with zero fetch',
    async (_name, mutate, serverMaximumDeadlineAt) => {
      const fixture = await systemFixture({
        ...(serverMaximumDeadlineAt ? { serverMaximumDeadlineAt } : {}),
      });
      const request = structuredClone(fixture.boundary.request);
      mutate(request);
      const response = await fetch(`${fixture.baseUrl}/v1/privacy-explorer/projections:read`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'cookie': '__Host-openpc_session=session-a',
        },
        body: JSON.stringify(request),
      });
      expect(response.status).toBe(400);
      expect(fixture.endpoint.calls()).toHaveLength(0);
    },
  );

  it('rejects a caller cursor reconciliation mutation with zero fetch', async () => {
    const fixture = await systemFixture();
    const request = structuredClone(fixture.boundary.request);
    request.page.cursor = 'caller-selected-cursor';
    const response = await fetch(`${fixture.baseUrl}/v1/privacy-explorer/projections:read`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cookie': '__Host-openpc_session=session-a',
      },
      body: JSON.stringify(request),
    });
    expect(response.status).toBe(503);
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('rejects an already-cancelled public call with zero fetch', async () => {
    const controller = new AbortController();
    controller.abort();
    const fixture = await systemFixture({ clientSignal: controller.signal });
    await expect(fixture.client.read(fixture.boundary.request)).rejects.toThrow();
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('returns byte-identical denial for invalid hidden and nonexistent sessions', async () => {
    const resolverMissFixture = await systemFixture();
    const terminalDenialFixture = await systemFixture({ terminalVerifierDenial: true });
    const denials: Readonly<{ status: number; body: string }>[] = [];
    for (const session of ['hidden', 'nonexistent']) {
      const response = await fetch(
        `${resolverMissFixture.baseUrl}/v1/privacy-explorer/projections:read`,
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'cookie': `__Host-openpc_session=${session}`,
          },
          body: JSON.stringify(resolverMissFixture.boundary.request),
        },
      );
      denials.push(Object.freeze({ status: response.status, body: await response.text() }));
    }
    const terminalDenialResponse = await fetch(
      `${terminalDenialFixture.baseUrl}/v1/privacy-explorer/projections:read`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'cookie': '__Host-openpc_session=session-a',
        },
        body: JSON.stringify(terminalDenialFixture.boundary.request),
      },
    );
    denials.push(
      Object.freeze({
        status: terminalDenialResponse.status,
        body: await terminalDenialResponse.text(),
      }),
    );
    expect(denials[1]).toEqual(denials[0]);
    expect(denials[2]).toEqual(denials[0]);
    expect(resolverMissFixture.endpoint.calls()).toHaveLength(0);
    expect(terminalDenialFixture.endpoint.calls()).toHaveLength(0);
  });

  it('successfully redacts every provider-only field and canary from the public result', async () => {
    const fixture = await systemFixture();
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result).toHaveProperty('data');
    const publicBytes = JSON.stringify(result);
    for (const field of [
      'provenanceDigest',
      'observedAt',
      'completeness',
      'freshness',
      'conflict',
      'responseDigest',
      'validationDigest',
      'redactionDigest',
    ])
      expect(publicBytes).not.toContain(`"${field}"`);
    for (const canary of [fixture.endpoint.origin, fixture.endpoint.privateMaterialRoot])
      expect(publicBytes).not.toContain(canary);
  });

  const tlsBindingFor = (endpoint: Gate3ConformantEndpoint) =>
    createTlsClientBinding({
      transportClass: 'LOCAL_DEVELOPMENT',
      trustAnchorId: 'openpc-i07-gate3-root@v1',
      clientIdentityId: 'openpc-i07-gate3-client@v1',
      trustAnchorPem: endpoint.trustAnchorPem,
      clientCertificatePem: endpoint.acceptedClientCertificatePem,
      clientPrivateKeyPem: endpoint.acceptedClientPrivateKeyPem,
    });

  const transportInputFor = (endpoint: Gate3ConformantEndpoint) => ({
    transportClass: 'LOCAL_DEVELOPMENT',
    origin: endpoint.origin,
    exportProfileDigest: `sha256:${'a'.repeat(64)}`,
    transportProfileId: 'openpc-i07-gate3-transport@v1',
    egressPolicyId: 'openpc-i07-gate3-egress@v1',
    requestByteLimit: 65_536,
    responseByteLimit: 65_536,
    maximumJsonDepth: 16,
    tlsClientBinding: tlsBindingFor(endpoint),
  });

  it.each([
    [
      'plain HTTP origin',
      (endpoint: Gate3ConformantEndpoint) => endpoint.origin.replace('https:', 'http:'),
    ],
    [
      'wrong host origin',
      (endpoint: Gate3ConformantEndpoint) => endpoint.origin.replace('127.0.0.1', 'localhost'),
    ],
  ] as const)('rejects a %s before any network call', async (_name, origin) => {
    const endpoint = await createGate3ConformantEndpoint([
      validVector(gate3EndpointPaths.read),
      validVector(gate3EndpointPaths.verify),
    ]);
    resources.push({ endpoint });
    expect(() =>
      createPrivacyExplorerTransportProfile({
        ...transportInputFor(endpoint),
        origin: origin(endpoint),
      }),
    ).toThrow('transport origin');
    expect(endpoint.calls()).toHaveLength(0);
  });

  it('rejects a fallback transport origin field before any network call', async () => {
    const endpoint = await createGate3ConformantEndpoint([
      validVector(gate3EndpointPaths.read),
      validVector(gate3EndpointPaths.verify),
    ]);
    resources.push({ endpoint });
    expect(() =>
      createPrivacyExplorerTransportProfile({
        ...transportInputFor(endpoint),
        fallbackOrigin: 'https://127.0.0.1:65535',
      }),
    ).toThrow();
    expect(endpoint.calls()).toHaveLength(0);
  });

  it('rejects a trust-all TLS option before constructing a binding', async () => {
    const endpoint = await createGate3ConformantEndpoint([
      validVector(gate3EndpointPaths.read),
      validVector(gate3EndpointPaths.verify),
    ]);
    resources.push({ endpoint });
    expect(() =>
      createTlsClientBinding({
        transportClass: 'LOCAL_DEVELOPMENT',
        trustAnchorId: 'openpc-i07-gate3-root@v1',
        clientIdentityId: 'openpc-i07-gate3-client@v1',
        trustAnchorPem: endpoint.trustAnchorPem,
        clientCertificatePem: endpoint.acceptedClientCertificatePem,
        clientPrivateKeyPem: endpoint.acceptedClientPrivateKeyPem,
        rejectUnauthorized: false,
      }),
    ).toThrow();
  });

  it('rejects optional client authentication material before constructing a binding', async () => {
    const endpoint = await createGate3ConformantEndpoint([
      validVector(gate3EndpointPaths.read),
      validVector(gate3EndpointPaths.verify),
    ]);
    resources.push({ endpoint });
    expect(() =>
      createTlsClientBinding({
        transportClass: 'LOCAL_DEVELOPMENT',
        trustAnchorId: 'openpc-i07-gate3-root@v1',
        clientIdentityId: 'openpc-i07-gate3-client@v1',
        trustAnchorPem: endpoint.trustAnchorPem,
        clientPrivateKeyPem: endpoint.acceptedClientPrivateKeyPem,
      }),
    ).toThrow();
  });

  it('rejects a forged Host header without consuming a vector', async () => {
    const endpoint = await createGate3ConformantEndpoint([
      validVector(gate3EndpointPaths.read),
      validVector(gate3EndpointPaths.verify),
    ]);
    resources.push({ endpoint });
    await expect(
      directRequest(endpoint, {
        path: gate3EndpointPaths.read,
        extraHeaders: { host: 'localhost:1' },
      }),
    ).resolves.toBe(400);
    expect(endpoint.calls()).toHaveLength(0);
  });

  it('reports an owned loopback HTTPS-only endpoint network inventory', async () => {
    const endpoint = await createGate3ConformantEndpoint([
      validVector(gate3EndpointPaths.read),
      validVector(gate3EndpointPaths.verify),
    ]);
    resources.push({ endpoint });
    expect(endpoint.networkInventory()).toEqual({
      protocol: 'https:',
      host: '127.0.0.1',
      port: Number(new URL(endpoint.origin).port),
      paths: [gate3EndpointPaths.read, gate3EndpointPaths.verify],
    });
    expect(endpoint.openSocketCount()).toBe(0);
  });

  it('contains a forged evidence receipt before public release', async () => {
    const fixture = await systemFixture({ evidenceFailure: 'FORGED' });
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result.problem).toMatchObject({ disclosure: 'NON_LEAKING_INVARIANT' });
    expect(fixture.evidence()).toHaveLength(0);
  });

  it('contains a composed evidence conflict before public release', async () => {
    const fixture = await systemFixture({ evidenceFailure: 'CONFLICT' });
    const result = await fixture.client.read(fixture.boundary.request);
    expect(result.problem).toMatchObject({ code: 'PC-RUNTIME-3007' });
    expect(fixture.evidence()).toHaveLength(0);
  });

  it.each(['TIMEOUT', 'MALFORMED'] as const)(
    'fails closed when the admission-rejection audit mode is %s',
    async (auditFailure) => {
      const fixture = await systemFixture({
        auditFailurePhase: 'ADMISSION_REJECTED',
        auditFailure,
        maximumSinkWaitMilliseconds: 20,
      });
      const response = await fetch(`${fixture.baseUrl}/v1/privacy-explorer/projections:read`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      });
      expect(response.status).toBe(503);
      expect(fixture.endpoint.calls()).toHaveLength(0);
    },
  );

  it.each(['TIMEOUT', 'MALFORMED'] as const)(
    'fails closed when the admission-suppression audit mode is %s',
    async (auditFailure) => {
      const fixture = await systemFixture({
        sessionMode: 'NEVER_SETTLE',
        auditFailurePhase: 'ADMISSION_SUPPRESSED',
        auditFailure,
        maximumSinkWaitMilliseconds: 20,
      });
      await disconnectDuringSessionResolution(fixture);
      await waitUntil(() => fixture.events().length === 1, 'admission audit event missing');
      expect(fixture.endpoint.calls()).toHaveLength(0);
    },
  );

  it.each(['TIMEOUT', 'MALFORMED'] as const)(
    'fails closed when the execution-rejection audit mode is %s',
    async (auditFailure) => {
      const fixture = await systemFixture({
        serviceFailure: true,
        auditFailurePhase: 'EXECUTION_REJECTED',
        auditFailure,
        maximumSinkWaitMilliseconds: 20,
      });
      const result = await fixture.client.read(fixture.boundary.request);
      expect(result.problem).toMatchObject({ httpStatus: 503 });
      expect(fixture.endpoint.calls()).toHaveLength(0);
    },
  );

  it('suppresses cancellation before provider dispatch', async () => {
    const fixture = await systemFixture({ phaseGate: 'BEFORE_DISPATCH' });
    const exchange = startPublicSocketRead(fixture);
    await fixture.phaseEntered;
    exchange.request.destroy();
    await fixture.abortObserved;
    fixture.releasePhase();
    await exchange.completed;
    await waitUntil(() => fixture.events().length === 1, 'before-dispatch suppression missing');
    expect(fixture.endpoint.calls()).toHaveLength(0);
  });

  it('suppresses cancellation during TLS transport', async () => {
    const fixture = await systemFixture({ responseMode: 'NEVER_SETTLE' });
    const exchange = startPublicSocketRead(fixture);
    await waitUntil(() => fixture.endpoint.calls().length === 1, 'TLS dispatch did not begin');
    exchange.request.destroy();
    await exchange.completed;
    await waitUntil(() => fixture.events().length === 1, 'TLS suppression missing');
    await waitUntil(
      () => fixture.endpoint.openSocketCount() === 0,
      'cancelled read transport socket remained open',
    );
    expect(fixture.endpoint.pendingTimerCount()).toBe(0);
    expect(fixture.endpoint.calls()).toHaveLength(1);
    expect(fixture.evidence()).toHaveLength(1);
    expect(fixture.audit()).toHaveLength(0);
    expect(fixture.events()).toHaveLength(1);

    const verification = await systemFixture({ verifyResponseMode: 'NEVER_SETTLE' });
    const controller = new AbortController();
    const pendingVerification = verifyEvidenceReference(
      verification.port,
      verification.verificationBoundary,
      { signal: controller.signal },
    );
    await waitUntil(
      () => verification.endpoint.calls().length === 1,
      'evidence verification TLS dispatch did not begin',
    );
    controller.abort();
    await expect(pendingVerification).rejects.toMatchObject({
      name: 'AbortError',
      occurrenceId: verification.reference.occurrenceId,
    });
    await waitUntil(
      () => verification.endpoint.openSocketCount() === 0,
      'cancelled evidence verification transport socket remained open',
    );
    expect(verification.endpoint.pendingTimerCount()).toBe(0);
    expect(verification.endpoint.calls()).toHaveLength(1);
    expect(verification.evidence()).toHaveLength(0);
    expect(verification.audit()).toHaveLength(0);
    expect(verification.events()).toHaveLength(0);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(fixture.endpoint.calls()).toHaveLength(1);
    expect(verification.endpoint.calls()).toHaveLength(1);
    expect(fixture.evidence()).toHaveLength(1);
    expect(verification.evidence()).toHaveLength(0);
  });

  it('suppresses cancellation after response bytes and before validation', async () => {
    const fixture = await systemFixture({ responseMode: 'LATE_CHUNKS', delayMilliseconds: 200 });
    const exchange = startPublicSocketRead(fixture);
    await waitUntil(
      () => fixture.endpoint.startedResponseCount() === 1,
      'endpoint response bytes did not begin',
    );
    exchange.request.destroy();
    await fixture.abortObserved;
    await exchange.completed;
    await waitUntil(() => fixture.events().length === 1, 'post-byte suppression missing');
    expect(fixture.endpoint.calls()).toHaveLength(1);
  });

  it('suppresses cancellation after validation and before evidence', async () => {
    const fixture = await systemFixture({ phaseGate: 'AFTER_VALIDATION' });
    const exchange = startPublicSocketRead(fixture);
    await fixture.phaseEntered;
    exchange.request.destroy();
    await fixture.abortObserved;
    fixture.releasePhase();
    await exchange.completed;
    await waitUntil(() => fixture.events().length === 1, 'post-validation suppression missing');
    expect(fixture.evidence()).toHaveLength(0);
  });

  it('suppresses cancellation during evidence acceptance', async () => {
    const fixture = await systemFixture({ phaseGate: 'DURING_EVIDENCE' });
    const exchange = startPublicSocketRead(fixture);
    await fixture.phaseEntered;
    exchange.request.destroy();
    await fixture.abortObserved;
    fixture.releasePhase();
    await exchange.completed;
    await waitUntil(() => fixture.events().length === 1, 'evidence-phase suppression missing');
    expect(fixture.endpoint.calls()).toHaveLength(1);
  });

  it('suppresses after accepted evidence and before public send', async () => {
    const holder: { request?: ReturnType<typeof httpRequest> } = {};
    const fixture = await systemFixture({
      onEvidenceAccepted: () => holder.request?.destroy(),
      waitForAbortAfterEvidenceAccepted: true,
    });
    const exchange = startPublicSocketRead(fixture);
    holder.request = exchange.request;
    await exchange.completed;
    await waitUntil(() => fixture.events().length === 1, 'accepted-sink suppression missing');
    expect(fixture.evidence()).toHaveLength(1);
  });

  it('owns transport cleanup when the client disconnects after public bytes are sent', async () => {
    const fixture = await systemFixture();
    const exchange = startPublicSocketRead(fixture);
    await exchange.firstByteReceived;
    exchange.request.destroy();
    await exchange.completed;
    expect(fixture.evidence()).toHaveLength(1);
    expect(fixture.endpoint.calls()).toHaveLength(1);
  });

  it('suppresses a late-chunk transport after the client disconnects', async () => {
    const fixture = await systemFixture({ responseMode: 'LATE_CHUNKS', delayMilliseconds: 200 });
    const exchange = startPublicSocketRead(fixture);
    await waitUntil(() => fixture.endpoint.calls().length === 1, 'late response did not begin');
    exchange.request.destroy();
    await exchange.completed;
    await waitUntil(() => fixture.events().length === 1, 'late response suppression missing');
  });

  registerGate3AtomicCases({ it: vitestIt, afterAll }, ({ id }: { id: string }) =>
    executeAtomicBody(id),
  );
});
