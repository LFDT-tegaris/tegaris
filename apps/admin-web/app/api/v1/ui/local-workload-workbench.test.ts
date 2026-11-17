import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  authenticated,
  identityCsrf,
  localRuntimeConfig,
  type IdentitySession,
} from './local-runtime';
import { digest, participantAction } from './local-governance-api';
import { mutateWorkloadWorkbench, readWorkloadWorkbench } from './local-workload-workbench';
import { discoveryCertificateRecoveryReceiptView } from '../../../../../../services/identity-service/src/contracts/discovery-certificate-recovery';
import { trustFixture } from '../../../../../../services/identity-service/src/domain/discovery-certificate-recovery.test-fixture';

vi.mock('./local-runtime', async (original) => ({
  ...(await original<typeof import('./local-runtime')>()),
  authenticated: vi.fn(),
  identityCsrf: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));

const id = (n: string) => `018f0000-0000-7000-8000-${n.padStart(12, '0')}`;
const actor: IdentitySession = {
  sessionId: id('701'),
  sessionToken: 'test-session',
  principalId: id('111'),
  participantId: id('101'),
  privacyDomainId: id('201'),
  contextEpoch: '2',
  contextMode: 'PARTICIPANT',
  role: 'operator',
  stepUpVerifiedAt: null,
};
const candidate = {
  credentialId: id('192'),
  participantId: actor.participantId,
  principalId: id('190'),
  workloadId: `urn:openpc:workload:${id('191')}`,
  publicKeySpkiDer: 'cHVibGljLWtleQ==',
};
const candidateDigest = digest(candidate);
const approvalId = id('801');
const approval = {
  approvalRequestId: `urn:openpc:resource:${approvalId}`,
  actionIntentId: participantAction.id,
  candidateDigest,
  state: 'APPROVED',
  makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
  checkerSubjectRef: `urn:openpc:resource:${id('112')}`,
  revision: '2',
  createdAt: '2026-10-08T00:00:00.000Z',
  updatedAt: '2026-10-08T00:00:00.000Z',
};
const proposal = {
  candidateDigest,
  resourceId: candidate.credentialId,
  makerPrincipalId: actor.principalId,
  catalogOperationId: 'ID-OP-WORKLOAD-ISSUE',
  expectedRevision: '0',
  state: 'CONSUMED',
  operationId: id('850'),
  expiresAt: '2026-10-08T00:15:00.000Z',
  candidate,
  approval: { approvalRequestId: approvalId, reason: 'Authorize this workload certificate.' },
};
function request(query: string) {
  return new NextRequest(`http://localhost/api/v1/ui/workload-workbench?${query}`);
}
function owners(detail: unknown = proposal, current: unknown = approval) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    const path = new URL(String(url)).pathname;
    if (path.includes('/workload-proposals/')) return Response.json(detail);
    if (path.includes('/approval-requests/')) return Response.json(current);
    throw new Error('Unexpected owner or catalogue read');
  });
}
beforeEach(() => {
  vi.mocked(authenticated).mockReset().mockResolvedValue(actor);
  vi.mocked(identityCsrf).mockReset().mockResolvedValue('test-csrf');
  vi.mocked(localRuntimeConfig).mockResolvedValue({
    publicApiUrl: 'http://gateway:8080',
    identityUrl: 'http://identity:3001',
    factUrl: 'http://fact:8081',
    policyUrl: 'http://policy:3002',
    oidcAuthorizationUrl: 'http://oidc/authorize',
    identityToken: 'test',
    factToken: 'test',
    policyToken: 'test',
    cookieKey: Buffer.alloc(32),
  });
});
afterEach(() => vi.restoreAllMocks());

it.each(['maker', 'unassigned', 'same-maker-checker'])(
  'rejects the %s before reading a workload proposal or issuing approval',
  async (selection) => {
    const caller = selection === 'unassigned' ? { ...actor, principalId: id('113') } : actor;
    vi.mocked(authenticated).mockResolvedValue(caller);
    const current = {
      ...approval,
      state: 'REQUESTED',
      revision: '1',
      ...(selection === 'same-maker-checker'
        ? { checkerSubjectRef: approval.makerSubjectRef }
        : {}),
    };
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      expect(new URL(String(url)).pathname).toBe(
        `/api/v1/approval-requests/${encodeURIComponent(current.approvalRequestId)}`,
      );
      return Response.json(current);
    });
    const response = await mutateWorkloadWorkbench(
      new NextRequest('http://localhost/api/v1/ui/workload-workbench', {
        method: 'POST',
        headers: {
          'host': 'localhost',
          'origin': 'http://localhost',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          command: 'APPROVE',
          approvalRequestId: approvalId,
          candidateDigest,
          expectedRevision: '1',
        }),
      }),
    );
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({ code: 'PC-AUTH-0005', retryable: false });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(vi.mocked(identityCsrf)).not.toHaveBeenCalled();
  },
);

it('retains native proposal validation and reconciliation for the assigned checker', async () => {
  vi.mocked(authenticated).mockResolvedValue({ ...actor, principalId: id('112'), role: 'viewer' });
  const fetcher = owners({ ...proposal, expiresAt: new Date(Date.now() + 600_000).toISOString() });
  const response = await mutateWorkloadWorkbench(
    new NextRequest('http://localhost/api/v1/ui/workload-workbench', {
      method: 'POST',
      headers: {
        'host': 'localhost',
        'origin': 'http://localhost',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        command: 'APPROVE',
        approvalRequestId: approvalId,
        candidateDigest,
        expectedRevision: '2',
      }),
    }),
  );
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({ reconciled: true, approval });
  expect(fetcher).toHaveBeenCalledTimes(3);
  expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});

it.each(['PROPOSED', 'CONSUMED'])(
  'reads exact %s original without catalogue discovery or a mutation',
  async (state) => {
    const fetcher = owners({
      ...proposal,
      state,
      operationId: state === 'CONSUMED' ? id('850') : null,
    });
    const response = await readWorkloadWorkbench(
      request(`originalApprovalRequestId=${approvalId}`),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = await response.json();
    expect(body.approvals[0].proposal).toMatchObject({ state, candidateDigest });
    expect(body.restoredReview).toBeUndefined();
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(
      true,
    );
    expect(new URL(String(fetcher.mock.calls[1]![0])).searchParams.get('approvalRequestId')).toBe(
      approvalId,
    );
    expect(authenticated).toHaveBeenCalledTimes(2);
  },
);

it('recovers a lost approval response by exact digest and revision, retaining the original approval', async () => {
  const fetcher = owners();
  const response = await readWorkloadWorkbench(
    request(new URLSearchParams({ candidateDigest, expectedRevision: '0' }).toString()),
  );
  expect(response.status).toBe(200);
  expect((await response.json()).approvals[0].approvalRequestId).toBe(approval.approvalRequestId);
  const first = new URL(String(fetcher.mock.calls[0]![0]));
  expect(first.searchParams.get('makerPrincipalId')).toBe(actor.principalId);
  expect(first.searchParams.get('expectedRevision')).toBe('0');
  expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});

it('reports a staged proposal without approval as PRESENT, never as no-effect or success', async () => {
  const staged = { ...proposal, approval: undefined };
  const fetcher = owners({ ...staged, state: 'PROPOSED', operationId: null });
  const response = await readWorkloadWorkbench(
    request(new URLSearchParams({ candidateDigest, expectedRevision: '0' }).toString()),
  );
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({ approvals: [], preapprovalState: 'PRESENT' });
  expect(fetcher).toHaveBeenCalledOnce();
});

it.each([401, 403, 404, 503])('keeps an exact original owner denial %s opaque', async (status) => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('PRIVATE_OWNER_DETAIL', { status }));
  const response = await readWorkloadWorkbench(request(`originalApprovalRequestId=${approvalId}`));
  expect(response.ok).toBe(false);
  expect(await response.text()).not.toContain('PRIVATE_OWNER_DETAIL');
});

it.each([
  'foreign actor',
  'wrong approval',
  'wrong maker',
  'wrong digest',
  'wrong revision',
  'wrong resource',
])('rejects %s rather than releasing another original', async (defect) => {
  const detail = structuredClone(proposal),
    current = structuredClone(approval);
  if (defect === 'foreign actor') current.makerSubjectRef = `urn:openpc:resource:${id('999')}`;
  if (defect === 'wrong approval') current.approvalRequestId = `urn:openpc:resource:${id('999')}`;
  if (defect === 'wrong maker') detail.makerPrincipalId = id('999');
  if (defect === 'wrong digest') detail.candidateDigest = `sha256:${'f'.repeat(64)}`;
  if (defect === 'wrong revision') detail.expectedRevision = '1';
  if (defect === 'wrong resource') detail.resourceId = id('999');
  const fetcher = owners(detail, current);
  const selector =
    defect === 'wrong revision'
      ? new URLSearchParams({ candidateDigest, expectedRevision: '0' }).toString()
      : `originalApprovalRequestId=${approvalId}`;
  expect((await readWorkloadWorkbench(request(selector))).ok).toBe(false);
  expect(fetcher.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
});

it.each(['session', 'privacy', 'logout'])(
  'withholds a completed original after %s changes during its read',
  async (change) => {
    owners();
    vi.mocked(authenticated)
      .mockResolvedValueOnce(actor)
      .mockResolvedValueOnce(
        change === 'logout'
          ? undefined
          : {
              ...actor,
              ...(change === 'session' ? { sessionId: id('702') } : { privacyDomainId: id('202') }),
            },
      );
    const response = await readWorkloadWorkbench(
      request(`originalApprovalRequestId=${approvalId}`),
    );
    expect(response.ok).toBe(false);
    expect(await response.text()).not.toContain(candidateDigest);
  },
);

it('permits authenticated checker readback in a new session without resealing maker authority', async () => {
  vi.mocked(authenticated).mockResolvedValue({
    ...actor,
    sessionId: id('702'),
    principalId: id('112'),
  });
  owners();
  const response = await readWorkloadWorkbench(request(`originalApprovalRequestId=${approvalId}`));
  expect(response.status).toBe(200);
  const body = await response.json();
  expect(body.actor.sessionId).toBe(id('702'));
  expect(body.approvals[0].proposal.operationId).toBe(id('850'));
  expect(body.restoredReview).toBeUndefined();
});

it.each([
  `originalApprovalRequestId=${approvalId}&credentialId=${candidate.credentialId}`,
  `originalApprovalRequestId=${approvalId}&cursor=next`,
  `originalApprovalRequestId=${approvalId}&originalApprovalRequestId=${id('802')}`,
  `candidateDigest=${candidateDigest}`,
  'expectedRevision=0',
  `originalApprovalRequestId=${approvalId}&candidateDigest=${candidateDigest}&expectedRevision=0`,
])('rejects ambiguous/incomplete selectors %s before an owner request', async (query) => {
  const fetcher = owners();
  expect((await readWorkloadWorkbench(request(query))).status).toBe(400);
  expect(fetcher).not.toHaveBeenCalled();
});

function discoveryReadback() {
  const source = trustFixture();
  const intent = {
    ...source.intent,
    validFrom: new Date(Date.now() - 1000).toISOString(),
    validUntil: new Date(Date.now() + 600000).toISOString(),
  };
  const session: IdentitySession = {
    ...actor,
    participantId: source.source.enrollment.participantId,
    principalId: intent.administrators[0].principalId,
    contextMode: 'PLATFORM',
    privacyDomainId: undefined,
  };
  const receipt = discoveryCertificateRecoveryReceiptView.parse({
    actors: {
      executorPrincipalId: source.source.enrollment.recoveryPrincipal.principalId,
      custodianPrincipalIds: source.source.enrollment.custodians.map((value) => value.principalId),
      administratorPrincipalIds: intent.administrators.map((value) => value.principalId),
    },
    recoveryId: intent.recoveryId,
    enrollmentId: intent.enrollmentId,
    intent,
    intentDigest: digest(intent),
    state: 'ACTIVE',
    revision: '4',
    assurance: source.source.enrollment.assurance,
    authority: 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY',
    proofs: [],
    activation: {
      recoveryId: intent.recoveryId,
      enrollmentId: intent.enrollmentId,
      operationId: id('930'),
      state: 'ACTIVE',
      authority: 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY',
      assurance: source.source.enrollment.assurance,
      activatedAt: intent.validFrom,
      expiresAt: intent.validUntil,
      intentDigest: digest(intent),
      bindings: intent.administrators.map((value, index) => ({
        principalId: value.principalId,
        principalEpoch: value.principalEpoch,
        envelopeId: id(String(931 + index)),
        assignmentId: id(String(933 + index)),
      })),
    },
  });
  const certificate = {
    credentialId: intent.certificateRecovery.successorCredentialId,
    participantId: session.participantId,
    principalId: intent.certificateRecovery.workloadPrincipalId,
    workloadId: `urn:openpc:workload:${id('991')}`,
    state: 'ACTIVE',
    workloadEpoch: '3',
    revision: '2',
    certificateDer: null,
    keyId: intent.certificateRecovery.successorPublicKeyDigest,
    certificateFingerprint: `sha256:${'c'.repeat(64)}`,
    uriSan: `urn:openpc:participant:${session.participantId}:workload:${id('991')}`,
    issuer: 'test-issuer',
    notBefore: intent.validFrom,
    notAfter: intent.validUntil,
    rotateAt: intent.validFrom,
    replacedCredentialId: intent.certificateRecovery.predecessorCredentialId,
  };
  const completed = discoveryCertificateRecoveryReceiptView.parse({
    ...receipt,
    state: 'COMPLETED',
    authority: 'NONE',
    completion: {
      issuanceId: id('951'),
      operationId: id('952'),
      predecessorCredentialId: certificate.replacedCredentialId,
      successorCredentialId: certificate.credentialId,
      certificateFingerprint: certificate.certificateFingerprint,
    },
  });
  const query = new URLSearchParams({
    recoveryEnrollmentId: intent.enrollmentId,
    recoveryId: intent.recoveryId,
    privacyDomainId: source.source.enrollment.privacyDomainId,
  });
  return {
    session,
    receipt,
    completed,
    certificate,
    request: new NextRequest(`http://localhost/api/v1/ui/workload-workbench?${query}`, {
      headers: { host: 'localhost' },
    }),
  };
}

it.each(['ABSENT', 'COMPLETED'])(
  'returns exact Discovery %s readback for the unchanged Platform actor',
  async (state) => {
    const value = discoveryReadback();
    vi.mocked(authenticated).mockResolvedValue(value.session);
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (String(url).includes('/discovery-certificate-recovery/'))
        return Response.json(state === 'COMPLETED' ? value.completed : value.receipt);
      if (String(url).includes('/workloads/')) return Response.json(value.certificate);
      if (String(url).includes('/workload-proposals/'))
        return Response.json({ preapprovalState: 'ABSENT' });
      throw new Error('Unexpected Discovery owner read');
    });
    const response = await readWorkloadWorkbench(value.request);
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toMatchObject(
      state === 'COMPLETED'
        ? { truthState: 'SUCCESS', readback: value.certificate }
        : {
            preapprovalState: 'ABSENT',
            actor: { privacyDomainId: value.request.nextUrl.searchParams.get('privacyDomainId') },
          },
    );
    expect(authenticated).toHaveBeenCalledTimes(2);
    expect(fetcher).toHaveBeenCalledTimes(2);
    const writes = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(writes).toHaveLength(1);
    expect(JSON.parse(String(writes[0]![1]!.body)).command).toEqual({
      kind: 'READ',
      recoveryId: value.receipt.recoveryId,
    });
  },
);

it.each(['session', 'principal', 'participant', 'mode', 'privacy', 'epoch', 'logout'])(
  'withholds delayed completed Discovery readback after the current %s changes',
  async (change) => {
    const value = discoveryReadback();
    vi.mocked(authenticated).mockResolvedValue(value.session);
    let release!: () => void;
    let entered!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const reading = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (String(url).includes('/discovery-certificate-recovery/'))
        return Response.json(value.completed);
      if (String(url).includes('/workloads/')) {
        entered();
        await held;
        return Response.json(value.certificate);
      }
      throw new Error('Unexpected Discovery owner read');
    });
    const pending = readWorkloadWorkbench(value.request);
    await reading;
    const changes: Record<string, Partial<IdentitySession>> = {
      session: { sessionId: id('999') },
      principal: { principalId: id('999') },
      participant: { participantId: id('999') },
      mode: { contextMode: 'PARTICIPANT' },
      privacy: { privacyDomainId: id('999') },
      epoch: { contextEpoch: '999' },
    };
    vi.mocked(authenticated).mockResolvedValue(
      change === 'logout' ? undefined : { ...value.session, ...changes[change] },
    );
    release();
    const response = await pending;
    expect(response.ok).toBe(false);
    const text = await response.text();
    expect(text).not.toContain(value.certificate.credentialId);
    expect(text).not.toContain(value.certificate.certificateFingerprint);
    expect(text).not.toContain(value.completed.completion!.operationId);
    expect(fetcher).toHaveBeenCalledTimes(2);
  },
);

it.each(['ABSENT', 'PRESENT', 'DIRECT_CERTIFICATE'])(
  'withholds Discovery %s readback after its final owner read changes the context',
  async (state) => {
    const value = discoveryReadback();
    vi.mocked(authenticated).mockResolvedValue(value.session);
    if (state === 'DIRECT_CERTIFICATE')
      value.request.nextUrl.searchParams.set('credentialId', value.certificate.credentialId);
    const binding = value.receipt.intent.certificateRecovery;
    const rotation = {
      replacedCredentialId: binding.predecessorCredentialId,
      credentialId: binding.successorCredentialId,
      publicKeySpkiDer: binding.successorPublicKeySpkiDer,
    };
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (String(url).includes('/discovery-certificate-recovery/'))
        return Response.json(value.receipt);
      vi.mocked(authenticated).mockResolvedValue({ ...value.session, contextEpoch: '999' });
      if (String(url).includes('/workloads/')) return Response.json(value.certificate);
      if (String(url).includes('/workload-proposals/'))
        return Response.json(
          state === 'PRESENT'
            ? {
                preapprovalState: 'PRESENT',
                proposal: {
                  candidateDigest: digest(rotation),
                  resourceId: binding.predecessorCredentialId,
                  makerPrincipalId: value.session.principalId,
                  catalogOperationId: 'ID-OP-WORKLOAD-ROTATE',
                  expectedRevision: binding.predecessorRevision,
                  state: 'PROPOSED',
                  operationId: null,
                  expiresAt: value.receipt.intent.validUntil,
                  candidate: rotation,
                },
              }
            : { preapprovalState: 'ABSENT' },
        );
      throw new Error('Unexpected Discovery owner read');
    });
    const response = await readWorkloadWorkbench(value.request);
    expect(response.ok).toBe(false);
    const text = await response.text();
    expect(text).not.toContain(value.certificate.credentialId);
    expect(text).not.toContain('preapprovalState');
    expect(authenticated).toHaveBeenCalledTimes(2);
    expect(fetcher).toHaveBeenCalledTimes(2);
  },
);

it.each(['receipt enrollment', 'receipt recovery', 'intent enrollment', 'intent recovery'])(
  'rejects a schema-valid different Discovery %s before reading another owner',
  async (selection) => {
    const value = discoveryReadback();
    vi.mocked(authenticated).mockResolvedValue(value.session);
    const wrong = structuredClone(value.receipt);
    if (selection === 'receipt enrollment') {
      wrong.enrollmentId = id('999');
      wrong.activation!.enrollmentId = wrong.enrollmentId;
    } else if (selection === 'receipt recovery') {
      wrong.recoveryId = id('999');
      wrong.activation!.recoveryId = wrong.recoveryId;
    } else if (selection === 'intent enrollment') wrong.intent.enrollmentId = id('999');
    else wrong.intent.recoveryId = id('999');
    wrong.intentDigest = digest(wrong.intent);
    wrong.activation!.intentDigest = wrong.intentDigest;
    discoveryCertificateRecoveryReceiptView.parse(wrong);
    const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(wrong));
    const response = await readWorkloadWorkbench(value.request);
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain(wrong.intentDigest);
    expect(fetcher).toHaveBeenCalledOnce();
  },
);
