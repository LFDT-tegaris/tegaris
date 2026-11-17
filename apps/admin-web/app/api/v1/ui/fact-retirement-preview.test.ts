import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { sha256 } from '../../../../../../services/control-api/src/configuration/digest';
import { retirementWireFixture } from '../../../../../../services/control-api/src/evidence/store-retirement-wire-fixture';
import { retirementWireBytes } from '../../../../../../services/control-api/src/evidence/store-retirement-wire';
import { factRetirementPreview, factRetirementSummary } from './fact-retirement-preview';
import {
  authenticated,
  localRuntimeConfig,
  openBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import {
  mutateTransactionWorkbench,
  readTransactionWorkbench,
} from './local-transaction-workbench';
import { transactionCandidate, transactionMutationPath } from './transaction-workbench-contract';

vi.mock('./local-runtime', async (load) => ({
  ...(await load<typeof import('./local-runtime')>()),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
}));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = (n: number) => `urn:openpc:resource:${id(n)}`;
const session: IdentitySession = {
  sessionToken: 'component-test-session',
  role: 'operator',
  sessionId: id(1),
  principalId: id(2),
  participantId: id(3),
  privacyDomainId: id(4),
  contextMode: 'PARTICIPANT',
  contextEpoch: '1',
  stepUpVerifiedAt: null,
};
const runtime: LocalConfig = {
  publicApiUrl: 'http://public-owner',
  identityUrl: 'http://identity',
  factUrl: 'http://facts',
  policyUrl: 'http://policy',
  oidcAuthorizationUrl: 'http://oidc',
  identityToken: 'fixture',
  factToken: 'fixture',
  policyToken: 'fixture',
  cookieKey: Buffer.alloc(32, 1),
};
const fields = { evidenceId: ref(5), hostDigest: 'a'.repeat(64), retentionPolicyId: ref(6) };
function plan(evidenceId = id(5), source: 'fact' | 'candidate' = 'fact') {
  const { attempt } = retirementWireFixture();
  const selection =
    source === 'fact'
      ? attempt.selection
      : {
          class: 'CANDIDATE_PROJECTION' as const,
          source: attempt.selection.source,
          rows: attempt.selection.rows.map(
            ({
              candidate_id,
              candidate_feed_sequence,
              payload_digest,
              payload_bytes,
              checkpoint_digest,
            }) => ({
              candidate_id,
              candidate_feed_sequence,
              payload_digest,
              payload_bytes,
              checkpoint_digest,
            }),
          ),
        };
  const manifest = [
    {
      candidateId: 'candidate',
      evidenceId,
      streamId: 'original-source',
      recordId: 'original-record',
      sequence: '1',
      recordDigest: 'sha256:' + 'a'.repeat(64),
      segmentId: id(7),
      objectDigest: 'sha256:' + 'b'.repeat(64),
    },
  ];
  const acknowledgements = [
    {
      candidateId: 'candidate',
      sinkReceipts: [
        {
          sinkId: 'archive',
          checkpointDigest: 'sha256:' + 'c'.repeat(64),
          receiptDigest: 'sha256:' + 'd'.repeat(64),
          acknowledgedAtMicros: '1800000000000000',
        },
      ],
    },
  ];
  return {
    hostDigest: fields.hostDigest,
    retentionPolicyId: fields.retentionPolicyId,
    nativeSourceCheck: 'REQUIRED_AT_ADMISSION',
    sourceBinding: {
      version: 'OPENPC_STORE_RETIREMENT_SOURCE_V1',
      selectionWireHex: retirementWireBytes(selection).toString('hex'),
      recordRefs: [{ candidateId: 'candidate', evidenceId }],
      manifest,
      acknowledgements,
      archiveManifestDigest: sha256(manifest).slice(7),
      archiveAcknowledgementDigest: sha256(acknowledgements).slice(7),
      retentionNotBeforeMs: '1800000000000',
      lifecycleRevision: '9',
    },
  };
}
const request = (body?: unknown) =>
  new NextRequest('http://localhost/api/v1/ui/transaction-workbench', {
    method: body ? 'POST' : 'GET',
    headers: {
      'Host': 'localhost',
      'Origin': 'http://localhost',
      'Content-Type': 'application/json',
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
beforeEach(() => {
  vi.mocked(authenticated).mockReset().mockResolvedValue(session);
  vi.mocked(localRuntimeConfig).mockReset().mockResolvedValue(runtime);
});
afterEach(() => vi.unstubAllGlobals());

it.each(['fact', 'candidate'] as const)(
  'reads the exact %s retirement kind from the digest-bound selection sharing one action',
  async (source) => {
    const selected = plan(id(5), source);
    const kind = source === 'fact' ? 'evidence-deletion-fact' : 'evidence-deletion-candidate';
    const { body } = transactionCandidate(
      kind,
      {
        hostDigest: selected.hostDigest,
        retentionPolicyId: selected.retentionPolicyId,
        sourceBinding: selected.sourceBinding,
        previousAttemptId: null,
      },
      'Retire the exact archived native payload',
      session.participantId,
    );
    const approvalId = ref(8);
    const timestamp = '2026-09-18T00:00:00.000000Z';
    const approval = {
      approvalRequestId: approvalId,
      actionIntentId: body.actionIntentId,
      candidateDigest: sha256(body),
      state: 'REQUESTED',
      makerSubjectRef: ref(2),
      checkerSubjectRef: ref(9),
      revision: '1',
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    let tampered = false,
      expired = false;
    const resumed: { body: unknown; key: string | null }[] = [];
    const fetch = vi.fn(async (url: string, options?: RequestInit) => {
      const path = decodeURIComponent(new URL(url).pathname);
      if (path === '/api/v1/session/csrf') return Response.json({ csrfToken: 'c'.repeat(48) });
      if (path === `/api/v1/approval-requests/${approvalId}`) {
        if (options?.method === 'PATCH') {
          resumed.push({
            body: JSON.parse(String(options.body)),
            key: new Headers(options.headers).get('Idempotency-Key'),
          });
          throw new Error('Lost response after public resume');
        }
        return Response.json(approval);
      }
      expect(path).toBe(`/api/v1/approval-requests/${approvalId}/candidate`);
      return Response.json({
        approvalRequestId: approvalId,
        actionIntentId: body.actionIntentId,
        candidateDigest: sha256(body),
        resourceRef: ref(10),
        expectedRevision: '0',
        state: expired ? 'EXPIRED' : 'APPROVAL_REQUESTED',
        attemptId: id(11),
        attempt: '1',
        businessIdempotencyKey: 'original-native-retirement-intent',
        approvalUsable: false,
        canRequestResume: expired,
        expiresAt: '2099-01-01T00:00:00.000Z',
        runtimePermission: 'NONE',
        operationRef: null,
        deploymentIntent: null,
        candidate: tampered ? { ...body, reason: 'Substituted input' } : body,
        redactedFields: [],
      });
    });
    vi.stubGlobal('fetch', fetch);
    const read = () =>
      readTransactionWorkbench(
        new NextRequest(`http://localhost/api/v1/ui/transaction-workbench?approvalId=${id(8)}`),
      );
    const response = await read();
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      kind,
      factRetirement: {
        class: source === 'fact' ? 'ADMITTED_FACT' : 'CANDIDATE_PROJECTION',
        candidateId: 'candidate',
      },
      candidate: { candidate: body, operationRef: null },
    });
    expired = true;
    const recovered = await (await read()).json();
    expect(recovered.stepUp).toBeNull();
    expect(
      openBffPayload(recovered.reviewToken, runtime.cookieKey, 'transaction-review'),
    ).toMatchObject({
      kind,
      key: id(11),
      businessKey: 'original-native-retirement-intent',
      body,
    });
    const resume = {
      command: 'RESUME',
      approvalId: id(8),
      predecessorCandidateId: id(11),
      expectedAttempt: '1',
      expectedRevision: '1',
      reason: 'Resume unchanged native retirement.',
    };
    expect(
      (await mutateTransactionWorkbench(request({ ...resume, expectedAttempt: '2' }))).status,
    ).toBe(404);
    expect(resumed).toHaveLength(0);
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await mutateTransactionWorkbench(request(resume));
      expect(response.status).toBe(202);
      expect(await response.json()).toMatchObject({
        truthState: 'UNKNOWN',
        reconciliation: 'READ_APPROVAL',
        approvalId: id(8),
      });
    }
    expect(resumed).toHaveLength(2);
    expect(resumed[0]).toEqual(resumed[1]);
    expect(resumed[0]).toMatchObject({
      key: `workbench-resume-${id(11)}`,
      body: {
        predecessorCandidateId: id(11),
        expectedAttempt: '1',
        expectedRevision: '1',
        candidateDigest: sha256(body),
      },
    });
    tampered = true;
    expect((await read()).status).toBe(503);
  },
);

it('resolves only the public record/target/policy selection before sealing the real review body', async () => {
  const fetch = vi.fn(async (_url: string, init?: RequestInit) => {
    expect(JSON.parse(String(init?.body))).toEqual({
      hostDigest: fields.hostDigest,
      retentionPolicyId: fields.retentionPolicyId,
    });
    expect(new Headers(init?.headers).get('OpenPC-Privacy-Domain-ID')).toBe(
      `urn:openpc:privacy-domain:${id(4)}`,
    );
    return Response.json(plan());
  });
  vi.stubGlobal('fetch', fetch);
  const response = await mutateTransactionWorkbench(
    request({
      command: 'PREVIEW',
      kind: 'evidence-deletion-fact',
      fields,
      reason: 'Retire the archived Fact payload',
    }),
  );
  expect(response.status).toBe(200);
  const { preview, reviewToken } = await response.json();
  expect(preview.authority).toBe('NONE');
  expect(preview.candidate.previousAttemptId).toBe(null);
  expect(preview.candidate.participantId).toBe(`urn:openpc:participant:${id(3)}`);
  expect(preview.candidateDigest).toBe(sha256(preview.candidate));
  expect(preview.factRetirement).toMatchObject({
    factId: 'fact',
    canonicalGeneration: '18446744073709551615',
    payloadBytes: '40',
    archiveAcknowledgements: 1,
    nativeSourceCheck: 'REQUIRED_AT_ADMISSION',
  });
  expect(openBffPayload(reviewToken, runtime.cookieKey, 'transaction-review')).toMatchObject({
    body: preview.candidate,
  });
  expect(transactionMutationPath('evidence-deletion-fact', preview.candidate)).toBe(
    '/api/v1/evidence-deletions/store-retirements',
  );
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(String(fetch.mock.calls[0]![0])).toContain('/fact-retirement-plan');
});

it('rejects injected selection, predecessor and authority fields before asking the owner', async () => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  for (const extra of [
    { selectionWireHex: '00' },
    { sourceBinding: {} },
    { eligible: true },
    { previousAttemptId: ref(8) },
    { participantId: id(8) },
  ]) {
    const result = await mutateTransactionWorkbench(
      request({
        command: 'PREVIEW',
        kind: 'evidence-deletion-fact',
        fields: { ...fields, ...extra },
        reason: 'Caller input',
      }),
    );
    expect(result.status).toBe(400);
  }
  expect(fetch).not.toHaveBeenCalled();
});

it('rejects valid but substituted owner plans and context changes after the read', async () => {
  for (const value of [
    plan(id(9)),
    { ...plan(), hostDigest: 'f'.repeat(64) },
    { ...plan(), retentionPolicyId: ref(9) },
    { ...plan(), eligible: true },
  ]) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json(value)),
    );
    const result = await factRetirementPreview(request(), runtime, session, fields);
    expect(result).toBeInstanceOf(Response);
    expect((await (result as Response).json()).code).toBe('PC-INTEGRATION-5001');
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json(plan())),
  );
  vi.mocked(authenticated).mockResolvedValue({ ...session, contextEpoch: '2' });
  const denied = await factRetirementPreview(request(), runtime, session, fields);
  expect((denied as Response).status).toBe(404);
});

it('preserves the native source denial and derives summaries from exact canonical candidate bytes', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ code: 'PC-DATA-6007' }, { status: 412 })),
  );
  const denied = await factRetirementPreview(request(), runtime, session, fields);
  expect((denied as Response).status).toBe(412);
  const resolved = plan();
  const candidate = transactionCandidate(
    'evidence-deletion-fact',
    {
      hostDigest: resolved.hostDigest,
      retentionPolicyId: resolved.retentionPolicyId,
      sourceBinding: resolved.sourceBinding,
      previousAttemptId: null,
    },
    'Exact row',
    id(3),
  );
  expect(factRetirementSummary(candidate.body).evidenceId).toBe(fields.evidenceId);
  expect(() =>
    factRetirementSummary({
      ...candidate.body,
      sourceBinding: { ...resolved.sourceBinding, selectionWireHex: '00' },
    }),
  ).toThrow();
});

it('seals candidate archive selection through its public owner and rejects a borrowed Fact plan', async () => {
  const fetch = vi.fn(async (_url: string) => Response.json(plan(id(5), 'candidate')));
  vi.stubGlobal('fetch', fetch);
  const response = await mutateTransactionWorkbench(
    request({
      command: 'PREVIEW',
      kind: 'evidence-deletion-candidate',
      fields,
      reason: 'Retire candidate payload',
    }),
  );
  expect(response.status).toBe(200);
  const { preview, reviewToken } = await response.json();
  expect(preview.factRetirement).toMatchObject({
    class: 'CANDIDATE_PROJECTION',
    candidateId: 'candidate',
    payloadBytes: '40',
    nativeSourceCheck: 'REQUIRED_AT_ADMISSION',
  });
  expect(preview.factRetirement).not.toHaveProperty('factId');
  expect(openBffPayload(reviewToken, runtime.cookieKey, 'transaction-review')).toMatchObject({
    body: preview.candidate,
  });
  expect(String(fetch.mock.calls[0]?.[0])).toContain('/candidate-retirement-plan');
  expect(transactionMutationPath('evidence-deletion-candidate', preview.candidate)).toBe(
    '/api/v1/evidence-deletions/store-retirements',
  );
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json(plan())),
  );
  const borrowed = await factRetirementPreview(request(), runtime, session, fields, 'candidate');
  expect((borrowed as Response).status).toBe(503);
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ code: 'PC-DATA-6007' }, { status: 412 })),
  );
  expect(
    ((await factRetirementPreview(request(), runtime, session, fields, 'candidate')) as Response)
      .status,
  ).toBe(412);
});
