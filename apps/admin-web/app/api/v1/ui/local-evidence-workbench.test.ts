import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { digest } from './local-governance-api';
import { createEvidenceRequest, readEvidenceWorkbench } from './local-evidence-workbench';

const state = vi.hoisted(() => ({ contextEpoch: '1', contextMode: 'PARTICIPANT' }));
const participantId = '018f0000-0000-7000-8000-000000000101',
  privacyDomainId = '018f0000-0000-7000-8000-000000000201';
vi.mock('./local-runtime', async (load) => ({
  ...(await load<typeof import('./local-runtime')>()),
  localRuntimeConfig: async () => ({ publicApiUrl: 'http://public-owner' }),
  authenticated: async () => ({
    sessionToken: 'session-token',
    sessionId: '018f0000-0000-7000-8000-000000000301',
    principalId: '018f0000-0000-7000-8000-000000000111',
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    ...state,
  }),
}));
const page = (items: unknown[]) => ({
  items,
  nextCursor: null,
  total: String(items.length),
  completeness: 'COMPLETE',
  authorizedEmpty: items.length === 0,
  snapshotRevision: '1',
});
const id = '018f0000-0000-7000-8000-000000000401',
  ref = `urn:openpc:resource:${id}`;
const time = '2026-09-21T00:00:00.000000Z';
const record = {
  evidenceId: ref,
  participantId: `urn:openpc:participant:${participantId}`,
  evidenceClass: 'BUSINESS_TRANSITION',
  recordDigest: digest('original'),
  sequence: '1',
  state: 'ADMITTED',
  occurredAt: time,
  revision: '1',
  createdAt: time,
  updatedAt: time,
};
const selection = {
  streamId: 'control-receipts',
  fromSequence: '1',
  throughSequence: '1',
  redactionProfileId: 'pc.evidence.minimized-audit.v1',
};
const request = (input?: unknown, query = '') =>
  new NextRequest(
    `http://localhost/api/v1/ui/evidence-workbench${query}`,
    input
      ? {
          method: 'POST',
          headers: {
            'Host': 'localhost',
            'Origin': 'http://localhost',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(input),
        }
      : {},
  );
beforeEach(() => {
  state.contextEpoch = '1';
  state.contextMode = 'PARTICIPANT';
});
afterEach(() => vi.unstubAllGlobals());

it('discovers installed Fact targets with current scope and no eligibility assertion', async () => {
  const hosts = {
    items: [{ hostDigest: 'a'.repeat(64), targetId: id, store: 'openpc_facts' }],
    authority: 'NONE',
  };
  const fetch = vi.fn(async () => Response.json(hosts));
  vi.stubGlobal('fetch', fetch);
  const result = await readEvidenceWorkbench(request(undefined, `?factRetirementRecordId=${id}`));
  expect(result.status).toBe(200);
  expect(result.headers.get('cache-control')).toBe('no-store');
  expect(await result.json()).toMatchObject({
    evidenceId: ref,
    hosts,
    actor: { participantId, privacyDomainId },
  });
  for (const query of [
    `?factRetirementRecordId=${id}&recordId=${id}`,
    `?factRetirementRecordId=${id}&factRetirementRecordId=${id}`,
  ])
    expect((await readEvidenceWorkbench(request(undefined, query))).status).toBe(400);
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      state.contextEpoch = '2';
      return Response.json(hosts);
    }),
  );
  expect(
    (await readEvidenceWorkbench(request(undefined, `?factRetirementRecordId=${id}`))).status,
  ).toBe(404);
});

it('uses real public catalogue contracts and rejects foreign or raw fields', async () => {
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    expect(new Headers(init?.headers).get('Cookie')).toBe('__Host-openpc_session=session-token');
    return Response.json(page(url.includes('evidence-records') ? [record] : []));
  });
  vi.stubGlobal('fetch', fetch);
  const response = await readEvidenceWorkbench(request());
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect((await response.json()).records.items).toEqual([record]);
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json(
        page([
          {
            ...record,
            participantId: 'urn:openpc:participant:018f0000-0000-7000-8000-000000000102',
          },
        ]),
      ),
    ),
  );
  expect((await readEvidenceWorkbench(request())).status).toBe(503);
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      Response.json(
        page(url.includes('evidence-records') ? [{ ...record, receiptBase64: 'secret' }] : []),
      ),
    ),
  );
  const filtered = await readEvidenceWorkbench(request());
  expect(await filtered.text()).not.toContain('secret');
});
it('purges an in-flight read when the active context changes and rejects duplicate queries', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      state.contextEpoch = '2';
      return Response.json(page([]));
    }),
  );
  expect((await readEvidenceWorkbench(request())).status).toBe(404);
  expect(
    (await readEvidenceWorkbench(request(undefined, `?exportId=${id}&exportId=${id}`))).status,
  ).toBe(400);
});
it('creates only a server-bound draft with stable idempotency and no claimed export effect', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json(page([]))),
  );
  const initial = await (await readEvidenceWorkbench(request())).json();
  const input = { actorKey: initial.actorKey, requestKey: id, selection, reason: 'Audit incident' };
  let original: unknown;
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith('/csrf')) return Response.json({ csrfToken: 'c'.repeat(32) });
    expect(url).toBe('http://public-owner/api/v1/evidence-exports/from-selection');
    const body = JSON.parse(String(init?.body));
    original = body;
    expect(body).toMatchObject({
      participantId: `urn:openpc:participant:${participantId}`,
      selection,
      actionIntentId: 'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1',
    });
    return Response.json(
      {
        operationId: id,
        resourceRef: ref,
        actionIntentId: body.actionIntentId,
        intentDigest: body.actionIntentDigest,
        idempotencyKey: new Headers(init?.headers).get('Idempotency-Key'),
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
        revision: '1',
        createdAt: time,
        updatedAt: time,
      },
      { status: 202 },
    );
  });
  vi.stubGlobal('fetch', fetch);
  expect((await createEvidenceRequest(request(input))).status).toBe(202);
  expect((await createEvidenceRequest(request(input))).status).toBe(202);
  expect(original).not.toHaveProperty('checkpoint');
  expect(original).not.toHaveProperty('outputDigest');
  state.contextEpoch = '2';
  fetch.mockClear();
  expect((await createEvidenceRequest(request(input))).status).toBe(404);
  expect(fetch).not.toHaveBeenCalled();
});
it('checks artifact digest and exact privacy scope before exposing any download', async () => {
  const artifact = {
    version: 'OPENPC_EVIDENCE_REDACTED_EXPORT_V1',
    evidenceExportId: ref,
    participantId: `urn:openpc:participant:${participantId}`,
    privacyDomainId: `urn:openpc:privacy-domain:${privacyDomainId}`,
    requestDigest: digest('selection'),
    range: selection,
    sinkId: 'local-sink',
    assurance: 'LOCAL_FSYNC_READBACK',
    records: [
      {
        evidenceId: ref,
        sequence: '1',
        evidenceClass: 'BUSINESS_TRANSITION',
        recordDigest: record.recordDigest,
        occurredAt: time,
        segmentDigest: digest('segment'),
        checkpointDigest: digest('checkpoint'),
      },
    ],
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ artifact, outputDigest: digest(artifact) })),
  );
  expect(
    (await readEvidenceWorkbench(request(undefined, `?exportId=${id}&artifact=1`))).status,
  ).toBe(200);
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ artifact, outputDigest: digest('forged') })),
  );
  expect(
    (await readEvidenceWorkbench(request(undefined, `?exportId=${id}&artifact=1`))).status,
  ).toBe(404);
  const foreign = {
    ...artifact,
    privacyDomainId: 'urn:openpc:privacy-domain:018f0000-0000-7000-8000-000000000202',
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ artifact: foreign, outputDigest: digest(foreign) })),
  );
  expect(
    (await readEvidenceWorkbench(request(undefined, `?exportId=${id}&artifact=1`))).status,
  ).toBe(404);
});

it('discovers a record range through its public owner and withholds stale or mismatched bindings', async () => {
  const fetch = vi.fn(async (url: string) => {
    expect(url).toBe(
      `http://public-owner/api/v1/evidence-records/${encodeURIComponent(ref)}/export-range`,
    );
    return Response.json({ evidenceId: ref, recordDigest: record.recordDigest, range: selection });
  });
  vi.stubGlobal('fetch', fetch);
  const response = await readEvidenceWorkbench(request(undefined, `?recordId=${id}`));
  expect(response.status).toBe(200);
  expect((await response.json()).record.range).toEqual(selection);
  expect(
    (await readEvidenceWorkbench(request(undefined, `?recordId=${id}&exportId=${id}`))).status,
  ).toBe(400);
  fetch.mockImplementation(async () => {
    state.contextEpoch = '2';
    return Response.json({ evidenceId: ref, recordDigest: record.recordDigest, range: selection });
  });
  expect((await readEvidenceWorkbench(request(undefined, `?recordId=${id}`))).status).toBe(404);
  fetch.mockImplementation(async () =>
    Response.json({
      evidenceId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000402',
      recordDigest: record.recordDigest,
      range: selection,
    }),
  );
  expect((await readEvidenceWorkbench(request(undefined, `?recordId=${id}`))).status).toBe(404);
});

it('reads scoped deletion eligibility without fabricating readiness or retaining a changed actor', async () => {
  const selection = {
    version: 'OPENPC_LOCAL_EVIDENCE_DELETION_V1',
    evidenceId: ref,
    participantId: `urn:openpc:participant:${participantId}`,
    privacyDomainId,
    retentionPolicyId: ref,
    policyDigest: digest('policy'),
    targetDatabase: 'openpc_control',
    dataClass: 'AUDIT_EVIDENCE',
    deletionMode: 'ROW_DELETE',
    streamId: 'authentication',
    segmentId: id,
    firstSequence: '1',
    throughSequence: '1',
    objectDigest: digest('object'),
    ciphertextBytes: 4096,
    recordCount: 1,
    eligibleAfterMicros: '1790000000000000',
    sinkReceipts: [],
    priorCursor: null,
  };
  const plan = {
    evidenceId: ref,
    localPayload: 'RETAINED',
    eligible: false,
    blockers: ['ACTIVE_HOLD'],
    selection,
    beforeDigest: digest('before'),
  };
  let result: Record<string, unknown> = plan,
    changeContext = false;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      expect(decodeURIComponent(url)).toContain(`/evidence-records/${ref}/deletion-plan`);
      expect(init?.method ?? 'GET').toBe('GET');
      if (changeContext) state.contextEpoch = '2';
      return Response.json(result);
    }),
  );
  const run = () => readEvidenceWorkbench(request(undefined, `?deletionRecordId=${id}`));
  const response = await run();
  expect(response.status).toBe(200);
  expect((await response.json()).plan).toEqual(plan);
  result = { ...plan, selection: { ...selection, participantId: `urn:openpc:participant:${id}` } };
  expect((await run()).status).toBeGreaterThanOrEqual(400);
  result = plan;
  changeContext = true;
  expect((await run()).status).toBe(404);
  expect(
    (await readEvidenceWorkbench(request(undefined, `?deletionRecordId=${id}&recordId=${id}`)))
      .status,
  ).toBe(400);
});

it('reads minimized provenance with exact scope and record binding, failing closed on context drift or raw fields', async () => {
  const provenance = {
    evidenceId: ref,
    participantId: `urn:openpc:participant:${participantId}`,
    privacyDomainId,
    evidenceClass: 'EFFECT',
    recordId: 'rpc:1',
    recordDigest: record.recordDigest,
    sourceFormat: 'OPENPC_RPC_DECISION_TRANSITION_V1',
    status: 'SOURCE_NOT_SUPPORTED',
    deployment: null,
    custody: {
      streamId: 'rpc',
      sequence: '1',
      segmentId: id,
      checkpoints: [],
      checkpointState: 'NONE_RECORDED',
      archiveAvailability: 'NOT_RECHECKED',
    },
  };
  const query = `?provenanceRecordId=${id}`;
  const fetch = vi.fn(async (url: string) => {
    expect(url).toBe(
      `http://public-owner/api/v1/evidence-records/${encodeURIComponent(ref)}/provenance`,
    );
    return Response.json(provenance);
  });
  vi.stubGlobal('fetch', fetch);
  const response = await readEvidenceWorkbench(request(undefined, query));
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect((await response.json()).provenance).toEqual(provenance);
  for (const changed of [
    { ...provenance, evidenceId: ref.replace('401', '402') },
    { ...provenance, privacyDomainId: privacyDomainId.replace('201', '202') },
    { ...provenance, participantId: `urn:openpc:participant:${privacyDomainId}` },
    { ...provenance, receiptBase64: 'private-source' },
  ]) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json(changed)),
    );
    const denied = await readEvidenceWorkbench(request(undefined, query));
    expect(denied.status).toBe(503);
    expect(await denied.text()).not.toContain('private-source');
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      state.contextEpoch = '2';
      return Response.json(provenance);
    }),
  );
  expect((await readEvidenceWorkbench(request(undefined, query))).status).toBe(404);
  expect((await readEvidenceWorkbench(request(undefined, `${query}&recordId=${id}`))).status).toBe(
    400,
  );
});

it('uses the existing exact receipt-digest catalogue filter and preserves it with pagination', async () => {
  const fetch = vi.fn(async (url: string) => {
    if (url.includes('evidence-records'))
      expect(new URL(url).searchParams.get('filter')).toBe(
        `recordDigest:eq:${record.recordDigest}`,
      );
    return Response.json(page([]));
  });
  vi.stubGlobal('fetch', fetch);
  expect(
    (
      await readEvidenceWorkbench(
        request(undefined, `?recordDigest=${record.recordDigest}&recordsCursor=pc2.cGFnZQ.c2ln`),
      )
    ).status,
  ).toBe(200);
  expect((await readEvidenceWorkbench(request(undefined, '?recordDigest=invalid'))).status).toBe(
    400,
  );
});

it.each(['search', 'retention-policy', 'normalized', 'fact', 'continuation'] as const)(
  'binds %s projection plans to the exact public owner and session',
  async (kind) => {
    const projectionKind =
      kind === 'fact' ? 'normalized' : kind === 'retention-policy' ? 'search' : kind;
    const dataClass =
      projectionKind === 'normalized' ? 'NORMALIZED_JSON_PROJECTION' : 'SEARCH_PROJECTION';
    const previous = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000301';
    const target = {
      evidenceId: ref,
      recordId: id,
      projectionDigest: digest('projection'),
      projectionBytes: 512,
      sourceReceiptDigest: digest('source'),
      beforeDigest: digest('before'),
    };
    const { beforeDigest, ...current } = target;
    const selection = {
      ...current,
      version: 'OPENPC_PROJECTION_DELETION_BATCH_V1',
      dataClass,
      deletionMode: 'PROJECTION_DELETE',
      participantId: `urn:openpc:participant:${participantId}`,
      privacyDomainId,
      retentionPolicyId: ref,
      policyDigest: digest('policy'),
      targetDatabase: 'openpc_control',
      sourceKind:
        kind === 'fact'
          ? 'FACT_PROVENANCE'
          : kind === 'normalized'
            ? 'RPC_PRE_ADMISSION_DENIAL'
            : kind === 'retention-policy'
              ? 'RETENTION_POLICY_CATALOGUE'
              : 'AUTHENTICATION_CATALOGUE',
      streamId: 'projection',
      segmentId: id,
      sequence: '1',
      archiveObjectDigest: digest('archive'),
      eligibleAfterMicros: '1790000000000000',
      sinkReceipts: [],
      targets:
        kind === 'continuation'
          ? [{ ...target, evidenceId: previous, recordId: previous.slice(-36) }, target]
          : [target],
      batchIndex: kind === 'continuation' ? 1 : 0,
      priorCursor:
        kind === 'continuation'
          ? { deletionJobId: previous, receiptDigest: digest('prior') }
          : null,
    };
    const plan = {
      evidenceId: ref,
      dataClass,
      projectionState: 'RETAINED',
      eligible: false,
      blockers: ['ACTIVE_HOLD'],
      selection,
      beforeDigest,
      continuationState: 'BLOCKED',
      nextDeletionJobId: null,
    };
    let result: Record<string, unknown> = plan,
      change = false;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        expect(decodeURIComponent(url)).toContain(
          kind === 'continuation'
            ? `/evidence-deletions/${previous}/projection-continuation-plan`
            : `/evidence-records/${ref}/${projectionKind}-projection-deletion-plan`,
        );
        if (change) state.contextEpoch = '2';
        return Response.json(result);
      }),
    );
    const query =
      kind === 'continuation'
        ? `projectionContinuationId=${previous.slice(-36)}`
        : `${projectionKind}ProjectionRecordId=${id}`;
    const run = () => readEvidenceWorkbench(request(undefined, `?${query}`));
    expect((await run()).status).toBe(200);
    for (const bad of [
      { ...plan, evidenceId: previous },
      { ...plan, dataClass: 'AUDIT_EVIDENCE' },
      { ...plan, selection: { ...selection, privacyDomainId: id } },
      { ...plan, rawProjection: 'forbidden' },
    ]) {
      result = bad;
      expect((await run()).status).toBe(503);
    }
    expect(
      (await readEvidenceWorkbench(request(undefined, `?${query}&recordId=${id}`))).status,
    ).toBe(400);
    result = plan;
    change = true;
    expect((await run()).status).toBe(404);
  },
);

it.each([false, true])(
  'reads exact raw-proof eligibility and rejects substituted ownership (continuation=%s)',
  async (continuation) => {
    const previous = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000301';
    const object = {
      objectRef: ref,
      objectVersion: '1',
      objectDigest: digest('proof'),
      payloadDigest: digest('packet'),
      ciphertextBytes: 4096,
      beforeDigest: digest('before'),
    };
    const selection = {
      version: 'OPENPC_RAW_PROOF_DELETION_BATCH_V1',
      participantId: `urn:openpc:participant:${participantId}`,
      privacyDomainId,
      retentionPolicyId: ref,
      policyDigest: digest('policy'),
      targetDatabase: 'openpc_control',
      dataClass: 'RAW_SOURCE_BODY',
      deletionMode: 'ROW_DELETE',
      objectRef: ref,
      objectVersion: '1',
      objectDigest: object.objectDigest,
      payloadDigest: object.payloadDigest,
      ciphertextBytes: object.ciphertextBytes,
      source: {
        evidenceId: ref,
        occurrenceId: id,
        operationId: id,
        sourceReceiptDigest: digest('source'),
        proofDigest: digest('proof'),
        assertionDigest: digest('assertion'),
        signatureDigest: digest('signature'),
        signerKeyDigest: digest('key'),
        occurredAt: time,
        materialType: 'IDENTITY_SIGNED_AUTHORIZATION_ASSERTION',
        evidenceClass: 'AUTHENTICATION',
        sourceFormat: 'IDENTITY_RUNTIME_ASSERTION_3002_2_13',
        occurrenceIntegrity: 'CONTROL_DATABASE_IMMUTABLE',
        proofIntegrity: 'IDENTITY_COSE_ED25519',
        finality: 'NOT_APPLICABLE',
        authorityEffect: 'NONE',
      },
      eligibleAfterMicros: '1790000000000000',
      sinkReceipts: [],
      targets: continuation ? [{ ...object, objectRef: previous }, object] : [object],
      batchIndex: continuation ? 1 : 0,
      priorCursor: continuation
        ? { deletionJobId: previous, receiptDigest: digest('prior') }
        : null,
    };
    const plan = {
      objectRef: ref,
      localPayload: 'RETAINED',
      eligible: false,
      blockers: ['ACTIVE_HOLD'],
      selection,
      beforeDigest: object.beforeDigest,
      continuationState: 'BLOCKED',
      nextDeletionJobId: null,
    };
    let result: Record<string, unknown> = plan,
      change = false;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        expect(decodeURIComponent(url)).toContain(
          continuation
            ? `/evidence-deletions/${previous}/raw-continuation-plan`
            : `/protected-proofs/${ref}/deletion-plan`,
        );
        if (change) state.contextEpoch = '2';
        return Response.json(result);
      }),
    );
    const query = continuation
      ? `rawDeletionContinuationId=${previous.slice(-36)}`
      : `rawDeletionObjectId=${id}`;
    const run = () => readEvidenceWorkbench(request(undefined, `?${query}`));
    expect((await run()).status).toBe(200);
    result = { ...plan, objectRef: previous };
    expect((await run()).status).toBe(503);
    result = { ...plan, selection: { ...selection, privacyDomainId: id } };
    expect((await run()).status).toBe(503);
    result = { ...plan, ciphertextBase64: 'forbidden' };
    expect((await run()).status).toBe(503);
    expect(
      (await readEvidenceWorkbench(request(undefined, `?${query}&recordId=${id}`))).status,
    ).toBe(400);
    result = plan;
    change = true;
    expect((await run()).status).toBe(404);
  },
);

it('discovers candidate hosts separately and rejects a substituted Fact store or mixed query', async () => {
  const hosts = {
    items: [{ hostDigest: 'b'.repeat(64), targetId: id, store: 'openpc_candidate_index' }],
    authority: 'NONE',
  };
  const fetch = vi.fn(async (_url: string) => Response.json(hosts));
  vi.stubGlobal('fetch', fetch);
  const result = await readEvidenceWorkbench(
    request(undefined, `?candidateRetirementRecordId=${id}`),
  );
  expect(result.status).toBe(200);
  expect((await result.json()).hosts).toEqual(hosts);
  expect(fetch.mock.calls[0]?.[0]).toContain('/candidate-retirement-hosts');
  expect(
    (
      await readEvidenceWorkbench(
        request(undefined, `?candidateRetirementRecordId=${id}&factRetirementRecordId=${id}`),
      )
    ).status,
  ).toBe(400);
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json({ ...hosts, items: [{ ...hosts.items[0], store: 'openpc_facts' }] }),
    ),
  );
  expect(
    (await readEvidenceWorkbench(request(undefined, `?candidateRetirementRecordId=${id}`))).status,
  ).toBe(503);
});

const catalogueCursor = 'pc2.cGFnZQ.c2ln';
const catalogueKinds = ['records', 'exports'] as const;
type CatalogueKind = (typeof catalogueKinds)[number];
function catalogueItems(kind: CatalogueKind, count: number) {
  return Array.from({ length: count }, (_, index) => {
    const resource = `urn:openpc:resource:018f0000-0000-7000-8000-${String(index + 501).padStart(12, '0')}`;
    return kind === 'records'
      ? { ...record, evidenceId: resource, sequence: String(index + 1) }
      : {
          evidenceExportId: resource,
          participantId: record.participantId,
          requestDigest: record.recordDigest,
          checkpoint: '0',
          state: 'REQUESTED',
          outputDigest: null,
          revision: '1',
          createdAt: time,
          updatedAt: time,
        };
  });
}
function cataloguePath(kind: CatalogueKind) {
  return kind === 'records' ? '/api/v1/evidence-records' : '/api/v1/evidence-exports';
}
it.each(['recordsCursor', 'exportsCursor'] as const)(
  'rejects malformed %s before any public owner read',
  async (field) => {
    const fetch = vi.fn(async () => Response.json(page([])));
    vi.stubGlobal('fetch', fetch);
    for (const cursor of [
      '',
      'cursor',
      'pc2.one',
      'pc2..signature',
      'pc2.value.signature.extra',
      'pc2.value.sig+other',
      'pc2.value.sig ',
      `pc2.${'a'.repeat(2041)}.sig`,
    ]) {
      fetch.mockClear();
      const response = await readEvidenceWorkbench(
        request(undefined, `?${new URLSearchParams({ [field]: cursor })}`),
      );
      expect(response.status, `cursor ${JSON.stringify(cursor)}`).toBe(400);
      expect(fetch).not.toHaveBeenCalled();
    }
  },
);
it.each(['recordsCursor', 'exportsCursor'] as const)(
  'rejects duplicate and mixed %s selectors without contacting owners',
  async (field) => {
    const fetch = vi.fn(async () => Response.json(page([])));
    vi.stubGlobal('fetch', fetch);
    const parameters = new URLSearchParams({ [field]: catalogueCursor });
    parameters.append(field, catalogueCursor);
    for (const query of [
      parameters.toString(),
      new URLSearchParams({ [field]: catalogueCursor, exportId: id }).toString(),
      new URLSearchParams({ [field]: catalogueCursor, recordId: id }).toString(),
      new URLSearchParams({ [field]: catalogueCursor, extra: 'hidden' }).toString(),
    ]) {
      fetch.mockClear();
      expect((await readEvidenceWorkbench(request(undefined, `?${query}`))).status).toBe(400);
      expect(fetch).not.toHaveBeenCalled();
    }
  },
);
it.each([catalogueCursor, `pc2.${'a'.repeat(2040)}.sig`])(
  'forwards producer-valid catalogue and export cursors unchanged, preserving the digest filter',
  async (cursor) => {
    const fetch = vi.fn(async (url: string, init?: RequestInit) => {
      const owner = new URL(url);
      expect(init?.method).toBeUndefined();
      expect(init?.cache).toBe('no-store');
      expect(new Headers(init?.headers).get('Cookie')).toBe('__Host-openpc_session=session-token');
      if (
        owner.pathname === cataloguePath('records') ||
        owner.pathname === cataloguePath('exports')
      ) {
        expect(owner.searchParams.get('cursor')).toBe(cursor);
        expect(owner.searchParams.get('limit')).toBe(
          owner.pathname === cataloguePath('records') ? '10' : '50',
        );
        expect(owner.searchParams.get('filter')).toBe(
          owner.pathname === cataloguePath('records')
            ? `recordDigest:eq:${record.recordDigest}`
            : null,
        );
      }
      return Response.json(page([]));
    });
    vi.stubGlobal('fetch', fetch);
    const response = await readEvidenceWorkbench(
      request(
        undefined,
        `?${new URLSearchParams({ recordsCursor: cursor, exportsCursor: cursor, recordDigest: record.recordDigest })}`,
      ),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toMatchObject({
      recordDigest: record.recordDigest,
      recordsCursor: cursor,
      records: page([]),
      exports: page([]),
      recordsUnavailable: false,
      exportsUnavailable: false,
    });
    expect(fetch).toHaveBeenCalledTimes(5);
  },
);
const invalidCataloguePages = [
  { name: '51 rows', count: 51, fields: {} },
  { name: 'authorized empty with a row', count: 1, fields: { authorizedEmpty: true, total: '0' } },
  {
    name: 'authorized empty with a nonzero total',
    count: 0,
    fields: { authorizedEmpty: true, total: '1' },
  },
  {
    name: 'authorized empty with an unknown total',
    count: 0,
    fields: { authorizedEmpty: true, total: null },
  },
  {
    name: 'authorized empty with unknown completeness',
    count: 0,
    fields: { authorizedEmpty: true, completeness: 'UNKNOWN' },
  },
];
it('withholds an oversized record page without exposing its cursor or metadata', async () => {
  const oversized = { ...page(catalogueItems('records', 11)), nextCursor: catalogueCursor };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) =>
      Response.json(new URL(url).pathname === cataloguePath('records') ? oversized : page([])),
    ),
  );
  const response = await readEvidenceWorkbench(request());
  expect(response.status).toBe(503);
  const body = await response.text();
  expect(body).not.toContain(catalogueCursor);
  expect(body).not.toContain(record.recordDigest);
  expect(body).not.toContain('nextCursor');
});
it.each(
  catalogueKinds.flatMap((kind) => invalidCataloguePages.map((invalid) => ({ kind, ...invalid }))),
)(
  'withholds $kind page with $name rather than repairing its claims',
  async ({ kind, count, fields }) => {
    const invalid = { ...page(catalogueItems(kind, count)), ...fields };
    const fetch = vi.fn(async (url: string, init?: RequestInit) => {
      expect(init?.method).toBeUndefined();
      return Response.json(new URL(url).pathname === cataloguePath(kind) ? invalid : page([]));
    });
    vi.stubGlobal('fetch', fetch);
    const response = await readEvidenceWorkbench(request());
    expect(response.status).toBe(503);
    const body = await response.json();
    expect(body.code).toBe('PC-INTEGRATION-5001');
    expect(body).not.toHaveProperty('records');
    expect(body).not.toHaveProperty('exports');
    expect(body).not.toHaveProperty('total');
    expect(body).not.toHaveProperty('nextCursor');
    expect(JSON.stringify(body)).not.toContain(record.recordDigest);
    expect(fetch.mock.calls.every(([, init]) => !(init as RequestInit | undefined)?.method)).toBe(
      true,
    );
  },
);
const admittedCataloguePages = [
  { name: '50 rows', count: 50, fields: { nextCursor: catalogueCursor } },
  { name: 'ordinary rows', count: 1, fields: {} },
  { name: 'authorized empty', count: 0, fields: {} },
  { name: 'empty without an authorization claim', count: 0, fields: { authorizedEmpty: false } },
  {
    name: 'rows with unknown total and completeness',
    count: 1,
    fields: { total: null, completeness: 'UNKNOWN', nextCursor: catalogueCursor },
  },
  {
    name: 'empty with unknown total and completeness',
    count: 0,
    fields: { authorizedEmpty: false, total: null, completeness: 'UNKNOWN' },
  },
];
it.each(
  catalogueKinds.flatMap((kind) =>
    admittedCataloguePages.map((admitted) => ({
      kind,
      ...admitted,
      ...(kind === 'records' && admitted.count === 50 ? { name: '10 rows', count: 10 } : {}),
    })),
  ),
)(
  'preserves $kind page with $name without inventing a count or empty claim',
  async ({ kind, count, fields }) => {
    const admitted = { ...page(catalogueItems(kind, count)), ...fields };
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        Response.json(new URL(url).pathname === cataloguePath(kind) ? admitted : page([])),
      ),
    );
    const response = await readEvidenceWorkbench(request());
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = await response.json();
    expect(body[kind]).toEqual(admitted);
    expect(body[`${kind}Unavailable`]).toBe(false);
  },
);
it.each(
  catalogueKinds.flatMap((kind) =>
    ([403, 404, 503, 'transport'] as const).map((failure) => ({ kind, failure })),
  ),
)(
  'preserves $kind unavailable after $failure while retaining an independent authorized sibling',
  async ({ kind, failure }) => {
    const sibling = kind === 'records' ? 'exports' : 'records';
    const admitted = page(catalogueItems(sibling, 1));
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        const path = new URL(url).pathname;
        if (path === cataloguePath(kind)) {
          if (failure === 'transport') throw new Error('lost owner response');
          return Response.json(
            { title: 'private upstream detail', token: 'hidden' },
            { status: failure },
          );
        }
        return Response.json(path === cataloguePath(sibling) ? admitted : page([]));
      }),
    );
    const response = await readEvidenceWorkbench(request());
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body[kind]).toBeNull();
    expect(body[`${kind}Unavailable`]).toBe(true);
    expect(body[sibling]).toEqual(admitted);
    expect(body[`${sibling}Unavailable`]).toBe(false);
    expect(JSON.stringify(body)).not.toContain('private upstream detail');
    expect(JSON.stringify(body)).not.toContain('hidden');
  },
);
it.each(catalogueKinds)(
  'withholds $kind foreign participant data under the original fence',
  async (kind) => {
    const foreign = {
      ...catalogueItems(kind, 1)[0],
      participantId: 'urn:openpc:participant:018f0000-0000-7000-8000-000000000102',
    };
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        Response.json(page(new URL(url).pathname === cataloguePath(kind) ? [foreign] : [])),
      ),
    );
    const response = await readEvidenceWorkbench(request());
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain(foreign.participantId);
  },
);
it.each(catalogueKinds)(
  'keeps malformed private $kind fields unavailable instead of exposing a synthetic empty page',
  async (kind) => {
    const raw = { ...catalogueItems(kind, 1)[0], receiptBase64: 'private-receipt' };
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) =>
        Response.json(page(new URL(url).pathname === cataloguePath(kind) ? [raw] : [])),
      ),
    );
    const response = await readEvidenceWorkbench(request());
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body[kind]).toBeNull();
    expect(body[`${kind}Unavailable`]).toBe(true);
    expect(JSON.stringify(body)).not.toContain('private-receipt');
  },
);
it.each(
  catalogueKinds.flatMap((kind) => [false, true].map((inconsistent) => ({ kind, inconsistent }))),
)(
  'prioritizes current context denial over $kind output with inconsistent=$inconsistent',
  async ({ kind, inconsistent }) => {
    const upstream = inconsistent
      ? { ...page(catalogueItems(kind, 1)), authorizedEmpty: true }
      : page(catalogueItems(kind, 1));
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (new URL(url).pathname === cataloguePath(kind)) {
          state.contextEpoch = '2';
          return Response.json(upstream);
        }
        return Response.json(page([]));
      }),
    );
    const response = await readEvidenceWorkbench(request());
    expect(response.status).toBe(404);
    const text = await response.text();
    expect(text).not.toContain(record.recordDigest);
    expect(text).not.toContain('evidenceExportId');
    expect(text).not.toContain('nextCursor');
  },
);
