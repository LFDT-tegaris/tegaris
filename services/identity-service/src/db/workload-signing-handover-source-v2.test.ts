import { createHash, generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { afterEach, expect, it, vi } from 'vitest';
import {
  businessSigningTrustDigest,
  businessSigningTrustPreimage,
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
  type BusinessSigningTrust,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import { workloadHandoverSigningFamilies } from '../../../../tests/integration/identity/workload-signing-handover-fixture.js';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';
import { workloadSigningHandoverAdmissionOperation as admission } from '../../../../packages/security-kernel/src/workload-signing-handover-operations.js';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import type { WorkloadSigningHandoverRequestV2 } from '../contracts/workload-signing-handover-v2.js';
import { businessSigningPurpose } from '../domain/business-signing-provider.js';
import { fenceBoundAuthorities, lockAuthorityFence } from './authority-fence.js';
import { readRetainedBusinessSigningTrust } from './business-signing-store.js';
import { captureIdentityEnvelopeRotationIssuer } from './identity-envelope-rotation-issuer.js';
import { readWorkloadSigningHandoverProvenance } from './workload-signing-handover-provenance.js';
import { captureWorkloadSigningEnvelopeCarry } from './workload-signing-handover-envelope-carry.js';
import {
  captureWorkloadSigningHandoverSourceV2,
  captureWorkloadSigningHandoverAdmissionSourceV2,
  workloadSigningHandoverSourceV2Digest,
  type WorkloadSigningHandoverCaptureScopeV2,
} from './workload-signing-handover-source-v2.js';

vi.mock('./authority-fence.js', () => ({
  fenceBoundAuthorities: vi.fn(),
  lockAuthorityFence: vi.fn(),
}));
vi.mock('./business-signing-store.js', () => ({ readRetainedBusinessSigningTrust: vi.fn() }));
vi.mock('./identity-envelope-rotation-issuer.js', async (original) => ({
  ...(await original<typeof import('./identity-envelope-rotation-issuer.js')>()),
  captureIdentityEnvelopeRotationIssuer: vi.fn(),
}));
vi.mock('./workload-signing-handover-provenance.js', () => ({
  readWorkloadSigningHandoverProvenance: vi.fn(),
}));
vi.mock('./workload-signing-handover-envelope-carry.js', () => ({
  captureWorkloadSigningEnvelopeCarry: vi.fn(),
}));
afterEach(() => vi.resetAllMocks());

const id = (n: number) => `01a10000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const digest = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}` as const;
const tagged = (b: Buffer) => 'sha256:' + b.toString('hex');
const bytes = (v: string) => Buffer.from(v.slice(7), 'hex');

// Native owners are mocked here. This fixture checks complete-set capture and
// version separation; it does not establish genuine repair or actor authority.
function fixture(maximumCarry = false) {
  const now = 1800000000000000000n;
  const issuer = {
    participantId: id(1),
    privacyDomainId: id(2),
    workloadCredentialId: id(4),
    workloadPrincipalId: id(5),
    workloadParticipantEpoch: '7',
    workloadPrincipalEpoch: '2',
    workloadCredentialEpoch: '2',
    workloadPublicKeyDigest: digest(1),
    credentialValidFromNs: (now - 60000000000n).toString(),
    credentialValidUntilNs: (now + 7200000000000n).toString(),
  };
  const families = workloadHandoverSigningFamilies()
    .filter((f) => f.role !== 'IDENTITY_ENVELOPE')
    .map((family, index) => {
      const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' });
      const trust: BusinessSigningTrust = {
        participantId: id(1),
        privacyDomainId: id(2),
        environmentId: 'synthetic-handover',
        signerId: evidenceKeyId(publicKey),
        publicKeySpkiDer: publicKey,
        workloadCredentialId: id(3),
        workloadCredentialEpoch: 1n,
        keyEpoch: 3n,
        validFromNs: now - 7200000000000n,
        validUntilNs: now - 60000000000n,
        admissionKind: 'BOOTSTRAP',
        admissionReference: 'synthetic-original-' + index,
        admissionDigest: Buffer.alloc(32, index + 1),
        secretClass: 'SECRET-SIGNING-KEY',
        secretReference: `secret://local/receipt-${index}#1`,
        secretVersion: '1',
        grants: family.profiles.map((p) => ({
          profileId: p.profileId,
          profileVersion: p.profileVersion,
          profileDigest: bytes(p.profileDigest),
          actionIntentId: p.actionIntentId,
          catalogOperationId: p.catalogOperationId,
        })),
      };
      return { role: family.role, trust };
    })
    .sort((a, b) => a.trust.signerId.localeCompare(b.trust.signerId));
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'der' });
  const carriedTrust: IdentityEnvelopeSigningTrust = {
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'synthetic-handover',
    signerId: evidenceKeyId(publicKey),
    publicKeySpkiDer: publicKey,
    workloadCredentialId: id(4),
    workloadCredentialEpoch: 2n,
    workloadParticipantEpoch: 7n,
    workloadPrincipalEpoch: 2n,
    keyEpoch: maximumCarry ? 18446744073709551615n : 2n,
    validFromNs: now - 60000000000n,
    validUntilNs: now + 3600000000000n,
    admissionKind: 'GOVERNED',
    admissionReference: `urn:openpc:resource:${id(40)}`,
    admissionDigest: Buffer.alloc(32, 9),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://local/repaired-envelope#2',
    secretVersion: '2',
    purpose: identityEnvelopeContext.purpose,
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
  };
  const carriedEnvelope: WorkloadSigningHandoverRequestV2['carriedEnvelope'] = {
    disposition: 'CARRY_COMPLETED_371_RECOVERY',
    purpose: carriedTrust.purpose,
    profileDigest: identityEnvelopeSigningProfileDigest,
    signerId: carriedTrust.signerId,
    trustDigest: identityEnvelopeSigningTrustDigest(carriedTrust),
    selectionAdmissionVersion: maximumCarry ? '18446744073709551615' : '2',
    recoveryId: id(39),
    rotationId: id(40),
    completionOperationId: id(41),
    leaseClosureOperationId: id(42),
    reviewOperationId: id(43),
  };
  const request: WorkloadSigningHandoverRequestV2 = {
    schemaVersion: 2,
    actionIntentId: signingRotationActions.create,
    actionIntentDigest: digest(2),
    environmentId: carriedTrust.environmentId,
    predecessorCredentialId: id(3),
    successorCredentialId: id(4),
    credentialRotationOperationId: id(6),
    reason: 'Preserve the repaired envelope while renewing receipt keys',
    replacements: families.map((f, index) => ({
      oldFingerprint: f.trust.signerId,
      oldTrustDigest: tagged(businessSigningTrustDigest(f.trust)),
      expectedKeyEpoch: f.trust.keyEpoch.toString(),
      oldReference: f.trust.secretReference,
      newReference: `secret://local/successor-receipt-${index}#2`,
      signerRole: f.role,
      purpose: businessSigningPurpose,
    })),
    carriedEnvelope,
  };
  const scope: WorkloadSigningHandoverCaptureScopeV2 = {
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: request.environmentId,
    localQaEnabled: true,
    verifier: { verifyCanonicalAssertion: async () => undefined },
    authority: {
      catalogOperationId: 'OPS-OP-CREATE-SIGNING-KEY-ROTATION',
      principalId: id(10),
      participantEpoch: '7',
      principalEpoch: '1',
      assignmentId: id(11),
      assignmentRowVersion: '1',
      authorityEnvelopeId: id(12),
      authorityEpoch: '1',
      delegationEpoch: '1',
      privacyDomainId: id(2),
      actionIntentId: signingRotationActions.create,
      resourceId: '*',
      sessionId: id(13),
      sessionEpoch: '1',
    },
  };
  const provenance = {
    participantId: id(1),
    privacyDomainId: id(2),
    predecessorCredentialId: id(3),
    predecessorCredentialEpoch: '1',
    successorCredentialId: id(4),
    successorCredentialEpoch: '2',
    credentialRotationOperationId: id(6),
    principalId: id(5),
    makerPrincipalId: id(10),
    checkerPrincipalId: id(14),
    candidateDigest: digest(3),
    evidenceDigest: digest(4),
  };
  const carry: Awaited<ReturnType<typeof captureWorkloadSigningEnvelopeCarry>> = {
    trust: carriedTrust,
    issuer: { ...issuer },
    recordedAtNs: now,
    document: {
      schema: 'pc.identity.workload-signing-handover.envelope-carry.v1',
      ...carriedEnvelope,
      participantId: id(1),
      privacyDomainId: id(2),
      environmentId: request.environmentId,
      issuer: { ...issuer },
      enrollmentId: id(44),
      enrollmentDigest: digest(44),
      custodyTrustDigest: digest(45),
      intentDigest: digest(46),
      activationOperationId: id(47),
      activationEvidenceDigest: digest(47),
      proofEvidenceDigest: digest(48),
      completionDigest: digest(49),
      cutoverEvidenceDigest: digest(50),
      consumer: {
        operationId: id(51),
        envelopeId: id(52),
        payloadDigest: digest(51),
        receiptDigest: digest(52),
      },
      closure: {
        recoveryId: id(39),
        enrollmentId: id(44),
        operationId: id(42),
        state: 'REVOKED',
        revision: '6',
        authority: 'NONE',
        actorPrincipalId: id(53),
        closedAt: '2026-10-03T06:06:00.000Z',
        evidenceDigest: digest(53),
      },
      review: {
        schema: 'pc.identity.workload-signing-handover.repair-review.v1',
        participantId: id(1),
        privacyDomainId: id(2),
        recoveryId: id(39),
        reviewOperationId: id(43),
        enrollmentId: id(44),
        enrollmentDigest: digest(44),
        leaseClosureState: 'REVOKED',
        closedCaseRevision: '6',
        mutationCandidateId: id(54),
        candidateDigest: digest(54),
        approvalRequestId: id(55),
        approvalDecisionId: id(56),
        approvalDecisionDigest: digest(56),
        reviewerPrincipalId: id(57),
        checkerPrincipalId: id(58),
        noteDigest: digest(59),
        reviewedAt: '2026-10-03T06:07:00.000Z',
        evidenceDigest: digest(60),
        resultDigest: digest(61),
      },
      trustPreimageBase64: identityEnvelopeSigningTrustPreimage(carriedTrust).toString('base64'),
      trustPreimageDigest: identityEnvelopeSigningTrustDigest(carriedTrust),
    },
  };
  const receipts = families
    .flatMap((f) =>
      f.trust.grants.map((g) => ({
        signerId: f.trust.signerId,
        credentialId: id(3),
        profileId: g.profileId,
        profileVersion: g.profileVersion,
        profileDigest: g.profileDigest,
        rowVersion: '4',
        admissionVersion: '2',
        fenceGeneration: '1',
        fencedOperationId: null as string | null,
      })),
    )
    .sort((a, b) => Buffer.compare(a.profileDigest, b.profileDigest));
  const envelopes = [
    {
      signerId: carriedTrust.signerId,
      credentialId: id(4),
      profileDigest: bytes(identityEnvelopeSigningProfileDigest),
      admissionVersion: carriedEnvelope.selectionAdmissionVersion,
    },
  ];
  const lives = [...families.map((f) => f.trust.signerId), carriedTrust.signerId]
    .sort()
    .map((signerId) => ({ signerId, state: 'ACTIVE' }));
  const credentials = [
    {
      credentialId: id(3),
      principalId: id(5),
      workloadId: 'synthetic-workload',
      epoch: '2',
      state: 'REVOKED',
    },
    {
      credentialId: id(4),
      principalId: id(5),
      workloadId: 'synthetic-workload',
      epoch: '2',
      state: 'ACTIVE',
    },
  ];
  const controls = {
    serializable: true,
    competing: false,
    reused: false,
    renewal: false,
    nowNs: now.toString(),
  };
  const queries: { sql: string; values?: unknown[] }[] = [];
  const query = vi.fn(async (sql: string, values?: unknown[]) => {
    queries.push({ sql, values });
    if (sql.includes('current_setting'))
      return { rowCount: 1, rows: [{ serializable: controls.serializable }] };
    if (sql.includes('from control.action_intent'))
      return { rowCount: 1, rows: [{ digest: bytes(request.actionIntentDigest) }] };
    if (sql.includes('from control.credential'))
      return { rowCount: credentials.length, rows: credentials };
    if (sql.includes('from control.business_signing_selection'))
      return { rowCount: receipts.length, rows: receipts };
    if (sql.includes('from control.identity_envelope_signing_selection'))
      return { rowCount: envelopes.length, rows: envelopes };
    if (sql.includes('from control.workload_renewal_signing_selection'))
      return { rowCount: controls.renewal ? 1 : 0, rows: controls.renewal ? [{}] : [] };
    if (sql.includes('from control.business_signing_key_state'))
      return { rowCount: lives.length, rows: lives };
    if (sql.includes('from control.signing_key_rotation'))
      return { rowCount: controls.competing ? 1 : 0, rows: [] };
    if (sql.includes('secret_reference=any'))
      return { rowCount: controls.reused ? 1 : 0, rows: [] };
    if (sql.includes('clock_timestamp()'))
      return { rowCount: 1, rows: [{ nowNs: controls.nowNs }] };
    throw new Error('Unexpected native source query');
  });
  vi.mocked(captureIdentityEnvelopeRotationIssuer).mockResolvedValue({ issuer, recordedAtNs: now });
  vi.mocked(readWorkloadSigningHandoverProvenance).mockResolvedValue(provenance);
  vi.mocked(captureWorkloadSigningEnvelopeCarry).mockResolvedValue(carry);
  vi.mocked(readRetainedBusinessSigningTrust).mockImplementation(
    async (_client, _scope, signerId) => {
      const f = families.find((f) => f.trust.signerId === signerId);
      if (!f) throw new Error();
      return f.trust;
    },
  );
  const client = { query } as unknown as PoolClient;
  const run = () => captureWorkloadSigningHandoverSourceV2(client, scope, request);
  return {
    request,
    scope,
    carry,
    issuer,
    provenance,
    families,
    receipts,
    envelopes,
    lives,
    credentials,
    controls,
    queries,
    client,
    run,
  };
}

it('captures all six receipt keys/eighteen selectors and preserves the single repaired envelope', async () => {
  const f = fixture();
  const result = await f.run();
  expect(result.document.schema).toBe('pc.identity.workload-signing-handover.source.v2');
  expect(result.document.keys).toHaveLength(6);
  expect(result.document.receiptSelections).toHaveLength(18);
  expect(result.document.envelopeSelections).toEqual(
    f.envelopes.map((r) => ({ ...r, profileDigest: tagged(r.profileDigest) })),
  );
  expect(result.document.carriedEnvelope).toBe(f.carry.document);
  expect(result.carriedTrust).toBe(f.carry.trust);
  expect(new Set(result.trusts.map((t) => t.signerRole))).toEqual(
    new Set(['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE']),
  );
  expect(result.document.keys.map((k) => k.oldTrustPreimageBase64)).toEqual(
    f.families.map((f) => businessSigningTrustPreimage(f.trust).toString('base64')),
  );
  const protectedIds = [...f.families.map((f) => f.trust.signerId), f.carry.trust.signerId].sort();
  expect(
    f.queries.find((q) => q.sql.includes('from control.signing_key_rotation'))?.values?.[2],
  ).toEqual(protectedIds);
  expect(vi.mocked(lockAuthorityFence).mock.invocationCallOrder[0]).toBeLessThan(
    vi.mocked(fenceBoundAuthorities).mock.invocationCallOrder[0]!,
  );
  expect(captureWorkloadSigningEnvelopeCarry).toHaveBeenCalledWith(
    f.client,
    expect.objectContaining({
      workloadCredentialId: f.request.successorCredentialId,
      localQaEnabled: true,
    }),
    f.request.carriedEnvelope,
    f.scope.verifier,
  );
  expect(f.queries.every((q) => !/^\s*(insert|update|delete|set)\b/iu.test(q.sql))).toBe(true);
});

it('keeps maximum carried counters unchanged while replacements remain incrementable', async () => {
  const f = fixture(true);
  const r = await f.run();
  expect(r.carriedTrust.keyEpoch).toBe(18446744073709551615n);
  expect(r.document.envelopeSelections[0]!.admissionVersion).toBe('18446744073709551615');
});

it('uses the exact admission action, catalog and handover resource for recapture', async () => {
  const f = fixture();
  f.scope.authority = {
    ...f.scope.authority,
    catalogOperationId: admission.catalogOperationId,
    actionIntentId: admission.actionIntentId,
    resourceId: id(80),
  };
  const r = await captureWorkloadSigningHandoverAdmissionSourceV2(
    f.client,
    { ...f.scope, handoverId: id(80) },
    f.request,
  );
  expect(r.document.schema).toBe('pc.identity.workload-signing-handover.source.v2');
  expect(fenceBoundAuthorities).toHaveBeenCalledWith(
    f.client,
    f.scope.participantId,
    [f.scope.authority],
    expect.anything(),
  );
});

it.each(['wrong catalog', 'wrong action', 'wrong resource', 'wildcard resource'])(
  'denies admission with %s before native reads',
  async (kind) => {
    const f = fixture();
    f.scope.authority = {
      ...f.scope.authority,
      catalogOperationId: admission.catalogOperationId,
      actionIntentId: admission.actionIntentId,
      resourceId: id(80),
    };
    if (kind === 'wrong catalog')
      f.scope.authority = { ...f.scope.authority, catalogOperationId: 'other' };
    if (kind === 'wrong action')
      f.scope.authority = { ...f.scope.authority, actionIntentId: signingRotationActions.create };
    if (kind === 'wrong resource') f.scope.authority = { ...f.scope.authority, resourceId: id(81) };
    const handoverId = kind === 'wildcard resource' ? '*' : id(80);
    await expect(
      captureWorkloadSigningHandoverAdmissionSourceV2(
        f.client,
        { ...f.scope, handoverId },
        f.request,
      ),
    ).rejects.toThrow();
    expect(f.queries).toHaveLength(0);
  },
);

const mutations: readonly [string, (f: ReturnType<typeof fixture>) => void][] = [
  [
    'incomplete replacements',
    (f) => {
      f.request.replacements.pop();
    },
  ],
  [
    'missing receipt selector',
    (f) => {
      f.receipts.pop();
    },
  ],
  [
    'extra receipt selector',
    (f) => {
      f.receipts.push({ ...f.receipts[0]! });
    },
  ],
  [
    'unlisted current key',
    (f) => {
      f.receipts[0]!.signerId = digest(999);
    },
  ],
  [
    'wrong receipt credential',
    (f) => {
      f.receipts[0]!.credentialId = id(4);
    },
  ],
  [
    'fenced receipt',
    (f) => {
      f.receipts[0]!.fencedOperationId = id(90);
    },
  ],
  [
    'additional envelope selector',
    (f) => {
      f.envelopes.push({ ...f.envelopes[0]! });
    },
  ],
  [
    'missing envelope',
    (f) => {
      f.envelopes.pop();
    },
  ],
  [
    'old envelope credential',
    (f) => {
      f.envelopes[0]!.credentialId = id(3);
    },
  ],
  [
    'changed carried selector',
    (f) => {
      f.envelopes[0]!.admissionVersion = '3';
    },
  ],
  [
    'unsupported renewal selection',
    (f) => {
      f.controls.renewal = true;
    },
  ],
  [
    'inactive protected key',
    (f) => {
      f.lives[0]!.state = 'REVOKED';
    },
  ],
  [
    'missing protected lifecycle',
    (f) => {
      f.lives.pop();
    },
  ],
  [
    'duplicate lifecycle row',
    (f) => {
      f.lives[1] = { ...f.lives[0]! };
    },
  ],
  [
    'unfinished rotation',
    (f) => {
      f.controls.competing = true;
    },
  ],
  [
    'reused successor reference',
    (f) => {
      f.controls.reused = true;
    },
  ],
  [
    'different current issuer',
    (f) => {
      f.carry.issuer = { ...f.carry.issuer, workloadPrincipalEpoch: '3' };
    },
  ],
  [
    'nonserializable context',
    (f) => {
      f.controls.serializable = false;
    },
  ],
  [
    'different workload audience',
    (f) => {
      f.credentials[1]!.workloadId = 'other-workload';
    },
  ],
  [
    'different workload principal',
    (f) => {
      f.credentials[1]!.principalId = id(99);
    },
  ],
  [
    'active predecessor',
    (f) => {
      f.credentials[0]!.state = 'ACTIVE';
    },
  ],
  [
    'old credential epoch',
    (f) => {
      f.credentials[1]!.epoch = '1';
    },
  ],
  [
    'expired carried key at final read',
    (f) => {
      f.controls.nowNs = f.carry.trust.validUntilNs.toString();
    },
  ],
];
it.each(mutations)('denies %s without returning partial source', async (_, mutate) => {
  const f = fixture();
  mutate(f);
  await expect(f.run()).rejects.toThrow();
});

it.each(['rowVersion', 'admissionVersion', 'fenceGeneration'] as const)(
  'rejects unincrementable replacement %s',
  async (field) => {
    const f = fixture();
    f.receipts[0]![field] = '18446744073709551615';
    await expect(f.run()).rejects.toThrow();
  },
);

it('propagates native repair denial instead of replacing the carried key', async () => {
  const f = fixture();
  vi.mocked(captureWorkloadSigningEnvelopeCarry).mockRejectedValue(
    new Error('Original repair denied'),
  );
  await expect(f.run()).rejects.toThrow('Original repair denied');
  expect(readRetainedBusinessSigningTrust).not.toHaveBeenCalled();
});

it('binds exact sourceV2 bytes and every carried history locator into its own digest domain', async () => {
  const f = fixture();
  const source = (await f.run()).document;
  const canonical = canonicalAuthorizationJson(source);
  const expected =
    'sha256:' +
    createHash('sha256')
      .update('pc.identity.workload-signing-handover.source.v2\0')
      .update(canonical)
      .digest('hex');
  expect(workloadSigningHandoverSourceV2Digest(source)).toBe(expected);
  const old =
    'sha256:' +
    createHash('sha256')
      .update('pc.identity.workload-signing-handover.source.v1\0')
      .update(canonical)
      .digest('hex');
  expect(expected).not.toBe(old);
  expect(
    workloadSigningHandoverSourceV2Digest({
      ...source,
      carriedEnvelope: { ...source.carriedEnvelope, reviewOperationId: id(99) },
    }),
  ).not.toBe(expected);
});
