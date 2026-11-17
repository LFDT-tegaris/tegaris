import { createHash, generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import {
  businessSigningTrustDigest,
  businessSigningTrustPreimage,
  businessTransitionProfileForOperation,
  configurationRequestDigest,
  encodeAdmittedReceipt,
  encodeCommandCommitted,
  signReceiptCose,
  type BusinessSigningTrust,
  type BusinessTransitionReceipt,
} from '@openpc/security-kernel';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import {
  workloadRenewalPolicyDefinitionBytes,
  workloadRenewalPolicyDefinitionDigest,
} from '../contracts/workload-renewal-policy.js';
import { identityActorKeyDigest } from '../domain/identity-runtime-authorization.js';
import { readRetainedBusinessSigningTrust } from './business-signing-store.js';
import {
  bindWorkloadRenewalPolicySnapshot,
  type WorkloadRenewalPolicyState,
} from './workload-renewal-policy-store.js';
import {
  verifyWorkloadRenewalPolicySource,
  readEligibleWorkloadRenewalPolicySource,
  WorkloadRenewalPolicySourceUnavailable,
  type WorkloadRenewalPolicySourceRow,
} from './workload-renewal-policy-source.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = (value: Buffer) => createHash('sha256').update(value).digest();
const ns = (value: string) => BigInt(Date.parse(value)) * 1000000n;
const profile = businessTransitionProfileForOperation('ID-OP-WORKLOAD-RENEWAL-POLICY-CREATE')!;
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const spki = publicKey.export({ type: 'spki', format: 'der' });
function fixture() {
  const scope = {
    participantId: id(1),
    privacyDomainId: id(2),
    policyId: id(3),
    policyRevision: '1',
  };
  const definition = {
    version: 1 as const,
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    policyId: scope.policyId,
    principalId: id(4),
    workloadId: `urn:openpc:workload:${id(4)}`,
    issuerProfileDigest: `sha256:${'11'.repeat(32)}`,
    providerQualificationDigest: `sha256:${'22'.repeat(32)}`,
    attestationProfileDigest: `sha256:${'33'.repeat(32)}`,
    managedAttestorScopeDigest: `sha256:${'44'.repeat(32)}`,
    maximumInstances: 10,
    maximumEnrollmentsPerMinute: 3,
    certificateLifetimeSeconds: 3600,
    recoveryReserveSeconds: 300,
    maximumOverlapSeconds: 30,
    validFrom: '2026-10-04T00:00:00.000Z',
    validUntil: '2026-10-05T00:00:00.000Z',
  };
  const grant = (principalId: string) => ({
    principalId,
    participantEpoch: '1',
    principalEpoch: '1',
    assignmentId: id(20),
    assignmentRowVersion: '1',
    authorityEnvelopeId: id(21),
    authorityEpoch: '1',
    delegationEpoch: '0',
    privacyDomainId: scope.privacyDomainId,
    actionIntentId: profile.actionIntentId,
    resourceId: scope.policyId,
  });
  const ancestors = [id(5), id(6)].map((principalId) => ({
    grant: grant(principalId),
    dependencies: { path: { principalIds: [principalId], delegationIds: [], roleId: null } },
  }));
  const trust: BusinessSigningTrust = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    environmentId: 'local-policy-source',
    signerId: sha256(spki),
    publicKeySpkiDer: spki,
    workloadCredentialId: id(9),
    workloadCredentialEpoch: 1n,
    keyEpoch: 1n,
    validFromNs: ns('2026-10-04T00:00:00.000Z'),
    validUntilNs: ns('2026-10-04T01:00:00.000Z'),
    admissionKind: 'BOOTSTRAP',
    admissionReference: 'local-trust-bootstrap',
    admissionDigest: Buffer.alloc(32, 9),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://local/renewal-policy-receipt#1',
    secretVersion: '1',
    grants: [
      {
        profileId: profile.profileId,
        profileVersion: profile.profileVersion,
        profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
        actionIntentId: profile.actionIntentId,
        catalogOperationId: profile.catalogOperationId,
      },
    ],
  };
  const operationId = id(10),
    candidate = {
      requestId: id(11),
      expectedRevision: '0',
      definition,
      reason: 'Managed deployment',
    };
  const authoritySnapshot = Buffer.from(
    canonicalDefinitionJson({
      schema: 'pc.control.precommit-authority-snapshot.v1',
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      operationId,
      decision: 'ALLOW',
      authorities: ancestors.map((a, i) => ({
        ...a.grant,
        sessionId: id(40 + i),
        sessionEpoch: '1',
      })),
      dependencies: {},
    }),
  );
  const after: WorkloadRenewalPolicyState = {
    revision: '1',
    definition,
    definitionDigest: workloadRenewalPolicyDefinitionDigest(definition),
    state: 'ACTIVE',
    governanceOperationId: operationId,
    businessAncestorsDigest: sha256(Buffer.from(canonicalDefinitionJson(ancestors))),
  };
  const beforeBinding = bindWorkloadRenewalPolicySnapshot(
    scope,
    profile.catalogOperationId,
    undefined,
  );
  const afterBinding = bindWorkloadRenewalPolicySnapshot(scope, profile.catalogOperationId, after);
  const actionIntentDigest = Buffer.alloc(32, 1),
    candidateDigest = Buffer.from(sha256(candidate).slice(7), 'hex');
  const eventPayload = encodeCommandCommitted({
    commandId: operationId,
    aggregateRef: `urn:openpc:workload-renewal-policy:${scope.policyId}`,
    actionIntentId: profile.actionIntentId,
    intentDigest: `sha256:${actionIntentDigest.toString('hex')}`,
  });
  const recordedAtNs = ns('2026-10-04T00:05:00.000Z');
  const receipt: BusinessTransitionReceipt = {
    receiptId: id(12),
    schemaDefinitionDigest: Buffer.from(profile.schemaDefinitionDigest.slice(7), 'hex'),
    transitionProfileId: profile.profileId,
    transitionProfileVersion: profile.profileVersion,
    transitionProfileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
    environmentId: trust.environmentId,
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    operationId,
    actionIntentId: profile.actionIntentId,
    catalogOperationId: profile.catalogOperationId,
    aggregateType: profile.aggregateType,
    aggregateId: scope.policyId,
    actorKeyDigest: identityActorKeyDigest(scope.participantId, id(5)),
    preCommitAuthorityDigest: hash(authoritySnapshot),
    actionIntentDigest,
    candidateDigest,
    idempotencyRecordId: id(13),
    before: beforeBinding.reference,
    after: afterBinding.reference,
    authorizationEvidence: [
      { kind: 3, evidenceId: id(14), evidenceDigest: Buffer.alloc(32, 3) },
      { kind: 4, evidenceId: id(15), evidenceDigest: Buffer.alloc(32, 4) },
    ],
    outboxEvents: [
      {
        eventId: id(16),
        eventType: 'io.openpc.control.command.committed.v1',
        dataSchemaUri:
          'https://schemas.openpc.local/event-payloads.schema.json#/$defs/CommandCommitted',
        source: 'urn:openpc:service:control-api',
        subject: `urn:openpc:workload-renewal-policy:${scope.policyId}`,
        aggregateSequence: 1n,
        occurredAtNs: recordedAtNs,
        correlationId: operationId,
        payloadDigest: hash(eventPayload),
      },
    ],
    transitionKind: 1,
    recordedAtNs,
    signerId: trust.signerId,
    signerTrustSnapshotDigest: businessSigningTrustDigest(trust),
    requestDigest: configurationRequestDigest({
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      principalId: id(5),
      actionIntentId: profile.actionIntentId,
      catalogOperationId: profile.catalogOperationId,
      aggregateType: profile.aggregateType,
      aggregateId: scope.policyId,
      expectedRevision: '0',
      candidateDigest,
      idempotencyKey: 'original-policy-request',
    }),
  };
  const payload = encodeAdmittedReceipt(receipt);
  const row: WorkloadRenewalPolicySourceRow = {
    revision: '1',
    definition,
    definitionCanonical: workloadRenewalPolicyDefinitionBytes(definition),
    definitionDigest: Buffer.from(after.definitionDigest.slice(7), 'hex'),
    businessAncestors: ancestors,
    governanceOperationId: operationId,
    state: 'ACTIVE',
    authoritySnapshot,
    beforeStatePreimage: beforeBinding.preimage,
    afterStatePreimage: afterBinding.preimage,
    prior: null,
    candidate,
    principalId: id(5),
    idempotencyKey: 'original-policy-request',
    evidenceId: id(17),
    receiptId: receipt.receiptId,
    operationId,
    payload,
    payloadDigest: hash(payload),
    coseSign1: signReceiptCose(privateKey.export({ type: 'pkcs8', format: 'der' }), spki, payload),
    publicKey: spki,
    trustDigest: businessSigningTrustDigest(trust),
    trustPreimage: businessSigningTrustPreimage(trust),
    signerId: trust.signerId,
    recordedAtNs: recordedAtNs.toString(),
    evidenceFormat: 'COSE_SIGN1_24001_1_338',
  };
  return { scope, row, trust, receipt, eventPayload };
}
it('verifies real historical P256 governance at its occurrence without current private-key selection or human session renewal', () => {
  const f = fixture();
  expect(verifyWorkloadRenewalPolicySource(f.row, f.scope, f.trust).definition).toEqual(
    f.row.definition,
  );
  expect(f.trust.validUntilNs).toBeLessThan(ns('2026-10-04T08:00:00.000Z'));
});
it.each([
  'signature',
  'definition',
  'parents',
  'snapshot',
  'before',
  'after',
  'candidate',
  'request',
  'operation',
  'state',
])('denies altered %s even when the policy row reports ACTIVE', (kind) => {
  const f = fixture();
  const row = { ...f.row };
  switch (kind) {
    case 'signature':
      row.coseSign1 = Buffer.from(row.coseSign1);
      row.coseSign1[row.coseSign1.length - 1] = row.coseSign1[row.coseSign1.length - 1]! ^ 1;
      break;
    case 'definition':
      row.definition = { ...f.receipt, maximumInstances: 99 };
      break;
    case 'parents':
      row.businessAncestors = [];
      break;
    case 'snapshot':
      row.authoritySnapshot = Buffer.from('{}');
      break;
    case 'before':
      row.beforeStatePreimage = Buffer.from('other');
      break;
    case 'after':
      row.afterStatePreimage = Buffer.from('other');
      break;
    case 'candidate':
      row.candidate = { ...(f.row.candidate as object), reason: 'changed original intent' };
      break;
    case 'request':
      row.idempotencyKey = 'another-business-intent';
      break;
    case 'operation':
      row.governanceOperationId = id(99);
      break;
    case 'state':
      row.state = 'SUSPENDED';
      break;
  }
  expect(() => verifyWorkloadRenewalPolicySource(row, f.scope, f.trust)).toThrow(
    WorkloadRenewalPolicySourceUnavailable,
  );
});
it.each(['participantId', 'privacyDomainId', 'policyId', 'policyRevision'] as const)(
  'denies foreign or superseded %s',
  (field) => {
    const f = fixture();
    expect(() =>
      verifyWorkloadRenewalPolicySource(
        f.row,
        { ...f.scope, [field]: field === 'policyRevision' ? '2' : id(99) },
        f.trust,
      ),
    ).toThrow();
  },
);
it('rejects a retained trust tuple or profile grant different from the original signed snapshot', () => {
  const f = fixture();
  for (const patch of [
    { environmentId: 'foreign' },
    { workloadCredentialEpoch: 2n },
    { grants: [] },
    { validUntilNs: ns('2026-10-04T00:01:00.000Z') },
  ])
    expect(() =>
      verifyWorkloadRenewalPolicySource(f.row, f.scope, { ...f.trust, ...patch }),
    ).toThrow();
});
function trustRow(f: ReturnType<typeof fixture>) {
  const t = f.trust;
  return {
    ...t,
    workloadCredentialEpoch: t.workloadCredentialEpoch.toString(),
    keyEpoch: t.keyEpoch.toString(),
    validFromNs: t.validFromNs.toString(),
    validUntilNs: t.validUntilNs.toString(),
    trustPreimage: f.row.trustPreimage,
    trustDigest: f.row.trustDigest,
  };
}
it('reconstructs historical public trust from exact338 immutable key and grant owners without lifecycle selection or new locks', async () => {
  const f = fixture();
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rowCount: 1, rows: [trustRow(f)] })
    .mockResolvedValueOnce({ rowCount: 1, rows: f.trust.grants });
  await expect(
    readRetainedBusinessSigningTrust({ query } as unknown as PoolClient, f.scope, f.trust.signerId),
  ).resolves.toEqual(f.trust);
  expect(query.mock.calls[0]![0]).toContain('signing_purpose_code=338');
  expect(query.mock.calls[0]![1]).toEqual([
    f.scope.participantId,
    f.scope.privacyDomainId,
    f.trust.signerId,
  ]);
  for (const [sql] of query.mock.calls)
    expect(sql).not.toMatch(
      /for share|for update|business_signing_selection|clock_timestamp|state='ACTIVE'/iu,
    );
});
it.each(['missing', 'compromised', 'superseded', 'inputs', 'outbox'])(
  'denies actual source suffix %s before returning an eligible policy or taking family/attempt effects',
  async (kind) => {
    const f = fixture();
    const query = vi
      .fn()
      .mockResolvedValueOnce({
        rowCount: kind === 'missing' ? 0 : 1,
        rows: kind === 'missing' ? [] : [f.row],
      })
      .mockResolvedValueOnce({ rowCount: 1, rows: [trustRow(f)] })
      .mockResolvedValueOnce({ rowCount: 1, rows: f.trust.grants })
      .mockResolvedValueOnce({
        rowCount: kind === 'compromised' ? 0 : 1,
        rows: [{ state: 'RETIRED' }],
      })
      .mockResolvedValueOnce({
        rowCount: kind === 'superseded' ? 0 : 1,
        rows: [{ policy_id: f.scope.policyId }],
      })
      .mockResolvedValueOnce({
        rowCount: kind === 'inputs' ? 0 : 2,
        rows: f.receipt.authorizationEvidence.map((e) => ({
          kind: e.kind,
          id: e.evidenceId,
          digest: e.evidenceDigest,
        })),
      })
      .mockResolvedValueOnce({ rowCount: 0, rows: [] });
    await expect(
      readEligibleWorkloadRenewalPolicySource({ query } as unknown as PoolClient, f.scope),
    ).rejects.toThrow();
    for (const [sql] of query.mock.calls)
      expect(sql).not.toMatch(
        /insert|update|delete|workload_renewal_attempt|workload_credential_family/iu,
      );
    if (kind === 'missing') expect(query).toHaveBeenCalledTimes(1);
  },
);
it('requires every actual current head, compromise, consumed-input and outbox predicate while accepting retired historical receipt trust', async () => {
  const f = fixture();
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rowCount: 1, rows: [f.row] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [trustRow(f)] })
    .mockResolvedValueOnce({ rowCount: 1, rows: f.trust.grants })
    .mockResolvedValueOnce({ rowCount: 1, rows: [{ state: 'RETIRED' }] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [{ policy_id: f.scope.policyId }] })
    .mockResolvedValueOnce({
      rowCount: 2,
      rows: f.receipt.authorizationEvidence.map((e) => ({
        kind: e.kind,
        id: e.evidenceId,
        digest: e.evidenceDigest,
      })),
    })
    .mockResolvedValueOnce({
      rowCount: 1,
      rows: [{ event_id: f.receipt.outboxEvents[0]!.eventId }],
    });
  const eligible = await readEligibleWorkloadRenewalPolicySource(
    { query } as unknown as PoolClient,
    f.scope,
  );
  expect(eligible.definition).toEqual(f.row.definition);
  expect(query.mock.calls[3]![0]).toContain("state<>'COMPROMISED' for share");
  expect(query.mock.calls[4]![0]).toContain("h.state='ACTIVE'");
  expect(query.mock.calls[4]![0]).toContain('p.valid_until>clock_timestamp()');
  query.mockResolvedValueOnce({ rowCount: 0, rows: [] });
  await expect(eligible.revalidate()).rejects.toThrow(WorkloadRenewalPolicySourceUnavailable);
  expect(query.mock.calls[7]![0]).not.toMatch(/for share|for update/iu);
  expect(query.mock.calls[7]![1]).toEqual([
    f.scope.participantId,
    f.scope.privacyDomainId,
    f.scope.policyId,
    f.scope.policyRevision,
    f.trust.signerId,
  ]);
});
