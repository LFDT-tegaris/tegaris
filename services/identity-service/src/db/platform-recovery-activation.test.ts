import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { platformRecoveryFixture } from '../domain/platform-recovery.test-fixture.js';
import { platformRecoveryLeaseActions } from '../domain/platform-recovery-lease.js';
import type { PlatformRecoveryProof } from '../domain/platform-recovery-ceremony.js';
import { trustFixture as discoveryFixture } from '../domain/discovery-certificate-recovery.test-fixture.js';
import { discoveryCertificateRecoveryPermissions } from '../domain/discovery-certificate-recovery.js';
import {
  activatePlatformRecoveryLease,
  activateDiscoveryCertificateRecoveryLease,
} from './platform-recovery-activation.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';

function fixture(failure?: string) {
  const { source, intent } = platformRecoveryFixture();
  intent.preparation.successorScope.administration.actionIntentIds = [
    ...platformRecoveryLeaseActions,
  ];
  const roles = intent.preparation.administrators.map((v) => ({
    roleId: `urn:openpc:authority-role:${v.roleId}`,
    version: '1',
    actions: [...platformRecoveryLeaseActions],
  }));
  intent.preparation.administrators.forEach((administrator, i) => {
    administrator.roleDigest = canonicalAuthorizationDigest({
      domain: 'pc.identity.envelope-role-binding.v1',
      participantId: source.enrollment.participantId,
      role: roles[i],
    });
  });
  const proofs: PlatformRecoveryProof[] = [
    source.enrollment.recoveryPrincipal,
    ...source.enrollment.custodians,
  ].map((v, i) => ({
    ...v,
    proofId: id(700 + i),
    sessionId: id(800 + i),
    sessionEpoch: '1',
    phase: i === 0 ? 'REQUEST' : 'APPROVE',
    intentDigest: canonicalAuthorizationDigest(intent),
    verifiedAt: source.now,
  }));
  const activationProof: PlatformRecoveryProof = {
    ...proofs[0]!,
    proofId: id(703),
    phase: 'ACTIVATE',
  };
  const writes: { sql: string; values: unknown[] }[] = [];
  const query = async (sql: string, values: unknown[]) => {
    if (sql.includes('from control.platform_recovery_proof proof'))
      return {
        rowCount: failure === 'missing activation proof' ? 0 : 1,
        rows: [{ digest: Buffer.alloc(32, 1) }],
      };
    if (sql.startsWith('select jsonb_build_object')) {
      const index = intent.preparation.administrators.findIndex((v) => v.roleId === values[1]);
      return {
        rowCount: 1,
        rows: [
          { role: failure === 'changed role' ? { ...roles[index], version: '2' } : roles[index] },
        ],
      };
    }
    if (/^(insert|update) /u.test(sql)) {
      writes.push({ sql, values });
      return { rowCount: 1, rows: [] };
    }
    throw new Error('Unexpected activation query');
  };
  const signer = {
    signCanonicalAssertion: async (value: Buffer) => ({
      evidenceCbor: failure === 'different signed bytes' ? Buffer.from('changed') : value,
      evidenceDigest: createHash('sha256').update(value).digest(),
      coseSign1: Buffer.from('mock-signature'),
      signerKeyDigest: Buffer.alloc(32, 1),
    }),
    verifyCanonicalAssertion: async () =>
      failure === 'unverified signature' ? undefined : { signerKeyDigest: Buffer.alloc(32, 1) },
  };
  const context = {
    enrollment: source.enrollment,
    intent,
    state: 'REQUESTED',
    proofs,
    now: source.now,
  };
  return { context, activationProof, writes, signer, client: { query } as never };
}
it('rotates only affected sessions and creates two separate fixed-purpose leases with signed durable evidence', async () => {
  const v = fixture();
  const result = await activatePlatformRecoveryLease(
    v.client,
    v.context,
    v.activationProof,
    id(900),
    v.signer,
  );
  expect(result).toMatchObject({
    state: 'ACTIVE',
    authority: 'FIXED_PLATFORM_HANDOFF_ONLY',
    expiresAt: v.context.intent.validUntil,
    assurance: 'LOCAL_QA_VIRTUAL_AUTHENTICATOR',
  });
  expect(result.bindings.map((v) => v.principalEpoch)).toEqual(['2', '2']);
  expect(v.writes.filter((v) => v.sql.startsWith('update control.principal'))).toHaveLength(2);
  expect(v.writes.filter((v) => v.sql.startsWith('update control.session'))).toHaveLength(2);
  const envelopes = v.writes.filter((v) =>
    v.sql.startsWith('insert into control.authority_envelope'),
  );
  expect(envelopes).toHaveLength(2);
  expect(envelopes.every((v) => v.sql.includes("'RECOVERY_V1'"))).toBe(true);
  expect(v.writes.filter((v) => v.sql.startsWith('insert into control.assignment'))).toHaveLength(
    2,
  );
  expect(v.writes.filter((v) => v.sql.startsWith('insert into control.outbox_event'))).toHaveLength(
    1,
  );
  expect(
    v.writes.some((v) =>
      /update control\.(authority_envelope|assignment|credential)\b/u.test(v.sql),
    ),
  ).toBe(false);
});
it.each([
  'missing activation proof',
  'changed role',
  'different signed bytes',
  'unverified signature',
])('rejects %s before any epoch, session or lease write', async (failure) => {
  const v = fixture(failure);
  await expect(
    activatePlatformRecoveryLease(v.client, v.context, v.activationProof, id(900), v.signer),
  ).rejects.toThrow();
  expect(v.writes).toHaveLength(0);
});
it('rejects missing custodian proof before any signed lease or effect', async () => {
  const v = fixture();
  v.context.proofs.pop();
  await expect(
    activatePlatformRecoveryLease(v.client, v.context, v.activationProof, id(900), v.signer),
  ).rejects.toThrow();
  expect(v.writes).toHaveLength(0);
});

it('issues only the separately enrolled certificate lease and cannot activate it as Root handoff', async () => {
  const f = discoveryFixture();
  const v = fixture();
  const actions = discoveryCertificateRecoveryPermissions(
    f.intent.certificateRecovery,
    f.source.enrollment.privacyDomainId,
    f.intent.administrators[0].principalId,
  ).actionIntentIds;
  const roles = f.intent.administrators.map((a) => ({
    roleId: `urn:openpc:role:${a.roleId}`,
    version: '1',
    actions,
  }));
  f.intent.administrators.forEach(
    (a, i) =>
      (a.roleDigest = canonicalAuthorizationDigest({
        domain: 'pc.identity.envelope-role-binding.v1',
        participantId: f.source.enrollment.participantId,
        role: roles[i],
      })),
  );
  const context = {
    ...v.context,
    enrollment: f.source.enrollment,
    intent: f.intent,
    now: f.source.now,
    proofs: v.context.proofs.map((p) => ({
      ...p,
      intentDigest: canonicalAuthorizationDigest(f.intent),
      verifiedAt: f.source.now,
    })),
  };
  const activationProof = {
    ...v.activationProof,
    intentDigest: canonicalAuthorizationDigest(f.intent),
    verifiedAt: f.source.now,
  };
  const client = {
    query: async (sql: string, values: unknown[]) => {
      if (sql.startsWith('select jsonb_build_object'))
        return {
          rowCount: 1,
          rows: [{ role: roles[f.intent.administrators.findIndex((a) => a.roleId === values[1])] }],
        };
      return (
        v.client as {
          query(sql: string, values: unknown[]): Promise<{ rowCount: number; rows: unknown[] }>;
        }
      ).query(sql, values);
    },
  } as never;
  await expect(
    activatePlatformRecoveryLease(client, context, activationProof, id(900), v.signer),
  ).rejects.toThrow();
  expect(v.writes).toHaveLength(0);
  const result = await activateDiscoveryCertificateRecoveryLease(
    client,
    context,
    activationProof,
    id(900),
    v.signer,
  );
  expect(result).toMatchObject({
    authority: 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY',
    state: 'ACTIVE',
  });
  expect(result.bindings.map((v) => v.principalEpoch)).toEqual(['4', '4']);
  const envelopes = v.writes.filter((v) =>
    v.sql.startsWith('insert into control.authority_envelope'),
  );
  expect(envelopes).toHaveLength(2);
  for (const envelope of envelopes) {
    expect(envelope.values[14]).toEqual(actions);
    expect(envelope.values[15]).toContain(f.intent.certificateRecovery.predecessorCredentialId);
    expect(envelope.values[15]).toContain(f.intent.certificateRecovery.successorCredentialId);
    expect(envelope.values[15]).not.toContain('*');
  }
  expect(
    v.writes.some((v) => /control\.(credential|platform_scope_replacement)/u.test(v.sql)),
  ).toBe(false);
});
