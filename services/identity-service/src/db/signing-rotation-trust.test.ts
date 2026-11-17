import { generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import {
  businessSigningTrustPreimage,
  evidenceKeyId,
  type BusinessSigningGrant,
} from '@openpc/security-kernel';
import { businessTransitionProfiles } from '../../../../packages/security-kernel/src/business-transition/profiles.generated.js';
import {
  signingRoleProfiles,
  type SigningRole,
} from '../../../../packages/security-kernel/src/signing-roles.js';
import { businessProviderDescriptorSchema } from '../domain/business-signing-provider.js';
import { signingRotationRequestSchema } from '../domain/signing-rotation.js';
import type { RotationRow } from './signing-rotation-store.js';
import { rotationPublicTrust } from './signing-rotation-trust.js';
import { receiptRotationKey } from './signing-rotation-key.js';

const id = (value: number) => '01990000-0000-7000-8000-' + String(value).padStart(12, '0');
const scope = { participantId: id(1), privacyDomainId: id(2), principalId: id(3) };
function grants(role: SigningRole): BusinessSigningGrant[] {
  return businessTransitionProfiles
    .filter((profile) => signingRoleProfiles[role].includes(profile.profileId))
    .map((profile) => ({
      profileId: profile.profileId,
      profileVersion: profile.profileVersion,
      profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
      actionIntentId: profile.actionIntentId,
      catalogOperationId: profile.catalogOperationId,
    }))
    .sort(
      (a, b) =>
        Buffer.compare(Buffer.from(a.profileId), Buffer.from(b.profileId)) ||
        a.profileVersion - b.profileVersion,
    );
}
function fixture(selected: BusinessSigningGrant[], role: SigningRole = 'BUSINESS_EFFECT') {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
  const fingerprint = evidenceKeyId(spki);
  const request = signingRotationRequestSchema.parse({
    actionIntentId: 'ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1',
    actionIntentDigest: 'sha256:' + '11'.repeat(32),
    secretClass: 'SECRET-SIGNING-KEY',
    environmentId: 'test',
    workloadCredentialId: id(4),
    oldReference: 'secret://test/original#1',
    oldFingerprint: 'sha256:' + '22'.repeat(32),
    newReference: 'secret://test/successor#2',
    signerRole: role,
    purpose: 'pc.cose.control-business-transition.v1',
    reason: 'governed successor',
  });
  if (request.signerRole === 'IDENTITY_ENVELOPE') throw Error();
  const row: RotationRow = {
    rotationId: id(5),
    request,
    candidateDigest: Buffer.alloc(32, 3),
    oldTrustDigest: Buffer.alloc(32, 4),
    state: 'DISTRIBUTED',
    revision: '4',
    approvalRequestId: id(6),
    makerPrincipalId: scope.principalId,
    cutoverAtNs: null,
    newSignerId: fingerprint,
    recoveryFromState: null,
    recoveryFromRevision: null,
    pendingOperation: null,
    recoveryContext: null,
    authorizationGeneration: null,
    authorityHold: null,
  };
  const descriptor = businessProviderDescriptorSchema.parse({
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    workloadCredentialId: request.workloadCredentialId,
    environmentId: 'test',
    secretClass: request.secretClass,
    purpose: request.purpose,
    reference: request.newReference,
    version: '2',
    algorithm: 'ES256',
    publicKeySpkiHex: spki.toString('hex'),
    fingerprint,
    validFromNs: '1791000000000000000',
    validUntilNs: '1791086400000000000',
    state: 'ACTIVE',
    revokedAtNs: null,
    retiredAtNs: null,
  });
  const query = vi
    .fn()
    .mockResolvedValueOnce({
      rowCount: 1,
      rows: [{ epoch: '1', workloadEpoch: '1', trustDigest: row.oldTrustDigest }],
    })
    .mockResolvedValueOnce({ rowCount: selected.length, rows: selected });
  return { row, descriptor, query, client: { query } as unknown as PoolClient };
}

it.each([1, 2, 8])(
  'preserves all %i admitted business profile grants without imposing lifecycle cardinality',
  async (count) => {
    const selected = grants('BUSINESS_EFFECT').slice(0, count);
    expect(selected).toHaveLength(count);
    const f = fixture(selected),
      trust = await rotationPublicTrust(f.client, scope, f.row, f.descriptor);
    expect(trust.grants).toEqual(selected);
    expect(trust.keyEpoch).toBe(2n);
    expect(businessSigningTrustPreimage(trust).length).toBeGreaterThan(0);
    expect(f.query).toHaveBeenCalledTimes(2);
  },
);

it('retains both lifecycle grants and rejects a partial lifecycle grant set', async () => {
  const selected = grants('LIFECYCLE_EVIDENCE');
  expect(selected).toHaveLength(2);
  const f = fixture(selected, 'LIFECYCLE_EVIDENCE');
  const trust = await rotationPublicTrust(f.client, scope, f.row, f.descriptor);
  expect(trust.grants).toEqual(selected);
  expect(businessSigningTrustPreimage(trust).length).toBeGreaterThan(0);
  const partial = fixture(selected.slice(0, 1), 'LIFECYCLE_EVIDENCE');
  await expect(
    rotationPublicTrust(partial.client, scope, partial.row, partial.descriptor),
  ).rejects.toThrow('DENIED');
});

it.each(['empty', 'foreign role', 'duplicate', 'reordered', 'too many'] as const)(
  'denies %s grants before publishing successor trust',
  async (failure) => {
    let selected = grants('BUSINESS_EFFECT').slice(0, 8);
    if (failure === 'empty') selected = [];
    if (failure === 'foreign role') selected = [grants('LIFECYCLE_EVIDENCE')[0]!];
    if (failure === 'duplicate') selected = [selected[0]!, selected[0]!];
    if (failure === 'reordered') selected.reverse();
    if (failure === 'too many') selected = Array.from({ length: 65 }, () => selected[0]!);
    const f = fixture(selected);
    await expect(rotationPublicTrust(f.client, scope, f.row, f.descriptor)).rejects.toThrow(
      'DENIED',
    );
  },
);

it.each(['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE'] as const)(
  'uses the same %s grant bounds at original source admission',
  async (role) => {
    const f = fixture(grants(role), role);
    if (f.row.request.signerRole === 'IDENTITY_ENVELOPE') throw Error();
    await receiptRotationKey(f.client, scope, f.row.request, 'original-intent');
    const values = f.query.mock.calls[0]![1];
    expect(values.slice(8)).toEqual([
      signingRoleProfiles[role],
      role === 'BUSINESS_EFFECT' ? 1 : 2,
      role === 'BUSINESS_EFFECT' ? 64 : 2,
    ]);
  },
);

it('rejects an unavailable original credential before reading or returning profile grants', async () => {
  const f = fixture(grants('BUSINESS_EFFECT').slice(0, 8));
  f.query.mockReset().mockResolvedValueOnce({ rowCount: 0, rows: [] });
  await expect(rotationPublicTrust(f.client, scope, f.row, f.descriptor)).rejects.toThrow('DENIED');
  expect(f.query).toHaveBeenCalledTimes(1);
});
