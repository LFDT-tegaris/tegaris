import { businessTransitionProfileForOperation } from './profiles.js';
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { evidenceKeyId } from './cose.js';
import {
  assertBusinessSigningGrant,
  businessSigningTrustDigest,
  type BusinessSigningTrust,
} from './signing-trust.js';

const publicKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
  format: 'der',
  type: 'spki',
});
const participantId = '01990000-0000-7000-8000-000000000001';
const privacyDomainId = '01990000-0000-7000-8000-000000000002';
const grant = {
  profileId: 'pc.control.indexer-create.v1',
  profileVersion: 1,
  profileDigest: Buffer.alloc(32, 1),
  actionIntentId: 'ACT-CONTROL_CREATE_INDEXER_PROFILE-V1',
  catalogOperationId: 'CFG-OP-INDEXER-CREATE',
};
const trust: BusinessSigningTrust = {
  participantId,
  privacyDomainId,
  environmentId: 'local',
  signerId: evidenceKeyId(publicKey),
  publicKeySpkiDer: publicKey,
  workloadCredentialId: '01990000-0000-7000-8000-000000000003',
  workloadCredentialEpoch: 1n,
  keyEpoch: 9007199254740993n,
  validFromNs: 1000n,
  validUntilNs: 900000n,
  admissionKind: 'BOOTSTRAP',
  admissionReference: 'local-initial-trust',
  admissionDigest: Buffer.alloc(32, 2),
  secretClass: 'SECRET-SIGNING-KEY',
  secretReference: 'secret://local/control-evidence#1',
  secretVersion: '1',
  grants: [grant],
};
const request = { ...grant, participantId, privacyDomainId, environmentId: 'local', nowNs: 2000n };

describe('purpose-bound business signing trust', () => {
  it('requires a separate explicit grant for initial indexer provenance version two', () => {
    const v1 = businessTransitionProfileForOperation('CFG-OP-CREATE-INDEXER-PROFILE', 1)!;
    const v2 = businessTransitionProfileForOperation('CFG-OP-CREATE-INDEXER-PROFILE', 2)!;
    expect(v2.profileId).toBe(v1.profileId);
    expect(v2.profileDigest).not.toBe(v1.profileDigest);
    const grants = [v1, v2].map((profile) => ({
      profileId: profile.profileId,
      profileVersion: profile.profileVersion,
      profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
      actionIntentId: profile.actionIntentId,
      catalogOperationId: profile.catalogOperationId,
    }));
    const legacyGrant = grants[0]!;
    const currentGrant = grants[1]!;
    expect(() =>
      assertBusinessSigningGrant(
        { ...trust, grants: [legacyGrant] },
        { ...request, ...currentGrant },
      ),
    ).toThrow();
    expect(() =>
      assertBusinessSigningGrant(
        { ...trust, grants: [currentGrant] },
        { ...request, ...currentGrant },
      ),
    ).not.toThrow();
    expect(
      businessTransitionProfileForOperation('CFG-OP-CREATE-INDEXER-PROFILE', 3),
    ).toBeUndefined();
  });
  it('admits only the exact scope, profile, action and validity interval', () => {
    expect(() => assertBusinessSigningGrant(trust, request)).not.toThrow();
    const mutations = [
      { participantId: trust.workloadCredentialId },
      { privacyDomainId: trust.workloadCredentialId },
      { environmentId: 'production' },
      { profileId: 'other' },
      { profileVersion: 2 },
      { profileDigest: Buffer.alloc(32, 3) },
      { actionIntentId: 'ACT-CONTROL_UPDATE_INDEXER_PROFILE-V1' },
      { catalogOperationId: 'CFG-OP-INDEXER-UPDATE' },
      { nowNs: 0n },
      { nowNs: 900000n },
    ];
    for (const change of mutations)
      expect(() => assertBusinessSigningGrant(trust, { ...request, ...change })).toThrow();
  });
  it.each(['MOD-OP-REGISTER', 'MOD-OP-INSTALL', 'MOD-OP-ENABLE', 'MOD-OP-DISABLE'])(
    'admits the sealed %s grant and rejects substituted identities',
    (operation) => {
      const profile = businessTransitionProfileForOperation(operation)!;
      const moduleGrant = {
        profileId: profile.profileId,
        profileVersion: profile.profileVersion,
        profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
        actionIntentId: profile.actionIntentId,
        catalogOperationId: profile.catalogOperationId,
      };
      const moduleTrust = { ...trust, grants: [moduleGrant] };
      expect(() =>
        assertBusinessSigningGrant(moduleTrust, { ...request, ...moduleGrant }),
      ).not.toThrow();
      for (const change of [
        { profileId: 'pc.other' },
        { profileVersion: 2 },
        { profileDigest: Buffer.alloc(32) },
        { actionIntentId: 'ACT-MODULES_DELETE_RESOURCE-V1' },
        { catalogOperationId: operation === 'MOD-OP-ENABLE' ? 'MOD-OP-INSTALL' : 'MOD-OP-ENABLE' },
        { catalogOperationId: 'MOD-OP-UNINSTALL' },
      ])
        expect(() =>
          businessSigningTrustDigest({ ...trust, grants: [{ ...moduleGrant, ...change }] }),
        ).toThrow();
    },
  );
  it('binds every public trust input including the immutable secret version and admission', () => {
    const hash = businessSigningTrustDigest(trust);
    const changes: Partial<BusinessSigningTrust>[] = [
      { participantId: trust.workloadCredentialId },
      { privacyDomainId: trust.workloadCredentialId },
      { environmentId: 'next' },
      { workloadCredentialId: participantId },
      { workloadCredentialEpoch: 2n },
      { keyEpoch: trust.keyEpoch + 1n },
      { validFromNs: 2000n },
      { validUntilNs: 901000n },
      { admissionKind: 'GOVERNED' },
      { admissionReference: 'approval-1' },
      { admissionDigest: Buffer.alloc(32, 3) },
      { secretReference: 'secret://local/next-key#1' },
      { secretReference: 'secret://local/control-evidence#2', secretVersion: '2' },
      { grants: [{ ...grant, profileDigest: Buffer.alloc(32, 3) }] },
    ];
    for (const change of changes)
      expect(businessSigningTrustDigest({ ...trust, ...change })).not.toEqual(hash);
  });
  it('rejects malformed, duplicate, wildcard, mixed-purpose and unversioned descriptors', () => {
    for (const change of [
      { signerId: 'sha256:' + '00'.repeat(32) },
      { keyEpoch: 0n },
      { keyEpoch: 1n << 64n },
      { validUntilNs: 1000n },
      { validFromNs: 1001n },
      { grants: [] },
      { grants: [grant, grant] },
      { grants: [{ ...grant, actionIntentId: '*' }] },
      { secretClass: 'SECRET-AUTHENTICATION' },
      { secretVersion: '' },
      { secretVersion: 'latest/version' },
      { privateKey: Buffer.alloc(32) },
      { environmentId: 'bad\u0000environment' },
    ]) {
      expect(() =>
        businessSigningTrustDigest({ ...trust, ...change } as BusinessSigningTrust),
      ).toThrow();
    }
  });
  it('requires canonical UTF-8 ordering of unique profile identities', () => {
    const second = { ...grant, profileId: 'pc.control.indexer-update.v1' };
    expect(() => businessSigningTrustDigest({ ...trust, grants: [grant, second] })).not.toThrow();
    expect(() => businessSigningTrustDigest({ ...trust, grants: [second, grant] })).toThrow();
    expect(() =>
      businessSigningTrustDigest({
        ...trust,
        grants: [grant, { ...grant, profileDigest: Buffer.alloc(32, 5) }],
      }),
    ).toThrow();
  });
});
