import assert from 'node:assert/strict';
import { businessTransitionProfiles } from '../../../packages/security-kernel/src/business-transition/profiles.generated.js';
import type { BusinessProviderDescriptor } from '../../../services/identity-service/src/domain/business-signing-provider.js';

// Separate initial local-test trust for newly admitted profiles. Never extend
// the immutable grants on an old key or replace a retained signing selection.
export const rpcRetirementSigningWorkload = Object.freeze({
  principalId: '018f0000-0000-7000-8000-000000091194',
  credentialId: '018f0000-0000-7000-8000-000000091195',
  workloadId: '018f0000-0000-7000-8000-000000091196',
});

export const rpcRetirementSigningFamilies = Object.freeze([
  Object.freeze({
    family: 'local-v2',
    profileId: 'pc.control.evidence-deletion.local',
    profileVersion: 2,
  }),
  Object.freeze({
    family: 'batch-v2',
    profileId: 'pc.control.evidence-deletion.batch',
    profileVersion: 2,
  }),
  Object.freeze({
    family: 'projection-v3',
    profileId: 'pc.control.evidence-deletion.projection',
    profileVersion: 3,
  }),
]);

// These precede payload retirement and keep their original signing caller.
export function projectionDeletionSigningProfiles(family: unknown) {
  const versions = new Map<string, readonly number[]>(
    family === 'hold'
      ? [
          ['pc.control.evidence-hold.create', [1]],
          ['pc.control.evidence-hold.release', [1]],
        ]
      : family === 'retention'
        ? [
            ['pc.control.retention-policy.activate', [1]],
            ['pc.control.retention-policy.retire', [1]],
          ]
        : family === 'deletion-local'
          ? [['pc.control.evidence-deletion.local', [1]]]
          : family === 'deletion-projection'
            ? [['pc.control.evidence-deletion.projection', [1, 2]]]
            : [],
  );
  assert.ok(versions.size, 'Exact projection deletion signing family required');
  const profiles = businessTransitionProfiles.filter((profile) =>
    versions.get(profile.profileId)?.includes(profile.profileVersion),
  );
  assert.equal(profiles.length, [...versions.values()].flat().length);
  return profiles;
}

export function verifyUnproposedRetirementTrust(rows: unknown) {
  assert.ok(Array.isArray(rows) && rows.length === 1);
  assert.equal(
    rows[0].has_candidates,
    false,
    'Missing initial retirement trust cannot be added after an affected business proposal',
  );
}
export function rpcRetirementSigningProfiles(family: unknown) {
  const binding = rpcRetirementSigningFamilies.find((item) => item.family === family);
  assert.ok(binding, 'Exact RPC retirement signing family required');
  const profiles = businessTransitionProfiles.filter(
    (profile) =>
      profile.profileId === binding.profileId && profile.profileVersion === binding.profileVersion,
  );
  assert.equal(profiles.length, 1, 'One canonical RPC retirement profile required');
  assert.ok(profiles[0]);
  assert.equal(profiles[0].aggregateType, 'evidence-deletion');
  return profiles;
}

export function verifyRetainedRpcRetirementSelection(
  family: unknown,
  rows: unknown,
  descriptor: Pick<
    BusinessProviderDescriptor,
    | 'participantId'
    | 'privacyDomainId'
    | 'workloadCredentialId'
    | 'reference'
    | 'version'
    | 'fingerprint'
    | 'publicKeySpkiHex'
    | 'validFromNs'
    | 'validUntilNs'
  >,
) {
  const [profile] = rpcRetirementSigningProfiles(family);
  assert.ok(profile);
  assert.equal(descriptor.workloadCredentialId, rpcRetirementSigningWorkload.credentialId);
  assert.equal(
    descriptor.reference,
    `secret://local/control-rpc-retirement-${descriptor.privacyDomainId}-${family}-evidence#1`,
  );
  assert.equal(descriptor.version, '1');
  assert.ok(Array.isArray(rows) && rows.length <= 1, 'No ambiguous retained signing selection');
  if (rows.length === 0) return false;
  const row = rows[0];
  assert.equal(row.profile_id, profile.profileId);
  assert.equal(row.profile_version, String(profile.profileVersion));
  assert.equal(row.state, 'ACTIVE');
  assert.ok(Buffer.isBuffer(row.profile_digest));
  assert.equal(`sha256:${row.profile_digest.toString('hex')}`, profile.profileDigest);
  assert.equal(row.participant_id, descriptor.participantId);
  assert.equal(row.privacy_domain_id, descriptor.privacyDomainId);
  assert.equal(row.environment_id, 'local');
  assert.equal(row.workload_credential_id, descriptor.workloadCredentialId);
  assert.equal(row.signer_id, descriptor.fingerprint);
  assert.ok(Buffer.isBuffer(row.public_key_spki_der));
  assert.equal(row.public_key_spki_der.toString('hex'), descriptor.publicKeySpkiHex);
  assert.equal(row.secret_reference, descriptor.reference);
  assert.equal(row.secret_version, descriptor.version);
  assert.equal(row.valid_from_ns, descriptor.validFromNs);
  assert.equal(row.valid_until_ns, descriptor.validUntilNs);
  return true;
}
