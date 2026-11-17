import type { PoolClient } from 'pg';
import {
  signingRoleProfiles,
  signingRoleGrantBounds,
} from '../../../../packages/security-kernel/src/signing-roles.js';
import {
  businessSigningTrustDigest,
  businessSigningTrustPreimage,
  type BusinessSigningGrant,
  type BusinessSigningTrust,
} from '@openpc/security-kernel';
import { type BusinessProviderDescriptor } from '../domain/business-signing-provider.js';
import { SigningRotationError } from '../domain/signing-rotation.js';
import {
  rotationDigest,
  type RotationRow,
  type SigningRotationPartition,
} from './signing-rotation-store.js';

export async function rotationPublicTrust(
  client: PoolClient,
  scope: SigningRotationPartition,
  row: RotationRow,
  descriptor: BusinessProviderDescriptor,
): Promise<BusinessSigningTrust> {
  if (row.request.signerRole === 'IDENTITY_ENVELOPE') throw new SigningRotationError('DENIED');
  const roleProfiles = signingRoleProfiles[row.request.signerRole];
  const bounds = signingRoleGrantBounds[row.request.signerRole];
  const old = await client.query<{ epoch: string; workloadEpoch: string; trustDigest: Buffer }>(
    `select k.key_epoch::text as epoch,
    k.workload_credential_epoch::text as "workloadEpoch",k.trust_digest as "trustDigest"
    from control.business_signing_key k join control.credential c on c.participant_id=k.participant_id and c.credential_id=k.workload_credential_id
    join control.principal p on p.participant_id=c.participant_id and p.principal_id=c.principal_id
    where k.participant_id=$1 and k.privacy_domain_id=$2 and k.signer_id=$3 and k.signing_purpose_code=338
      and c.state='ACTIVE' and p.state='ACTIVE' and p.kind='WORKLOAD' and c.credential_epoch=k.workload_credential_epoch
      and c.valid_from<=clock_timestamp() and (c.valid_until is null or c.valid_until>clock_timestamp())`,
    [scope.participantId, scope.privacyDomainId, row.request.oldFingerprint],
  );
  if (
    old.rowCount !== 1 ||
    !old.rows[0]!.trustDigest.equals(row.oldTrustDigest) ||
    descriptor.fingerprint === row.request.oldFingerprint ||
    descriptor.fingerprint !== row.newSignerId ||
    descriptor.workloadCredentialId !== row.request.workloadCredentialId ||
    descriptor.reference !== row.request.newReference ||
    descriptor.environmentId !== row.request.environmentId ||
    descriptor.participantId !== scope.participantId ||
    descriptor.privacyDomainId !== scope.privacyDomainId ||
    descriptor.state !== 'ACTIVE'
  )
    throw new SigningRotationError('DENIED');
  const grants = await client.query<BusinessSigningGrant>(
    `select p.profile_id as "profileId",p.profile_version::integer as "profileVersion",
    p.profile_digest as "profileDigest",p.action_intent_id as "actionIntentId",p.catalog_operation_id as "catalogOperationId"
    from control.business_signing_grant g join control.business_transition_profile p using(profile_digest)
    where g.participant_id=$1 and g.privacy_domain_id=$2 and g.signer_id=$3 order by convert_to(p.profile_id,'UTF8'),p.profile_version`,
    [scope.participantId, scope.privacyDomainId, row.request.oldFingerprint],
  );
  if (
    grants.rowCount !== grants.rows.length ||
    grants.rows.length < bounds.minimum ||
    grants.rows.length > bounds.maximum ||
    !grants.rows.every((grant) => roleProfiles.includes(grant.profileId)) ||
    grants.rows.some((grant, index) => {
      if (index === 0) return false;
      const previous = grants.rows[index - 1]!;
      const order = Buffer.compare(Buffer.from(previous.profileId), Buffer.from(grant.profileId));
      return order > 0 || (order === 0 && previous.profileVersion >= grant.profileVersion);
    })
  )
    throw new SigningRotationError('DENIED');
  return {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    environmentId: row.request.environmentId,
    signerId: descriptor.fingerprint,
    publicKeySpkiDer: Buffer.from(descriptor.publicKeySpkiHex, 'hex'),
    workloadCredentialId: row.request.workloadCredentialId,
    workloadCredentialEpoch: BigInt(old.rows[0]!.workloadEpoch),
    keyEpoch: BigInt(old.rows[0]!.epoch) + 1n,
    validFromNs: BigInt(descriptor.validFromNs),
    validUntilNs: BigInt(descriptor.validUntilNs),
    admissionKind: 'GOVERNED',
    admissionReference: `urn:openpc:resource:${row.rotationId}`,
    admissionDigest: rotationDigest({
      rotationId: row.rotationId,
      candidateDigest: row.candidateDigest.toString('hex'),
      approvalRequestId: row.approvalRequestId,
      oldTrustDigest: row.oldTrustDigest.toString('hex'),
    }),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: row.request.newReference,
    secretVersion: descriptor.version,
    grants: grants.rows,
  };
}

export async function admitRotationTrust(client: PoolClient, trust: BusinessSigningTrust) {
  const digest = businessSigningTrustDigest(trust);
  await client.query(
    `insert into control.business_signing_key(participant_id,privacy_domain_id,signer_id,environment_id,
    public_key_spki_der,workload_credential_id,workload_credential_epoch,key_epoch,valid_from_ns,valid_until_ns,
    admission_kind,admission_reference,admission_digest,secret_class,secret_reference,secret_version,trust_preimage,trust_digest)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
    [
      trust.participantId,
      trust.privacyDomainId,
      trust.signerId,
      trust.environmentId,
      trust.publicKeySpkiDer,
      trust.workloadCredentialId,
      trust.workloadCredentialEpoch.toString(),
      trust.keyEpoch.toString(),
      trust.validFromNs.toString(),
      trust.validUntilNs.toString(),
      trust.admissionKind,
      trust.admissionReference,
      trust.admissionDigest,
      trust.secretClass,
      trust.secretReference,
      trust.secretVersion,
      businessSigningTrustPreimage(trust),
      digest,
    ],
  );
  for (const grant of trust.grants)
    await client.query(
      `insert into control.business_signing_grant(participant_id,privacy_domain_id,signer_id,profile_digest)
    values($1,$2,$3,$4)`,
      [trust.participantId, trust.privacyDomainId, trust.signerId, grant.profileDigest],
    );
  await client.query(
    `insert into control.business_signing_key_state(participant_id,privacy_domain_id,signer_id,state,row_version,changed_at_ns,change_reference,change_digest)
    values($1,$2,$3,'ADMITTED',1,floor(extract(epoch from clock_timestamp())*1000000)*1000,$4,$5)`,
    [trust.participantId, trust.privacyDomainId, trust.signerId, trust.admissionReference, digest],
  );
}
