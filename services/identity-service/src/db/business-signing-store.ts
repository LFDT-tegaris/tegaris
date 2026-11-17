import { createHash } from 'node:crypto';
import {
  assertBusinessSigningGrant,
  businessSigningTrustDigest,
  businessSigningTrustPreimage,
  BusinessSigningTrustError,
  type BusinessSigningGrant,
  type BusinessSigningTrust,
} from '@openpc/security-kernel';
import type { PoolClient } from 'pg';
import type { AuthorityFence } from './authority-fence.js';

export interface BusinessSigningScope extends BusinessSigningGrant {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly environmentId: string;
}
export interface BusinessSigningDiscovery {
  readonly signerId: string;
  readonly workloadPrincipalId: string;
  readonly workloadCredentialId: string;
  readonly selectionVersion: string;
  readonly admissionVersion: string;
  readonly authorityFence: AuthorityFence;
}

/** Discover before the shared authority fence; no authority is granted by this read. */
export async function discoverBusinessSigningKey(
  client: PoolClient,
  scope: BusinessSigningScope,
): Promise<BusinessSigningDiscovery> {
  const selected = await client.query<{
    signerId: string;
    workloadPrincipalId: string;
    workloadCredentialId: string;
    selectionVersion: string;
    admissionVersion: string;
  }>(
    `select s.signer_id as "signerId",s.row_version::text as "selectionVersion",s.admission_version::text as "admissionVersion",
     k.workload_credential_id as "workloadCredentialId",c.principal_id as "workloadPrincipalId"
    from control.business_signing_selection s
    join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
    join control.credential c on c.participant_id=k.participant_id and c.credential_id=k.workload_credential_id
   where s.participant_id=$1 and s.privacy_domain_id=$2 and s.environment_id=$3 and s.profile_digest=$4`,
    [scope.participantId, scope.privacyDomainId, scope.environmentId, scope.profileDigest],
  );
  if (selected.rowCount !== 1 || selected.rows[0] === undefined)
    throw new BusinessSigningTrustError();
  const row = selected.rows[0];
  return {
    ...row,
    authorityFence: {
      principal: [{ id: row.workloadPrincipalId }],
      credential: [{ id: row.workloadCredentialId }],
    },
  };
}

type TrustRow = {
  signerId: string;
  environmentId: string;
  publicKeySpkiDer: Buffer;
  workloadCredentialId: string;
  workloadCredentialEpoch: string;
  keyEpoch: string;
  validFromNs: string;
  validUntilNs: string;
  admissionKind: 'BOOTSTRAP' | 'GOVERNED';
  admissionReference: string;
  admissionDigest: Buffer;
  secretClass: 'SECRET-SIGNING-KEY';
  secretReference: string;
  secretVersion: string;
  trustPreimage: Buffer;
  trustDigest: Buffer;
};

/**
 * The caller first merges discovery.authorityFence into the shared authority lock plan.
 * Then this owner locks selection and key lifecycle, revalidates that exact discovery,
 * and returns the actual public trust tuple. Locks remain held through commit/rollback.
 */
export async function fenceBusinessSigningKey(
  client: PoolClient,
  scope: BusinessSigningScope,
  discovery: BusinessSigningDiscovery,
): Promise<{ readonly trust: BusinessSigningTrust; readonly nowNs: bigint }> {
  const parameters = [
    scope.participantId,
    scope.privacyDomainId,
    scope.environmentId,
    scope.profileDigest,
  ];
  const selection = await client.query<{
    signerId: string;
    version: string;
    admissionVersion: string;
  }>(
    `select signer_id as "signerId",row_version::text as version,admission_version::text as "admissionVersion" from control.business_signing_selection
     where participant_id=$1 and privacy_domain_id=$2 and environment_id=$3 and profile_digest=$4 for share`,
    parameters,
  );
  if (
    selection.rowCount !== 1 ||
    selection.rows[0]?.signerId !== discovery.signerId ||
    selection.rows[0]?.version !== discovery.selectionVersion ||
    selection.rows[0]?.admissionVersion !== discovery.admissionVersion
  )
    throw new BusinessSigningTrustError();
  const state = await client.query(
    `select 1 from control.business_signing_key_state
    where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3 and state='ACTIVE' for share`,
    [scope.participantId, scope.privacyDomainId, discovery.signerId],
  );
  if (state.rowCount !== 1) throw new BusinessSigningTrustError();
  const trust = await readRetainedBusinessSigningTrust(client, scope, discovery.signerId);
  if (trust.workloadCredentialId !== discovery.workloadCredentialId)
    throw new BusinessSigningTrustError();
  const live = await client.query<{ nowNs: string }>(
    `select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text as "nowNs"
    from control.credential c join control.principal p using(participant_id,principal_id)
    join control.participant participant using(participant_id)
    join control.privacy_domain privacy on privacy.participant_id=c.participant_id and privacy.privacy_domain_id=$5
    where c.participant_id=$1 and c.credential_id=$2 and c.principal_id=$3 and c.credential_epoch=$4
      and c.kind in ('WORKLOAD_MTLS','WORKLOAD_OIDC') and c.state='ACTIVE'
      and p.kind='WORKLOAD' and p.state='ACTIVE' and participant.state='ACTIVE' and privacy.state='ACTIVE'
      and c.valid_from<=clock_timestamp() and (c.valid_until is null or c.valid_until>clock_timestamp())
      and c.public_key_digest is distinct from $6`,
    [
      scope.participantId,
      discovery.workloadCredentialId,
      discovery.workloadPrincipalId,
      trust.workloadCredentialEpoch.toString(),
      scope.privacyDomainId,
      createHash('sha256').update(trust.publicKeySpkiDer).digest(),
    ],
  );
  if (live.rowCount !== 1 || live.rows[0] === undefined) throw new BusinessSigningTrustError();
  const nowNs = BigInt(live.rows[0].nowNs);
  assertBusinessSigningGrant(trust, { ...scope, nowNs });
  return { trust, nowNs };
}

/** Reconstruct historical 338 trust from its owning immutable key and exact
 * profile grants. This proves receipt provenance only, never current signing
 * eligibility or a grant of routine purpose376. No new locks are taken. */
export async function readRetainedBusinessSigningTrust(
  client: PoolClient,
  scope: Pick<BusinessSigningScope, 'participantId' | 'privacyDomainId'>,
  signerId: string,
): Promise<BusinessSigningTrust> {
  const key = await client.query<TrustRow>(
    `select signer_id as "signerId",environment_id as "environmentId",
    public_key_spki_der as "publicKeySpkiDer",workload_credential_id as "workloadCredentialId",
    workload_credential_epoch::text as "workloadCredentialEpoch",key_epoch::text as "keyEpoch",
    valid_from_ns::text as "validFromNs",valid_until_ns::text as "validUntilNs",
    admission_kind as "admissionKind",admission_reference as "admissionReference",admission_digest as "admissionDigest",
    secret_class as "secretClass",secret_reference as "secretReference",secret_version as "secretVersion",
    trust_preimage as "trustPreimage",trust_digest as "trustDigest"
    from control.business_signing_key where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3 and signing_purpose_code=338`,
    [scope.participantId, scope.privacyDomainId, signerId],
  );
  if (key.rowCount !== 1 || key.rows[0] === undefined || key.rows[0].signerId !== signerId)
    throw new BusinessSigningTrustError();
  const row = key.rows[0];
  const grants = await client.query<BusinessSigningGrant>(
    `select p.profile_id as "profileId",
    p.profile_version::integer as "profileVersion",p.profile_digest as "profileDigest",
    p.action_intent_id as "actionIntentId",p.catalog_operation_id as "catalogOperationId"
    from control.business_signing_grant g join control.business_transition_profile p using(profile_digest)
    where g.participant_id=$1 and g.privacy_domain_id=$2 and g.signer_id=$3
    order by convert_to(p.profile_id,'UTF8'),p.profile_version`,
    [scope.participantId, scope.privacyDomainId, signerId],
  );
  const trust: BusinessSigningTrust = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    environmentId: row.environmentId,
    signerId: row.signerId,
    publicKeySpkiDer: row.publicKeySpkiDer,
    workloadCredentialId: row.workloadCredentialId,
    workloadCredentialEpoch: BigInt(row.workloadCredentialEpoch),
    keyEpoch: BigInt(row.keyEpoch),
    validFromNs: BigInt(row.validFromNs),
    validUntilNs: BigInt(row.validUntilNs),
    admissionKind: row.admissionKind,
    admissionReference: row.admissionReference,
    admissionDigest: row.admissionDigest,
    secretClass: row.secretClass,
    secretReference: row.secretReference,
    secretVersion: row.secretVersion,
    grants: grants.rows,
  };
  if (
    !businessSigningTrustPreimage(trust).equals(row.trustPreimage) ||
    !businessSigningTrustDigest(trust).equals(row.trustDigest)
  )
    throw new BusinessSigningTrustError();
  return trust;
}
