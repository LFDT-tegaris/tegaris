import type { PoolClient } from 'pg';
import {
  workloadRenewalSigningProfileDigest,
  workloadRenewalSigningTrustDigest,
  workloadRenewalSigningTrustPreimage,
  type WorkloadRenewalSigningTrust,
} from '@openpc/security-kernel';
import { readWorkloadRenewalParticipantSecurityEpoch } from './workload-renewal-participant-security.js';

export class WorkloadRenewalSigningUnavailable extends Error {
  constructor() {
    super('Workload renewal signing is unavailable');
  }
}
const deny = (): never => {
  throw new WorkloadRenewalSigningUnavailable();
};
export interface WorkloadRenewalSigningScope {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly environmentId: string;
}
export interface WorkloadRenewalSigningDiscovery {
  readonly signerId: string;
  readonly familyId: string;
  readonly principalId: string;
  readonly credentialId: string;
}
interface KeyRow {
  participant_id: string;
  privacy_domain_id: string;
  environment_id: string;
  signer_id: string;
  public_key_spki_der: Buffer;
  principal_id: string;
  workload_id: string;
  family_id: string;
  family_security_epoch: string;
  participant_security_invalidation_epoch: string;
  key_security_generation: string;
  provider_qualification_digest: Buffer;
  key_epoch: string;
  valid_from_ns: string;
  valid_until_ns: string;
  admission_kind: 'BOOTSTRAP' | 'GOVERNED';
  admission_reference: string;
  admission_digest: Buffer;
  secret_class: 'SECRET-SIGNING-KEY';
  secret_reference: string;
  secret_version: string;
  trust_preimage: Buffer;
  trust_digest: Buffer;
}
const hex = (bytes: Buffer) => `sha256:${bytes.toString('hex')}`;
/** Immutable public provenance only. No current transport, policy, provider,
 * consumer capability or instance authority follows from this reconstruction. */
export function authenticatedWorkloadRenewalSigningTrust(row: KeyRow): WorkloadRenewalSigningTrust {
  try {
    const trust: WorkloadRenewalSigningTrust = {
      participantId: row.participant_id,
      privacyDomainId: row.privacy_domain_id,
      environmentId: row.environment_id,
      principalId: row.principal_id,
      workloadId: row.workload_id,
      familyId: row.family_id,
      familySecurityEpoch: BigInt(row.family_security_epoch),
      participantSecurityInvalidationEpoch: BigInt(row.participant_security_invalidation_epoch),
      keySecurityGeneration: BigInt(row.key_security_generation),
      providerQualificationDigest: hex(row.provider_qualification_digest),
      signerId: row.signer_id,
      publicKeySpkiDer: row.public_key_spki_der,
      keyEpoch: BigInt(row.key_epoch),
      validFromNs: BigInt(row.valid_from_ns),
      validUntilNs: BigInt(row.valid_until_ns),
      admissionKind: row.admission_kind,
      admissionReference: row.admission_reference,
      admissionDigest: hex(row.admission_digest),
      secretClass: row.secret_class,
      secretReference: row.secret_reference,
      secretVersion: row.secret_version,
      purpose: 'pc.cose.identity.workload-renewal-policy-authorization.v1',
      profileId: 'pc.identity.workload-renewal.policy-authorization.v1',
      profileVersion: 2,
      profileDigest: workloadRenewalSigningProfileDigest,
    };
    if (
      !workloadRenewalSigningTrustPreimage(trust).equals(row.trust_preimage) ||
      workloadRenewalSigningTrustDigest(trust) !== hex(row.trust_digest)
    )
      return deny();
    return trust;
  } catch {
    return deny();
  }
}
const parameters = (scope: WorkloadRenewalSigningScope) => [
  scope.participantId,
  scope.privacyDomainId,
  scope.environmentId,
  Buffer.from(workloadRenewalSigningProfileDigest.slice(7), 'hex'),
];

/** Trusted composition resolves immutable selectors before acquiring C04.
 * The discovery is not eligibility and cannot select another key as fallback. */
export async function discoverWorkloadRenewalSigningDependencies(
  client: PoolClient,
  scope: WorkloadRenewalSigningScope,
): Promise<WorkloadRenewalSigningDiscovery> {
  await client.query('select openpc.assert_request_context(true)');
  const result = await client.query<WorkloadRenewalSigningDiscovery>(
    `select s.signer_id as "signerId",g.family_id as "familyId",
  g.principal_id as "principalId",f.current_credential_id as "credentialId"
  from control.workload_renewal_signing_selection s join control.workload_renewal_signing_grant g
   using(participant_id,privacy_domain_id,signer_id,profile_digest)
  join control.workload_credential_family f on f.participant_id=g.participant_id and f.privacy_domain_id=g.privacy_domain_id and f.family_id=g.family_id
  where s.participant_id=$1 and s.privacy_domain_id=$2 and s.environment_id=$3 and s.profile_digest=$4 and s.admission_version=1`,
    parameters(scope),
  );
  if (result.rowCount !== 1 || !result.rows[0]) return deny();
  return result.rows[0];
}

const currentSql = `select k.*,g.principal_id,g.workload_id,g.family_id,g.family_security_epoch::text,
 g.participant_security_invalidation_epoch::text,g.key_security_generation::text,g.provider_qualification_digest,
 f.current_credential_id as "credentialId",c.credential_epoch::text as "credentialEpoch",f.generation::text as "familyGeneration",
 f.row_version::text as "familyVersion",encode(f.current_fingerprint,'hex') as "fingerprint",
 (floor(extract(epoch from clock_timestamp())*1000000)*1000)::numeric::text as "nowNs"
 from control.workload_renewal_signing_selection s join control.workload_renewal_signing_grant g
  using(participant_id,privacy_domain_id,signer_id,profile_digest)
 join control.workload_renewal_signing_profile profile on profile.profile_digest=g.profile_digest
 join control.business_signing_key k on k.participant_id=g.participant_id and k.privacy_domain_id=g.privacy_domain_id
  and k.signer_id=g.signer_id and k.signing_purpose_code=g.signing_purpose_code
 join control.business_signing_key_state state on state.participant_id=k.participant_id and state.privacy_domain_id=k.privacy_domain_id and state.signer_id=k.signer_id
 join control.workload_credential_family f on f.participant_id=g.participant_id and f.privacy_domain_id=g.privacy_domain_id and f.family_id=g.family_id
 join control.credential c on c.participant_id=f.participant_id and c.credential_id=f.current_credential_id
 join control.principal p on p.participant_id=f.participant_id and p.principal_id=f.principal_id
 join control.participant participant on participant.participant_id=f.participant_id
 join control.privacy_domain d on d.participant_id=f.participant_id and d.privacy_domain_id=f.privacy_domain_id
 where s.participant_id=$1 and s.privacy_domain_id=$2 and s.environment_id=$3 and s.profile_digest=$4
  and s.signer_id=$5 and g.family_id=$6 and g.principal_id=$7 and f.current_credential_id=$8
  and s.admission_version=1 and k.environment_id=$3 and k.signing_purpose_code=376 and profile.profile_version=2 and profile.signing_purpose_code=376
  and state.state='ACTIVE' and state.row_version=g.key_security_generation
  and f.state='ACTIVE' and f.principal_id=g.principal_id and f.workload_id=g.workload_id and f.security_epoch=g.family_security_epoch
  and c.state='ACTIVE' and c.kind='WORKLOAD_MTLS' and c.principal_id=f.principal_id and c.audience=f.workload_id
  and c.secret_fingerprint=f.current_fingerprint and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()
  and p.kind='WORKLOAD' and p.state='ACTIVE' and participant.state='ACTIVE' and d.state='ACTIVE'
  and k.valid_from_ns<=floor(extract(epoch from clock_timestamp())*1000000)*1000
  and k.valid_until_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000`;
interface CurrentRow extends KeyRow {
  credentialId: string;
  credentialEpoch: string;
  familyGeneration: string;
  familyVersion: string;
  fingerprint: string;
  nowNs: string;
}
/** C04 dependencies must already be fenced by the actual authenticated peer
 * owner. Lock exact selection, lifecycle, then signer family before any target
 * policy/family locks. This is key eligibility only; other owners remain gates. */
export async function fenceWorkloadRenewalSigningTrust(
  client: PoolClient,
  scope: WorkloadRenewalSigningScope,
  discovered: WorkloadRenewalSigningDiscovery,
) {
  await client.query('select openpc.assert_request_context(true)');
  const args = [
    ...parameters(scope),
    discovered.signerId,
    discovered.familyId,
    discovered.principalId,
    discovered.credentialId,
  ];
  const selection = await client.query(
    `select signer_id from control.workload_renewal_signing_selection
  where participant_id=$1 and privacy_domain_id=$2 and environment_id=$3 and profile_digest=$4 and signer_id=$5 and admission_version=1 for share`,
    args.slice(0, 5),
  );
  if (selection.rowCount !== 1) return deny();
  const lifecycle = await client.query(
    `select signer_id from control.business_signing_key_state
  where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3 and state='ACTIVE' for share`,
    [scope.participantId, scope.privacyDomainId, discovered.signerId],
  );
  if (lifecycle.rowCount !== 1) return deny();
  const family = await client.query(
    `select family_id from control.workload_credential_family
  where participant_id=$1 and privacy_domain_id=$2 and family_id=$3 and principal_id=$4 and current_credential_id=$5 and state='ACTIVE' for share`,
    [
      scope.participantId,
      scope.privacyDomainId,
      discovered.familyId,
      discovered.principalId,
      discovered.credentialId,
    ],
  );
  if (family.rowCount !== 1) return deny();
  const read = async () => {
    const result = await client.query<CurrentRow>(currentSql, args),
      row = result.rows[0];
    if (result.rowCount !== 1 || !row) return deny();
    const trust = authenticatedWorkloadRenewalSigningTrust(row);
    if (
      trust.participantSecurityInvalidationEpoch !==
      (await readWorkloadRenewalParticipantSecurityEpoch(client, scope))
    )
      return deny();
    return { row, trust };
  };
  const initial = await read();
  return {
    trust: initial.trust,
    recordedAtNs: BigInt(initial.row.nowNs),
    current: {
      credentialId: initial.row.credentialId,
      credentialEpoch: BigInt(initial.row.credentialEpoch),
    },
    familyGeneration: BigInt(initial.row.familyGeneration),
    fingerprint: `sha256:${initial.row.fingerprint}`,
    /** Read only final recheck under existing locks. No new dependency discovery,
     * lock acquisition, selection change, provider I/O or permission fabrication. */
    revalidate: async () => {
      const latest = await read();
      if (
        !latest.row.trust_preimage.equals(initial.row.trust_preimage) ||
        latest.row.credentialId !== initial.row.credentialId ||
        latest.row.credentialEpoch !== initial.row.credentialEpoch ||
        latest.row.familyVersion !== initial.row.familyVersion ||
        latest.row.familyGeneration !== initial.row.familyGeneration ||
        latest.row.fingerprint !== initial.row.fingerprint
      )
        return deny();
    },
  };
}
