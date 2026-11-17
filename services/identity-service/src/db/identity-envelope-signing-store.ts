import type { PoolClient } from 'pg';
import {
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';

export class IdentityEnvelopeSigningUnavailable extends Error {
  constructor() {
    super('Identity envelope signing is unavailable');
  }
}
export interface IdentityEnvelopeSigningKeyRow {
  participant_id: string;
  privacy_domain_id: string;
  signer_id: string;
  environment_id: string;
  public_key_spki_der: Buffer;
  workload_credential_id: string;
  workload_credential_epoch: string;
  key_epoch: string;
  envelope_workload_participant_epoch: string;
  envelope_workload_principal_epoch: string;
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
  now_ns: string;
}
/** Use the caller's real scoped transaction. Locks current lifecycle/identity
 * rows; no new connection, privileged role, provider call or authority seed.
 * The final publication owner must recheck validity after provider I/O. */
export async function fenceIdentityEnvelopeSigningTrust(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string; environmentId: string },
) {
  await client.query('select openpc.assert_request_context(true)');
  const result = await client.query<IdentityEnvelopeSigningKeyRow>(
    `select key.*,floor(extract(epoch from clock_timestamp())*1000000)::numeric*1000 as now_ns
      from control.identity_envelope_signing_selection selection
      join control.identity_envelope_signing_grant grant_row
        on grant_row.participant_id=selection.participant_id and grant_row.privacy_domain_id=selection.privacy_domain_id
       and grant_row.signer_id=selection.signer_id and grant_row.profile_digest=selection.profile_digest
      join control.identity_envelope_signing_profile profile on profile.profile_digest=grant_row.profile_digest
      join control.business_signing_key key
        on key.participant_id=grant_row.participant_id and key.privacy_domain_id=grant_row.privacy_domain_id
       and key.signer_id=grant_row.signer_id and key.signing_purpose_code=grant_row.signing_purpose_code
      join control.business_signing_key_state lifecycle
        on lifecycle.participant_id=key.participant_id and lifecycle.privacy_domain_id=key.privacy_domain_id and lifecycle.signer_id=key.signer_id
      join control.credential credential on credential.participant_id=key.participant_id and credential.credential_id=key.workload_credential_id
      join control.principal principal on principal.participant_id=credential.participant_id and principal.principal_id=credential.principal_id
      join control.participant participant on participant.participant_id=key.participant_id
     where selection.participant_id=$1 and selection.privacy_domain_id=$2 and selection.environment_id=$3
       and selection.profile_digest=$4 and selection.admission_version>0 and key.environment_id=$3
       and key.signing_purpose_code=371 and profile.signing_purpose_code=371
       and lifecycle.state='ACTIVE' and key.valid_from_ns<=floor(extract(epoch from clock_timestamp())*1000000)*1000
       and key.valid_until_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000
       and credential.state='ACTIVE' and credential.kind='WORKLOAD_MTLS' and credential.credential_epoch=key.workload_credential_epoch
       and credential.valid_from<=clock_timestamp() and (credential.valid_until is null or credential.valid_until>clock_timestamp())
       and principal.kind='WORKLOAD' and principal.state='ACTIVE' and participant.state='ACTIVE'
       and participant.authority_epoch=key.envelope_workload_participant_epoch and principal.authority_epoch=key.envelope_workload_principal_epoch
     for share of lifecycle,credential,principal,participant`,
    [
      scope.participantId,
      scope.privacyDomainId,
      scope.environmentId,
      Buffer.from(identityEnvelopeSigningProfileDigest.slice(7), 'hex'),
    ],
  );
  const row = result.rows[0];
  if (result.rowCount !== 1 || row === undefined) throw new IdentityEnvelopeSigningUnavailable();
  return {
    trust: authenticatedIdentityEnvelopeSigningTrust(row),
    recordedAtNs: BigInt(row.now_ns),
  };
}

/** Authenticate immutable public provenance. This grants no current signing
 * eligibility; callers must separately enforce selection, lifecycle and epochs. */
export function authenticatedIdentityEnvelopeSigningTrust(row: IdentityEnvelopeSigningKeyRow) {
  const trust: IdentityEnvelopeSigningTrust = {
    participantId: row.participant_id,
    privacyDomainId: row.privacy_domain_id,
    environmentId: row.environment_id,
    signerId: row.signer_id,
    publicKeySpkiDer: row.public_key_spki_der,
    workloadCredentialId: row.workload_credential_id,
    workloadCredentialEpoch: BigInt(row.workload_credential_epoch),
    keyEpoch: BigInt(row.key_epoch),
    validFromNs: BigInt(row.valid_from_ns),
    validUntilNs: BigInt(row.valid_until_ns),
    workloadParticipantEpoch: BigInt(row.envelope_workload_participant_epoch),
    workloadPrincipalEpoch: BigInt(row.envelope_workload_principal_epoch),
    admissionKind: row.admission_kind,
    admissionReference: row.admission_reference,
    admissionDigest: row.admission_digest,
    secretClass: row.secret_class,
    secretReference: row.secret_reference,
    secretVersion: row.secret_version,
    purpose: 'pc.cose.identity-authority-envelope.v1',
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
  };
  try {
    if (
      !identityEnvelopeSigningTrustPreimage(trust).equals(row.trust_preimage) ||
      identityEnvelopeSigningTrustDigest(trust) !== `sha256:${row.trust_digest.toString('hex')}`
    )
      throw new IdentityEnvelopeSigningUnavailable();
  } catch {
    throw new IdentityEnvelopeSigningUnavailable();
  }
  return trust;
}
