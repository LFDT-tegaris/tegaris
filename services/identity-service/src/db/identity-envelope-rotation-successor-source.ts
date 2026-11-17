import type { PoolClient } from 'pg';
import { identityEnvelopeSigningTrustDigest } from '@openpc/security-kernel';
import type {
  IdentityEnvelopeRecoveryEnrollment,
  IdentityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { captureIdentityEnvelopeRotationIssuer } from './identity-envelope-rotation-issuer.js';
import {
  authenticatedIdentityEnvelopeSigningTrust,
  fenceIdentityEnvelopeSigningTrust,
  type IdentityEnvelopeSigningKeyRow,
} from './identity-envelope-signing-store.js';

/** Actual selected successor and unchanged original issuer after cutover.
 * Old public provenance is retained for canonical planning, never reselected. */
export async function captureIdentityEnvelopeRotationSuccessorSource(
  client: PoolClient,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  lease: IdentityEnvelopeRecoveryLease,
) {
  const scope = {
    participantId: enrollment.participantId,
    privacyDomainId: enrollment.privacyDomainId,
    environmentId: enrollment.request.environmentId,
  };
  const { issuer } = await captureIdentityEnvelopeRotationIssuer(client, {
    ...scope,
    workloadCredentialId: lease.issuer.workloadCredentialId,
  });
  if (canonicalAuthorizationDigest(issuer) !== canonicalAuthorizationDigest(lease.issuer))
    throw new PlatformRecoveryError();
  const selected = await fenceIdentityEnvelopeSigningTrust(client, scope);
  const result = await client.query<IdentityEnvelopeSigningKeyRow & { cutoverAtNs: string }>(
    `select key.*,r.cutover_at_ns::text as "cutoverAtNs" from control.signing_key_rotation r
 join control.business_signing_key key on key.participant_id=r.participant_id and key.privacy_domain_id=r.privacy_domain_id and key.signer_id=r.old_signer_id
 join control.business_signing_key_state old_life on old_life.participant_id=key.participant_id and old_life.privacy_domain_id=key.privacy_domain_id and old_life.signer_id=key.signer_id
 join control.identity_envelope_signing_selection selection on selection.participant_id=r.participant_id and selection.privacy_domain_id=r.privacy_domain_id and selection.environment_id=r.environment_id and selection.signer_id=r.new_signer_id
 where r.participant_id=$1 and r.privacy_domain_id=$2 and r.rotation_id=$3 and r.recovery_case_id=$4 and r.state in('CUTOVER_FENCED','OBSERVING','OLD_REVOKED','OLD_RETIRED')
 and r.new_signer_id=$5 and selection.admission_version=$6 and r.cutover_at_ns is not null and key.signing_purpose_code=371 and old_life.state=(case when r.state in('CUTOVER_FENCED','OBSERVING') then 'ACTIVE' else 'REVOKED' end) for share of r,selection,old_life`,
    [
      scope.participantId,
      scope.privacyDomainId,
      lease.rotationId,
      lease.recoveryId,
      selected.trust.signerId,
      (BigInt(lease.selectionAdmissionVersion) + 1n).toString(),
    ],
  );
  const row = result.rows[0];
  if (result.rowCount !== 1 || !row) throw new PlatformRecoveryError();
  const trust = authenticatedIdentityEnvelopeSigningTrust(row);
  if (
    identityEnvelopeSigningTrustDigest(trust) !== lease.oldTrustDigest ||
    trust.secretReference !== enrollment.request.oldReference ||
    trust.signerId !== enrollment.request.oldFingerprint ||
    selected.trust.secretReference !== enrollment.request.newReference ||
    selected.recordedAtNs >= BigInt(Date.parse(lease.validUntil)) * 1000000n ||
    selected.recordedAtNs < BigInt(row.cutoverAtNs)
  )
    throw new PlatformRecoveryError();
  return {
    trust,
    selectedTrust: selected.trust,
    issuer,
    recordedAtNs: selected.recordedAtNs,
    cutoverAtNs: BigInt(row.cutoverAtNs),
  };
}
