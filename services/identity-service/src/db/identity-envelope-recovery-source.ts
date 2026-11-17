import type { PoolClient } from 'pg';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import type { AuthenticatedIdentityActor } from '../domain/identity-kernel.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { verifyIdentityEnvelopeRecoveryCustody } from '../domain/identity-envelope-recovery-custody.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { readCurrentPlatformScope } from './platform-envelope-scope.js';
import { assertPlatformRecoverySigners } from './platform-recovery-enrollment.js';
import { readPlatformRecoverySession } from './platform-recovery-proof.js';
import { captureIdentityEnvelopeRotationSource } from './identity-envelope-rotation-candidate.js';

/** Live source facts under the Participant write fence. Installed custody alone
 * creates no lease: the fixed actor and every current source are revalidated. */
export async function readIdentityEnvelopeRecoverySource(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  localQaEnabled: boolean,
  verifier?: IdentityRuntimeVerifier,
) {
  const deny = () => {
    throw new PlatformRecoveryError();
  };
  const selected = await client.query<{
    document: unknown;
    document_digest: Buffer;
    signature: Buffer;
    state: string;
    row_version: string;
  }>(
    `select document,document_digest,signature,state,row_version::text
    from openpc.lock_identity_envelope_recovery_enrollment($1)`,
    [enrollmentId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row || row.state !== 'ACTIVE' || row.row_version !== '1') deny();
  // Structure is validated by signature verification; the public pin comes only
  // from its independently installed exact enrollment relationship.
  const pin = await client.query<{
    document: unknown;
    now: Date;
    current: boolean;
    revision: string;
  }>(
    `select t.document,clock_timestamp() as now,
      openpc.identity_envelope_recovery_source_current(e.enrollment_id) as current,e.row_version::text as revision
     from control.identity_envelope_recovery_enrollment e
     join control.identity_envelope_recovery_custody_trust t on t.custody_trust_id=e.custody_trust_id
      and t.participant_id=e.participant_id and t.privacy_domain_id=e.privacy_domain_id
      and t.document_digest=e.custody_trust_digest and t.state='ACTIVE' and t.row_version=1
     where e.participant_id=$1 and e.enrollment_id=$2`,
    [actor.participantId, enrollmentId],
  );
  const receiving = pin.rows[0];
  if (pin.rowCount !== 1 || !receiving || receiving.current !== true) deny();
  const now = new Date(receiving!.now);
  const enrollment = verifyIdentityEnvelopeRecoveryCustody(
    receiving!.document,
    {
      document: row!.document,
      signature: row!.signature.toString('base64url'),
    },
    now,
    localQaEnabled,
  );
  if (
    enrollment.enrollmentId !== enrollmentId ||
    actor.participantId !== enrollment.participantId ||
    canonicalAuthorizationDigest(enrollment) !== `sha256:${row!.document_digest.toString('hex')}` ||
    ![
      enrollment.recoveryPrincipal.principalId,
      ...enrollment.custodians.map((v) => v.principalId),
    ].includes(actor.principalId)
  )
    deny();
  const root = await readCurrentPlatformScope(
    client,
    enrollment.platformContextId,
    enrollment.rootEpoch,
  );
  if (
    root.ownerParticipantId !== enrollment.participantId ||
    root.installationPrivacyDomainId !== enrollment.privacyDomainId ||
    root.platformAuthorityDigest !== enrollment.rootDigest ||
    root.installationDigest !== enrollment.installationDigest ||
    root.environmentId !== enrollment.installationEnvironmentId ||
    BigInt(root.grantable.validFromNs) > BigInt(now.getTime()) * 1000000n ||
    BigInt(root.grantable.validUntilNs) <= BigInt(now.getTime()) * 1000000n
  )
    deny();
  await readPlatformRecoverySession(client, actor, enrollment);
  await assertPlatformRecoverySigners(client, enrollment, localQaEnabled);
  const current = await captureIdentityEnvelopeRotationSource(
    client,
    enrollment,
    enrollment.request,
    verifier,
  );
  if (
    current.issuer.workloadPrincipalId !== enrollment.issuerPrincipalId ||
    current.issuer.workloadParticipantEpoch !== enrollment.issuerParticipantEpoch ||
    current.issuer.workloadPrincipalEpoch !== enrollment.issuerPrincipalEpoch ||
    current.issuer.workloadCredentialEpoch !== enrollment.issuerCredentialEpoch ||
    current.issuer.workloadPublicKeyDigest !== enrollment.issuerCredentialPublicKeyDigest ||
    `sha256:${current.row.trust_digest.toString('hex')}` !== enrollment.oldTrustDigest ||
    current.row.admission_version !== enrollment.selectionAdmissionVersion ||
    (current.trust.workloadParticipantEpoch.toString() === enrollment.issuerParticipantEpoch &&
      current.trust.workloadPrincipalEpoch.toString() === enrollment.issuerPrincipalEpoch &&
      current.trust.workloadCredentialId === enrollment.request.workloadCredentialId &&
      current.trust.workloadCredentialEpoch.toString() === enrollment.issuerCredentialEpoch)
  )
    deny();
  return { enrollment, enrollmentRevision: row!.row_version, now, root, issuer: current.issuer };
}
