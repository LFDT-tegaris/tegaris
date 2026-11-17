import type { PoolClient } from 'pg';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import type { AuthenticatedIdentityActor } from '../domain/identity-kernel.js';
import { identityEnvelopeRecoveryIntent } from '../contracts/identity-envelope-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { localOperationId } from '../domain/local-operation-id.js';
import {
  defaultRecoveryLifetimes,
  recoveryLifetimeSettings,
  type RecoveryLifetimeSettings,
} from '../domain/platform-recovery-lifetimes.js';
import { readIdentityEnvelopeRecoverySource } from './identity-envelope-recovery-source.js';
import { readRecoveryCeremonyProofs } from './platform-recovery-case.js';
import type { PlatformRecoveryCeremonyContext } from './platform-recovery-proof.js';

/** Reserves one exact server-generated rotation and creation operation only.
 * DRAFT custody is not an ordinary grant, Root handoff or active recovery lease. */
export async function createIdentityEnvelopeRecoveryCase(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  localQaEnabled: boolean,
  configuredLifetimes: RecoveryLifetimeSettings = defaultRecoveryLifetimes,
  verifier?: IdentityRuntimeVerifier,
) {
  const source = await readIdentityEnvelopeRecoverySource(
    client,
    actor,
    enrollmentId,
    localQaEnabled,
    verifier,
  );
  if (actor.principalId !== source.enrollment.recoveryPrincipal.principalId)
    throw new PlatformRecoveryError();
  const settings = recoveryLifetimeSettings.parse(configuredLifetimes);
  if (
    settings.profile !== 'C17' &&
    (!localQaEnabled || source.enrollment.assurance !== 'LOCAL_QA_VIRTUAL_AUTHENTICATOR')
  )
    throw new PlatformRecoveryError();
  const existing = await client.query(
    `select 1 from control.platform_recovery_case c join control.identity_envelope_recovery_enrollment e
      on e.enrollment_id=c.signer_repair_enrollment_id and e.participant_id=c.participant_id
    where c.participant_id=$2 and (c.signer_repair_enrollment_id=$1 and c.state in ('DRAFT','REQUESTED','ACTIVE')
      or e.document->>'issuerPrincipalId'=$3 and c.activated_at is not null and c.reviewed_at is null)`,
    [enrollmentId, actor.participantId, source.enrollment.issuerPrincipalId],
  );
  if (existing.rowCount !== 0) throw new PlatformRecoveryError();
  const intent = identityEnvelopeRecoveryIntent.parse({
    schema: 'pc.identity.identity-envelope-recovery-intent',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: localOperationId(),
    enrollmentId,
    enrollmentRevision: source.enrollmentRevision,
    enrollmentDigest: canonicalAuthorizationDigest(source.enrollment),
    rotationId: localOperationId(),
    creationOperationId: localOperationId(),
    sourceParticipantEpoch: source.issuer.workloadParticipantEpoch,
    sourceIssuerPrincipalEpoch: source.issuer.workloadPrincipalEpoch,
    sourceIssuerCredentialEpoch: source.issuer.workloadCredentialEpoch,
    oldTrustDigest: source.enrollment.oldTrustDigest,
    selectionAdmissionVersion: source.enrollment.selectionAdmissionVersion,
    validFrom: source.now.toISOString(),
    validUntil: new Date(
      Math.min(
        source.now.getTime() +
          (settings.profile === 'LOCAL_QA_10X'
            ? settings.leaseMs
            : Math.min(settings.leaseMs, 900000)),
        Date.parse(source.enrollment.validUntil),
        Number(BigInt(source.root.grantable.validUntilNs) / 1000000n),
        source.issuer.credentialValidUntilNs === null
          ? Infinity
          : Number(BigInt(source.issuer.credentialValidUntilNs) / 1000000n),
      ),
    ).toISOString(),
    ...(settings.profile === 'LOCAL_QA_10X' ? { lifetimes: settings } : {}),
    postReviewRequired: true,
  });
  const intentDigest = canonicalAuthorizationDigest(intent);
  await client.query(
    `insert into control.platform_recovery_case(recovery_id,participant_id,privacy_domain_id,signer_repair_enrollment_id,
    enrollment_revision,enrollment_digest,intent,intent_digest,planned_record_ids,valid_from,valid_until)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      intent.recoveryId,
      source.enrollment.participantId,
      source.enrollment.privacyDomainId,
      enrollmentId,
      intent.enrollmentRevision,
      Buffer.from(intent.enrollmentDigest.slice(7), 'hex'),
      intent,
      Buffer.from(intentDigest.slice(7), 'hex'),
      JSON.stringify([intent.rotationId, intent.creationOperationId]),
      intent.validFrom,
      intent.validUntil,
    ],
  );
  return {
    intent,
    intentDigest,
    state: 'DRAFT' as const,
    authority: 'NONE' as const,
    assurance: source.enrollment.assurance,
  };
}

export async function readIdentityEnvelopeRecoveryCeremony(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  recoveryId: string,
  localQaEnabled: boolean,
  verifier?: IdentityRuntimeVerifier,
): Promise<PlatformRecoveryCeremonyContext> {
  const source = await readIdentityEnvelopeRecoverySource(
    client,
    actor,
    enrollmentId,
    localQaEnabled,
    verifier,
  );
  const selected = await client.query<{ intent: unknown; digest: Buffer; state: string }>(
    `select intent,intent_digest as digest,state from control.platform_recovery_case
     where participant_id=$1 and privacy_domain_id=$2 and signer_repair_enrollment_id=$3 and recovery_id=$4 for update`,
    [source.enrollment.participantId, source.enrollment.privacyDomainId, enrollmentId, recoveryId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw new PlatformRecoveryError();
  const intent = identityEnvelopeRecoveryIntent.parse(row.intent);
  if (
    intent.recoveryId !== recoveryId ||
    intent.enrollmentId !== enrollmentId ||
    intent.enrollmentRevision !== source.enrollmentRevision ||
    intent.enrollmentDigest !== canonicalAuthorizationDigest(source.enrollment) ||
    canonicalAuthorizationDigest(intent) !== `sha256:${row.digest.toString('hex')}` ||
    intent.sourceParticipantEpoch !== source.issuer.workloadParticipantEpoch ||
    intent.sourceIssuerPrincipalEpoch !== source.issuer.workloadPrincipalEpoch ||
    intent.sourceIssuerCredentialEpoch !== source.issuer.workloadCredentialEpoch ||
    intent.oldTrustDigest !== source.enrollment.oldTrustDigest ||
    intent.selectionAdmissionVersion !== source.enrollment.selectionAdmissionVersion ||
    Date.parse(intent.validUntil) > Date.parse(source.enrollment.validUntil) ||
    BigInt(Date.parse(intent.validUntil)) * 1000000n > BigInt(source.root.grantable.validUntilNs)
  )
    throw new PlatformRecoveryError();
  const proofs = await readRecoveryCeremonyProofs(client, source.enrollment, recoveryId);
  return { enrollment: source.enrollment, intent, state: row.state, now: source.now, proofs };
}
