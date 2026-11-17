import type { PoolClient } from 'pg';
import { discoveryCertificateRecoveryIntent } from '../contracts/discovery-certificate-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { assertDiscoveryCertificateRecoveryIntent } from '../domain/discovery-certificate-recovery.js';
import {
  defaultRecoveryLifetimes,
  recoveryLifetimeSettings,
  type RecoveryLifetimeSettings,
} from '../domain/platform-recovery-lifetimes.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeAssertionVerifier,
} from '../domain/identity-kernel.js';
import { localOperationId } from '../domain/local-operation-id.js';
import { readDiscoveryCertificateRecoverySource } from './discovery-certificate-recovery-source.js';
import { readRecoveryCeremonyProofs } from './platform-recovery-case.js';
import type { PlatformRecoveryCeremonyContext } from './platform-recovery-proof.js';

/** Proposed custody only. Every target, credential, key and administrator bound
 * here is derived from installed trust and current owners, never caller names. */
export async function createDiscoveryCertificateRecoveryCase(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  localQaEnabled: boolean,
  configuredLifetimes: RecoveryLifetimeSettings = defaultRecoveryLifetimes,
  verifier?: IdentityRuntimeAssertionVerifier,
) {
  const source = await readDiscoveryCertificateRecoverySource(
    client,
    enrollmentId,
    localQaEnabled,
    actor,
    null,
    verifier,
  );
  if (actor.principalId !== source.enrollment.recoveryPrincipal.principalId)
    throw new PlatformRecoveryError();
  const lifetimes = recoveryLifetimeSettings.parse(configuredLifetimes);
  if (
    lifetimes.profile !== 'C17' &&
    (!localQaEnabled || source.enrollment.assurance !== 'LOCAL_QA_VIRTUAL_AUTHENTICATOR')
  )
    throw new PlatformRecoveryError();
  const existing = await client.query(
    `select 1 from control.platform_recovery_case where enrollment_id=$1 and state in ('DRAFT','REQUESTED','ACTIVE')`,
    [enrollmentId],
  );
  if (existing.rowCount !== 0) throw new PlatformRecoveryError();
  const intent = discoveryCertificateRecoveryIntent.parse({
    schema: 'pc.identity.discovery-certificate-recovery-intent',
    schemaVersion: source.intentVersion,
    recoveryId: localOperationId(),
    enrollmentId,
    enrollmentRevision: source.enrollmentRevision,
    enrollmentDigest: canonicalAuthorizationDigest(source.enrollment),
    certificateRecovery: source.enrollment.certificateRecovery,
    administrators: source.administrators,
    validFrom: source.now.toISOString(),
    validUntil: new Date(
      Math.min(
        source.now.getTime() + lifetimes.leaseMs,
        Date.parse(source.enrollment.validUntil),
        source.rootValidUntil.getTime(),
      ),
    ).toISOString(),
    lifetimes,
  });
  assertDiscoveryCertificateRecoveryIntent(intent, source);
  const intentDigest = canonicalAuthorizationDigest(intent);
  await client.query(
    `insert into control.platform_recovery_case(recovery_id,participant_id,privacy_domain_id,enrollment_id,
      enrollment_revision,enrollment_digest,intent,intent_digest,planned_record_ids,valid_from,valid_until)
     values($1,$2,$3,$4,$5,$6,$7,$8,'[]'::jsonb,$9,$10)`,
    [
      intent.recoveryId,
      source.enrollment.participantId,
      source.enrollment.privacyDomainId,
      enrollmentId,
      intent.enrollmentRevision,
      Buffer.from(intent.enrollmentDigest.slice(7), 'hex'),
      intent,
      Buffer.from(intentDigest.slice(7), 'hex'),
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

/** Source locks precede the case and each fresh independent proof. */
export async function readDiscoveryCertificateRecoveryCeremony(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  recoveryId: string,
  localQaEnabled: boolean,
  verifier?: IdentityRuntimeAssertionVerifier,
): Promise<PlatformRecoveryCeremonyContext> {
  const source = await readDiscoveryCertificateRecoverySource(
    client,
    enrollmentId,
    localQaEnabled,
    actor,
    recoveryId,
    verifier,
  );
  const selected = await client.query<{ intent: unknown; intentDigest: Buffer; state: string }>(
    `select intent,intent_digest as "intentDigest",state from control.platform_recovery_case
     where participant_id=$1 and privacy_domain_id=$2 and enrollment_id=$3 and recovery_id=$4 for update`,
    [source.enrollment.participantId, source.enrollment.privacyDomainId, enrollmentId, recoveryId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw new PlatformRecoveryError();
  const intent = discoveryCertificateRecoveryIntent.parse(row.intent);
  if (
    intent.recoveryId !== recoveryId ||
    canonicalAuthorizationDigest(intent) !== `sha256:${row.intentDigest.toString('hex')}`
  )
    throw new PlatformRecoveryError();
  assertDiscoveryCertificateRecoveryIntent(intent, source);
  const proofs = await readRecoveryCeremonyProofs(client, source.enrollment, recoveryId);
  return { enrollment: source.enrollment, intent, state: row.state, now: source.now, proofs };
}
