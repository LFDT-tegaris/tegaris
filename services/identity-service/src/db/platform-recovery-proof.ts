import { localQaDurationMultiplier } from '../../../../packages/security-kernel/src/local-qa-duration-profile.js';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { PoolClient } from 'pg';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  assertPlatformRecoveryCeremony,
  platformRecoverySignerForPhase,
  type PlatformRecoveryPhase,
  type PlatformRecoveryProof,
  type RecoveryCustodyEnrollment,
  type RecoveryCustodyIntent,
} from '../domain/platform-recovery-ceremony.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { verifyLocalWebAuthnAssertion } from '../domain/local-webauthn-trust-adapter.js';
import { verifiedWebAuthnAssertionDigest } from '../domain/trust-adapter.js';
import { localOperationId } from '../domain/local-operation-id.js';
import type { AuthenticatedIdentityActor } from '../domain/identity-kernel.js';

function recoveryProofTables(context: PlatformRecoveryCeremonyContext) {
  return context.enrollment.schema === 'pc.identity.local-root-expiry-recovery-enrollment'
    ? {
        challenge: 'control.root_expiry_recovery_challenge',
        proof: 'control.root_expiry_recovery_proof',
      }
    : {
        challenge: 'control.platform_recovery_challenge',
        proof: 'control.platform_recovery_proof',
      };
}

const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();
const bytes = (value: string) => Buffer.from(value.slice(7), 'hex');
const deny = () => new PlatformRecoveryError();
/** Cryptographic purpose binding is distinct from any custom role/action grant. */
export const platformRecoveryProofAction = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';

export interface PlatformRecoveryCeremonyContext {
  readonly enrollment: RecoveryCustodyEnrollment;
  readonly intent: RecoveryCustodyIntent;
  readonly state: string;
  readonly proofs: readonly PlatformRecoveryProof[];
  readonly now: Date;
}

/** A live opaque Platform session proves identity only. It never establishes recovery authority. */
export async function readPlatformRecoverySession(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollment: RecoveryCustodyEnrollment,
) {
  if (!actor.platform || actor.participantId !== enrollment.participantId) throw deny();
  const [participantId, sessionId, extra] = actor.sessionToken.split('.');
  if (
    participantId !== actor.participantId ||
    !sessionId ||
    extra !== undefined ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(sessionId)
  )
    throw deny();
  const selected = await client.query<{
    tokenDigest: Buffer;
    sessionEpoch: string;
    durationProfile: string;
    expiresAt: Date;
  }>(
    `select s.opaque_token_digest as "tokenDigest",s.session_epoch::text as "sessionEpoch",
      s.duration_profile as "durationProfile",least(s.idle_expires_at,s.absolute_expires_at) as "expiresAt"
       from control.session s join control.principal p on p.participant_id=s.participant_id and p.principal_id=s.principal_id
       join control.participant participant on participant.participant_id=s.participant_id
     where s.participant_id=$1 and s.principal_id=$2 and s.session_id=$3 and s.context_mode='PLATFORM' and s.privacy_domain_id is null
       and s.state='ACTIVE' and s.idle_expires_at>clock_timestamp() and s.absolute_expires_at>clock_timestamp()
       and p.state='ACTIVE' and participant.state='ACTIVE' and s.authority_epoch=p.authority_epoch
       and s.participant_epoch=participant.authority_epoch for share of s,p,participant`,
    [actor.participantId, actor.principalId, sessionId],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    row.tokenDigest.length !== 32 ||
    !timingSafeEqual(row.tokenDigest, hash(actor.sessionToken))
  )
    throw deny();
  return {
    sessionId,
    sessionEpoch: row.sessionEpoch,
    durationProfile: row.durationProfile,
    expiresAt: row.expiresAt,
  };
}

/** The caller retains the source/case/credential fences for this entire transaction. */
export async function issuePlatformRecoveryChallenge(
  client: PoolClient,
  context: PlatformRecoveryCeremonyContext,
  actor: AuthenticatedIdentityActor,
  phase: PlatformRecoveryPhase,
  origin: string,
) {
  if (new URL(origin).origin !== origin) throw deny();
  const { enrollment, intent, state, proofs, now } = context;
  assertPlatformRecoveryCeremony(enrollment, intent, state, proofs, phase, actor.principalId, now);
  const signer = platformRecoverySignerForPhase(enrollment, actor.principalId, phase);
  const session = await readPlatformRecoverySession(client, actor, enrollment);
  const credential = await client.query<{ subject: string; validUntil: Date | null }>(
    `select subject,valid_until as "validUntil" from control.credential where participant_id=$1 and principal_id=$2 and credential_id=$3
       and credential_epoch=$4 and state='ACTIVE' and kind='WEBAUTHN' and valid_from<=clock_timestamp()
       and (valid_until is null or valid_until>clock_timestamp()) for share`,
    [enrollment.participantId, signer.principalId, signer.credentialId, signer.credentialEpoch],
  );
  if (credential.rowCount !== 1) throw deny();
  const challengeId = localOperationId();
  const challenge = randomBytes(32).toString('base64url');
  const intentDigest = canonicalAuthorizationDigest(intent);
  const qaChallenge =
    localQaDurationMultiplier(process.env) === 10 &&
    session.durationProfile === 'LOCAL_QA_10X' &&
    (('lifetimes' in intent && intent.lifetimes?.profile === 'LOCAL_QA_10X') ||
      ('qaDurationProfile' in intent && intent.qaDurationProfile === 'LOCAL_QA_10X'));
  const expiresAt = new Date(
    Math.min(
      now.getTime() + (qaChallenge ? 3000000 : 300000),
      Date.parse(intent.validUntil),
      session.expiresAt.getTime(),
      credential.rows[0]!.validUntil?.getTime() ?? Infinity,
    ),
  );
  await client.query(
    `insert into ${recoveryProofTables(context).challenge}(challenge_id,participant_id,privacy_domain_id,recovery_id,principal_id,credential_id,
       session_id,session_epoch,phase,intent_digest,challenge_digest,origin,created_at,expires_at,duration_profile,verified_proof_max_age_ms)
     values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
    [
      challengeId,
      enrollment.participantId,
      enrollment.privacyDomainId,
      intent.recoveryId,
      signer.principalId,
      signer.credentialId,
      session.sessionId,
      session.sessionEpoch,
      phase,
      bytes(intentDigest),
      hash(challenge),
      origin,
      now,
      expiresAt,
      qaChallenge ? 'LOCAL_QA_10X' : 'C17',
      qaChallenge ? 3000000 : 300000,
    ],
  );
  return {
    challengeId,
    challenge,
    intentDigest,
    phase,
    rpId: new URL(origin).hostname,
    credentialIds: [credential.rows[0]!.subject],
    userVerification: 'required' as const,
    expiresAt: expiresAt.toISOString(),
  };
}

/** Verifies UV, origin, nonce, the exact stored intent, session, signer epochs and counter before persisting any proof. */
export async function acceptPlatformRecoveryProof(
  client: PoolClient,
  context: PlatformRecoveryCeremonyContext,
  actor: AuthenticatedIdentityActor,
  phase: PlatformRecoveryPhase,
  origin: string,
  input: {
    readonly challengeId: string;
    readonly challenge: string;
    readonly intentDigest: string;
    readonly assertion: string;
  },
): Promise<PlatformRecoveryProof> {
  const { enrollment, intent, state, proofs, now } = context;
  assertPlatformRecoveryCeremony(enrollment, intent, state, proofs, phase, actor.principalId, now);
  const signer = platformRecoverySignerForPhase(enrollment, actor.principalId, phase);
  const session = await readPlatformRecoverySession(client, actor, enrollment);
  const intentDigest = canonicalAuthorizationDigest(intent);
  if (input.intentDigest !== intentDigest) throw deny();
  const challenge = await client.query<{ verifiedProofMaxAgeMs: 300000 | 3000000 }>(
    `select verified_proof_max_age_ms::integer as "verifiedProofMaxAgeMs" from ${recoveryProofTables(context).challenge} where challenge_id=$1 and participant_id=$2 and privacy_domain_id=$3
       and recovery_id=$4 and principal_id=$5 and credential_id=$6 and session_id=$7 and session_epoch=$8 and phase=$9
       and intent_digest=$10 and challenge_digest=$11 and origin=$12 and expires_at>clock_timestamp() and consumed_at is null for update`,
    [
      input.challengeId,
      enrollment.participantId,
      enrollment.privacyDomainId,
      intent.recoveryId,
      signer.principalId,
      signer.credentialId,
      session.sessionId,
      session.sessionEpoch,
      phase,
      bytes(intentDigest),
      hash(input.challenge),
      origin,
    ],
  );
  if (
    challenge.rowCount !== 1 ||
    ![300000, 3000000].includes(challenge.rows[0]?.verifiedProofMaxAgeMs ?? 0)
  )
    throw deny();
  const credential = await client.query<{
    subject: string;
    publicKey: Buffer;
    keyDigest: Buffer;
    counter: string;
  }>(
    `select subject,public_key_spki_der as "publicKey",public_key_digest as "keyDigest",authenticator_sign_count::text as counter
     from control.credential where participant_id=$1 and principal_id=$2 and credential_id=$3 and credential_epoch=$4
       and kind='WEBAUTHN' and state='ACTIVE' and valid_from<=clock_timestamp()
       and (valid_until is null or valid_until>clock_timestamp()) for update`,
    [enrollment.participantId, signer.principalId, signer.credentialId, signer.credentialEpoch],
  );
  const row = credential.rows[0];
  if (credential.rowCount !== 1 || !row) throw deny();
  const verified = verifyLocalWebAuthnAssertion(
    {
      credentialId: signer.credentialId,
      externalCredentialId: row.subject,
      publicKeyDigest: row.keyDigest,
      publicKeySpkiDer: row.publicKey,
    },
    {
      principalId: signer.principalId,
      sessionId: session.sessionId,
      actionIntentId: platformRecoveryProofAction,
      resourceDigest: intentDigest,
      challenge: input.challenge,
      rpIdHash: `sha256:${hash(new URL(origin).hostname).toString('hex')}`,
      allowedOrigin: origin,
      assertion: input.assertion,
    },
    now,
  );
  if (!verified || (BigInt(row.counter) > 0n && BigInt(verified.signCount) <= BigInt(row.counter)))
    throw deny();
  const proof: PlatformRecoveryProof = {
    ...signer,
    sessionId: session.sessionId,
    sessionEpoch: session.sessionEpoch,
    verifiedProofMaxAgeMs: challenge.rows[0]!.verifiedProofMaxAgeMs,
    phase,
    intentDigest,
    verifiedAt: now,
    proofId: localOperationId(),
  };
  await client.query(
    `insert into ${recoveryProofTables(context).proof}(proof_id,participant_id,privacy_domain_id,recovery_id,challenge_id,principal_id,credential_id,
       principal_epoch,credential_epoch,session_id,session_epoch,phase,intent_digest,assertion_evidence,assertion_digest,authenticator_sign_count,verified_at)
     values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
    [
      proof.proofId,
      enrollment.participantId,
      enrollment.privacyDomainId,
      intent.recoveryId,
      input.challengeId,
      signer.principalId,
      signer.credentialId,
      signer.principalEpoch,
      signer.credentialEpoch,
      session.sessionId,
      session.sessionEpoch,
      phase,
      bytes(intentDigest),
      { assertion: JSON.parse(input.assertion), verified },
      verifiedWebAuthnAssertionDigest(verified),
      verified.signCount,
      now,
    ],
  );
  const consumed = await client.query(
    `update ${recoveryProofTables(context).challenge} set consumed_at=$3,proof_id=$4 where participant_id=$1 and challenge_id=$2
       and consumed_at is null and expires_at>clock_timestamp()`,
    [enrollment.participantId, input.challengeId, now, proof.proofId],
  );
  if (consumed.rowCount !== 1) throw deny();
  const counted = await client.query(
    `update control.credential set authenticator_sign_count=$4,row_version=row_version+1
     where participant_id=$1 and credential_id=$2 and authenticator_sign_count=$3 and state='ACTIVE' and credential_epoch=$5`,
    [
      enrollment.participantId,
      signer.credentialId,
      row.counter,
      verified.signCount,
      signer.credentialEpoch,
    ],
  );
  if (counted.rowCount !== 1) throw deny();
  return proof;
}
