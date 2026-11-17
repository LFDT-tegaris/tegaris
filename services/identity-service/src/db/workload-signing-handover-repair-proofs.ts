import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type {
  IdentityEnvelopeRecoveryEnrollment,
  IdentityEnvelopeRecoveryIntent,
  IdentityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import { verifyLocalWebAuthnAssertion } from '../domain/local-webauthn-trust-adapter.js';
import {
  assertPlatformRecoveryCeremony,
  platformRecoveryProofMaxAgeMs,
  platformRecoverySignerForPhase,
  type PlatformRecoveryProof,
} from '../domain/platform-recovery-ceremony.js';
import { verifiedWebAuthnAssertionDigest } from '../domain/trust-adapter.js';

export class WorkloadSigningRepairProofUnavailable extends Error {
  constructor() {
    super('Original signing repair proofs are unavailable');
  }
}
interface ProofRow {
  participantId: string;
  privacyDomainId: string;
  recoveryId: string;
  proofId: string;
  principalId: string;
  principalEpoch: string;
  credentialId: string;
  credentialEpoch: string;
  sessionId: string;
  sessionEpoch: string;
  phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE';
  intentDigest: Buffer;
  assertionEvidence: unknown;
  assertionDigest: Buffer;
  signCount: string;
  verifiedAt: Date;
  challengeDigest: Buffer;
  origin: string;
  createdAt: Date;
  expiresAt: Date;
  consumedAt: Date;
  durationProfile: string;
  maxAgeMs: 300000 | 3000000;
  externalCredentialId: string;
  publicKey: Buffer;
  publicKeyDigest: Buffer;
}
const epoch = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const tagged = (value: Buffer) => 'sha256:' + value.toString('hex');
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();
const evidenceSchema = z.strictObject({ assertion: z.unknown(), verified: z.unknown() });

/** The caller authenticates original installed custody and the signed activation
 * lease first. Reverify its exact four immutable proof/challenge records, using
 * the original verification time and public key. Today's counter/session state
 * cannot recreate past authority. The original expiry ceilings not separately
 * retained in those records remain commitments of the signed native activation;
 * mutable current session deadlines are never substituted for those ceilings.
 */
export async function readWorkloadSigningRepairProofs(
  client: PoolClient,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  intent: IdentityEnvelopeRecoveryIntent,
  lease: IdentityEnvelopeRecoveryLease,
) {
  await client.query('select openpc.assert_request_context(true)');
  const result = await client.query<ProofRow>(
    `select p.participant_id::text as "participantId",p.privacy_domain_id::text as "privacyDomainId",
      p.recovery_id::text as "recoveryId",p.proof_id::text as "proofId",p.principal_id::text as "principalId",
      p.principal_epoch::text as "principalEpoch",p.credential_id::text as "credentialId",
      p.credential_epoch::text as "credentialEpoch",p.session_id::text as "sessionId",p.session_epoch::text as "sessionEpoch",
      p.phase,p.intent_digest as "intentDigest",p.assertion_evidence as "assertionEvidence",
      p.assertion_digest as "assertionDigest",p.authenticator_sign_count::text as "signCount",p.verified_at as "verifiedAt",
      h.challenge_digest as "challengeDigest",h.origin,h.created_at as "createdAt",h.expires_at as "expiresAt",
      h.consumed_at as "consumedAt",h.duration_profile as "durationProfile",h.verified_proof_max_age_ms::integer as "maxAgeMs",
      c.subject as "externalCredentialId",c.public_key_spki_der as "publicKey",c.public_key_digest as "publicKeyDigest"
    from control.platform_recovery_proof p
    join control.platform_recovery_challenge h on h.participant_id=p.participant_id and h.privacy_domain_id=p.privacy_domain_id
      and h.recovery_id=p.recovery_id and h.challenge_id=p.challenge_id and h.proof_id=p.proof_id
      and h.principal_id=p.principal_id and h.credential_id=p.credential_id and h.session_id=p.session_id
      and h.session_epoch=p.session_epoch and h.phase=p.phase and h.intent_digest=p.intent_digest
      and h.consumed_at is not null
    join control.credential c on c.participant_id=p.participant_id and c.principal_id=p.principal_id
      and c.credential_id=p.credential_id and c.kind='WEBAUTHN'
    where p.participant_id=$1 and p.privacy_domain_id=$2 and p.recovery_id=$3 and p.proof_id=any($4::uuid[])
      and openpc.matches_participant($1::uuid) and openpc.matches_privacy($2::uuid)
    limit 5`,
    [enrollment.participantId, enrollment.privacyDomainId, lease.recoveryId, lease.proofIds],
  );
  try {
    if (
      intent.enrollmentId !== enrollment.enrollmentId ||
      intent.enrollmentDigest !== canonicalAuthorizationDigest(enrollment) ||
      lease.enrollmentId !== enrollment.enrollmentId ||
      lease.enrollmentDigest !== intent.enrollmentDigest ||
      lease.intentDigest !== canonicalAuthorizationDigest(intent) ||
      lease.recoveryId !== intent.recoveryId ||
      lease.rotationId !== intent.rotationId ||
      lease.creationOperationId !== intent.creationOperationId ||
      lease.executorPrincipalId !== enrollment.recoveryPrincipal.principalId ||
      lease.proofIds.length !== 4 ||
      new Set(lease.proofIds).size !== 4 ||
      result.rowCount !== 4 ||
      result.rows.length !== 4 ||
      new Set(result.rows.map((row) => row.proofId)).size !== 4
    )
      throw new WorkloadSigningRepairProofUnavailable();
    const ordered = lease.proofIds.map((id) => {
      const row = result.rows.find((proof) => proof.proofId === id);
      if (!row) throw new WorkloadSigningRepairProofUnavailable();
      return row;
    });
    const committed: (Omit<PlatformRecoveryProof, 'verifiedProofMaxAgeMs'> & {
      assertionDigest: string;
    })[] = [];
    const proofs: PlatformRecoveryProof[] = [];
    const activationAt = new Date(lease.validFrom);
    for (const row of ordered) {
      z.uuidv7().parse(row.proofId);
      z.uuidv7().parse(row.sessionId);
      epoch.parse(row.sessionEpoch);
      const signer = platformRecoverySignerForPhase(enrollment, row.principalId, row.phase);
      const created = row.createdAt.getTime(),
        verifiedAt = row.verifiedAt.getTime(),
        expires = row.expiresAt.getTime();
      if (
        row.participantId !== enrollment.participantId ||
        row.privacyDomainId !== enrollment.privacyDomainId ||
        row.recoveryId !== lease.recoveryId ||
        row.principalEpoch !== signer.principalEpoch ||
        row.credentialId !== signer.credentialId ||
        row.credentialEpoch !== signer.credentialEpoch ||
        !Buffer.isBuffer(row.intentDigest) ||
        tagged(row.intentDigest) !== lease.intentDigest ||
        ![row.assertionDigest, row.challengeDigest, row.publicKeyDigest].every(
          (bytes) => Buffer.isBuffer(bytes) && bytes.length === 32,
        ) ||
        ![created, verifiedAt, expires, row.consumedAt.getTime(), activationAt.getTime()].every(
          Number.isFinite,
        ) ||
        created > verifiedAt ||
        expires <= verifiedAt ||
        row.consumedAt.getTime() !== verifiedAt ||
        verifiedAt > activationAt.getTime() ||
        verifiedAt < Date.parse(intent.validFrom) ||
        !['C17', 'LOCAL_QA_10X'].includes(row.durationProfile) ||
        ![300000, 3000000].includes(row.maxAgeMs) ||
        (row.maxAgeMs === 3000000 &&
          (row.durationProfile !== 'LOCAL_QA_10X' ||
            intent.lifetimes?.profile !== 'LOCAL_QA_10X' ||
            expires <= activationAt.getTime())) ||
        expires - created > (row.durationProfile === 'LOCAL_QA_10X' ? 3000000 : 300000)
      )
        throw new WorkloadSigningRepairProofUnavailable();
      const evidence = evidenceSchema.parse(row.assertionEvidence);
      const encoded = z
        .object({ clientDataJson: z.string() })
        .parse(evidence.assertion).clientDataJson;
      const clientData = Buffer.from(encoded, 'base64url');
      if (clientData.toString('base64url') !== encoded)
        throw new WorkloadSigningRepairProofUnavailable();
      const challenge = z
        .object({ challenge: z.string().min(32).max(256) })
        .parse(JSON.parse(clientData.toString('utf8'))).challenge;
      if (!hash(challenge).equals(row.challengeDigest))
        throw new WorkloadSigningRepairProofUnavailable();
      const verified = verifyLocalWebAuthnAssertion(
        {
          credentialId: row.credentialId,
          externalCredentialId: row.externalCredentialId,
          publicKeyDigest: row.publicKeyDigest,
          publicKeySpkiDer: row.publicKey,
        },
        {
          principalId: row.principalId,
          sessionId: row.sessionId,
          actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          resourceDigest: lease.intentDigest,
          challenge,
          rpIdHash: tagged(hash(new URL(row.origin).hostname)),
          allowedOrigin: row.origin,
          assertion: JSON.stringify(evidence.assertion),
        },
        row.verifiedAt,
      );
      if (
        !verified ||
        verified.signCount !== row.signCount ||
        !verifiedWebAuthnAssertionDigest(verified).equals(row.assertionDigest) ||
        canonicalAuthorizationDigest(Object.fromEntries(Object.entries(verified))) !==
          canonicalAuthorizationDigest(evidence.verified)
      )
        throw new WorkloadSigningRepairProofUnavailable();
      const proof: PlatformRecoveryProof = {
        proofId: row.proofId,
        principalId: row.principalId,
        principalEpoch: row.principalEpoch,
        credentialId: row.credentialId,
        credentialEpoch: row.credentialEpoch,
        sessionId: row.sessionId,
        sessionEpoch: row.sessionEpoch,
        phase: row.phase,
        intentDigest: lease.intentDigest,
        verifiedAt: row.verifiedAt,
        verifiedProofMaxAgeMs: row.maxAgeMs,
      };
      if (activationAt.getTime() - verifiedAt >= platformRecoveryProofMaxAgeMs(proof, intent))
        throw new WorkloadSigningRepairProofUnavailable();
      proofs.push(proof);
      const original = { ...proof };
      delete original.verifiedProofMaxAgeMs;
      committed.push({ ...original, assertionDigest: tagged(row.assertionDigest) });
    }
    const activation = proofs[3]!;
    assertPlatformRecoveryCeremony(
      enrollment,
      intent,
      'REQUESTED',
      proofs.slice(0, 3),
      'ACTIVATE',
      lease.executorPrincipalId,
      activationAt,
    );
    if (
      activation.phase !== 'ACTIVATE' ||
      activation.principalId !== lease.executorPrincipalId ||
      canonicalAuthorizationDigest(
        committed.map((proof) => ({ ...proof, verifiedAt: proof.verifiedAt.toISOString() })),
      ) !== lease.proofEvidenceDigest
    )
      throw new WorkloadSigningRepairProofUnavailable();
    return Object.freeze({
      proofIds: Object.freeze([...lease.proofIds]),
      proofEvidenceDigest: lease.proofEvidenceDigest,
    });
  } catch {
    throw new WorkloadSigningRepairProofUnavailable();
  }
}
