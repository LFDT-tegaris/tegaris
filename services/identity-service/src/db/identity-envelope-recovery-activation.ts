import type { PoolClient } from 'pg';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryIntent,
  identityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeEvidenceSigner,
} from '../domain/identity-kernel.js';
import {
  assertPlatformRecoveryCeremony,
  platformRecoveryProofMaxAgeMs,
  type PlatformRecoveryProof,
} from '../domain/platform-recovery-ceremony.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import {
  identityEnvelopeRecoveryEvidencePayload,
  signIdentityEnvelopeRecoveryEvidence,
} from '../domain/identity-envelope-recovery-evidence.js';
import { readIdentityEnvelopeRecoverySource } from './identity-envelope-recovery-source.js';
import { captureIdentityEnvelopeRotationIssuer } from './identity-envelope-rotation-issuer.js';
import type { PlatformRecoveryCeremonyContext } from './platform-recovery-proof.js';
import { localOperationId } from '../domain/local-operation-id.js';

/** The caller's transaction owns proof/counter consumption, the issuer fence,
 * signed exact lease and outbox. Any signing/persistence failure rolls it all
 * back; a consumed activation proof always reconciles the original receipt. */
export async function activateIdentityEnvelopeRecoveryLease(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  context: PlatformRecoveryCeremonyContext,
  activationProof: PlatformRecoveryProof,
  operationId: string,
  signer: IdentityRuntimeEvidenceSigner,
  localQaEnabled: boolean,
) {
  if (
    context.enrollment.schema !== 'pc.identity.identity-envelope-recovery-enrollment' ||
    context.intent.schema !== 'pc.identity.identity-envelope-recovery-intent'
  )
    throw new PlatformRecoveryError();
  const intent = identityEnvelopeRecoveryIntent.parse(context.intent);
  const source = await readIdentityEnvelopeRecoverySource(
    client,
    actor,
    intent.enrollmentId,
    localQaEnabled,
    signer,
  );
  const e = source.enrollment;
  if (
    actor.principalId !== e.recoveryPrincipal.principalId ||
    canonicalAuthorizationDigest(e) !== intent.enrollmentDigest ||
    source.enrollmentRevision !== intent.enrollmentRevision ||
    intent.sourceParticipantEpoch !== source.issuer.workloadParticipantEpoch ||
    intent.sourceIssuerPrincipalEpoch !== source.issuer.workloadPrincipalEpoch ||
    intent.sourceIssuerCredentialEpoch !== source.issuer.workloadCredentialEpoch ||
    intent.oldTrustDigest !== e.oldTrustDigest ||
    intent.selectionAdmissionVersion !== e.selectionAdmissionVersion
  )
    throw new PlatformRecoveryError();
  assertPlatformRecoveryCeremony(
    e,
    intent,
    context.state,
    context.proofs,
    'ACTIVATE',
    actor.principalId,
    source.now,
  );
  const executor = e.recoveryPrincipal;
  if (
    activationProof.phase !== 'ACTIVATE' ||
    activationProof.principalId !== executor.principalId ||
    activationProof.principalEpoch !== executor.principalEpoch ||
    activationProof.credentialId !== executor.credentialId ||
    activationProof.credentialEpoch !== executor.credentialEpoch ||
    activationProof.intentDigest !== canonicalAuthorizationDigest(intent) ||
    !Number.isFinite(activationProof.verifiedAt.getTime()) ||
    activationProof.verifiedAt.getTime() < Date.parse(intent.validFrom) ||
    activationProof.verifiedAt.getTime() > source.now.getTime() ||
    source.now.getTime() - activationProof.verifiedAt.getTime() >=
      platformRecoveryProofMaxAgeMs(activationProof, intent)
  )
    throw new PlatformRecoveryError();
  const proofs = [...context.proofs, activationProof];
  const checked = await client.query<{ proofId: string; digest: Buffer; expiresAt: Date }>(
    `select p.proof_id::text as "proofId",p.assertion_digest as digest,
      least(s.idle_expires_at,s.absolute_expires_at,c.valid_until) as "expiresAt"
     from control.platform_recovery_proof p join control.platform_recovery_challenge h
      on h.participant_id=p.participant_id and h.recovery_id=p.recovery_id and h.proof_id=p.proof_id
       and h.challenge_id=p.challenge_id and h.consumed_at is not null
     join control.principal principal on principal.participant_id=p.participant_id and principal.principal_id=p.principal_id
      and principal.state='ACTIVE' and principal.authority_epoch=p.principal_epoch
     join control.credential c on c.participant_id=p.participant_id and c.principal_id=p.principal_id
      and c.credential_id=p.credential_id and c.credential_epoch=p.credential_epoch and c.state='ACTIVE' and c.kind='WEBAUTHN'
     join control.session s on s.participant_id=p.participant_id and s.principal_id=p.principal_id and s.session_id=p.session_id
      and s.session_epoch=p.session_epoch and s.authority_epoch=p.principal_epoch and s.state='ACTIVE'
      and s.context_mode='PLATFORM' and s.privacy_domain_id is null and s.participant_epoch=$5
     where p.participant_id=$1 and p.privacy_domain_id=$2 and p.recovery_id=$3 and p.proof_id=any($4::uuid[])
      and p.intent_digest=$6 and p.verified_at>clock_timestamp()-make_interval(secs=>h.verified_proof_max_age_ms/1000.0)
      and (h.verified_proof_max_age_ms=300000 or (h.verified_proof_max_age_ms=3000000
        and h.duration_profile='LOCAL_QA_10X' and s.duration_profile='LOCAL_QA_10X' and h.expires_at>clock_timestamp()))
      and p.verified_at<=clock_timestamp() and c.valid_from<=clock_timestamp()
      and (c.valid_until is null or c.valid_until>clock_timestamp())
      and s.idle_expires_at>clock_timestamp() and s.absolute_expires_at>clock_timestamp()
     for share of principal,c,s`,
    [
      e.participantId,
      e.privacyDomainId,
      intent.recoveryId,
      proofs.map((p) => p.proofId),
      intent.sourceParticipantEpoch,
      Buffer.from(canonicalAuthorizationDigest(intent).slice(7), 'hex'),
    ],
  );
  if (
    checked.rowCount !== 4 ||
    checked.rows.some((p) => p.digest.length !== 32) ||
    new Set(checked.rows.map((p) => p.proofId)).size !== 4 ||
    proofs.some((p) => !checked.rows.some((row) => row.proofId === p.proofId))
  )
    throw new PlatformRecoveryError();
  const validUntil = new Date(
    Math.min(
      Date.parse(intent.validUntil),
      Date.parse(e.validUntil),
      source.now.getTime() + (intent.lifetimes?.leaseMs ?? 900000),
      Number(BigInt(source.root.grantable.validUntilNs) / 1000000n),
      source.issuer.credentialValidUntilNs === null
        ? Infinity
        : Number(BigInt(source.issuer.credentialValidUntilNs) / 1000000n),
      ...checked.rows.map((row) => new Date(row.expiresAt).getTime()),
    ),
  ).toISOString();
  if (Date.parse(validUntil) <= source.now.getTime()) throw new PlatformRecoveryError();
  // This exact SQL owner independently rechecks the stored original case and
  // all four consumed proofs before advancing the actual issuer epoch.
  const fenced = await client.query<{ epoch: string }>(
    'select openpc.fence_identity_envelope_recovery_issuer($1,$2)::text as epoch',
    [intent.recoveryId, activationProof.proofId],
  );
  if (
    fenced.rowCount !== 1 ||
    fenced.rows[0]?.epoch !== (BigInt(intent.sourceIssuerPrincipalEpoch) + 1n).toString()
  )
    throw new PlatformRecoveryError();
  const { issuer } = await captureIdentityEnvelopeRotationIssuer(client, {
    participantId: e.participantId,
    privacyDomainId: e.privacyDomainId,
    workloadCredentialId: e.request.workloadCredentialId,
  });
  if (
    issuer.workloadPrincipalEpoch !== fenced.rows[0].epoch ||
    issuer.workloadParticipantEpoch !== intent.sourceParticipantEpoch ||
    issuer.workloadCredentialEpoch !== intent.sourceIssuerCredentialEpoch ||
    issuer.workloadPrincipalId !== e.issuerPrincipalId ||
    issuer.workloadPublicKeyDigest !== e.issuerCredentialPublicKeyDigest
  )
    throw new PlatformRecoveryError();
  const lease = identityEnvelopeRecoveryLease.parse({
    schema: 'pc.identity.identity-envelope-recovery-lease',
    schemaVersion: 1,
    purpose: intent.purpose,
    recoveryId: intent.recoveryId,
    enrollmentId: e.enrollmentId,
    enrollmentDigest: intent.enrollmentDigest,
    intentDigest: canonicalAuthorizationDigest(intent),
    rotationId: intent.rotationId,
    creationOperationId: intent.creationOperationId,
    activationOperationId: operationId,
    executorPrincipalId: actor.principalId,
    issuer,
    oldTrustDigest: intent.oldTrustDigest,
    selectionAdmissionVersion: intent.selectionAdmissionVersion,
    proofIds: proofs.map((p) => p.proofId),
    proofEvidenceDigest: canonicalAuthorizationDigest(
      proofs.map(({ verifiedProofMaxAgeMs: _age, ...p }) => ({
        ...p,
        verifiedAt: p.verifiedAt.toISOString(),
        assertionDigest: `sha256:${checked.rows.find((row) => row.proofId === p.proofId)!.digest.toString('hex')}`,
      })),
    ),
    validFrom: source.now.toISOString(),
    validUntil,
    ...(intent.lifetimes ? { lifetimes: intent.lifetimes } : {}),
    postReviewRequired: true,
  });
  const signed = await signIdentityEnvelopeRecoveryEvidence(
    identityEnvelopeRecoveryEvidencePayload({
      enrollment: e,
      operationId,
      actorPrincipalId: actor.principalId,
      purpose: 'activation',
      value: lease,
      authenticationDigest: lease.proofEvidenceDigest,
      issuedAt: lease.validFrom,
      expiresAt: lease.validUntil,
    }),
    signer,
  );
  const activated = await client.query(
    `update control.platform_recovery_case set state='ACTIVE',row_version=row_version+1,updated_at=clock_timestamp(),
      activated_at=$4,activation_operation_id=$5,activation_evidence_cbor=$6,activation_evidence_digest=$7,activation_cose=$8,lease_bindings=$9
     where participant_id=$1 and signer_repair_enrollment_id=$2 and recovery_id=$3 and state='REQUESTED' and valid_until>clock_timestamp()`,
    [
      e.participantId,
      e.enrollmentId,
      intent.recoveryId,
      source.now,
      operationId,
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      JSON.stringify(lease),
    ],
  );
  if (activated.rowCount !== 1) throw new PlatformRecoveryError();
  await client.query(
    `insert into control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence)
    values($1,'platform-recovery',$2,1)`,
    [e.participantId, intent.recoveryId],
  );
  await client.query(
    `insert into control.outbox_event(participant_id,privacy_domain_id,aggregate_type,aggregate_id,aggregate_sequence,
    event_id,event_type,payload_cbor,payload_digest,cose_sign1,occurred_at)
    values($1,$2,'platform-recovery',$3,1,$4,'openpc.identity.envelope-recovery.activated.v1',$5,$6,$7,$8)`,
    [
      e.participantId,
      e.privacyDomainId,
      intent.recoveryId,
      localOperationId(),
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      source.now,
    ],
  );
  return lease;
}
