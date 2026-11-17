import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeEvidenceSigner,
} from '../domain/identity-kernel.js';
import type { PlatformRecoveryCommand } from './platform-recovery-command.js';
import type { RecoveryLifetimeSettings } from '../domain/platform-recovery-lifetimes.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import {
  createIdentityEnvelopeRecoveryCase,
  readIdentityEnvelopeRecoveryCeremony,
} from './identity-envelope-recovery-case.js';
import { readIdentityEnvelopeRecoverySource } from './identity-envelope-recovery-source.js';
import { readIdentityEnvelopeRecoveryReceipt } from './identity-envelope-recovery-readback.js';
import { activateIdentityEnvelopeRecoveryLease } from './identity-envelope-recovery-activation.js';
import { closeIdentityEnvelopeRecoveryCase } from './identity-envelope-recovery-closure.js';
import { createIdentityEnvelopeRecoveryRotation } from './identity-envelope-recovery-rotation.js';
import { queueIdentityEnvelopeRecoveryRotation } from './identity-envelope-recovery-rotation-queue.js';
import {
  issuePlatformRecoveryChallenge,
  acceptPlatformRecoveryProof,
} from './platform-recovery-proof.js';

/** Existing command URL, authenticated stored purpose, exact immutable case.
 * Original consumed proofs reconcile without re-verification or reactivation. */
export async function executeIdentityEnvelopeRecoveryCommand(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  command: PlatformRecoveryCommand,
  origin: string,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
  lifetimes: RecoveryLifetimeSettings,
) {
  if (command.kind === 'ROTATION_ADVANCE')
    return queueIdentityEnvelopeRecoveryRotation(
      client,
      actor,
      enrollmentId,
      command,
      operationId,
      localQaEnabled,
      signer,
    );
  if (command.kind === 'ROTATION_CREATE')
    return createIdentityEnvelopeRecoveryRotation(
      client,
      actor,
      enrollmentId,
      command.recoveryId,
      operationId,
      localQaEnabled,
      signer,
    );
  if (command.kind === 'CREATE') {
    if ('preparation' in command) throw new PlatformRecoveryError();
    return createIdentityEnvelopeRecoveryCase(
      client,
      actor,
      enrollmentId,
      localQaEnabled,
      lifetimes,
      signer,
    );
  }
  if (command.kind === 'SOURCE') {
    const source = await readIdentityEnvelopeRecoverySource(
      client,
      actor,
      enrollmentId,
      localQaEnabled,
      signer,
    );
    const live = await client.query<{ recoveryId: string; state: string }>(
      `select recovery_id::text as "recoveryId",state from control.platform_recovery_case
      where participant_id=$1 and signer_repair_enrollment_id=$2 and state in ('DRAFT','REQUESTED','ACTIVE')`,
      [actor.participantId, enrollmentId],
    );
    if ((live.rowCount ?? 0) > 1) throw new PlatformRecoveryError();
    return {
      enrollmentId,
      purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
      authority: 'NONE',
      request: source.enrollment.request,
      source: {
        rootEpoch: source.enrollment.rootEpoch,
        rootDigest: source.enrollment.rootDigest,
        oldTrustDigest: source.enrollment.oldTrustDigest,
        issuerPrincipalId: source.enrollment.issuerPrincipalId,
        executorPrincipalId: source.enrollment.recoveryPrincipal.principalId,
        custodianPrincipalIds: source.enrollment.custodians.map((v) => v.principalId),
      },
      liveCase: live.rows[0] ?? null,
    };
  }
  if (command.kind === 'READ')
    return (
      await readIdentityEnvelopeRecoveryReceipt(
        client,
        actor,
        enrollmentId,
        command.recoveryId,
        localQaEnabled,
        signer,
      )
    ).receipt;
  if (command.kind === 'CLOSE') {
    await client.query('select * from openpc.lock_identity_envelope_recovery_enrollment($1)', [
      enrollmentId,
    ]);
    const read = await readIdentityEnvelopeRecoveryReceipt(
      client,
      actor,
      enrollmentId,
      command.recoveryId,
      localQaEnabled,
      signer,
    );
    if (['COMPLETED', 'REVOKED', 'EXPIRED'].includes(read.receipt.state)) return read.receipt;
    await closeIdentityEnvelopeRecoveryCase(
      client,
      actor,
      read.enrollment,
      command.recoveryId,
      read.receipt.revision,
      read.session,
      operationId,
      signer,
    );
    return (
      await readIdentityEnvelopeRecoveryReceipt(
        client,
        actor,
        enrollmentId,
        command.recoveryId,
        localQaEnabled,
        signer,
      )
    ).receipt;
  }
  if (command.kind === 'PROVE') {
    const prior = await client.query<{
      assertion: unknown;
      sessionId: string;
      sessionEpoch: string;
    }>(
      `select p.assertion_evidence->'assertion' as assertion,p.session_id::text as "sessionId",p.session_epoch::text as "sessionEpoch"
       from control.platform_recovery_proof p join control.platform_recovery_challenge h
        on h.participant_id=p.participant_id and h.recovery_id=p.recovery_id and h.challenge_id=p.challenge_id and h.proof_id=p.proof_id
       join control.platform_recovery_case c on c.recovery_id=p.recovery_id and c.participant_id=p.participant_id
       where p.participant_id=$1 and c.signer_repair_enrollment_id=$2 and p.recovery_id=$3 and p.principal_id=$4 and p.phase=$5
        and p.challenge_id=$6 and p.intent_digest=$7 and h.origin=$8 and h.challenge_digest=$9 and h.consumed_at is not null`,
      [
        actor.participantId,
        enrollmentId,
        command.recoveryId,
        actor.principalId,
        command.phase,
        command.proof.challengeId,
        Buffer.from(command.proof.intentDigest.slice(7), 'hex'),
        origin,
        createHash('sha256').update(command.proof.challenge).digest(),
      ],
    );
    if (prior.rowCount !== 0) {
      const row = prior.rows[0];
      if (
        prior.rowCount !== 1 ||
        !row ||
        canonicalAuthorizationJson(row.assertion) !==
          canonicalAuthorizationJson(JSON.parse(command.proof.assertion))
      )
        throw new PlatformRecoveryError();
      const read = await readIdentityEnvelopeRecoveryReceipt(
        client,
        actor,
        enrollmentId,
        command.recoveryId,
        localQaEnabled,
        signer,
      );
      if (
        row.sessionId !== read.session.sessionId ||
        row.sessionEpoch !== read.session.sessionEpoch
      )
        throw new PlatformRecoveryError();
      return read.receipt;
    }
  }
  const context = await readIdentityEnvelopeRecoveryCeremony(
    client,
    actor,
    enrollmentId,
    command.recoveryId,
    localQaEnabled,
    signer,
  );
  if (command.kind === 'CHALLENGE')
    return issuePlatformRecoveryChallenge(client, context, actor, command.phase, origin);
  const proof = await acceptPlatformRecoveryProof(
    client,
    context,
    actor,
    command.phase,
    origin,
    command.proof,
  );
  if (command.phase === 'ACTIVATE') {
    await activateIdentityEnvelopeRecoveryLease(
      client,
      actor,
      context,
      proof,
      operationId,
      signer,
      localQaEnabled,
    );
  } else if (command.phase === 'REQUEST') {
    const requested = await client.query(
      `update control.platform_recovery_case set state='REQUESTED',row_version=row_version+1,updated_at=clock_timestamp()
      where participant_id=$1 and signer_repair_enrollment_id=$2 and recovery_id=$3 and state='DRAFT' and valid_until>clock_timestamp()`,
      [actor.participantId, enrollmentId, command.recoveryId],
    );
    if (requested.rowCount !== 1) throw new PlatformRecoveryError();
  }
  return (
    await readIdentityEnvelopeRecoveryReceipt(
      client,
      actor,
      enrollmentId,
      command.recoveryId,
      localQaEnabled,
      signer,
    )
  ).receipt;
}
