import type { PoolClient } from 'pg';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type { IdentityEnvelopeRecoveryEnrollment } from '../contracts/identity-envelope-recovery.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeEvidenceSigner,
} from '../domain/identity-kernel.js';
import {
  identityEnvelopeRecoveryEvidencePayload,
  signIdentityEnvelopeRecoveryEvidence,
} from '../domain/identity-envelope-recovery-evidence.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { localOperationId } from '../domain/local-operation-id.js';

/** Enrolled authenticated humans may deny further recovery use even when source
 * trust has expired. Closure preserves immutable lease bytes and review debt. */
export async function closeIdentityEnvelopeRecoveryCase(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollment: IdentityEnvelopeRecoveryEnrollment,
  recoveryId: string,
  revision: string,
  session: { sessionId: string; sessionEpoch: string },
  operationId: string,
  signer: IdentityRuntimeEvidenceSigner,
) {
  if (
    ![
      enrollment.recoveryPrincipal.principalId,
      ...enrollment.custodians.map((p) => p.principalId),
    ].includes(actor.principalId)
  )
    throw new PlatformRecoveryError();
  const closed = await client.query<{ state: string; revision: string; now: Date }>(
    `update control.platform_recovery_case set state=case when valid_until<=clock_timestamp() then 'EXPIRED' else 'REVOKED' end,
      row_version=row_version+1,updated_at=clock_timestamp()
     where participant_id=$1 and signer_repair_enrollment_id=$2 and recovery_id=$3 and row_version=$4
      and state in ('DRAFT','REQUESTED','ACTIVE') returning state,row_version::text as revision,updated_at as now`,
    [actor.participantId, enrollment.enrollmentId, recoveryId, revision],
  );
  const row = closed.rows[0];
  if (closed.rowCount !== 1 || !row) throw new PlatformRecoveryError();
  const result = {
    recoveryId,
    enrollmentId: enrollment.enrollmentId,
    operationId,
    state: row.state,
    revision: row.revision,
    authority: 'NONE',
    actorPrincipalId: actor.principalId,
    closedAt: row.now.toISOString(),
  };
  const signed = await signIdentityEnvelopeRecoveryEvidence(
    identityEnvelopeRecoveryEvidencePayload({
      enrollment,
      operationId,
      actorPrincipalId: actor.principalId,
      purpose: 'closure',
      value: result,
      authenticationDigest: canonicalAuthorizationDigest([actor.principalId, session]),
      issuedAt: result.closedAt,
      expiresAt: new Date(row.now.getTime() + 60000).toISOString(),
    }),
    signer,
  );
  const head = await client.query<{ sequence: string }>(
    `insert into control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence)
    values($1,'platform-recovery',$2,1) on conflict(participant_id,aggregate_type,aggregate_id)
    do update set last_sequence=control.outbox_aggregate_head.last_sequence+1,updated_at=clock_timestamp()
    returning last_sequence::text as sequence`,
    [actor.participantId, recoveryId],
  );
  if (head.rowCount !== 1) throw new PlatformRecoveryError();
  await client.query(
    `insert into control.outbox_event(participant_id,privacy_domain_id,aggregate_type,aggregate_id,aggregate_sequence,
    event_id,event_type,payload_cbor,payload_digest,cose_sign1,occurred_at)
    values($1,$2,'platform-recovery',$3,$4,$5,'openpc.identity.envelope-recovery.closed.v1',$6,$7,$8,$9)`,
    [
      actor.participantId,
      enrollment.privacyDomainId,
      recoveryId,
      head.rows[0]!.sequence,
      localOperationId(),
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      row.now,
    ],
  );
}
