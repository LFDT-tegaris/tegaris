import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { encodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';
import type { RecoveryCustodyEnrollment } from '../domain/platform-recovery-ceremony.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeEvidenceSigner,
} from '../domain/identity-kernel.js';
import { identityActorKeyDigest } from '../domain/identity-runtime-authorization.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { localOperationId } from '../domain/local-operation-id.js';

/** Denial takes effect with the signed closure event, atomically. No activation bytes or original grant are changed. */
export async function closePlatformRecoveryCase(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollment: RecoveryCustodyEnrollment,
  recoveryId: string,
  revision: string,
  session: { sessionId: string; sessionEpoch: string },
  operationId: string,
  signer: IdentityRuntimeEvidenceSigner,
) {
  const closed = await client.query<{ state: string; revision: string; now: Date }>(
    `update control.platform_recovery_case set state=case when valid_until<=clock_timestamp() then 'EXPIRED' else 'REVOKED' end,
      row_version=row_version+1,updated_at=clock_timestamp()
     where participant_id=$1 and enrollment_id=$2 and recovery_id=$3 and row_version=$4 and state in ('DRAFT','REQUESTED','ACTIVE')
     returning state,row_version::text as revision,updated_at as now`,
    [actor.participantId, enrollment.enrollmentId, recoveryId, revision],
  );
  const row = closed.rows[0];
  if (closed.rowCount !== 1 || !row) throw new PlatformRecoveryError();
  const now = new Date(row.now);
  const commit = (purpose: string, value: unknown) =>
    canonicalAuthorizationDigestBytes({
      domain: `pc.identity.platform-recovery.${purpose}.v1`,
      value,
    });
  const result = {
    recoveryId,
    enrollmentId: enrollment.enrollmentId,
    operationId,
    state: row.state,
    revision: row.revision,
    authority: 'NONE',
    actorPrincipalId: actor.principalId,
    closedAt: now.toISOString(),
  };
  const payload = encodeIdentityAuthContextAssertionPayload({
    assertionId: operationId,
    actorKind: 0,
    actorKeyDigest: identityActorKeyDigest(actor.participantId, actor.principalId),
    participantContextDigest: commit('context', [
      enrollment.participantId,
      enrollment.privacyDomainId,
      enrollment.platformContextId,
      enrollment.rootEpoch,
      enrollment.rootDigest,
    ]),
    audienceDigest: commit('closure', result),
    senderBindingKind: 1,
    senderCredentialBindingDigest: commit('closure-session', session),
    assuranceProfileDigest: commit('assurance', [
      enrollment.assurance,
      'authenticated-enrolled-actor-closure',
      'no-authority',
    ]),
    authorityVectorDigest: commit('closure-source', [enrollment, recoveryId, revision]),
    authenticationEvidenceDigest: commit('closure-actor', [actor.principalId, session]),
    issuedAtNs: BigInt(now.getTime()) * 1000000n,
    expiresAtNs: BigInt(now.getTime() + 60000) * 1000000n,
  });
  const signed = await signer.signCanonicalAssertion(payload);
  if (
    !signed.evidenceCbor.equals(payload) ||
    !signed.evidenceDigest.equals(createHash('sha256').update(payload).digest()) ||
    !(await signer.verifyCanonicalAssertion(payload, signed.coseSign1))
  )
    throw new PlatformRecoveryError();
  const head = await client.query<{ sequence: string }>(
    `insert into control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence)
     values($1,'platform-recovery',$2,1) on conflict(participant_id,aggregate_type,aggregate_id)
     do update set last_sequence=control.outbox_aggregate_head.last_sequence+1,updated_at=clock_timestamp()
     returning last_sequence::text as sequence`,
    [actor.participantId, recoveryId],
  );
  if (head.rowCount !== 1) throw new PlatformRecoveryError();
  await client.query(
    `insert into control.outbox_event(participant_id,privacy_domain_id,aggregate_type,aggregate_id,aggregate_sequence,event_id,event_type,payload_cbor,payload_digest,cose_sign1,occurred_at)
     values($1,$2,'platform-recovery',$3,$4,$5,'openpc.identity.platform-recovery.closed.v1',$6,$7,$8,$9)`,
    [
      actor.participantId,
      enrollment.privacyDomainId,
      recoveryId,
      head.rows[0]!.sequence,
      localOperationId(),
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      now,
    ],
  );
}
