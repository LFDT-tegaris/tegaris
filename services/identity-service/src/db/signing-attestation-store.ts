import { signingTransitionEffects } from '../../../../packages/security-kernel/src/signing-transitions.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  businessSigningTrustDigest,
  businessTransitionProfileForOperation,
  configurationRequestDigest,
  decodeIdentityAuthContextAssertionPayload,
  encodeAdmittedReceipt,
  type BusinessTransitionReceipt,
} from '@openpc/security-kernel';
import {
  encodeCbor,
  type CborValue,
} from '../../../../packages/security-kernel/src/business-transition/cbor.js';
import { uuidBytes } from '../../../../packages/security-kernel/src/business-transition/payload.js';
import { localOperationId } from '../domain/local-operation-id.js';
import {
  signingRotationStatePreimage,
  validateSigningRotationReceipt,
} from '../domain/signing-rotation-receipt.js';
import { SigningRotationError, type SigningRotationState } from '../domain/signing-rotation.js';
import {
  businessProviderRequestDigest,
  businessSigningPurpose,
  type BusinessProviderRequest,
} from '../domain/business-signing-provider.js';
import { discoverBusinessSigningKey, fenceBusinessSigningKey } from './business-signing-store.js';
import {
  receiptSigningAttemptId,
  reserveReceiptSigningAttempt,
} from './receipt-signing-attempt-store.js';
import type { RotationRow, SigningRotationPartition } from './signing-rotation-store.js';
import type { RotationCommand } from './signing-rotation-command.js';
import type { VerifiedSigningContinuation } from '../domain/signing-continuation.js';
import type { RetainedAuthoritySnapshot } from './authority-snapshot.js';

const hash = (bytes: Buffer) => createHash('sha256').update(bytes).digest();

/** Reserve exact lifecycle receipt bytes under the rotation/authority/key locks; the caller commits before dispatch. */
export async function reserveSigningRotationAttestation(
  client: PoolClient,
  scope: SigningRotationPartition,
  row: RotationRow,
  command: RotationCommand,
  input: {
    readonly targetState: SigningRotationState;
    readonly newSignerId: string | null;
    readonly authoritySnapshot: RetainedAuthoritySnapshot;
    readonly callerWorkloadCredentialId: string;
    readonly continuation?: VerifiedSigningContinuation;
  },
): Promise<BusinessProviderRequest> {
  const effects = signingTransitionEffects(command.actionIntentId, row.state, input.targetState);
  if (!effects || (effects.resumeFrom !== null && effects.resumeFrom !== row.recoveryFromState))
    throw new SigningRotationError('CONFLICT');
  const catalogOperationId =
    command.actionIntentId === 'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1'
      ? 'OPS-OP-RECOVER-SIGNING-KEY-ROTATION'
      : 'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION';
  const profile = businessTransitionProfileForOperation(catalogOperationId);
  if (
    !profile ||
    profile.actionIntentId !== command.actionIntentId ||
    command.rotationId !== row.rotationId
  )
    throw new SigningRotationError('CONFLICT');
  const signingScope = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    environmentId: row.request.environmentId,
    profileId: profile.profileId,
    profileVersion: profile.profileVersion,
    profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
    actionIntentId: profile.actionIntentId,
    catalogOperationId,
  };
  // The lifecycle fence already holds both role selections and their workload authority.
  const discovery = await discoverBusinessSigningKey(client, signingScope);
  const { trust, nowNs } = await fenceBusinessSigningKey(client, signingScope, discovery);
  if (trust.workloadCredentialId !== input.callerWorkloadCredentialId)
    throw new SigningRotationError('DENIED');
  const metadata = await client.query<{
    idempotencyRecordId: string;
    evidenceId: string;
    evidenceCbor: Buffer;
    evidenceDigest: Buffer;
    priorHistoryDigest: Buffer;
    receiptOrdinal: string;
    eventSequence: string;
    attester: string;
    selectionVersion: string;
    slot: string;
  }>(
    `select i.idempotency_record_id::text as "idempotencyRecordId",e.mutation_evidence_id::text as "evidenceId",
    e.evidence_cbor as "evidenceCbor",e.evidence_digest as "evidenceDigest",h.history_digest as "priorHistoryDigest",
    (1+coalesce((select max(receipt_ordinal) from control.signing_rotation_history where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3),0))::text as "receiptOrdinal",
    (1+coalesce((select last_sequence from control.business_outbox_head where participant_id=$1 and privacy_domain_id=$2
     and aggregate_type='signing-key-rotation' and aggregate_id=$3 and sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1'),0))::text as "eventSequence",
    jsonb_build_object('signerId',k.signer_id,'keyEpoch',k.key_epoch,'trustDigest',encode(k.trust_digest,'hex'),
      'selectionVersion',s.row_version,'admissionVersion',s.admission_version,'fenceGeneration',s.fence_generation)::text as attester,s.row_version::text as "selectionVersion",
    'receipt-'||(select count(*) from control.signing_rotation_attestation where participant_id=$1 and privacy_domain_id=$2 and operation_id=$4)::text as slot
    from control.signing_rotation_command c join control.idempotency_record i using(participant_id,privacy_domain_id,operation_id)
    join control.mutation_evidence e on e.mutation_evidence_id=c.authorization_evidence_id
    join control.signing_rotation_history h on h.participant_id=c.participant_id and h.privacy_domain_id=c.privacy_domain_id and h.rotation_id=c.rotation_id and h.revision=$5
    join control.business_signing_selection s on s.participant_id=c.participant_id and s.privacy_domain_id=c.privacy_domain_id and s.environment_id=$6 and s.profile_digest=$7
    join control.business_signing_key k on k.participant_id=s.participant_id and k.privacy_domain_id=s.privacy_domain_id and k.signer_id=s.signer_id
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.rotation_id=$3 and c.operation_id=$4 and i.terminal_state is null
    and not exists(select 1 from control.signing_rotation_attestation a join control.signing_provider_attempt p using(attempt_id)
     where a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id and a.operation_id=c.operation_id and p.state NOT IN ('REJECTED','SUPERSEDED'))`,
    [
      scope.participantId,
      scope.privacyDomainId,
      row.rotationId,
      command.operationId,
      row.revision,
      row.request.environmentId,
      signingScope.profileDigest,
    ],
  );
  const m = metadata.rows[0];
  if (metadata.rowCount !== 1 || !m) throw new SigningRotationError('CONFLICT');
  const terminalEvent = effects.eventType;
  const eventId = terminalEvent === null ? null : localOperationId();
  const evidenceRecordId = localOperationId();
  const eventPayload =
    terminalEvent === null
      ? null
      : encodeCbor(
          new Map<number, CborValue>([
            [0, uuidBytes(row.rotationId)],
            [1, row.request.signerRole],
            [2, Buffer.from(row.request.oldFingerprint.slice(7), 'hex')],
            [3, Buffer.from((input.newSignerId ?? '').slice(7), 'hex')],
          ]),
        );
  if (terminalEvent && !input.newSignerId) throw new SigningRotationError('CONFLICT');
  const performsCutover = effects.cutover;
  const cutoverAtNs = performsCutover ? nowNs.toString() : row.cutoverAtNs;
  let recoveryFromState = ['RECOVERY', 'FORWARD_RECOVERY'].includes(effects.kind)
    ? (row.recoveryFromState ?? row.state)
    : row.recoveryFromState;
  let recoveryFromRevision = ['RECOVERY', 'FORWARD_RECOVERY'].includes(effects.kind)
    ? (row.recoveryFromRevision ?? row.revision)
    : row.recoveryFromRevision;
  if (effects.kind === 'ADVANCE' || effects.kind === 'FAILURE') {
    recoveryFromState = null;
    recoveryFromRevision = null;
  }
  if (
    command.authorizationGenerationId !== null &&
    command.actionIntentId === 'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' &&
    input.targetState === 'RECOVERING'
  ) {
    const plan = await client.query<{ resumeState: SigningRotationState; resumeRevision: string }>(
      `select resume_state as "resumeState",resume_revision::text as "resumeRevision" from control.signing_authorization_generation
       where generation_id=$1 and state='STAGED' and resume_state is not null and resume_revision is not null`,
      [command.authorizationGenerationId],
    );
    if (plan.rowCount !== 1) throw new SigningRotationError('CONFLICT');
    recoveryFromState = plan.rows[0]!.resumeState;
    recoveryFromRevision = plan.rows[0]!.resumeRevision;
  }
  const projected = await client.query<{ historyPreimage: Buffer }>(
    `select openpc.rotation_history_preimage(jsonb_populate_record(r,jsonb_build_object('state',$6::text,'revision',r.revision+1,
      'new_signer_id',$7::text,'cutover_at_ns',$8::numeric,'recovery_from_state',$9::text,'recovery_from_revision',$10::bigint)),
      r.state,$4,$11,null,$12,$13::jsonb,$14::numeric) as "historyPreimage"
     from control.signing_key_rotation r where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 and revision=$5`,
    [
      scope.participantId,
      scope.privacyDomainId,
      row.rotationId,
      command.operationId,
      row.revision,
      input.targetState,
      input.newSignerId,
      cutoverAtNs,
      recoveryFromState,
      recoveryFromRevision,
      eventId,
      evidenceRecordId,
      m.attester,
      m.receiptOrdinal,
    ],
  );
  const historyPreimage = projected.rows[0]?.historyPreimage;
  if (projected.rowCount !== 1 || !historyPreimage) throw new SigningRotationError('CONFLICT');
  const historyDigest = hash(historyPreimage);
  const identity = {
    transitionProfileDigest: signingScope.profileDigest,
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    aggregateId: row.rotationId,
  };
  const state = (state: SigningRotationState, digest: Buffer, fingerprint: string | null) => ({
    state,
    historyDigest: digest,
    candidateDigest: row.candidateDigest,
    signerRole: row.request.signerRole,
    oldFingerprint: Buffer.from(row.request.oldFingerprint.slice(7), 'hex'),
    ...(fingerprint === null ? {} : { newFingerprint: Buffer.from(fingerprint.slice(7), 'hex') }),
  });
  const beforeStatePreimage = signingRotationStatePreimage(
    identity,
    BigInt(row.revision),
    state(row.state, m.priorHistoryDigest, row.newSignerId),
  );
  const afterStatePreimage = signingRotationStatePreimage(
    identity,
    BigInt(row.revision) + 1n,
    state(input.targetState, historyDigest, input.newSignerId),
  );
  const unsigned: BusinessTransitionReceipt = {
    ...identity,
    receiptId: command.operationId,
    schemaDefinitionDigest: Buffer.from(profile.schemaDefinitionDigest.slice(7), 'hex'),
    transitionProfileId: profile.profileId,
    transitionProfileVersion: profile.profileVersion,
    environmentId: row.request.environmentId,
    operationId: command.operationId,
    actionIntentId: command.actionIntentId,
    catalogOperationId,
    aggregateType: 'signing-key-rotation',
    actorKeyDigest: decodeIdentityAuthContextAssertionPayload(m.evidenceCbor).actorKeyDigest,
    preCommitAuthorityDigest: input.authoritySnapshot.digest,
    actionIntentDigest: command.actionIntentDigest,
    candidateDigest: command.inputDigest,
    idempotencyRecordId: m.idempotencyRecordId,
    before: {
      existence: 1,
      revision: BigInt(row.revision),
      stateDigest: hash(beforeStatePreimage),
    },
    after: {
      existence: 1,
      revision: BigInt(row.revision) + 1n,
      stateDigest: hash(afterStatePreimage),
    },
    authorizationEvidence: [
      { kind: 2 as const, evidenceId: m.evidenceId, evidenceDigest: m.evidenceDigest },
      ...(input.continuation
        ? [
            {
              kind: 2 as const,
              evidenceId: input.continuation.assertionId,
              evidenceDigest: input.continuation.assertionDigest,
            },
          ]
        : []),
    ].sort((left, right) =>
      Buffer.compare(Buffer.from(left.evidenceId), Buffer.from(right.evidenceId)),
    ),
    outboxEvents:
      eventId && eventPayload && terminalEvent
        ? [
            {
              eventId,
              eventType: terminalEvent,
              dataSchemaUri: `https://schemas.openpc.local/event-payloads.schema.json#/$defs/${terminalEvent === 'io.openpc.ops.secret.revoked.v1' ? 'SecretRevoked' : 'SecretRotated'}`,
              source: 'urn:openpc:service:control-api',
              subject: `urn:openpc:signing-key-rotation:${row.rotationId}`,
              aggregateSequence: BigInt(m.eventSequence),
              occurredAtNs: nowNs,
              correlationId: command.operationId,
              payloadDigest: hash(eventPayload),
            },
          ]
        : [],
    transitionKind: profile.transitionKind,
    recordedAtNs: nowNs,
    signerId: trust.signerId,
    signerTrustSnapshotDigest: businessSigningTrustDigest(trust),
    requestDigest: configurationRequestDigest({
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      principalId: command.principalId,
      actionIntentId: command.actionIntentId,
      catalogOperationId,
      aggregateType: 'signing-key-rotation',
      aggregateId: row.rotationId,
      expectedRevision: command.fromRevision,
      candidateDigest: command.inputDigest,
      idempotencyKey: command.idempotencyKey,
    }),
  };
  const receipt = { ...unsigned, receiptId: receiptSigningAttemptId(unsigned) };
  validateSigningRotationReceipt(receipt, beforeStatePreimage, afterStatePreimage);
  const payload = encodeAdmittedReceipt(receipt);
  await reserveReceiptSigningAttempt(client, receipt, trust, 'LIFECYCLE_DURABLE');
  const request: BusinessProviderRequest = {
    method: 'SIGN_RECEIPT',
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    workloadCredentialId: trust.workloadCredentialId,
    callerWorkloadCredentialId: input.callerWorkloadCredentialId,
    environmentId: trust.environmentId,
    secretClass: trust.secretClass,
    purpose: businessSigningPurpose,
    reference: trust.secretReference,
    version: trust.secretVersion,
    expectedFingerprint: trust.signerId,
    attemptId: receipt.receiptId,
    operationId: command.operationId,
    payloadHex: payload.toString('hex'),
  };
  await client.query(
    `insert into control.signing_provider_attempt(participant_id,privacy_domain_id,rotation_id,attempt_id,operation_id,
    from_revision,from_state,slot,to_state,request,request_digest,state) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'READY')`,
    [
      scope.participantId,
      scope.privacyDomainId,
      row.rotationId,
      receipt.receiptId,
      command.operationId,
      row.revision,
      row.state,
      m.slot,
      input.targetState,
      request,
      Buffer.from(businessProviderRequestDigest(request).slice(7), 'hex'),
    ],
  );
  await client.query(
    `insert into control.signing_rotation_attestation(participant_id,privacy_domain_id,rotation_id,operation_id,attempt_id,
    from_revision,to_state,receipt_ordinal,signer_id,selection_version,signer_trust_digest,history_preimage,history_digest,
    before_state_preimage,after_state_preimage,authority_snapshot,receipt_cbor,event_id,event_sequence,event_payload,evidence_record_id,continuation_assertion_id)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
    [
      scope.participantId,
      scope.privacyDomainId,
      row.rotationId,
      command.operationId,
      receipt.receiptId,
      row.revision,
      input.targetState,
      m.receiptOrdinal,
      trust.signerId,
      m.selectionVersion,
      businessSigningTrustDigest(trust),
      historyPreimage,
      historyDigest,
      beforeStatePreimage,
      afterStatePreimage,
      input.authoritySnapshot.bytes,
      payload,
      eventId,
      eventId ? m.eventSequence : null,
      eventPayload,
      evidenceRecordId,
      input.continuation?.assertionId ?? null,
    ],
  );
  if (performsCutover) {
    const fenced = await client.query(
      `update control.business_signing_selection set row_version=row_version+1,fence_generation=fence_generation+1,
      fenced_operation_id=$5,changed_at_ns=$6,change_reference=$7,change_digest=$8
      where participant_id=$1 and privacy_domain_id=$2 and environment_id=$3 and signer_id=$4 and fenced_operation_id is null`,
      [
        scope.participantId,
        scope.privacyDomainId,
        row.request.environmentId,
        row.request.oldFingerprint,
        command.operationId,
        nowNs.toString(),
        `urn:openpc:resource:${row.rotationId}`,
        historyDigest,
      ],
    );
    if (fenced.rowCount !== 2) throw new SigningRotationError('CONFLICT');
  }
  return request;
}
