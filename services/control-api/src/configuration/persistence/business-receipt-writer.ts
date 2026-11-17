import { stepUpReceiptInput } from '../../../../identity-service/src/db/step-up-receipt-inputs.js';
import { governedReceiptInputs } from '../../../../identity-service/src/db/governed-receipt-inputs.js';
import { createHash, randomBytes } from 'node:crypto';
import {
  businessSigningTrustDigest,
  configurationRequestDigest,
  decodeIdentityAuthContextAssertionPayload,
  encodeCommandCommitted,
  commandCommittedEventType,
  commandCommittedDataSchema,
  type BusinessTransitionProfile,
  type BusinessTransitionReceipt,
  type BusinessSigningTrust,
} from '@openpc/security-kernel';
import type { PoolClient } from 'pg';
import { persistBusinessReceipt } from '../../../../identity-service/src/db/business-receipt-store.js';
import {
  receiptSigningAttemptId,
  reserveReceiptSigningAttempt,
} from '../../../../identity-service/src/db/receipt-signing-attempt-store.js';
import {
  signBusinessReceipt,
  type BusinessReceiptSigningCapability,
} from '../../../../identity-service/src/domain/business-receipt-signer.js';
import type { RetainedAuthoritySnapshot } from '../../../../identity-service/src/db/authority-snapshot.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
  type MutationBusinessState,
} from './types.js';

export interface ConfigurationBusinessEvidence {
  readonly environmentId: string;
  readonly signer: BusinessReceiptSigningCapability;
}
export interface PreparedBusinessReceipt {
  readonly profile: BusinessTransitionProfile;
  readonly trust: BusinessSigningTrust;
  readonly authoritySnapshot: RetainedAuthoritySnapshot;
  readonly signer: BusinessReceiptSigningCapability;
}
function uuidv7(): string {
  const bytes = randomBytes(16);
  bytes.writeUIntBE(Date.now(), 0, 6);
  bytes[6] = (bytes[6]! & 15) | 0x70;
  bytes[8] = (bytes[8]! & 63) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Same existing transaction as the domain effect, authority input and idempotency reservation. */
export async function appendBusinessReceipt(
  client: PoolClient,
  context: MutationContext,
  operationId: string,
  candidateDigest: Buffer,
  evidenceId: string,
  state: MutationBusinessState,
  prepared: PreparedBusinessReceipt,
): Promise<void> {
  const { profile, trust, authoritySnapshot, signer } = prepared;
  const scope = [context.authorization.participantId, context.authorization.privacyDomainId];
  const sequence = await client.query<{ sequence: string }>(
    `insert into control.business_outbox_head
  (participant_id,privacy_domain_id,sequence_namespace,aggregate_type,aggregate_id,last_sequence)
  values($1,$2,'CONTROL_BUSINESS_TRANSITION_V1',$3,$4,1)
  on conflict(participant_id,privacy_domain_id,sequence_namespace,aggregate_type,aggregate_id)
  do update set last_sequence=control.business_outbox_head.last_sequence+1,updated_at=clock_timestamp()
  returning last_sequence::text as sequence`,
    [...scope, profile.aggregateType, context.resourceId],
  );
  const metadata = await client.query<{
    idempotencyRecordId: string;
    recordedAt: string;
    recordedAtNs: string;
  }>(
    `with instant as materialized(select clock_timestamp() at)
   select i.idempotency_record_id as "idempotencyRecordId",instant.at::text as "recordedAt",
    (floor(extract(epoch from instant.at)*1000000)*1000)::text as "recordedAtNs"
   from control.idempotency_record i cross join instant where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
    [...scope, operationId],
  );
  if (
    sequence.rowCount !== 1 ||
    metadata.rowCount !== 1 ||
    sequence.rows[0] === undefined ||
    metadata.rows[0] === undefined
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const { idempotencyRecordId, recordedAtNs } = metadata.rows[0];
  const eventId = uuidv7();
  const aggregateRef = `urn:openpc:${profile.aggregateType}:${context.resourceId}`;
  const payload = encodeCommandCommitted({
    commandId: operationId,
    aggregateRef,
    actionIntentId: context.actionIntentId,
    intentDigest: context.actionIntentDigest,
  });
  const payloadDigest = createHash('sha256').update(payload).digest();
  const receiptInputs =
    context.authorization.evidenceKind === 'IDENTITY_RUNTIME' ||
    context.authorization.evidenceKind === 'IDENTITY_RUNTIME_STEP_UP'
      ? {
          actorKeyDigest: decodeIdentityAuthContextAssertionPayload(
            context.authorization.evidenceCbor,
          ).actorKeyDigest,
          authorizationEvidence: [
            { kind: 2 as const, evidenceId, evidenceDigest: context.authorization.evidenceDigest },
            ...(context.authorization.evidenceKind === 'IDENTITY_RUNTIME_STEP_UP'
              ? [await stepUpReceiptInput(client, context, operationId)]
              : []),
          ],
        }
      : await governedReceiptInputs(client, context, operationId);
  const unsignedReceipt: BusinessTransitionReceipt = {
    receiptId: operationId,
    schemaDefinitionDigest: Buffer.from(profile.schemaDefinitionDigest.slice(7), 'hex'),
    transitionProfileId: profile.profileId,
    transitionProfileVersion: profile.profileVersion,
    transitionProfileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
    environmentId: trust.environmentId,
    participantId: scope[0]!,
    privacyDomainId: scope[1]!,
    operationId,
    actionIntentId: context.actionIntentId,
    catalogOperationId: context.catalogOperationId,
    aggregateType: profile.aggregateType,
    aggregateId: context.resourceId,
    actorKeyDigest: receiptInputs.actorKeyDigest,
    preCommitAuthorityDigest: authoritySnapshot.digest,
    actionIntentDigest: Buffer.from(context.actionIntentDigest.slice(7), 'hex'),
    candidateDigest,
    idempotencyRecordId,
    before: state.before.reference,
    after: state.after.reference,
    authorizationEvidence: receiptInputs.authorizationEvidence,
    outboxEvents: [
      {
        eventId,
        eventType: commandCommittedEventType,
        dataSchemaUri: commandCommittedDataSchema,
        source: 'urn:openpc:service:control-api',
        subject: aggregateRef,
        aggregateSequence: BigInt(sequence.rows[0].sequence),
        occurredAtNs: BigInt(recordedAtNs),
        correlationId: operationId,
        payloadDigest,
      },
    ],
    transitionKind: profile.transitionKind,
    recordedAtNs: BigInt(recordedAtNs),
    signerId: trust.signerId,
    signerTrustSnapshotDigest: businessSigningTrustDigest(trust),
    requestDigest: configurationRequestDigest({
      participantId: scope[0]!,
      privacyDomainId: scope[1]!,
      principalId: context.authorization.principalId,
      actionIntentId: context.actionIntentId,
      catalogOperationId: context.catalogOperationId,
      aggregateType: profile.aggregateType,
      aggregateId: context.resourceId,
      expectedRevision: context.expectedRevision,
      candidateDigest,
      idempotencyKey: context.idempotencyKey,
    }),
  };
  const receipt = { ...unsignedReceipt, receiptId: receiptSigningAttemptId(unsignedReceipt) };
  await reserveReceiptSigningAttempt(client, receipt, trust, 'ORDINARY_ATOMIC');
  const signed = await signBusinessReceipt(receipt, trust, signer);
  await persistBusinessReceipt(client, {
    receipt,
    payload: signed.payload,
    coseSign1: signed.coseSign1,
    beforeStatePreimage: state.before.preimage,
    afterStatePreimage: state.after.preimage,
    authoritySnapshot: authoritySnapshot.bytes,
    eventPayloads: new Map([[eventId, payload]]),
  });
}
