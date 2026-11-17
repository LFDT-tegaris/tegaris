import { platformRecoveryPendingExpiryEffectPolicy } from './platform-recovery-source.js';
import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  numeric,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { identityEnvelopeProposals } from './identity-envelope-proposal.js';
import { approvalRequests, idempotencyRecords, mutationCandidates } from './workflow.js';

const u64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });

/** One initial activation business intent, independent of the request-cache
 * expiry. PREPARED has never dispatched; every DISPATCHED continuation may only
 * look up its original attempt. A retained observation is not publication. */
export const identityEnvelopeActivations = control
  .table(
    'identity_envelope_activation',
    {
      operationId: uuid('operation_id').primaryKey(),
      attemptId: uuid('attempt_id').notNull().unique(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      envelopeId: uuid('envelope_id').notNull(),
      expectedApprovedVersion: u64('expected_approved_version').notNull(),
      principalId: uuid('principal_id').notNull(),
      idempotencyKey: text('idempotency_key').notNull(),
      idempotencyRecordId: uuid('idempotency_record_id').notNull().unique(),
      candidateId: uuid('candidate_id').notNull().unique(),
      candidateDigest: bytea('candidate_digest').notNull(),
      approvalRequestId: uuid('approval_request_id').notNull().unique(),
      makerChallengeId: uuid('maker_challenge_id').notNull().unique(),
      proposalDigest: bytea('proposal_digest').notNull(),
      makerAuthority: jsonb('maker_authority').notNull(),
      checkerAuthority: jsonb('checker_authority').notNull(),
      payloadCbor: bytea('payload_cbor').notNull(),
      payloadDigest: bytea('payload_digest').notNull(),
      request: jsonb('request').notNull(),
      requestDigest: bytea('request_digest').notNull(),
      reservedAtNs: u64('reserved_at_ns').notNull(),
      state: text('state').notNull().default('PREPARED'),
      observation: jsonb('observation'),
      coseSign1: bytea('cose_sign1'),
      dispatchedAt: time('dispatched_at'),
      observedAt: time('observed_at'),
      committedAt: time('committed_at'),
      rowVersion: u64('row_version')
        .notNull()
        .default(sql`1`),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('identity_envelope_activation_subject_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.envelopeId,
        t.expectedApprovedVersion,
      ),
      unique('identity_envelope_activation_intent_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.principalId,
        t.idempotencyKey,
      ),
      foreignKey({
        name: 'identity_envelope_activation_proposal_fk',
        columns: [t.participantId, t.privacyDomainId, t.envelopeId],
        foreignColumns: [
          identityEnvelopeProposals.participantId,
          identityEnvelopeProposals.privacyDomainId,
          identityEnvelopeProposals.envelopeId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_activation_idempotency_fk',
        columns: [t.participantId, t.privacyDomainId, t.operationId, t.idempotencyRecordId],
        foreignColumns: [
          idempotencyRecords.participantId,
          idempotencyRecords.privacyDomainId,
          idempotencyRecords.operationId,
          idempotencyRecords.idempotencyRecordId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_activation_candidate_fk',
        columns: [t.participantId, t.candidateId],
        foreignColumns: [mutationCandidates.participantId, mutationCandidates.mutationCandidateId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_activation_approval_fk',
        columns: [t.participantId, t.approvalRequestId],
        foreignColumns: [approvalRequests.participantId, approvalRequests.approvalRequestId],
      }).onDelete('restrict'),
      check(
        'identity_envelope_activation_digest_ck',
        sql`octet_length(${t.candidateDigest})=32 and octet_length(${t.proposalDigest})=32
          and octet_length(${t.payloadDigest})=32 and ${t.payloadDigest}=sha256(${t.payloadCbor})
          and octet_length(${t.payloadCbor}) between 1 and 65536
          and octet_length(${t.requestDigest})=32 and jsonb_typeof(${t.request})='object'
          and jsonb_typeof(${t.makerAuthority})='object' and jsonb_typeof(${t.checkerAuthority})='object'`,
      ),
      check(
        'identity_envelope_activation_initial_ck',
        sql`${t.expectedApprovedVersion}=3 and length(${t.idempotencyKey}) between 1 and 256
          and ${t.reservedAtNs}>0 and ${t.reservedAtNs}<=18446744073709551615
          and mod(${t.reservedAtNs},1000)=0`,
      ),
      check(
        'identity_envelope_activation_request_ck',
        sql`(${t.request}->>'participantId') is not distinct from ${t.participantId}::text
          and (${t.request}->>'privacyDomainId') is not distinct from ${t.privacyDomainId}::text
          and (${t.request}->>'operationId') is not distinct from ${t.operationId}::text
          and (${t.request}->>'attemptId') is not distinct from ${t.attemptId}::text
          and (${t.request}->>'payloadHex') is not distinct from encode(${t.payloadCbor},'hex')
          and (${t.request}->>'method') is not distinct from 'SIGN_AUTHORITY_ENVELOPE'`,
      ),
      check(
        'identity_envelope_activation_phase_ck',
        sql`(${t.state}='PREPARED' and ${t.rowVersion}=1 and ${t.dispatchedAt} is null
            and ${t.observation} is null and ${t.coseSign1} is null and ${t.observedAt} is null and ${t.committedAt} is null)
          or (${t.state}='DISPATCHED' and ${t.rowVersion}=2 and ${t.dispatchedAt} is not null
            and ${t.observation} is null and ${t.coseSign1} is null and ${t.observedAt} is null and ${t.committedAt} is null)
          or (${t.state} in ('OBSERVED','COMMITTED')
            and ${t.rowVersion}=case when ${t.state}='OBSERVED' then 3 else 4 end
            and ${t.dispatchedAt} is not null and ${t.observedAt} is not null
            and ${t.observation} is not null and jsonb_typeof(${t.observation})='object'
            and ${t.coseSign1} is not null and octet_length(${t.coseSign1}) between 1 and 66560
            and (${t.state}='COMMITTED')=(${t.committedAt} is not null))`,
      ),
      platformRecoveryPendingExpiryEffectPolicy(
        t.participantId,
        t.privacyDomainId,
        sql`(source.document#>>'{source,pendingExpiry,schemaVersion}'='2' or source.document#>>'{source,activatedHandoff,schemaVersion}'='1')
          and ${t.envelopeId}::text=partial_effect->>'envelopeId'`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
