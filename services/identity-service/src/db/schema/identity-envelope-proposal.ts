import { sql } from 'drizzle-orm';
import {
  platformRecoveryPendingExpiryEffectPolicy,
  platformRecoveryUneffectedEffectPolicy,
} from './platform-recovery-source.js';
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
import { authorityEnvelopes } from './authority.js';
import { participants, principals, privacyDomains } from './participants.js';
import { approvalRequests, mutationCandidates } from './workflow.js';

/** Issuer-owned governance history, distinct from the target's assignable
 * envelope. Neither issuer nor target obtains the other's row policy. */
export const identityEnvelopeProposals = control
  .table(
    'identity_envelope_proposal',
    {
      envelopeId: uuid('envelope_id').primaryKey(),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      targetParticipantId: uuid('target_participant_id').notNull(),
      makerPrincipalId: uuid('maker_principal_id').notNull(),
      proposalCbor: bytea('proposal_cbor').notNull(),
      proposalDigest: bytea('proposal_digest').notNull(),
      issuerAuthority: jsonb('issuer_authority').notNull(),
      createOperationId: uuid('create_operation_id').notNull().unique(),
      createCandidateId: uuid('create_candidate_id').notNull(),
      createApprovalId: uuid('create_approval_id').notNull(),
      state: text('state').notNull().default('DRAFT'),
      submissionOperationId: uuid('submission_operation_id').unique(),
      submissionIntentDigest: bytea('submission_intent_digest'),
      submissionApprovalId: uuid('submission_approval_id').unique(),
      submissionMaker: jsonb('submission_maker'),
      submissionChecker: jsonb('submission_checker'),
      submissionCheckerAuthority: jsonb('submission_checker_authority'),
      rowVersion: numeric('row_version', { precision: 20, scale: 0, mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      createdAt: timestamp('created_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('identity_envelope_proposal_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.envelopeId,
      ),
      unique('identity_envelope_proposal_digest_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.proposalDigest,
      ),
      foreignKey({
        name: 'identity_envelope_proposal_target_fk',
        columns: [t.targetParticipantId, t.participantId, t.privacyDomainId, t.envelopeId],
        foreignColumns: [
          authorityEnvelopes.participantId,
          authorityEnvelopes.issuerParticipantId,
          authorityEnvelopes.issuerPrivacyDomainId,
          authorityEnvelopes.authorityEnvelopeId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_proposal_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_proposal_maker_fk',
        columns: [t.participantId, t.makerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_proposal_candidate_fk',
        columns: [t.participantId, t.createCandidateId],
        foreignColumns: [mutationCandidates.participantId, mutationCandidates.mutationCandidateId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_proposal_create_approval_fk',
        columns: [t.participantId, t.createApprovalId],
        foreignColumns: [approvalRequests.participantId, approvalRequests.approvalRequestId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_proposal_submission_approval_fk',
        columns: [t.participantId, t.submissionApprovalId],
        foreignColumns: [approvalRequests.participantId, approvalRequests.approvalRequestId],
      }).onDelete('restrict'),
      check(
        'identity_envelope_proposal_bytes_ck',
        sql`octet_length(${t.proposalCbor}) between 1 and 65536 and octet_length(${t.proposalDigest})=32 and ${t.proposalDigest}=sha256(${t.proposalCbor})`,
      ),
      check(
        'identity_envelope_proposal_state_ck',
        sql`
    (${t.state}='DRAFT' and ${t.rowVersion}=1 and ${t.submissionOperationId} is null and ${t.submissionIntentDigest} is null and ${t.submissionApprovalId} is null and ${t.submissionMaker} is null and ${t.submissionChecker} is null and ${t.submissionCheckerAuthority} is null)
    or (${t.state} in ('SUBMITTED','APPROVED') and ${t.rowVersion}=case when ${t.state}='SUBMITTED' then 2 else 3 end
      and ${t.submissionOperationId} is not null and ${t.submissionIntentDigest} is not null and octet_length(${t.submissionIntentDigest})=32
      and ${t.submissionApprovalId} is not null and ${t.submissionMaker} is not null
      and (${t.state}='APPROVED')=(${t.submissionChecker} is not null)
      and (${t.state}='APPROVED')=(${t.submissionCheckerAuthority} is not null))`,
      ),
      participantIsolationPolicy(t.participantId),
      platformRecoveryUneffectedEffectPolicy(
        t.participantId,
        t.privacyDomainId,
        sql`${t.envelopeId}::text=uneffected_administrator->>'envelopeId'`,
        sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        'identity_envelope_proposal',
      ),
      platformRecoveryPendingExpiryEffectPolicy(
        t.participantId,
        t.privacyDomainId,
        sql`${t.envelopeId}::text=partial_effect->>'envelopeId'`,
      ),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
