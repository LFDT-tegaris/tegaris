import { sql } from 'drizzle-orm';
import { bigint, check, foreignKey, text, uniqueIndex, uuid } from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { mutationCandidates } from './workflow.js';
import { signingKeyRotations } from './signing-rotation.js';

/** An approved replacement is effective only when its consuming operation commits a signed lifecycle revision. */
export const signingAuthorizationGenerations = control
  .table(
    'signing_authorization_generation',
    {
      generationId: uuid('generation_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      rotationId: uuid('rotation_id').notNull(),
      candidateId: uuid('candidate_id').notNull(),
      candidateDigest: bytea('candidate_digest').notNull(),
      inputDigest: bytea('input_digest').notNull(),
      originalOperationId: uuid('original_operation_id').notNull(),
      priorGenerationId: uuid('prior_generation_id'),
      holdId: uuid('hold_id'),
      actionIntentId: text('action_intent_id').notNull(),
      fromRevision: bigint('from_revision', { mode: 'bigint' }).notNull(),
      targetState: text('target_state').notNull(),
      resumeState: text('resume_state'),
      resumeRevision: bigint('resume_revision', { mode: 'bigint' }),
      state: text('state').$type<'STAGED' | 'CONSUMED'>().notNull(),
      consumedOperationId: uuid('consumed_operation_id'),
      resultRevision: bigint('result_revision', { mode: 'bigint' }),
    },
    (t) => [
      foreignKey({
        name: 'signing_generation_rotation_fk',
        columns: [t.participantId, t.privacyDomainId, t.rotationId],
        foreignColumns: [
          signingKeyRotations.participantId,
          signingKeyRotations.privacyDomainId,
          signingKeyRotations.rotationId,
        ],
      }),
      foreignKey({
        name: 'signing_generation_candidate_fk',
        columns: [t.candidateId],
        foreignColumns: [mutationCandidates.mutationCandidateId],
      }),
      uniqueIndex('signing_generation_candidate_uq').on(t.candidateId),
      uniqueIndex('signing_generation_commit_uq')
        .on(t.participantId, t.privacyDomainId, t.rotationId, t.resultRevision)
        .where(sql`${t.state}='CONSUMED'`),
      check(
        'signing_generation_digest_ck',
        sql`octet_length(${t.candidateDigest})=32 and octet_length(${t.inputDigest})=32`,
      ),
      check(
        'signing_generation_state_ck',
        sql`${t.state} in ('STAGED','CONSUMED') and (${t.state}='CONSUMED')=(${t.consumedOperationId} is not null and ${t.resultRevision} is not null) and ${t.fromRevision}>0`,
      ),
      check(
        'signing_generation_action_ck',
        sql`${t.actionIntentId} in ('ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1','ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1')`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
