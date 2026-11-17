import { sql } from 'drizzle-orm';
import { check, foreignKey, numeric, text, uuid } from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { signingRotationCommands, signingProviderAttempts } from './signing-rotation.js';
import { signingContinuations } from './signing-continuation.js';

/** Protected denial/result evidence for operations that provably made no lifecycle transition. */
export const signingOperationEvidence = control
  .table(
    'signing_rotation_operation_evidence',
    {
      operationId: uuid('operation_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      rotationId: uuid('rotation_id').notNull(),
      providerAttemptId: uuid('provider_attempt_id').notNull(),
      continuationAssertionId: uuid('continuation_assertion_id'),
      kind: text('kind')
        .$type<'AUTHORITY_CHANGED_BEFORE_DISPATCH' | 'NO_EFFECT_RETRYABLE'>()
        .notNull(),
      preimage: bytea('preimage').notNull(),
      digest: bytea('digest').notNull(),
      recordedAtNs: numeric('recorded_at_ns', {
        precision: 20,
        scale: 0,
        mode: 'bigint',
      }).notNull(),
    },
    (t) => [
      foreignKey({
        name: 'signing_operation_evidence_command_fk',
        columns: [t.operationId],
        foreignColumns: [signingRotationCommands.operationId],
      }),
      foreignKey({
        name: 'signing_operation_evidence_attempt_fk',
        columns: [t.providerAttemptId],
        foreignColumns: [signingProviderAttempts.attemptId],
      }),
      foreignKey({
        name: 'signing_operation_evidence_continuation_fk',
        columns: [t.continuationAssertionId],
        foreignColumns: [signingContinuations.assertionId],
      }),
      check(
        'signing_operation_evidence_kind_ck',
        sql`${t.kind} in ('AUTHORITY_CHANGED_BEFORE_DISPATCH','NO_EFFECT_RETRYABLE') and (${t.kind}='NO_EFFECT_RETRYABLE')=(${t.continuationAssertionId} is not null)`,
      ),
      check(
        'signing_operation_evidence_digest_ck',
        sql`octet_length(${t.preimage}) between 2 and 262144 and ${t.digest}=sha256(${t.preimage}) and octet_length(${t.digest})=32 and ${t.recordedAtNs}>0`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
