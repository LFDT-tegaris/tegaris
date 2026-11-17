import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceTimestamp as time,
  evidenceBytes as bytes,
} from './schema.js';

export const protectedProofObjects = control
  .table(
    'protected_proof_object',
    {
      objectId: uuid('object_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      source: jsonb('source').notNull(),
      objectVersion: ordinal('object_version').notNull().default('1'),
      objectDigest: text('object_digest').notNull(),
      purpose: text('purpose').notNull(),
      caseReference: text('case_reference').notNull(),
      retainUntil: time('retain_until').notNull(),
      approvalRequestId: uuid('approval_request_id').notNull(),
      creationOperationId: uuid('creation_operation_id').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('protected_proof_object_scope_uq').on(t.participantId, t.privacyDomainId, t.objectId),
      unique('protected_proof_object_version_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.objectId,
        t.objectVersion,
        t.objectDigest,
      ),
      unique('protected_proof_object_operation_uq').on(t.creationOperationId),
      check(
        'protected_proof_object_version_ck',
        sql`${t.objectVersion}=1 and ${t.objectDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'protected_proof_object_purpose_ck',
        sql`length(${t.purpose}) between 1 and 256 and length(${t.caseReference}) between 1 and 256 and ${t.retainUntil}>${t.createdAt}`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Ciphertext is not part of any catalogue, review document or operation response. */
export const protectedProofPayloads = control
  .table(
    'protected_proof_payload',
    {
      objectId: uuid('object_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      keyId: text('key_id').notNull(),
      nonce: bytes('nonce').notNull(),
      ciphertext: bytes('ciphertext').notNull(),
    },
    (t) => [
      foreignKey({
        name: 'protected_proof_payload_object_fk',
        columns: [t.participantId, t.privacyDomainId, t.objectId],
        foreignColumns: [
          protectedProofObjects.participantId,
          protectedProofObjects.privacyDomainId,
          protectedProofObjects.objectId,
        ],
      }).onDelete('restrict'),
      check(
        'protected_proof_payload_shape_ck',
        sql`length(${t.keyId}) between 1 and 128 and octet_length(${t.nonce})=12 and octet_length(${t.ciphertext}) between 17 and 65552`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

export const protectedProofAccess = control
  .table(
    'protected_proof_access',
    {
      accessId: uuid('access_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      objectId: uuid('object_id').notNull(),
      objectBinding: jsonb('object_binding').notNull(),
      purpose: text('purpose').notNull(),
      caseReference: text('case_reference').notNull(),
      recipientPrincipalId: uuid('recipient_principal_id').notNull(),
      senderSessionId: uuid('sender_session_id').notNull(),
      expiresAt: time('expires_at').notNull(),
      approvalRequestId: uuid('approval_request_id').notNull(),
      creationOperationId: uuid('creation_operation_id').notNull(),
      consumptionOperationId: uuid('consumption_operation_id'),
      consumedAt: time('consumed_at'),
      consumptionRequest: jsonb('consumption_request'),
      revision: ordinal('revision').notNull().default('1'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('protected_proof_access_scope_uq').on(t.participantId, t.privacyDomainId, t.accessId),
      unique('protected_proof_access_creation_uq').on(t.creationOperationId),
      unique('protected_proof_access_consumption_uq').on(t.consumptionOperationId),
      foreignKey({
        name: 'protected_proof_access_object_fk',
        columns: [t.participantId, t.privacyDomainId, t.objectId],
        foreignColumns: [
          protectedProofObjects.participantId,
          protectedProofObjects.privacyDomainId,
          protectedProofObjects.objectId,
        ],
      }).onDelete('restrict'),
      check(
        'protected_proof_access_state_ck',
        sql`(${t.revision}=1 and ${t.consumedAt} is null and ${t.consumptionOperationId} is null and ${t.consumptionRequest} is null)
    or (${t.revision}=2 and ${t.consumedAt} is not null and ${t.consumptionOperationId} is not null and ${t.consumptionRequest} is not null)`,
      ),
      check(
        'protected_proof_access_expiry_ck',
        sql`${t.expiresAt}>${t.createdAt} and ${t.expiresAt}<=${t.createdAt}+interval '5 minutes'`,
      ),
      check(
        'protected_proof_access_purpose_ck',
        sql`length(${t.purpose}) between 1 and 256 and length(${t.caseReference}) between 1 and 256`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
