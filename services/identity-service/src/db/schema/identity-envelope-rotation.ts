import { sql } from 'drizzle-orm';
import {
  check,
  type AnyPgColumn,
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
import { signingKeyRotations } from './signing-rotation.js';
import { platformRecoveryCases } from './platform-recovery.js';
import { identityEnvelopeActivations } from './identity-envelope-activation.js';
import type { SigningRotationState } from '../../domain/signing-rotation.js';
import type {
  IdentityEnvelopeRotationRequest,
  IdentityEnvelopeRotationObservation,
} from '../../domain/identity-envelope-rotation-provider.js';

const u64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });

/** Purpose371 uses the shared rotation identity/state machine. Its exact custody
 * provenance remains separate from ordinary maker/checker approval records. */
export const identityEnvelopeRotationSteps = control
  .table(
    'identity_envelope_rotation_step',
    {
      operationId: uuid('operation_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      rotationId: uuid('rotation_id').notNull(),
      recoveryId: uuid('recovery_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      consumerActivationOperationId: uuid('consumer_activation_operation_id'),
      consumerObservationOperationId: uuid('consumer_observation_operation_id').references(
        (): AnyPgColumn => identityEnvelopeRotationSteps.operationId,
        { onDelete: 'restrict' },
      ),
      idempotencyKey: text('idempotency_key').notNull(),
      fromRevision: u64('from_revision').notNull(),
      fromState: text('from_state').$type<SigningRotationState>().notNull(),
      toState: text('to_state').$type<SigningRotationState>().notNull(),
      authorityBinding: jsonb('authority_binding').notNull(),
      authorityDigest: bytea('authority_digest').notNull(),
      state: text('state')
        .$type<'READY' | 'STARTED' | 'COMMITTED' | 'WRITE_AMBIGUITY' | 'FAILED'>()
        .notNull()
        .default('READY'),
      result: jsonb('result'),
      evidenceCbor: bytea('evidence_cbor'),
      evidenceDigest: bytea('evidence_digest'),
      coseSign1: bytea('cose_sign1'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      startedAt: time('started_at'),
      completedAt: time('completed_at'),
    },
    (t) => [
      unique('identity_envelope_rotation_step_revision_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.rotationId,
        t.fromRevision,
      ),
      unique('identity_envelope_rotation_step_key_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.principalId,
        t.idempotencyKey,
      ),
      unique('identity_envelope_rotation_step_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.rotationId,
        t.operationId,
      ),
      foreignKey({
        name: 'identity_envelope_rotation_step_rotation_fk',
        columns: [t.participantId, t.privacyDomainId, t.rotationId],
        foreignColumns: [
          signingKeyRotations.participantId,
          signingKeyRotations.privacyDomainId,
          signingKeyRotations.rotationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_rotation_step_recovery_fk',
        columns: [t.participantId, t.privacyDomainId, t.recoveryId],
        foreignColumns: [
          platformRecoveryCases.participantId,
          platformRecoveryCases.privacyDomainId,
          platformRecoveryCases.recoveryId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_rotation_step_consumer_fk',
        columns: [t.consumerActivationOperationId],
        foreignColumns: [identityEnvelopeActivations.operationId],
      }).onDelete('restrict'),
      check(
        'identity_envelope_rotation_step_consumer_ck',
        sql`(${t.fromState}='CUTOVER_FENCED' and ${t.fromRevision}=6 and ${t.toState}='OBSERVING' and ${t.consumerActivationOperationId} is not null)
        or (${t.fromState}<>'CUTOVER_FENCED' and ${t.consumerActivationOperationId} is null)`,
      ),
      check(
        'identity_envelope_rotation_step_consumer_observation_ck',
        sql`(${t.fromState} in ('OBSERVING','OLD_REVOKED','OLD_RETIRED') and ${t.consumerObservationOperationId} is not null)
         or (${t.fromState} not in ('OBSERVING','OLD_REVOKED','OLD_RETIRED') and ${t.consumerObservationOperationId} is null)`,
      ),
      check(
        'identity_envelope_rotation_step_digest_ck',
        sql`octet_length(${t.authorityDigest})=32 and ${t.fromRevision}>0`,
      ),
      check(
        'identity_envelope_rotation_step_state_ck',
        sql`${t.state} in ('READY','STARTED','COMMITTED','WRITE_AMBIGUITY','FAILED')`,
      ),
      check(
        'identity_envelope_rotation_step_evidence_ck',
        sql`(${t.state} in ('READY','STARTED','WRITE_AMBIGUITY') and ${t.result} is null and ${t.evidenceCbor} is null and ${t.evidenceDigest} is null and ${t.coseSign1} is null and ${t.completedAt} is null)
    or (${t.state} in ('COMMITTED','FAILED') and ${t.result} is not null and octet_length(${t.evidenceCbor})>0 and octet_length(${t.evidenceDigest})=32 and octet_length(${t.coseSign1})>0 and ${t.completedAt} is not null)`,
      ),
      check(
        'identity_envelope_rotation_step_start_ck',
        sql`(${t.state}='READY' and ${t.startedAt} is null) or (${t.state}<>'READY' and ${t.startedAt} is not null)`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** Every request is immutable before STARTED is committed. A restarted worker
 * only looks up the exact recorded attempt; it never blind-replays provider I/O. */
export const identityEnvelopeRotationAttempts = control
  .table(
    'identity_envelope_rotation_attempt',
    {
      attemptId: uuid('attempt_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      rotationId: uuid('rotation_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      slot: text('slot').notNull(),
      request: jsonb('request').$type<IdentityEnvelopeRotationRequest>().notNull(),
      requestDigest: bytea('request_digest').notNull(),
      state: text('state')
        .$type<'READY' | 'STARTED' | 'OBSERVED' | 'WRITE_AMBIGUITY'>()
        .notNull()
        .default('READY'),
      observation: jsonb('observation').$type<IdentityEnvelopeRotationObservation>(),
      observationDigest: bytea('observation_digest'),
      firstObservation: jsonb('first_observation').$type<IdentityEnvelopeRotationObservation>(),
      firstObservationDigest: bytea('first_observation_digest'),
      ambiguityKind: text('ambiguity_kind').$type<'LOOKUP_UNAVAILABLE' | 'NOT_FOUND' | 'UNKNOWN'>(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      startedAt: time('started_at'),
      observedAt: time('observed_at'),
    },
    (t) => [
      unique('identity_envelope_rotation_attempt_slot_uq').on(t.operationId, t.slot),
      foreignKey({
        name: 'identity_envelope_rotation_attempt_step_fk',
        columns: [t.participantId, t.privacyDomainId, t.rotationId, t.operationId],
        foreignColumns: [
          identityEnvelopeRotationSteps.participantId,
          identityEnvelopeRotationSteps.privacyDomainId,
          identityEnvelopeRotationSteps.rotationId,
          identityEnvelopeRotationSteps.operationId,
        ],
      }).onDelete('restrict'),
      check(
        'identity_envelope_rotation_attempt_digest_ck',
        sql`octet_length(${t.requestDigest})=32`,
      ),
      check(
        'identity_envelope_rotation_recovery_possession_ck',
        sql`not (${t.request} ? 'recoveryPredecessor') or
          (${t.slot}='old' and ${t.request}->>'method'='PROVE'
           and jsonb_typeof(${t.request}->'recoveryPredecessor')='object'
           and ${t.request}#>>'{recoveryPredecessor,purpose}'='IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY')`,
      ),
      check(
        'identity_envelope_rotation_attempt_ambiguity_ck',
        sql`${t.ambiguityKind} is null or (${t.ambiguityKind} in ('LOOKUP_UNAVAILABLE','NOT_FOUND','UNKNOWN') and ${t.startedAt} is not null)`,
      ),
      check(
        'identity_envelope_rotation_attempt_first_ck',
        sql`(${t.firstObservation} is null and ${t.firstObservationDigest} is null)
    or (${t.firstObservation} is not null and octet_length(${t.firstObservationDigest})=32 and ${t.startedAt} is not null)`,
      ),
      check(
        'identity_envelope_rotation_attempt_state_ck',
        sql`${t.state} in ('READY','STARTED','OBSERVED','WRITE_AMBIGUITY') and ${t.slot} in ('old','new','effective')`,
      ),
      check(
        'identity_envelope_rotation_attempt_observation_ck',
        sql`(${t.state}<>'OBSERVED' and ${t.observation} is null and ${t.observationDigest} is null and ${t.observedAt} is null)
    or (${t.state}='OBSERVED' and ${t.observation} is not null and octet_length(${t.observationDigest})=32 and ${t.observedAt} is not null)`,
      ),
      check(
        'identity_envelope_rotation_attempt_start_ck',
        sql`(${t.state}='READY' and ${t.startedAt} is null) or (${t.state}<>'READY' and ${t.startedAt} is not null)`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
