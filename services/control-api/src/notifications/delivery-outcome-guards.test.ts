import { expect, it } from 'vitest';
import { pgTable, uuid, getTableConfig } from 'drizzle-orm/pg-core';
import {
  notificationOutcomeObservationLinkColumns,
  notificationOutcomeObservationLinks,
  notificationDeliveryOutcomes,
  notificationDeliveryOutcomeSigning,
} from './delivery-outcome-schema.js';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
const module: Record<string, unknown> = await import(
  new URL('./delivery-outcome-guards.mjs', import.meta.url).href
);
if (typeof module.notificationDeliveryOutcomeObservationGuardsSql !== 'string')
  throw new Error('Missing outcome SQL');
const sql = module.notificationDeliveryOutcomeObservationGuardsSql;
it('validates shared SQL conditional structure', () =>
  expect(() => verifyConditionCases(sql)).not.toThrow());
it('requires original claimed native receipt and cannot authorize result publication', () => {
  for (const text of [
    'check_notification_delivery_start_original(start)',
    'check_notification_delivery_dispatch_intent_original(intent)',
    "intent.state IS DISTINCT FROM 'CLAIMED'",
    'intent.claim_token IS DISTINCT FROM item.dispatch_claim_token',
    'item.observed_at_ms<intent.claimed_at_ms',
    'item.operation_id IN (item.start_operation_id,start.source_operation_id,start.attempt_id)',
    'archive_cose_binding(payload,cose,signer,24010,347)',
    'BEFORE UPDATE OR DELETE OR TRUNCATE',
    'REVOKE ALL',
    'NOTIFICATION-OUTCOME-NATIVE',
    'NOTIFICATION-OUTCOME-CLAIMS',
  ])
    expect(sql).toContain(text);
  expect(sql).not.toMatch(
    /SECURITY DEFINER|GRANT\s|BEFORE INSERT|check_notification_delivery_signing_current|current_notification_delivery_limit|check_notification_delivery_start_complete|insert into control\.|update control\./iu,
  );
});
it('declares single first observation and a distinct exact scoped final operation FK without another ledger', () => {
  // Metadata-only table models, never SQL execution or fabricated runtime owner.
  const scope = () => ({
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    operationId: uuid('operation_id').notNull(),
    attemptId: uuid('attempt_id').notNull(),
  });
  const final = notificationDeliveryOutcomes;
  const observation = pgTable(
    'test_existing_observation',
    { ...scope(), ...notificationOutcomeObservationLinkColumns() },
    (t) => notificationOutcomeObservationLinks(t, final),
  );
  const config = getTableConfig(observation);
  const first = config.uniqueConstraints.find(
    (c) => c.name === 'notification_observation_first_uq',
  );
  expect(first?.columns.map((c) => c.name)).toEqual([
    'participant_id',
    'privacy_domain_id',
    'attempt_id',
  ]);
  const fk = config.foreignKeys
    .find((f) => f.getName() === 'notification_observation_outcome_fk')
    ?.reference();
  expect(fk?.columns.map((c) => c.name)).toEqual([
    'participant_id',
    'privacy_domain_id',
    'operation_id',
    'attempt_id',
  ]);
  expect(fk?.foreignTable).toBe(final);
  const result = getTableConfig(final);
  expect(result.name).toBe('notification_delivery_outcome');
  expect(
    result.foreignKeys
      .find((f) => f.getName() === 'notification_outcome_signing_fk')
      ?.reference()
      .columns.map((c) => c.name),
  ).toEqual([
    'participant_id',
    'privacy_domain_id',
    'operation_id',
    'receipt_id',
    'attempt_id',
    'start_operation_id',
  ]);
  expect(result.enableRLS).toBe(true);
  expect(
    result.uniqueConstraints
      .find((c) => c.name === 'notification_outcome_operation_attempt_uq')
      ?.columns.map((c) => c.name),
  ).toEqual(['participant_id', 'privacy_domain_id', 'operation_id', 'attempt_id']);
  expect(
    result.foreignKeys
      .find((f) => f.getName() === 'notification_outcome_start_fk')
      ?.reference()
      .columns.map((c) => c.name),
  ).toEqual([
    'participant_id',
    'privacy_domain_id',
    'start_operation_id',
    'attempt_id',
    'notification_occurrence_id',
    'payload_digest',
  ]);
});
it('makes the distinct signed result immutable without a provisional INSERT authority', () => {
  const result = module.notificationDeliveryOutcomeImmutabilityGuardsSql;
  if (typeof result !== 'string') throw new Error('Missing result immutability SQL');
  expect(() => verifyConditionCases(result)).not.toThrow();
  expect(result).toContain(
    'BEFORE UPDATE OR DELETE OR TRUNCATE ON control.notification_delivery_outcome',
  );
  expect(result).not.toMatch(/GRANT\s|SECURITY DEFINER|BEFORE INSERT|insert into/iu);
});
it('declares a native signing intent separately from the final observation/result', () => {
  const config = getTableConfig(notificationDeliveryOutcomeSigning);
  expect(config.enableRLS).toBe(true);
  expect(config.name).toBe('notification_delivery_outcome_signing');
  expect(
    config.uniqueConstraints
      .find((c) => c.name === 'notification_outcome_signing_revision_uq')
      ?.columns.map((c) => c.name),
  ).toEqual(['participant_id', 'privacy_domain_id', 'attempt_id', 'delivery_revision']);
  expect(config.columns.map((c) => c.name)).toEqual(
    expect.arrayContaining([
      'request_digest',
      'preparation_bytes',
      'preparation_digest',
      'state',
      'dispatch_token',
      'dispatched_at_ms',
      'observation_bytes',
      'observation_digest',
    ]),
  );
});
it('closes durable signing against stale preparation, claim retake and first-observation overwrite without final grants', () => {
  const signing = module.notificationDeliveryOutcomeSigningGuardsSql;
  if (typeof signing !== 'string') throw new Error('Missing durable outcome signing guards');
  expect(() => verifyConditionCases(signing)).not.toThrow();
  for (const required of [
    'relforcerowsecurity',
    'notification_outcome_signing_guard',
    'notification_outcome_signing_immutable',
    'check_notification_delivery_observation_original(native)',
    'NOTIFICATION-OUTCOME-SIGNING-LINEAGE',
    'NOTIFICATION-OUTCOME-SIGNING-TRUST',
    'NOTIFICATION-OUTCOME-SIGNING-BEFORE',
    'NOTIFICATION-OUTCOME-SIGNING-AFTER',
    'NOTIFICATION-OUTCOME-SIGNING-STALE',
    "OLD.state='PREPARED' AND NEW.state='DISPATCHED'",
    "OLD.state='DISPATCHED' AND NEW.state='OBSERVED'",
    'NEW.dispatch_token IS DISTINCT FROM OLD.dispatch_token',
    'NEW.dispatched_at_ms IS DISTINCT FROM OLD.dispatched_at_ms',
    'NOTIFICATION-OUTCOME-SIGNING-ONE-SHOT',
    'BEFORE DELETE OR TRUNCATE',
    'REVOKE ALL',
    'archive_cose_binding(decode(q',
  ])
    expect(signing).toContain(required);
  expect(signing).not.toMatch(
    /GRANT\s|SECURITY DEFINER|current_notification_delivery_limit|insert into control\.|update control\./iu,
  );
});
