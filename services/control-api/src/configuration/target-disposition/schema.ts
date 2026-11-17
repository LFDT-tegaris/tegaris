import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import { runtimeTargets } from '../schema.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
  evidenceTimestamp as time,
} from '../../evidence/schema.js';

const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
  runtimeTargetId: uuid('runtime_target_id').notNull(),
});

/** Separate bridge for native signature verification. Runtime SQL roles cannot
 * read or install this key; it is never shared with Fact admission. */
export const runtimeTargetDispositionKeys = control.table(
  'runtime_target_disposition_key',
  {
    databaseRole: text('database_role').primaryKey(),
    verifierSecret: bytes('verifier_secret').notNull(),
  },
  (t) => [
    check('runtime_target_disposition_key_size_ck', sql`octet_length(${t.verifierSecret})=32`),
  ],
);

/** The pending denial exists before signing or transport. A missing delivery
 * remains pending, including after a signer/process crash. */
export const runtimeTargetDispositionAdmissions = control
  .table(
    'runtime_target_disposition_admission',
    {
      ...scope(),
      revision: ordinal('revision').notNull(),
      binding: jsonb('binding').notNull(),
      restorationProof: jsonb('restoration_proof'),
      activationProof: jsonb('activation_proof'),
      admissionDigest: text('admission_digest').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId, t.revision] }),
      foreignKey({
        name: 'runtime_target_disposition_admission_target_fk',
        columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId],
        foreignColumns: [
          runtimeTargets.participantId,
          runtimeTargets.privacyDomainId,
          runtimeTargets.runtimeTargetId,
        ],
      }).onDelete('restrict'),
      check(
        'runtime_target_disposition_admission_revision_ck',
        sql`${t.revision} between 1 and 9223372036854775807`,
      ),
      check(
        'runtime_target_disposition_admission_digest_ck',
        sql`${t.admissionDigest}='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(case when ${t.activationProof} is not null then jsonb_build_object('binding',${t.binding},'activationProof',${t.activationProof}) when ${t.restorationProof} is null then ${t.binding} else jsonb_build_object('binding',${t.binding},'restorationProof',${t.restorationProof}) end),'UTF8')),'hex') and jsonb_typeof(${t.binding})='object' and coalesce(((${t.binding}->>'action'='Withdraw' and ${t.restorationProof} is null and ${t.activationProof} is null) or (${t.binding}->>'action'='Restore' and jsonb_typeof(${t.restorationProof})='object' and ${t.activationProof} is null) or (${t.binding}->>'action'='ConfirmActivation' and ${t.restorationProof} is null and jsonb_typeof(${t.activationProof})='object')),false)`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Append-only canonical deliveries. Pending withdrawal is durable before any
 * transport attempt; missing or old acknowledgements cannot change this head.
 * Claims and signed bytes are the original wire, not a second authority model. */
export const runtimeTargetDispositionDeliveries = control
  .table(
    'runtime_target_disposition_delivery',
    {
      ...scope(),
      revision: ordinal('revision').notNull(),
      predecessorDigest: text('predecessor_digest'),
      claims: jsonb('claims').notNull(),
      signedDelivery: bytes('signed_delivery').notNull(),
      deliveryDigest: text('delivery_digest').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId, t.revision] }),
      unique('runtime_target_disposition_delivery_digest_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.runtimeTargetId,
        t.deliveryDigest,
      ),
      foreignKey({
        name: 'runtime_target_disposition_admission_fk',
        columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId, t.revision],
        foreignColumns: [
          runtimeTargetDispositionAdmissions.participantId,
          runtimeTargetDispositionAdmissions.privacyDomainId,
          runtimeTargetDispositionAdmissions.runtimeTargetId,
          runtimeTargetDispositionAdmissions.revision,
        ],
      }).onDelete('restrict'),
      check(
        'runtime_target_disposition_revision_ck',
        sql`${t.revision} between 1 and 9223372036854775807`,
      ),
      check(
        'runtime_target_disposition_predecessor_ck',
        sql`(${t.revision}=1 and ${t.predecessorDigest} is null) or (${t.revision}>1 and ${t.predecessorDigest} ~ '^sha256:[0-9a-f]{64}$')`,
      ),
      check(
        'runtime_target_disposition_delivery_ck',
        sql`octet_length(${t.signedDelivery}) between 1 and 65536 and ${t.deliveryDigest}='sha256:'||encode(sha256(${t.signedDelivery}),'hex') and jsonb_typeof(${t.claims})='object'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Exact target acknowledgement retained independently of the current head.
 * This records the authenticated durable target result; it cannot retroactively
 * acknowledge a newer delivery or authorize serving by itself. */
export const runtimeTargetDispositionAcknowledgements = control
  .table(
    'runtime_target_disposition_acknowledgement',
    {
      ...scope(),
      deliveryDigest: text('delivery_digest').notNull(),
      claims: jsonb('claims').notNull(),
      signedAcknowledgement: bytes('signed_acknowledgement').notNull(),
      acknowledgementDigest: text('acknowledgement_digest').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId, t.deliveryDigest],
      }),
      foreignKey({
        name: 'runtime_target_disposition_ack_delivery_fk',
        columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId, t.deliveryDigest],
        foreignColumns: [
          runtimeTargetDispositionDeliveries.participantId,
          runtimeTargetDispositionDeliveries.privacyDomainId,
          runtimeTargetDispositionDeliveries.runtimeTargetId,
          runtimeTargetDispositionDeliveries.deliveryDigest,
        ],
      }).onDelete('restrict'),
      check(
        'runtime_target_disposition_ack_ck',
        sql`octet_length(${t.signedAcknowledgement}) between 1 and 65536 and ${t.acknowledgementDigest}='sha256:'||encode(sha256(${t.signedAcknowledgement}),'hex') and jsonb_typeof(${t.claims})='object'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
