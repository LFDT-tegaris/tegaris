import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  primaryKey,
  text,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  credentials,
  privacyDomains,
} from '../../../identity-service/src/db/schema/participants.js';
import { retentionPolicies } from './retention-schema.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
  evidenceTimestamp as time,
} from './schema.js';

const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});

const verified = () => ({
  verificationNonce: bytes('verification_nonce').notNull(),
  verificationMac: bytes('verification_mac').notNull(),
});

/** Installed public target identity. Neither a proposal nor a dispatcher may
 * enroll a host, replace its key, or turn another scope's outcome into evidence. */
export const storeRetirementHosts = control
  .table(
    'store_retirement_host',
    {
      ...scope(),
      hostDigest: text('host_digest').notNull(),
      hostWire: bytes('host_wire').notNull(),
      controlSpki: bytes('control_spki').notNull(),
      targetSpki: bytes('target_spki').notNull(),
      databaseRole: text('database_role').notNull(),
      workloadCredentialId: uuid('workload_credential_id').notNull(),
      workloadCredentialEpoch: ordinal('workload_credential_epoch').notNull(),
      validFromMs: ordinal('valid_from_ms').notNull(),
      validUntilMs: ordinal('valid_until_ms').notNull(),
      installationReference: text('installation_reference').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.hostDigest] }),
      foreignKey({
        name: 'store_retirement_host_workload_fk',
        columns: [t.participantId, t.workloadCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'store_retirement_host_validity_ck',
        sql`${t.workloadCredentialEpoch} between 0 and 18446744073709551615 and ${t.validFromMs}>=0 and ${t.validUntilMs}>${t.validFromMs} and ${t.validUntilMs}<=9223372036854775807`,
      ),
      foreignKey({
        name: 'store_retirement_host_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      check(
        'store_retirement_host_wire_ck',
        sql`${t.hostDigest}=encode(sha256(${t.hostWire}),'hex') and octet_length(${t.hostWire}) between 1 and 2048`,
      ),
      check(
        'store_retirement_host_keys_ck',
        sql`octet_length(${t.controlSpki})=91 and octet_length(${t.targetSpki})=91 and ${t.controlSpki}<>${t.targetSpki} and length(${t.installationReference}) between 1 and 256`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Immutable governed admission, atomically bound to its real Control business
 * receipt and outbox. It records no physical effect and grants no target I/O
 * until that transaction has been read back as committed. */
export const storeRetirementAdmissions = control
  .table(
    'store_retirement_admission',
    {
      ...scope(),
      ...verified(),
      retirementId: uuid('retirement_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      previousAttemptId: uuid('previous_attempt_id'),
      hostDigest: text('host_digest').notNull(),
      retentionPolicyId: uuid('retention_policy_id').notNull(),
      approvalRequestId: uuid('approval_request_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      // Exact integer-preserving typed wire, never JSON.stringify of parsed u64s.
      attemptWire: bytes('attempt_wire').notNull(),
      attemptDigest: text('attempt_digest').notNull(),
      selectionDigest: text('selection_digest').notNull(),
      sourceBinding: jsonb('source_binding').notNull(),
      sourceBindingDigest: text('source_binding_digest').notNull(),
      lifecycleRevision: ordinal('lifecycle_revision').notNull(),
      dispatchNotAfterMs: ordinal('dispatch_not_after_ms').notNull(),
      revision: ordinal('revision').notNull().default('1'),
      admittedAt: time('admitted_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.attemptId] }),
      unique('store_retirement_admission_operation_uq').on(t.operationId),
      unique('store_retirement_admission_attempt_uq').on(t.attemptId),
      unique('store_retirement_admission_verifier_uq').on(t.hostDigest, t.verificationNonce),
      check(
        'store_retirement_admission_verifier_ck',
        sql`octet_length(${t.verificationNonce})=32 and octet_length(${t.verificationMac})=32`,
      ),
      unique('store_retirement_admission_successor_uq').on(t.previousAttemptId),
      uniqueIndex('store_retirement_admission_initial_uq')
        .on(t.participantId, t.privacyDomainId, t.retirementId)
        .where(sql`${t.previousAttemptId} is null`),
      foreignKey({
        name: 'store_retirement_admission_previous_fk',
        columns: [t.participantId, t.privacyDomainId, t.previousAttemptId],
        foreignColumns: [t.participantId, t.privacyDomainId, t.attemptId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'store_retirement_admission_host_fk',
        columns: [t.participantId, t.privacyDomainId, t.hostDigest],
        foreignColumns: [
          storeRetirementHosts.participantId,
          storeRetirementHosts.privacyDomainId,
          storeRetirementHosts.hostDigest,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'store_retirement_admission_policy_fk',
        columns: [t.participantId, t.privacyDomainId, t.retentionPolicyId],
        foreignColumns: [
          retentionPolicies.participantId,
          retentionPolicies.privacyDomainId,
          retentionPolicies.retentionPolicyId,
        ],
      }).onDelete('restrict'),
      check(
        'store_retirement_admission_wire_ck',
        sql`octet_length(${t.attemptWire}) between 1 and 1048576 and ${t.attemptDigest} ~ '^[0-9a-f]{64}$' and ${t.selectionDigest} ~ '^[0-9a-f]{64}$'`,
      ),
      check(
        'store_retirement_admission_source_ck',
        sql`jsonb_typeof(${t.sourceBinding})='object' and octet_length(${t.sourceBinding}::text) between 1 and 1048576 and ${t.sourceBindingDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'store_retirement_admission_revision_ck',
        sql`${t.lifecycleRevision} between 1 and 9223372036854775807 and ${t.revision}=1 and ${t.previousAttemptId} is distinct from ${t.attemptId} and ${t.dispatchNotAfterMs}>floor(extract(epoch from ${t.admittedAt})*1000) and ${t.dispatchNotAfterMs}<=floor(extract(epoch from ${t.admittedAt})*1000)+60000`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** A committed cancellation decision is durable independently of its short
 * lived delivery signature. A late hold stays PENDING until the target's exact
 * original outcome resolves whether cancellation prevented the physical effect. */
export const storeRetirementCancellations = control
  .table(
    'store_retirement_cancellation',
    {
      ...scope(),
      attemptId: uuid('attempt_id').notNull(),
      cancellationId: uuid('cancellation_id').notNull(),
      lifecycleRevision: ordinal('lifecycle_revision').notNull(),
      cause: jsonb('cause').notNull(),
      committedDigest: text('committed_digest').notNull(),
      committedAt: time('committed_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.attemptId] }),
      unique('store_retirement_cancellation_id_uq').on(t.cancellationId),
      foreignKey({
        name: 'store_retirement_cancellation_admission_fk',
        columns: [t.participantId, t.privacyDomainId, t.attemptId],
        foreignColumns: [
          storeRetirementAdmissions.participantId,
          storeRetirementAdmissions.privacyDomainId,
          storeRetirementAdmissions.attemptId,
        ],
      }).onDelete('restrict'),
      check(
        'store_retirement_cancellation_binding_ck',
        sql`${t.lifecycleRevision} between 1 and 9223372036854775807 and ${t.committedDigest} ~ '^[0-9a-f]{64}$' and jsonb_typeof(${t.cause})='object' and octet_length(${t.cause}::text) between 1 and 8192`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Exact signed delivery bytes commit before transport. REQUEST has one finite
 * window; expiry does not authorize renewal. CANCEL may renew its delivery
 * window while retaining the original durable cancellation and attempt. */
export const storeRetirementDeliveries = control
  .table(
    'store_retirement_delivery',
    {
      ...scope(),
      ...verified(),
      deliveryId: uuid('delivery_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      purpose: text('purpose').notNull(),
      signedWire: bytes('signed_wire').notNull(),
      wireDigest: text('wire_digest').notNull(),
      issuedAtMs: ordinal('issued_at_ms').notNull(),
      expiresAtMs: ordinal('expires_at_ms').notNull(),
      committedAt: time('committed_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.deliveryId] }),
      unique('store_retirement_delivery_verifier_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.verificationNonce,
      ),
      check(
        'store_retirement_delivery_verifier_ck',
        sql`octet_length(${t.verificationNonce})=32 and octet_length(${t.verificationMac})=32`,
      ),
      unique('store_retirement_delivery_wire_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.wireDigest,
      ),
      uniqueIndex('store_retirement_delivery_request_uq')
        .on(t.participantId, t.privacyDomainId, t.attemptId)
        .where(sql`${t.purpose}='REQUEST'`),
      foreignKey({
        name: 'store_retirement_delivery_admission_fk',
        columns: [t.participantId, t.privacyDomainId, t.attemptId],
        foreignColumns: [
          storeRetirementAdmissions.participantId,
          storeRetirementAdmissions.privacyDomainId,
          storeRetirementAdmissions.attemptId,
        ],
      }).onDelete('restrict'),
      check(
        'store_retirement_delivery_wire_ck',
        sql`${t.purpose} in ('REQUEST','CANCEL') and octet_length(${t.signedWire}) between 1 and 1048576 and ${t.wireDigest}=encode(sha256(${t.signedWire}),'hex')`,
      ),
      check(
        'store_retirement_delivery_lifetime_ck',
        sql`${t.issuedAtMs}>0 and ${t.expiresAtMs}>${t.issuedAtMs} and ${t.expiresAtMs}-${t.issuedAtMs}<=60000 and ${t.expiresAtMs}<=9223372036854775807`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** The independently verified original target result. Missing rows mean UNKNOWN,
 * never a synthesized no-effect result. Original signed bytes survive retries. */
export const storeRetirementOutcomes = control
  .table(
    'store_retirement_outcome',
    {
      ...scope(),
      ...verified(),
      attemptId: uuid('attempt_id').notNull(),
      state: text('state').notNull(),
      signedWire: bytes('signed_wire').notNull(),
      wireDigest: text('wire_digest').notNull(),
      completedAtMs: ordinal('completed_at_ms').notNull(),
      recordedAt: time('recorded_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.attemptId] }),
      unique('store_retirement_outcome_verifier_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.verificationNonce,
      ),
      check(
        'store_retirement_outcome_verifier_ck',
        sql`octet_length(${t.verificationNonce})=32 and octet_length(${t.verificationMac})=32`,
      ),
      foreignKey({
        name: 'store_retirement_outcome_admission_fk',
        columns: [t.participantId, t.privacyDomainId, t.attemptId],
        foreignColumns: [
          storeRetirementAdmissions.participantId,
          storeRetirementAdmissions.privacyDomainId,
          storeRetirementAdmissions.attemptId,
        ],
      }).onDelete('restrict'),
      check(
        'store_retirement_outcome_wire_ck',
        sql`${t.state} in ('APPLIED','REJECTED_NO_EFFECT','CANCELLED_NO_EFFECT') and octet_length(${t.signedWire}) between 1 and 1048576 and ${t.wireDigest}=encode(sha256(${t.signedWire}),'hex') and ${t.completedAtMs} between 1 and 9223372036854775807`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Host/database peer secret used only to authenticate the owner's verified
 * native-source, delivery and original-outcome commits in distinct domains.
 * No runtime, worker or public read policy grants access to this table. */
export const storeRetirementVerifierKeys = control
  .table(
    'store_retirement_verifier_key',
    {
      ...scope(),
      hostDigest: text('host_digest').notNull(),
      verifierSecret: bytes('verifier_secret').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.hostDigest] }),
      foreignKey({
        name: 'store_retirement_verifier_host_fk',
        columns: [t.participantId, t.privacyDomainId, t.hostDigest],
        foreignColumns: [
          storeRetirementHosts.participantId,
          storeRetirementHosts.privacyDomainId,
          storeRetirementHosts.hostDigest,
        ],
      }).onDelete('restrict'),
      check('store_retirement_verifier_key_ck', sql`octet_length(${t.verifierSecret})=32`),
    ],
  )
  .enableRLS();
