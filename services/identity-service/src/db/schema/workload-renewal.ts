import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  numeric,
  pgPolicy,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
  type AnyPgColumn,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  controlRuntimeRole,
  controlWorkerRole,
  controlReaderRole,
} from './common.js';
import { credentials, principals, privacyDomains } from './participants.js';
import { mutationEvidence } from './workflow.js';
import { auditOccurrences } from './business-receipts.js';
import type { WorkloadRenewalPolicyDefinition } from '../../contracts/workload-renewal-policy.js';
import type { DurableAuthority } from '../authority-fence.js';
import { workloadRenewalOriginalSchema } from '../../contracts/workload-renewal.js';
import type {
  WorkloadRenewalOriginal,
  WorkloadRenewalReadback,
} from '../../domain/workload-renewal-worker-contract.js';

const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const counter = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
const originalKeys = sql.raw(
  `ARRAY[${Object.keys(workloadRenewalOriginalSchema.shape)
    .map((key) => `'${key}'`)
    .join(',')}]::text[]`,
);
const scopedRead = (name: string, participant: AnyPgColumn, domain: AnyPgColumn) =>
  pgPolicy(`${name}_read`, {
    for: 'select',
    to: [controlRuntimeRole, controlWorkerRole, controlReaderRole],
    using: sql`openpc.matches_participant(${participant}) and openpc.matches_privacy(${domain})`,
  });
const governedPolicyWrite = (
  name: string,
  participant: AnyPgColumn,
  domain: AnyPgColumn,
  update = false,
) =>
  pgPolicy(name, {
    for: update ? 'update' : 'insert',
    to: [controlRuntimeRole],
    ...(update
      ? {
          using: sql`openpc.matches_participant(${participant}) and openpc.matches_privacy(${domain}) and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'`,
        }
      : {}),
    withCheck: sql`openpc.matches_participant(${participant}) and openpc.matches_privacy(${domain}) and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'`,
  });

/** Human policy writes require the separately installed governed receipt owner.
 * Instance/intent/worker writes remain closed until their dedicated admission;
 * bootstrap never creates active renewal business state. */
export const workloadRenewalPolicies = control
  .table(
    'workload_renewal_policy',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      policyId: uuid('policy_id').notNull(),
      revision: counter('revision').notNull(),
      principalId: uuid('principal_id').notNull(),
      workloadId: text('workload_id').notNull(),
      digest: bytea('digest').notNull(),
      definition: jsonb('definition').$type<WorkloadRenewalPolicyDefinition>().notNull(),
      definitionCanonical: bytea('definition_canonical').notNull(),
      governanceOperationId: uuid('governance_operation_id').notNull(),
      businessAncestors: jsonb('business_ancestors').$type<readonly DurableAuthority[]>().notNull(),
      attestationProfileDigest: bytea('attestation_profile_digest').notNull(),
      issuerProfileDigest: bytea('issuer_profile_digest').notNull(),
      providerQualificationDigest: bytea('provider_qualification_digest').notNull(),
      validFrom: time('valid_from').notNull(),
      validUntil: time('valid_until').notNull(),
      state: text('state').notNull(),
    },
    (t) => [
      primaryKey({
        name: 'wr_policy_pk',
        columns: [t.participantId, t.privacyDomainId, t.policyId, t.revision],
      }),
      foreignKey({
        name: 'wr_policy_scope_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }),
      foreignKey({
        name: 'wr_policy_principal_fk',
        columns: [t.participantId, t.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }),
      foreignKey({
        name: 'wr_policy_governance_fk',
        columns: [t.participantId, t.governanceOperationId],
        foreignColumns: [mutationEvidence.participantId, mutationEvidence.operationId],
      }),
      foreignKey({
        name: 'wr_policy_receipt_operation_fk',
        columns: [t.participantId, t.privacyDomainId, t.governanceOperationId],
        foreignColumns: [
          auditOccurrences.participantId,
          auditOccurrences.privacyDomainId,
          auditOccurrences.operationId,
        ],
      }),
      unique('wr_policy_operation_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.governanceOperationId,
      ),
      check(
        'wr_policy_definition_ck',
        sql`octet_length(${t.definitionCanonical}) between 1 and 65536 and ${t.digest}=sha256(${t.definitionCanonical}) and jsonb_typeof(${t.definition})='object'`,
      ),
      check(
        'wr_policy_bounds_ck',
        sql`${t.revision} between 1 and 18446744073709551615 and ${t.validUntil}>${t.validFrom} and ${t.state} in ('ACTIVE','SUSPENDED','REVOKED') and jsonb_typeof(${t.businessAncestors})='array' and jsonb_array_length(${t.businessAncestors}) between 1 and 64`,
      ),
      check(
        'wr_policy_digests_ck',
        sql`octet_length(${t.digest})=32 and octet_length(${t.attestationProfileDigest})=32 and octet_length(${t.issuerProfileDigest})=32 and octet_length(${t.providerQualificationDigest})=32`,
      ),
      scopedRead('wr_policy', t.participantId, t.privacyDomainId),
      governedPolicyWrite('wr_policy_insert', t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** Current selection is separate from immutable revision/receipt provenance.
 * A historical ACTIVE revision cannot remain eligible after suspension,
 * revocation or an independently governed revision. */
export const workloadRenewalPolicyHeads = control
  .table(
    'workload_renewal_policy_head',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      policyId: uuid('policy_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      workloadId: text('workload_id').notNull(),
      currentRevision: counter('current_revision').notNull(),
      state: text('state').notNull(),
      rowVersion: counter('row_version')
        .notNull()
        .default(sql`1`),
    },
    (t) => [
      primaryKey({
        name: 'wr_policy_head_pk',
        columns: [t.participantId, t.privacyDomainId, t.policyId],
      }),
      foreignKey({
        name: 'wr_policy_head_revision_fk',
        columns: [t.participantId, t.privacyDomainId, t.policyId, t.currentRevision],
        foreignColumns: [
          workloadRenewalPolicies.participantId,
          workloadRenewalPolicies.privacyDomainId,
          workloadRenewalPolicies.policyId,
          workloadRenewalPolicies.revision,
        ],
      }),
      check(
        'wr_policy_head_bounds_ck',
        sql`${t.currentRevision} between 1 and 18446744073709551615 and ${t.rowVersion} between 1 and 18446744073709551615 and ${t.state} in ('ACTIVE','SUSPENDED','REVOKED')`,
      ),
      scopedRead('wr_policy_head', t.participantId, t.privacyDomainId),
      governedPolicyWrite('wr_policy_head_insert', t.participantId, t.privacyDomainId),
      governedPolicyWrite('wr_policy_head_update', t.participantId, t.privacyDomainId, true),
    ],
  )
  .enableRLS();

/** One family per independently admitted instance, never per pod display name.
 * CURRENT is a pointer to an existing authenticated credential. PREPARED leaves
 * are stored separately and do not change this pointer or security epoch. */
export const workloadCredentialFamilies = control
  .table(
    'workload_credential_family',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      familyId: uuid('family_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      workloadId: text('workload_id').notNull(),
      instanceId: uuid('instance_id').notNull(),
      instanceGeneration: counter('instance_generation').notNull(),
      generation: counter('generation').notNull(),
      securityEpoch: counter('security_epoch').notNull(),
      currentCredentialId: uuid('current_credential_id').notNull(),
      currentFingerprint: bytea('current_fingerprint').notNull(),
      policyId: uuid('policy_id').notNull(),
      policyRevision: counter('policy_revision').notNull(),
      instanceAdmissionOperationId: uuid('instance_admission_operation_id').notNull(),
      state: text('state').notNull(),
      rowVersion: counter('row_version')
        .notNull()
        .default(sql`1`),
    },
    (t) => [
      primaryKey({
        name: 'wr_family_pk',
        columns: [t.participantId, t.privacyDomainId, t.familyId],
      }),
      unique('wr_family_id_uq').on(t.familyId),
      unique('wr_family_instance_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.instanceId,
        t.instanceGeneration,
      ),
      foreignKey({
        name: 'wr_family_scope_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }),
      foreignKey({
        name: 'wr_family_principal_fk',
        columns: [t.participantId, t.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }),
      foreignKey({
        name: 'wr_family_current_fk',
        columns: [t.participantId, t.currentCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }),
      foreignKey({
        name: 'wr_family_policy_fk',
        columns: [t.participantId, t.privacyDomainId, t.policyId, t.policyRevision],
        foreignColumns: [
          workloadRenewalPolicies.participantId,
          workloadRenewalPolicies.privacyDomainId,
          workloadRenewalPolicies.policyId,
          workloadRenewalPolicies.revision,
        ],
      }),
      foreignKey({
        name: 'wr_family_admission_fk',
        columns: [t.participantId, t.instanceAdmissionOperationId],
        foreignColumns: [mutationEvidence.participantId, mutationEvidence.operationId],
      }),
      check(
        'wr_family_bounds_ck',
        sql`${t.generation} between 1 and 18446744073709551615 and ${t.instanceGeneration} between 1 and 18446744073709551615 and ${t.securityEpoch} between 0 and 18446744073709551615 and ${t.rowVersion} between 1 and 18446744073709551615 and octet_length(${t.currentFingerprint})=32 and ${t.state} in ('ACTIVE','REVOKED','TERMINATED')`,
      ),
      scopedRead('wr_family', t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const workloadRenewalIntents = control
  .table(
    'workload_renewal_intent',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      renewalId: uuid('renewal_id').notNull(),
      familyId: uuid('family_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      credentialId: uuid('credential_id').notNull(),
      original: jsonb('original').$type<WorkloadRenewalOriginal>().notNull(),
      requestBytes: bytea('request_bytes').notNull(),
      requestDigest: bytea('request_digest').notNull(),
      familySecurityEpoch: counter('family_security_epoch').notNull(),
      admissionOperationId: uuid('admission_operation_id').notNull(),
      attestationEvidence: bytea('attestation_evidence').notNull(),
      attestationValidUntil: time('attestation_valid_until').notNull(),
      nextAttemptAt: time('next_attempt_at').notNull(),
      renewalDeadline: time('renewal_deadline').notNull(),
      state: text('state').notNull(),
      providerOutcome: text('provider_outcome').notNull().default('UNRESOLVED'),
      cleanupRequired: text('cleanup_required').notNull().default('NONE'),
      rowVersion: counter('row_version')
        .notNull()
        .default(sql`1`),
      leaseFence: counter('lease_fence')
        .notNull()
        .default(sql`0`),
      leaseExpiresAt: time('lease_expires_at'),
      workerId: text('worker_id'),
      latestObservationId: uuid('latest_observation_id'),
      certificateDer: bytea('certificate_der'),
      certificateFingerprint: bytea('certificate_fingerprint'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        name: 'wr_intent_pk',
        columns: [t.participantId, t.privacyDomainId, t.renewalId],
      }),
      unique('wr_intent_id_uq').on(t.renewalId),
      unique('wr_intent_operation_uq').on(t.operationId),
      unique('wr_intent_credential_uq').on(t.credentialId),
      // FAILED with unknown or issued effects still occupies this original family.
      uniqueIndex('wr_intent_pending_uq')
        .on(t.participantId, t.privacyDomainId, t.familyId)
        .where(sql`${t.state}<>'COMPLETE'`),
      foreignKey({
        name: 'wr_intent_family_fk',
        columns: [t.participantId, t.privacyDomainId, t.familyId],
        foreignColumns: [
          workloadCredentialFamilies.participantId,
          workloadCredentialFamilies.privacyDomainId,
          workloadCredentialFamilies.familyId,
        ],
      }),
      foreignKey({
        name: 'wr_intent_admission_fk',
        columns: [t.participantId, t.admissionOperationId],
        foreignColumns: [mutationEvidence.participantId, mutationEvidence.operationId],
      }),
      check(
        'wr_intent_original_ck',
        sql`coalesce((jsonb_typeof(${t.original})='object' and ${t.original} ?& ${originalKeys} and ${t.original}-${originalKeys}='{}'::jsonb and octet_length(${t.requestBytes}) between 1 and 24576 and octet_length(${t.requestDigest})=32 and sha256(${t.requestBytes})=${t.requestDigest} and (${t.original}->>'version')='2' and (${t.original}->>'renewalId')=${t.renewalId}::text and (${t.original}->>'providerRequestId')=${t.renewalId}::text and (${t.original}->>'operationId')=${t.operationId}::text and (${t.original}->>'credentialId')=${t.credentialId}::text and (${t.original}->>'participantId')=${t.participantId}::text and (${t.original}->>'privacyDomainId')=${t.privacyDomainId}::text and (${t.original}->>'familyId')=${t.familyId}::text and (${t.original}->>'providerRequestDigest')='sha256:'||encode(${t.requestDigest},'hex') and decode(${t.original}->>'providerRequestBase64','base64')=${t.requestBytes}),false)`,
      ),
      check(
        'wr_intent_state_ck',
        sql`${t.state} in ('RECOVERING','PREPARED','FAILED','COMPLETE') and ${t.providerOutcome} in ('UNRESOLVED','NOT_ISSUED','ISSUED') and ${t.cleanupRequired} in ('NONE','RECONCILE','REVOKE') and ${t.rowVersion} between 1 and 18446744073709551615 and ${t.leaseFence} between 0 and 18446744073709551615 and ${t.familySecurityEpoch} between 0 and 18446744073709551615 and (${t.workerId} is null)=(${t.leaseExpiresAt} is null)`,
      ),
      check(
        'wr_intent_prepared_ck',
        sql`${t.state}<>'PREPARED' or (${t.providerOutcome}='ISSUED' and ${t.certificateDer} is not null and ${t.certificateFingerprint} is not null and octet_length(${t.certificateDer}) between 1 and 24576 and sha256(${t.certificateDer})=${t.certificateFingerprint})`,
      ),
      check(
        'wr_intent_attestation_ck',
        sql`octet_length(${t.attestationEvidence}) between 1 and 65536 and ${t.renewalDeadline}>${t.createdAt}`,
      ),
      scopedRead('wr_intent', t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const workloadRenewalAttempts = control
  .table(
    'workload_renewal_attempt',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      renewalId: uuid('renewal_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      workerId: text('worker_id').notNull(),
      leaseFence: counter('lease_fence').notNull(),
      leaseExpiresAt: time('lease_expires_at').notNull(),
      providerTimeoutMs: numeric('provider_timeout_ms', { precision: 6, scale: 0 }).notNull(),
      claimedAt: time('claimed_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        name: 'wr_attempt_pk',
        columns: [t.participantId, t.privacyDomainId, t.attemptId],
      }),
      unique('wr_attempt_fence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.renewalId,
        t.leaseFence,
      ),
      unique('wr_attempt_original_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.renewalId,
        t.attemptId,
      ),
      foreignKey({
        name: 'wr_attempt_intent_fk',
        columns: [t.participantId, t.privacyDomainId, t.renewalId],
        foreignColumns: [
          workloadRenewalIntents.participantId,
          workloadRenewalIntents.privacyDomainId,
          workloadRenewalIntents.renewalId,
        ],
      }),
      check(
        'wr_attempt_bounds_ck',
        sql`${t.leaseFence} between 1 and 18446744073709551615 and ${t.providerTimeoutMs} between 1 and 60000 and length(${t.workerId}) between 1 and 160 and ${t.leaseExpiresAt}>${t.claimedAt}`,
      ),
      scopedRead('wr_attempt', t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const workloadRenewalObservations = control
  .table(
    'workload_renewal_observation',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      observationId: uuid('observation_id').notNull(),
      renewalId: uuid('renewal_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      observation: jsonb('observation').$type<WorkloadRenewalReadback>().notNull(),
      proofDigest: bytea('proof_digest'),
      proofRevision: counter('proof_revision'),
      disposition: text('disposition').notNull(),
      recordedAt: time('recorded_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        name: 'wr_observation_pk',
        columns: [t.participantId, t.privacyDomainId, t.observationId],
      }),
      foreignKey({
        name: 'wr_observation_intent_fk',
        columns: [t.participantId, t.privacyDomainId, t.renewalId],
        foreignColumns: [
          workloadRenewalIntents.participantId,
          workloadRenewalIntents.privacyDomainId,
          workloadRenewalIntents.renewalId,
        ],
      }),
      foreignKey({
        name: 'wr_observation_attempt_fk',
        columns: [t.participantId, t.privacyDomainId, t.renewalId, t.attemptId],
        foreignColumns: [
          workloadRenewalAttempts.participantId,
          workloadRenewalAttempts.privacyDomainId,
          workloadRenewalAttempts.renewalId,
          workloadRenewalAttempts.attemptId,
        ],
      }),
      unique('wr_observation_original_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.renewalId,
        t.attemptId,
        t.observationId,
      ),
      check(
        'wr_observation_bounds_ck',
        sql`${t.disposition} in ('CURRENT','STALE','UNQUALIFIED') and (${t.proofDigest} is null)=(${t.proofRevision} is null) and (${t.proofDigest} is null or (octet_length(${t.proofDigest})=32 and ${t.proofRevision} between 1 and 18446744073709551615))`,
      ),
      scopedRead('wr_observation', t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const workloadRenewalIssueAuthorizations = control
  .table(
    'workload_renewal_issue_authorization',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      authorizationId: uuid('authorization_id').notNull(),
      renewalId: uuid('renewal_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      observationId: uuid('observation_id').notNull(),
      leaseFence: counter('lease_fence').notNull(),
      committedAt: time('committed_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        name: 'wr_authorization_pk',
        columns: [t.participantId, t.privacyDomainId, t.authorizationId],
      }),
      unique('wr_authorization_observation_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.observationId,
      ),
      foreignKey({
        name: 'wr_authorization_attempt_fk',
        columns: [t.participantId, t.privacyDomainId, t.renewalId, t.attemptId],
        foreignColumns: [
          workloadRenewalAttempts.participantId,
          workloadRenewalAttempts.privacyDomainId,
          workloadRenewalAttempts.renewalId,
          workloadRenewalAttempts.attemptId,
        ],
      }),
      foreignKey({
        name: 'wr_authorization_observation_fk',
        columns: [t.participantId, t.privacyDomainId, t.renewalId, t.attemptId, t.observationId],
        foreignColumns: [
          workloadRenewalObservations.participantId,
          workloadRenewalObservations.privacyDomainId,
          workloadRenewalObservations.renewalId,
          workloadRenewalObservations.attemptId,
          workloadRenewalObservations.observationId,
        ],
      }),
      check('wr_authorization_fence_ck', sql`${t.leaseFence} between 1 and 18446744073709551615`),
      scopedRead('wr_authorization', t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
