import { identityEnvelopeRecoverySigningSourcePolicies } from './identity-envelope-recovery-source.js';
import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  numeric,
  primaryKey,
  smallint,
  text,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';

import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { credentials, privacyDomains } from './participants.js';
import { businessTransitionProfiles } from './business-evidence.js';
import { signingSecretReferencePattern } from '../../../../../packages/security-kernel/src/business-transition/secret-reference.js';

const u64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });

/** Immutable admitted key descriptor; contains no private key bytes. */
export const businessSigningKeys = control
  .table(
    'business_signing_key',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      signerId: text('signer_id').notNull(),
      // Immutable discriminator. The default preserves existing 338 rows and
      // trust bytes; it is never a grant of the separately admitted 371 purpose.
      signingPurposeCode: smallint('signing_purpose_code').notNull().default(338),
      envelopeWorkloadParticipantEpoch: u64('envelope_workload_participant_epoch'),
      envelopeWorkloadPrincipalEpoch: u64('envelope_workload_principal_epoch'),
      environmentId: text('environment_id').notNull(),
      publicKeySpkiDer: bytea('public_key_spki_der').notNull(),
      workloadCredentialId: uuid('workload_credential_id').notNull(),
      workloadCredentialEpoch: u64('workload_credential_epoch').notNull(),
      keyEpoch: u64('key_epoch').notNull(),
      validFromNs: u64('valid_from_ns').notNull(),
      validUntilNs: u64('valid_until_ns').notNull(),
      admissionKind: text('admission_kind').notNull(),
      admissionReference: text('admission_reference').notNull(),
      admissionDigest: bytea('admission_digest').notNull(),
      secretClass: text('secret_class').notNull(),
      secretReference: text('secret_reference').notNull(),
      secretVersion: text('secret_version').notNull(),
      trustPreimage: bytea('trust_preimage').notNull(),
      trustDigest: bytea('trust_digest').notNull(),
    },
    (table) => [
      primaryKey({
        name: 'business_signing_key_pk',
        columns: [table.participantId, table.privacyDomainId, table.signerId],
      }),
      unique('business_signing_key_snapshot_uq').on(
        table.participantId,
        table.privacyDomainId,
        table.signerId,
        table.trustDigest,
      ),
      unique('business_signing_key_purpose_uq').on(
        table.participantId,
        table.privacyDomainId,
        table.signerId,
        table.signingPurposeCode,
      ),
      check('business_signing_key_purpose_ck', sql`${table.signingPurposeCode} in (338,371,376)`),
      check(
        'business_signing_key_envelope_epochs_ck',
        sql`(${table.signingPurposeCode} in (338,376) and ${table.envelopeWorkloadParticipantEpoch} is null and ${table.envelopeWorkloadPrincipalEpoch} is null)
        or (${table.signingPurposeCode}=371 and ${table.envelopeWorkloadParticipantEpoch} is not null and ${table.envelopeWorkloadPrincipalEpoch} is not null
          and ${table.envelopeWorkloadParticipantEpoch} between 0 and 18446744073709551615 and ${table.envelopeWorkloadPrincipalEpoch} between 0 and 18446744073709551615)`,
      ),
      foreignKey({
        name: 'business_signing_key_privacy_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'business_signing_key_credential_fk',
        columns: [table.participantId, table.workloadCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'business_signing_key_id_ck',
        sql`${table.signerId}='sha256:'||encode(sha256(${table.publicKeySpkiDer}),'hex')`,
      ),
      check(
        'business_signing_key_spki_ck',
        sql`octet_length(${table.publicKeySpkiDer})=91 and substring(${table.publicKeySpkiDer} from 1 for 27)=decode('3059301306072a8648ce3d020106082a8648ce3d03010703420004','hex')`,
      ),
      check(
        'business_signing_key_epoch_ck',
        sql`${table.keyEpoch} between 1 and 18446744073709551615 and ${table.workloadCredentialEpoch} between 0 and 18446744073709551615`,
      ),
      check(
        'business_signing_key_validity_ck',
        sql`${table.validFromNs}>=0 and ${table.validUntilNs}>${table.validFromNs} and ${table.validUntilNs}<=18446744073709551615 and mod(${table.validFromNs},1000)=0 and mod(${table.validUntilNs},1000)=0`,
      ),
      check(
        'business_signing_key_admission_ck',
        sql`${table.admissionKind} in ('BOOTSTRAP','GOVERNED') and length(${table.admissionReference}) between 1 and 256 and octet_length(${table.admissionDigest})=32`,
      ),
      check(
        'business_signing_key_secret_ck',
        sql`${table.secretClass}='SECRET-SIGNING-KEY' and ${table.secretReference} ~ ${sql.raw(`'${signingSecretReferencePattern}'`)} and split_part(${table.secretReference},'#',2)=${table.secretVersion} and lower(${table.secretVersion}) not in ('latest','current')`,
      ),
      check(
        'business_signing_key_environment_ck',
        sql`length(${table.environmentId}) between 1 and 160`,
      ),
      check(
        'business_signing_key_trust_ck',
        sql`octet_length(${table.trustPreimage}) between 1 and 65536 and octet_length(${table.trustDigest})=32 and ${table.trustDigest}=sha256(${table.trustPreimage})`,
      ),
      participantIsolationPolicy(table.participantId),
      ...identityEnvelopeRecoverySigningSourcePolicies(
        table.participantId,
        table.privacyDomainId,
        table.signerId,
        false,
      ),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();

/** Each row is an exact profile grant in the immutable trust preimage. */
export const businessSigningGrants = control
  .table(
    'business_signing_grant',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      signerId: text('signer_id').notNull(),
      profileDigest: bytea('profile_digest').notNull(),
    },
    (table) => [
      primaryKey({
        name: 'business_signing_grant_pk',
        columns: [table.participantId, table.privacyDomainId, table.signerId, table.profileDigest],
      }),
      foreignKey({
        name: 'business_signing_grant_profile_fk',
        columns: [table.profileDigest],
        foreignColumns: [businessTransitionProfiles.profileDigest],
      }).onDelete('restrict'),
      foreignKey({
        name: 'business_signing_grant_key_fk',
        columns: [table.participantId, table.privacyDomainId, table.signerId],
        foreignColumns: [
          businessSigningKeys.participantId,
          businessSigningKeys.privacyDomainId,
          businessSigningKeys.signerId,
        ],
      }).onDelete('restrict'),
      participantIsolationPolicy(table.participantId),
      ...identityEnvelopeRecoverySigningSourcePolicies(
        table.participantId,
        table.privacyDomainId,
        table.signerId,
        false,
      ),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();

/** Lifecycle mutations lock this row; immutable trust remains available for historical verification. */
export const businessSigningKeyStates = control
  .table(
    'business_signing_key_state',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      signerId: text('signer_id').notNull(),
      state: text('state').notNull(),
      rowVersion: u64('row_version')
        .notNull()
        .default(sql`1`),
      changedAtNs: u64('changed_at_ns').notNull(),
      changeReference: text('change_reference').notNull(),
      changeDigest: bytea('change_digest').notNull(),
    },
    (table) => [
      primaryKey({
        name: 'business_signing_state_pk',
        columns: [table.participantId, table.privacyDomainId, table.signerId],
      }),
      foreignKey({
        name: 'business_signing_state_key_fk',
        columns: [table.participantId, table.privacyDomainId, table.signerId],
        foreignColumns: [
          businessSigningKeys.participantId,
          businessSigningKeys.privacyDomainId,
          businessSigningKeys.signerId,
        ],
      }).onDelete('restrict'),
      check(
        'business_signing_state_ck',
        sql`${table.state} in ('ADMITTED','ACTIVE','RETIRED','REVOKED','COMPROMISED')`,
      ),
      check(
        'business_signing_state_version_ck',
        sql`${table.rowVersion} between 1 and 18446744073709551615`,
      ),
      check(
        'business_signing_state_change_ck',
        sql`${table.changedAtNs} between 0 and 18446744073709551615 and mod(${table.changedAtNs},1000)=0 and length(${table.changeReference}) between 1 and 256 and octet_length(${table.changeDigest})=32`,
      ),
      participantIsolationPolicy(table.participantId),
      ...identityEnvelopeRecoverySigningSourcePolicies(
        table.participantId,
        table.privacyDomainId,
        table.signerId,
        true,
      ),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();

/** Selection is exact per admitted profile. No implicit fallback to another key or epoch. */
export const businessSigningSelections = control
  .table(
    'business_signing_selection',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      environmentId: text('environment_id').notNull(),
      profileDigest: bytea('profile_digest').notNull(),
      signerId: text('signer_id').notNull(),
      rowVersion: u64('row_version')
        .notNull()
        .default(sql`1`),
      fenceGeneration: u64('fence_generation')
        .notNull()
        .default(sql`1`),
      fencedOperationId: uuid('fenced_operation_id'),
      // A changed row aborts pre-fence SERIALIZABLE writers without invalidating an exact retained signature.
      admissionVersion: u64('admission_version')
        .notNull()
        .default(sql`1`),
      changedAtNs: u64('changed_at_ns').notNull(),
      changeReference: text('change_reference').notNull(),
      changeDigest: bytea('change_digest').notNull(),
    },
    (table) => [
      primaryKey({
        name: 'business_signing_selection_pk',
        columns: [
          table.participantId,
          table.privacyDomainId,
          table.environmentId,
          table.profileDigest,
        ],
      }),
      foreignKey({
        name: 'business_signing_selection_grant_fk',
        columns: [table.participantId, table.privacyDomainId, table.signerId, table.profileDigest],
        foreignColumns: [
          businessSigningGrants.participantId,
          businessSigningGrants.privacyDomainId,
          businessSigningGrants.signerId,
          businessSigningGrants.profileDigest,
        ],
      }).onDelete('restrict'),
      check(
        'business_signing_selection_version_ck',
        sql`${table.rowVersion} between 1 and 18446744073709551615 and ${table.fenceGeneration} between 1 and 18446744073709551615 and ${table.admissionVersion} between 1 and 18446744073709551615`,
      ),
      check(
        'business_signing_selection_change_ck',
        sql`${table.changedAtNs} between 0 and 18446744073709551615 and mod(${table.changedAtNs},1000)=0 and length(${table.changeReference}) between 1 and 256 and octet_length(${table.changeDigest})=32`,
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();
