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
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { businessSigningKeys } from './business-signing.js';
import { uuid } from 'drizzle-orm/pg-core';
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileJson,
  identityEnvelopeSigningProfileDigest,
} from '../../../../../packages/security-kernel/src/identity-envelope/generated.js';

const literal = (value: string) => sql.raw(`'${value.replaceAll("'", "''")}'`);
const uint64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
/** Exact generated signing admission; not a receipt profile or envelope. */
export const identityEnvelopeSigningProfiles = control.table(
  'identity_envelope_signing_profile',
  {
    profileId: text('profile_id').notNull(),
    profileVersion: smallint('profile_version').notNull(),
    profileDigest: bytea('profile_digest').primaryKey(),
    schemaDefinitionDigest: bytea('schema_definition_digest').notNull(),
    definitionCanonicalJson: bytea('definition_canonical_json').notNull(),
    signingPurposeCode: smallint('signing_purpose_code').notNull(),
  },
  (table) => [
    unique('identity_envelope_signing_profile_identity_uq').on(
      table.profileId,
      table.profileVersion,
    ),
    check(
      'identity_envelope_signing_profile_exact_ck',
      sql`${table.profileId}=${literal(identityEnvelopeSigningProfile.profileId)}
    and ${table.profileVersion}=1 and ${table.signingPurposeCode}=371
    and ${table.profileDigest}=decode(${literal(identityEnvelopeSigningProfileDigest.slice(7))},'hex')
    and ${table.schemaDefinitionDigest}=decode(${literal(identityEnvelopeContext.definitionDigest.slice(7))},'hex')
    and ${table.definitionCanonicalJson}=convert_to(${literal(identityEnvelopeSigningProfileJson)},'UTF8')
    and ${table.profileDigest}=sha256(${table.definitionCanonicalJson})`,
    ),
  ],
);

/** Same immutable key/lifecycle owner, separate exact purpose grant. */
export const identityEnvelopeSigningGrants = control
  .table(
    'identity_envelope_signing_grant',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      signerId: text('signer_id').notNull(),
      signingPurposeCode: smallint('signing_purpose_code').notNull().default(371),
      profileDigest: bytea('profile_digest').notNull(),
    },
    (table) => [
      primaryKey({
        name: 'identity_envelope_signing_grant_pk',
        columns: [table.participantId, table.privacyDomainId, table.signerId, table.profileDigest],
      }),
      foreignKey({
        name: 'identity_envelope_signing_grant_profile_fk',
        columns: [table.profileDigest],
        foreignColumns: [identityEnvelopeSigningProfiles.profileDigest],
      }).onDelete('restrict'),
      foreignKey({
        name: 'identity_envelope_signing_grant_key_fk',
        columns: [
          table.participantId,
          table.privacyDomainId,
          table.signerId,
          table.signingPurposeCode,
        ],
        foreignColumns: [
          businessSigningKeys.participantId,
          businessSigningKeys.privacyDomainId,
          businessSigningKeys.signerId,
          businessSigningKeys.signingPurposeCode,
        ],
      }).onDelete('restrict'),
      check('identity_envelope_signing_grant_purpose_ck', sql`${table.signingPurposeCode}=371`),
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

/** Initial installation selection. Purpose-371 rotation is not inferred from
 * generic key metadata; unsupported replacement remains forbidden. */
export const identityEnvelopeSigningSelections = control
  .table(
    'identity_envelope_signing_selection',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      environmentId: text('environment_id').notNull(),
      profileDigest: bytea('profile_digest').notNull(),
      signerId: text('signer_id').notNull(),
      admissionVersion: uint64('admission_version')
        .notNull()
        .default(sql`1`),
    },
    (table) => [
      primaryKey({
        name: 'identity_envelope_signing_selection_pk',
        columns: [
          table.participantId,
          table.privacyDomainId,
          table.environmentId,
          table.profileDigest,
        ],
      }),
      foreignKey({
        name: 'identity_envelope_signing_selection_grant_fk',
        columns: [table.participantId, table.privacyDomainId, table.signerId, table.profileDigest],
        foreignColumns: [
          identityEnvelopeSigningGrants.participantId,
          identityEnvelopeSigningGrants.privacyDomainId,
          identityEnvelopeSigningGrants.signerId,
          identityEnvelopeSigningGrants.profileDigest,
        ],
      }).onDelete('restrict'),
      check('identity_envelope_signing_selection_version_ck', sql`${table.admissionVersion}>0`),
      check(
        'identity_envelope_signing_selection_environment_ck',
        sql`length(${table.environmentId}) between 1 and 160`,
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
