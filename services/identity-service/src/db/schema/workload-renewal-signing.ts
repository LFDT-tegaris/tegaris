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
import { businessSigningKeys } from './business-signing.js';
import { workloadCredentialFamilies } from './workload-renewal.js';
import {
  workloadRenewalSigningProfile,
  workloadRenewalSigningProfileCanonicalJson,
  workloadRenewalSigningProfileDigest,
} from '../../../../../packages/security-kernel/src/workload-renewal/generated-signing.js';

const literal = (value: string) => sql.raw(`'${value.replaceAll("'", "''")}'`);
const u64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });

/** Unsigned, exact generated trust admission for the frozen 376 artifact. */
export const workloadRenewalSigningProfiles = control.table(
  'workload_renewal_signing_profile',
  {
    profileId: text('profile_id').notNull(),
    profileVersion: smallint('profile_version').notNull(),
    profileDigest: bytea('profile_digest').primaryKey(),
    schemaDefinitionDigest: bytea('schema_definition_digest').notNull(),
    definitionCanonicalJson: bytea('definition_canonical_json').notNull(),
    signingPurposeCode: smallint('signing_purpose_code').notNull(),
  },
  (t) => [
    unique('wr_signing_profile_identity_uq').on(t.profileId, t.profileVersion),
    check(
      'wr_signing_profile_exact_ck',
      sql`${t.profileId}=${literal(workloadRenewalSigningProfile.profileId)}
    and ${t.profileVersion}=2 and ${t.signingPurposeCode}=376
    and ${t.profileDigest}=decode(${literal(workloadRenewalSigningProfileDigest.slice(7))},'hex')
    and ${t.schemaDefinitionDigest}=decode(${literal(workloadRenewalSigningProfile.schemaDefinitionDigest.slice(7))},'hex')
    and ${t.definitionCanonicalJson}=decode(${literal(Buffer.from(workloadRenewalSigningProfileCanonicalJson).toString('hex'))},'hex')
    and ${t.profileDigest}=sha256(${t.definitionCanonicalJson})`,
    ),
  ],
);

/** Immutable signer-family/security provenance. This is neither a current
 * transport credential nor a policy or instance admission. */
export const workloadRenewalSigningGrants = control
  .table(
    'workload_renewal_signing_grant',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      signerId: text('signer_id').notNull(),
      signingPurposeCode: smallint('signing_purpose_code').notNull().default(376),
      profileDigest: bytea('profile_digest').notNull(),
      principalId: uuid('principal_id').notNull(),
      workloadId: text('workload_id').notNull(),
      familyId: uuid('family_id').notNull(),
      familySecurityEpoch: u64('family_security_epoch').notNull(),
      participantSecurityInvalidationEpoch: u64(
        'participant_security_invalidation_epoch',
      ).notNull(),
      keySecurityGeneration: u64('key_security_generation').notNull(),
      providerQualificationDigest: bytea('provider_qualification_digest').notNull(),
    },
    (t) => [
      primaryKey({
        name: 'wr_signing_grant_pk',
        columns: [t.participantId, t.privacyDomainId, t.signerId, t.profileDigest],
      }),
      unique('wr_signing_grant_key_uq').on(t.participantId, t.privacyDomainId, t.signerId),
      foreignKey({
        name: 'wr_signing_grant_profile_fk',
        columns: [t.profileDigest],
        foreignColumns: [workloadRenewalSigningProfiles.profileDigest],
      }).onDelete('restrict'),
      foreignKey({
        name: 'wr_signing_grant_key_fk',
        columns: [t.participantId, t.privacyDomainId, t.signerId, t.signingPurposeCode],
        foreignColumns: [
          businessSigningKeys.participantId,
          businessSigningKeys.privacyDomainId,
          businessSigningKeys.signerId,
          businessSigningKeys.signingPurposeCode,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'wr_signing_grant_family_fk',
        columns: [t.participantId, t.privacyDomainId, t.familyId],
        foreignColumns: [
          workloadCredentialFamilies.participantId,
          workloadCredentialFamilies.privacyDomainId,
          workloadCredentialFamilies.familyId,
        ],
      }).onDelete('restrict'),
      check('wr_signing_grant_purpose_ck', sql`${t.signingPurposeCode}=376`),
      check(
        'wr_signing_grant_security_ck',
        sql`${t.familySecurityEpoch} between 0 and 18446744073709551615
    and ${t.participantSecurityInvalidationEpoch} between 0 and 18446744073709551615
    and ${t.keySecurityGeneration} between 1 and 18446744073709551615
    and octet_length(${t.providerQualificationDigest})=32`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** Initial governed installation only. Replacement requires its own admitted
 * lifecycle; no fallback or implicit generic 338/371 rotation. */
export const workloadRenewalSigningSelections = control
  .table(
    'workload_renewal_signing_selection',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      environmentId: text('environment_id').notNull(),
      profileDigest: bytea('profile_digest').notNull(),
      signerId: text('signer_id').notNull(),
      admissionVersion: u64('admission_version')
        .notNull()
        .default(sql`1`),
    },
    (t) => [
      primaryKey({
        name: 'wr_signing_selection_pk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId, t.profileDigest],
      }),
      foreignKey({
        name: 'wr_signing_selection_grant_fk',
        columns: [t.participantId, t.privacyDomainId, t.signerId, t.profileDigest],
        foreignColumns: [
          workloadRenewalSigningGrants.participantId,
          workloadRenewalSigningGrants.privacyDomainId,
          workloadRenewalSigningGrants.signerId,
          workloadRenewalSigningGrants.profileDigest,
        ],
      }).onDelete('restrict'),
      check('wr_signing_selection_version_ck', sql`${t.admissionVersion}=1`),
      check(
        'wr_signing_selection_environment_ck',
        sql`length(${t.environmentId}) between 1 and 160`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
