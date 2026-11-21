import {
  governedInitialEnrollmentGuardsSql,
  governedInitialEnrollmentGrantsSql,
} from './governed-initial-enrollment-guards.mjs';
import { migrationInputs } from '../../../../scripts/migrations/legacy-inputs.mjs';
import { workloadSigningHandoverPossessionGuardsSql } from './workload-signing-handover-possession-guards.mjs';
import {
  workloadSigningHandoverAdmissionGuardsSql,
  workloadSigningHandoverAdmissionGrantsSql,
} from './workload-signing-handover-admission-guards.mjs';
import { workloadSigningHandoverExecutionGuardsSql } from './workload-signing-handover-execution-guards.mjs';
import { workloadSigningHandoverPreparationGuardsSql } from './workload-signing-handover-preparation-guards.mjs';
import {
  qaSessionDurationGuardsSql,
  orderQaSessionDurationUpgrade,
} from './qa-duration-profile-guards.mjs';
import {
  discoveryApprovalResumeSourceSql,
  discoveryApprovalResumeGuardsSql,
  discoveryApprovalResumeTargetSql,
  discoveryApprovalResumeGrantsSql,
  discoveryApprovalResumeTargetGrantsSql,
} from './discovery-approval-resume-guards.mjs';
import {
  selectNewControlMigration,
  assertUnprojectedControlMigration,
} from './control-migration-generation.mjs';
import {
  rootExpiryRecoveryGuardsSql,
  rootExpiryRecoveryGrantsSql,
  rootExpiryAncestryPreambleSql,
} from './root-expiry-recovery-guards.mjs';
import {
  discoveryCertificateIssuerAttemptGuardsSql,
  discoveryCertificateIssuerAttemptGrantsSql,
} from './discovery-certificate-issuer-attempt-guards.mjs';
import {
  discoveryCertificateRecoveryGuardsSql,
  discoveryCertificateRecoveryGrantsSql,
  discoveryPreapprovalTargetGuardsSql,
  discoveryPreapprovalTargetGrantsSql,
} from './discovery-certificate-recovery-guards.mjs';
import {
  platformRecoveryLeaseProjectionSql,
  platformRecoveryLeaseGrantsSql,
  platformRecoveryResourceSql,
  platformRecoveryResourceGrantsSql,
} from './platform-recovery-lease-guards.mjs';
import {
  platformRecoveryGuardsSql,
  platformRecoveryGrantsSql,
  platformRecoveryContinuationRootPreambleSql,
} from './platform-recovery-guards.mjs';
import {
  platformRecoveryApprovalResumeGuardsSql,
  platformRecoveryApprovalResumeGrantsSql,
} from './platform-recovery-approval-resume-guards.mjs';
import { identityEnvelopeRecoveryGuardsSql } from './identity-envelope-recovery-guards.mjs';
import { identityEnvelopeRecoveryLeaseGuardsSql } from './identity-envelope-recovery-lease-guards.mjs';
import { workloadCredentialContinuationReadSql } from './workload-credential-successor.mjs';
import {
  identityEnvelopeRotationGuardsSql,
  identityEnvelopeRotationGrantsSql,
} from './identity-envelope-rotation-guards.mjs';
import { identityEnvelopeSelectionGuardsSql } from './identity-envelope-selection-guards.mjs';
import {
  administrationResourceScopeSql,
  administrationResourceScopeGrantsSql,
} from './administration-resource-scope-guards.mjs';
import { workItemLifecycleGuardsSql } from './work-item-receipt-guards.mjs';
import {
  notificationCompletionAdmissionSql,
  notificationCompletionAdmissionGrantsSql,
} from './notification-completion-admission-guards.mjs';
import { secretRecipientGuardsSql, secretRecipientGrantsSql } from './secret-recipient-guards.mjs';
import {
  mutationResumeGuardsSql,
  mutationResumeGrantsSql,
  discoveryPreapprovalFinalGuardsSql,
} from './mutation-resume-guards.mjs';
import { participantLifecycleGuardsSql } from './participant-lifecycle-guards.mjs';
import {
  authenticationOccurrenceGuardsSql,
  authenticationOccurrenceGrantsSql,
} from './authentication-occurrence-guards.mjs';
import {
  platformContextGuardsSql,
  platformContextGrantsSql,
  platformContextReadSql,
} from './platform-context-guards.mjs';
import { platformEnvelopeScopeGuardsSql } from './platform-envelope-scope-guards.mjs';
import {
  platformScopeReplacementGuardsSql,
  platformScopeReplacementGrantsSql,
  platformScopeReplacementSourcePoliciesSql,
} from './platform-scope-replacement-guards.mjs';
import { identityEnvelopeProposalGuardsSql } from './identity-envelope-proposal-guards.mjs';
import { identityEnvelopeActivationGuardsSql } from './identity-envelope-activation-guards.mjs';
import { identityEnvelopeActivationSourceGrantsSql } from './identity-envelope-activation-source-guards.mjs';
import { mfaChallengeResourceGuardsSql } from './mfa-challenge-resource-guards.mjs';
import { walletBindingGuardsSql } from './wallet-binding-guards.mjs';
import {
  authorityGroupGuardsSql,
  authorityGroupGrantsSql,
  authorityGroupUpgradeSql,
} from './authority-group-guards.mjs';
import { directoryGuardsSql } from './directory-guards.mjs';
import { invitationGuardsSql } from './invitation-guards.mjs';
import { bootstrapCustodyGuardsSql } from './bootstrap-custody-guards.mjs';
import { directoryGroupGuardsSql, directoryGroupGrantsSql } from './directory-group-guards.mjs';
import { signingOperationEvidenceGuardsSql } from './signing-operation-evidence-guards.mjs';
import { identitySubjectUpgradeSql, identitySubjectGuardsSql } from './identity-subject-guards.mjs';
import {
  identityOidcBindingUpgradeSql,
  identityOidcBindingGuardsSql,
  identityOidcBindingGrantsSql,
} from './identity-oidc-binding-guards.mjs';
import {
  scopeFunctionRevocations,
  restoreFunctionGrantsAfterReset,
  verifyConditionCases,
  verifyFunctionGrants,
} from './function-grants.ts';
import { signingGovernanceSql, signingGovernanceGrantsSql } from './signing-governance-guards.mjs';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { orderControlMigrationConstraints } from './control-migration-order.ts';

import {
  pendingDeliveryInternalActions,
  pendingDeliverySql,
} from '../generated/pending-delivery-projection.ts';
import { idempotencyPrivacyUpgrade } from './idempotency-privacy-upgrade.mjs';
import { businessCborSql } from './business-cbor.mjs';
import { businessSigningGuardsSql } from './business-signing-guards.mjs';
import { orderIdentityEnvelopeSigningPrerequisite } from './identity-envelope-signing-upgrade.mjs';
import { orderIdentityEnvelopeProposalUpgrade } from './identity-envelope-proposal-upgrade.mjs';
import { businessReceiptGuardsSql } from './business-receipt-guards.mjs';
import { authoritySnapshotGuardsSql } from './authority-snapshot-guards.mjs';
import { businessCustodyGuardsSql } from './business-custody-guards.mjs';
import {
  signingContinuationGuardsSql,
  signingContinuationGrantsSql,
} from './signing-continuation-guards.mjs';
import { signingAttemptAuthorityGrantsSql } from './signing-attempt-authority.mjs';
import { signingRotationGuardsSql } from './signing-rotation-guards.mjs';
import { workloadRenewalGuardsSql } from './workload-renewal-guards.mjs';
import { workloadRenewalPolicyGuardsSql } from './workload-renewal-policy-guards.mjs';
import { workloadRenewalSigningGuardsSql } from './workload-renewal-signing-guards.mjs';
import { getTableConfig, PgDialect } from 'drizzle-orm/pg-core';
import { workloadRenewalSigningProfiles } from './schema/workload-renewal-signing.ts';
import { receiptSigningAttemptGuardsSql } from './receipt-signing-attempt-guards.mjs';
import {
  authorityRoleUpgradeSql,
  authorityRoleGuardsSql,
  authorityRoleGrantsSql,
} from './authority-role-guards.mjs';

const preambleStart = '-- OPENPC GENERATED REQUEST CONTEXT PREAMBLE; DO NOT EDIT';
const preambleEnd = '-- END OPENPC GENERATED REQUEST CONTEXT PREAMBLE';
const tailMarker = '-- OPENPC GENERATED SECURITY TAIL; DO NOT EDIT';
const directory = fileURLToPath(
  new URL('../../../../migrations/postgres/identity/', import.meta.url),
);
const { migrations, readMigration } = await migrationInputs(directory);
const migration = selectNewControlMigration(process.argv.slice(2), migrations);

const path = join(directory, migration);
const generated = await readFile(path, 'utf8');
assertUnprojectedControlMigration(generated);
const withoutPreamble = generated.includes(preambleEnd)
  ? generated.slice(generated.indexOf(preambleEnd) + preambleEnd.length).trimStart()
  : generated;
const previousMigration = migrations.at(-2);
const priorSnapshot =
  previousMigration === undefined
    ? undefined
    : JSON.parse(
        await readFile(
          join(directory, 'meta', `${previousMigration.slice(0, 4)}_snapshot.json`),
          'utf8',
        ),
      );
let base = orderControlMigrationConstraints(
  withoutPreamble.split(tailMarker, 1)[0].trimEnd(),
  priorSnapshot,
);
if (base.includes('CONSTRAINT "wr_signing_profile_exact_ck"')) {
  const constraint = getTableConfig(workloadRenewalSigningProfiles).checks.find(
    (check) => check.name === 'wr_signing_profile_exact_ck',
  );
  if (!constraint) throw new Error('Missing owning renewal signing profile constraint');
  const expected = new PgDialect().sqlToQuery(constraint.value).sql.replaceAll(/\s+/gu, ' ').trim();
  if (!base.replaceAll(/\s+/gu, ' ').includes(`CHECK (${expected})`))
    throw new Error(
      'Generated renewal signing profile CHECK differs from its complete owning schema',
    );
}
const history = (
  await Promise.all(
    migrations.map(async (name) => {
      const contents = await readMigration(name);
      const unwrapped = contents.includes(preambleEnd)
        ? contents.slice(contents.indexOf(preambleEnd) + preambleEnd.length)
        : contents;
      return unwrapped.split(tailMarker, 1)[0];
    }),
  )
).join('\n');
if (base.includes('authority_group_member_active_uq') && !base.includes('DO $group_upgrade$'))
  base += '\n' + authorityGroupUpgradeSql;
const rlsTables = [
  ...history.matchAll(/ALTER TABLE "control"\."([^"]+)" ENABLE ROW LEVEL SECURITY;/gu),
]
  .map((match) => match[1])
  .filter((table, index, tables) => tables.indexOf(table) === index)
  .sort();
const allTables = [...history.matchAll(/CREATE TABLE "control"\."([^"]+)"/gu)]
  .map((match) => match[1])
  .filter((table, index, tables) => tables.indexOf(table) === index)
  .sort();
const discoveryPreapprovalReady = [
  'participant',
  'privacy_domain',
  'principal',
  'session',
  'assignment',
  'authority_envelope',
  'platform_recovery_case',
  'platform_recovery_enrollment',
  'mutation_candidate',
  'mfa_challenge',
  'credential',
  'mutation_evidence',
  'idempotency_record',
  'outbox_event',
  'approval_decision_record',
  'approval_request',
  'discovery_certificate_issuance',
  'discovery_certificate_issuer_attempt',
  'audit_occurrence',
  'receipt_signing_attempt',
  'business_transition_profile',
].every((table) => allTables.includes(table));

if (rlsTables.length === 0 || allTables.length === 0) {
  throw new Error('No Drizzle control tables were generated');
}

if (allTables.includes('pending_delivery')) {
  const activeIndex = /CREATE UNIQUE INDEX "pending_delivery_active_full_identity_uq"[^;]+;/u;
  const match = history.match(activeIndex);
  if (match === null) throw new Error('pending delivery active identity index is missing');
  const normalized = match[0].replaceAll(/\s+/gu, '').toLowerCase();
  if (
    !normalized.includes(
      pendingDeliverySql.fullIdentityColumns.replaceAll(/\s+/gu, '').toLowerCase(),
    ) ||
    !normalized.includes(pendingDeliverySql.activePredicate.replaceAll(/\s+/gu, '').toLowerCase())
  ) {
    throw new Error('pending delivery active identity index drifted from its projection');
  }
  const currentMatch = base.match(activeIndex);
  if (currentMatch !== null && !currentMatch[0].includes('NULLS NOT DISTINCT')) {
    const corrected = currentMatch[0].replace(/\) WHERE/u, ') NULLS NOT DISTINCT WHERE');
    if (corrected === currentMatch[0]) {
      throw new Error('unable to project NULLS NOT DISTINCT onto the active identity index');
    }
    base = base.replace(currentMatch[0], corrected);
  }
  const historyConstraint =
    /CONSTRAINT "pending_delivery_full_identity_history_uq" UNIQUE NULLS NOT DISTINCT\([^;]+\)/u;
  const historyMatch = history.match(historyConstraint);
  if (
    historyMatch === null ||
    !historyMatch[0]
      .replaceAll(/\s+/gu, '')
      .toLowerCase()
      .includes(pendingDeliverySql.fullIdentityColumns.replaceAll(/\s+/gu, '').toLowerCase())
  ) {
    throw new Error('pending delivery history identity constraint drifted from its projection');
  }
  const successorConstraint = /CONSTRAINT "pending_delivery_successor_guard_uq" UNIQUE\([^;]+\)/u;
  const successorMatch = history.match(successorConstraint);
  if (
    successorMatch === null ||
    !successorMatch[0]
      .replaceAll(/\s+/gu, '')
      .toLowerCase()
      .includes(pendingDeliverySql.successorGuardColumns.replaceAll(/\s+/gu, '').toLowerCase())
  ) {
    throw new Error('pending delivery successor guard drifted from its projection');
  }
}

const workloadConstraint =
  /ALTER TABLE "control"\."credential" ADD CONSTRAINT "credential_workload_mtls_ck" CHECK \([^;]+\);/u;
const privacyColumn =
  'ALTER TABLE "control"."idempotency_record" ADD COLUMN "privacy_domain_id" uuid NOT NULL;';
if (base.includes(privacyColumn)) {
  base = base.replace(
    privacyColumn,
    () =>
      'ALTER TABLE "control"."idempotency_record" ADD COLUMN "privacy_domain_id" uuid;\n' +
      idempotencyPrivacyUpgrade +
      '\nALTER TABLE "control"."idempotency_record" ALTER COLUMN "privacy_domain_id" SET NOT NULL;',
  );
}
base = base.replace(
  /UPDATE "control"\."credential"[\s\S]*?(?=ALTER TABLE "control"\."credential" ADD CONSTRAINT "credential_workload_mtls_ck")/u,
  '',
);
const workloadConstraintMatch = base.match(workloadConstraint);
if (workloadConstraintMatch !== null) {
  const workloadUpgrade = `UPDATE "control"."credential"
SET "audience" = "subject",
    "subject" = 'urn:openpc:participant:' || "participant_id"::text || ':workload:' ||
                substring("subject" from '([0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$')
WHERE "kind" = 'WORKLOAD_MTLS' AND "audience" IS NULL
  AND "subject" ~ '^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';`;
  base = base.replace(
    workloadConstraintMatch[0],
    () => `${workloadUpgrade}\n${workloadConstraintMatch[0]}`,
  );
}

// Drizzle 0.31 emits a commented placeholder when replacing an inline primary key.
// Resolve only this known invitation-history transition, preserving every receipt.
const invitationPrimaryKeyPlaceholder =
  '-- ALTER TABLE "participant_invitation_acceptance" DROP CONSTRAINT "<constraint_name>";';
if (base.includes(invitationPrimaryKeyPlaceholder)) {
  if (!base.includes('PRIMARY KEY("invitation_id","token_version")'))
    throw new Error('Unexpected invitation acceptance primary key transition');
  base = base.replace(
    invitationPrimaryKeyPlaceholder,
    () => `DO $$
DECLARE previous_key text;
BEGIN
 SELECT constraint_row.conname INTO STRICT previous_key FROM pg_catalog.pg_constraint constraint_row
 JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=constraint_row.conrelid AND attribute.attname='invitation_id'
 WHERE constraint_row.conrelid='control.participant_invitation_acceptance'::regclass AND constraint_row.contype='p'
   AND constraint_row.conkey=ARRAY[attribute.attnum]::smallint[];
 EXECUTE format('ALTER TABLE control.participant_invitation_acceptance DROP CONSTRAINT %I',previous_key);
END $$;`,
  );
}

// Drizzle emits new foreign keys to existing tables before the new referenced
// unique keys. Move only these generated prerequisites, after ADD COLUMN and
// before FK creation; keep the schema, constraints and names authoritative.
if (base.includes('CREATE TABLE "control"."audit_occurrence"')) {
  const prerequisites = [
    /ALTER TABLE "control"\."credential" ADD CONSTRAINT "credential_participant_id_uq" UNIQUE[^;]+;/u,
    /CREATE UNIQUE INDEX "idempotency_record_scope_id_uq"[^;]+;/u,
  ];
  const statements = [];
  for (const pattern of prerequisites) {
    const match = base.match(pattern);
    if (match === null) throw new Error('Business receipt FK prerequisite missing');
    statements.push(match[0]);
    base = base.replace(match[0], '');
  }
  const foreignKey = /ALTER TABLE "control"\."[^"]+" ADD CONSTRAINT "[^"]+" FOREIGN KEY/u;
  const match = base.match(foreignKey);
  if (match === null) throw new Error('Business receipt FK boundary missing');
  base = base.replace(match[0], () => statements.join('\n') + '\n' + match[0]);
}

base = orderIdentityEnvelopeSigningPrerequisite(base);
base = orderIdentityEnvelopeProposalUpgrade(base);
base = orderQaSessionDurationUpgrade(base);
const quoteTables = (tables) => tables.map((table) => `"control"."${table}"`).join(', ');
if (base.includes('CREATE TABLE "control"."authority_role"')) {
  base = base.replace(
    /-- OPENPC GENERATED ROLE UPGRADE[\s\S]*?-- END OPENPC GENERATED ROLE UPGRADE\n?/u,
    '',
  );
  const roleForeignKey =
    /ALTER TABLE "control"\."assignment" ADD CONSTRAINT "assignment_role_fk"[^;]+;/u;
  const match = base.match(roleForeignKey);
  if (match === null) throw new Error('Assignment role migration binding is missing');
  base = base.replace(match[0], () => authorityRoleUpgradeSql + '\n' + match[0]);
}
const quotedAllTables = quoteTables(allTables);
if (base.includes('CREATE TABLE "control"."identity_oidc_binding"'))
  base =
    base.replaceAll(identityOidcBindingUpgradeSql.trim(), '').trimEnd() +
    '\n' +
    identityOidcBindingUpgradeSql;
if (base.includes('CREATE TABLE "control"."identity_subject"')) {
  base =
    base.replace(identitySubjectUpgradeSql.trim(), '').trimEnd() + '\n' + identitySubjectUpgradeSql;
}
const mutableRuntimeTables = allTables.filter(
  (table) =>
    ![
      'workload_signing_handover',
      'workload_signing_handover_attempt',
      'workload_signing_handover_generation',
      'workload_signing_handover_dispatch',
      'workload_signing_handover_observation',
      'action_intent',
      'approval_decision_record',
      'authority_envelope',
      'platform_context',
      'root_expiry_recovery_trust',
      'root_expiry_recovery_enrollment',
      'root_expiry_recovery_scope',
      'root_expiry_recovery_case',
      'root_expiry_recovery_challenge',
      'root_expiry_recovery_proof',
      'platform_recovery_enrollment',
      'identity_envelope_recovery_custody_trust',
      'identity_envelope_recovery_enrollment',
      'platform_recovery_case',
      'platform_recovery_challenge',
      'platform_recovery_proof',
      'platform_envelope_scope',
      'platform_scope_replacement',
      'platform_envelope_scope_successor',
      'identity_envelope_proposal',
      'identity_envelope_activation',
      'mutation_evidence',
      'mutation_candidate',
      'outbox_aggregate_head',
      'outbox_event',
      'pending_delivery',
      'revocation',
      'business_transition_profile',
      'business_outbox_head',
      'business_signing_key',
      'business_signing_grant',
      'business_signing_key_state',
      'business_signing_selection',
      'identity_envelope_signing_profile',
      'identity_envelope_signing_grant',
      'identity_envelope_signing_selection',
      'workload_renewal_signing_profile',
      'workload_renewal_signing_grant',
      'workload_renewal_signing_selection',
      'audit_occurrence',
      'evidence_record',
      'receipt_signing_attempt',
      'signing_rotation_attestation',
      'signing_rotation_observation',
      'signing_continuation',
      'signing_rotation_authority_hold',
      'signing_rotation_operation_evidence',
      'signing_authorization_generation',
      'identity_envelope_rotation_step',
      'identity_envelope_rotation_attempt',
      'identity_runtime_snapshot',
      'identity_runtime_snapshot_content',
      'identity_runtime_authority_set',
    ].includes(table),
);
const hasBusinessReceipts = allTables.includes('audit_occurrence');
// Post-reset fragments must contain ACL statements only. Moving a function or
// trigger here would bypass ownership normalization and the shared reset.
const envelopeRotationAcl = identityEnvelopeRotationGrantsSql
  .split(';')
  .map((statement) => statement.trim())
  .filter(Boolean);
if (
  envelopeRotationAcl.length !== 4 ||
  envelopeRotationAcl.some((statement) => !/^(GRANT|REVOKE)\b/u.test(statement))
)
  throw new Error('Envelope rotation grants must contain only the four owned ACL statements');
const [rotationDefinitions, rotationGrants] = allTables.includes('signing_key_rotation')
  ? signingRotationGuardsSql.split(/(?=REVOKE INSERT,UPDATE ON control\.qualified_receipt_inbox)/u)
  : ['', ''];
const businessImmutableTables = [
  'workload_signing_handover',
  'workload_signing_handover_attempt',
  'workload_signing_handover_generation',
  'workload_signing_handover_dispatch',
  'workload_signing_handover_observation',
  'business_transition_profile',
  'business_signing_key',
  'business_signing_grant',
  'identity_envelope_signing_profile',
  'identity_envelope_signing_grant',
  'workload_renewal_signing_profile',
  'workload_renewal_signing_grant',
  'audit_occurrence',
  'evidence_record',
  'receipt_signing_attempt',
  'signing_rotation_attestation',
  'signing_rotation_observation',
];
const businessGuards = hasBusinessReceipts
  ? (
      businessCborSql +
      businessSigningGuardsSql +
      businessReceiptGuardsSql +
      administrationResourceScopeSql +
      authoritySnapshotGuardsSql +
      businessCustodyGuardsSql +
      receiptSigningAttemptGuardsSql +
      workloadSigningHandoverPreparationGuardsSql +
      workloadSigningHandoverExecutionGuardsSql +
      workloadSigningHandoverPossessionGuardsSql +
      workloadSigningHandoverAdmissionGuardsSql +
      businessImmutableTables
        .map(
          (table) => `
CREATE TRIGGER ${table}_immutable BEFORE UPDATE OR DELETE ON control.${table} FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();`,
        )
        .join('')
    ).replace(
      /CREATE (?:CONSTRAINT )?TRIGGER ([a-z_]+)([\s\S]*?) ON control\.([a-z_]+)/gu,
      (match, name, _body, table) =>
        `DROP TRIGGER IF EXISTS ${name} ON control.${table};\n${match}`,
    )
  : '';
const businessGrants = hasBusinessReceipts
  ? `
${[
  'business_signing_key',
  'business_signing_grant',
  'business_signing_key_state',
  'business_signing_selection',
  'identity_envelope_signing_grant',
  'identity_envelope_signing_selection',
  'workload_renewal_signing_grant',
  'workload_renewal_signing_selection',
]
  .map(
    (table) => `
DROP POLICY IF EXISTS key_governor_scope ON control.${table};
CREATE POLICY key_governor_scope ON control.${table} AS PERMISSIVE FOR ALL TO openpc_control_key_governor
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));`,
  )
  .join('')}
${['credential', 'principal', 'participant']
  .map(
    (table) => `
DROP POLICY IF EXISTS key_governor_identity_read ON control.${table};
CREATE POLICY key_governor_identity_read ON control.${table} AS PERMISSIVE FOR SELECT TO openpc_control_key_governor
 USING(openpc.matches_participant(participant_id));`,
  )
  .join('')}
GRANT INSERT ON control.workload_signing_handover_generation,control.workload_signing_handover,control.workload_signing_handover_attempt,control.workload_signing_handover_dispatch,control.workload_signing_handover_observation TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT ON control.audit_occurrence,control.evidence_record,control.receipt_signing_attempt,control.signing_rotation_attestation TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT,UPDATE(last_sequence,updated_at) ON control.business_outbox_head TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT UPDATE(row_version) ON control.business_signing_selection,control.business_signing_key_state TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT INSERT ON control.business_signing_key,control.business_signing_grant,control.business_signing_key_state,control.business_signing_selection TO openpc_control_key_governor;
GRANT INSERT ON control.identity_envelope_signing_profile,control.identity_envelope_signing_grant,control.identity_envelope_signing_selection TO openpc_control_key_governor;
GRANT INSERT,SELECT ON control.workload_renewal_signing_profile,control.workload_renewal_signing_grant,control.workload_renewal_signing_selection TO openpc_control_key_governor;
-- PostgreSQL row locks require a column UPDATE privilege. The selection's
-- immutable trigger rejects every actual UPDATE/DELETE, including this column.
GRANT UPDATE(admission_version) ON control.workload_renewal_signing_selection TO openpc_control_runtime,openpc_control_platform_runtime;
-- Permit a consistency row lock, not a selector write. The selection guard
-- requires a changed signer and exact governed provenance for any UPDATE,
-- while this column grant cannot update signer_id.
GRANT UPDATE(admission_version) ON control.identity_envelope_signing_selection TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT SELECT ON control.workload_credential_family,control.privacy_domain TO openpc_control_key_governor;
DROP POLICY IF EXISTS wr_signing_installation_family_read ON control.workload_credential_family;
CREATE POLICY wr_signing_installation_family_read ON control.workload_credential_family AS PERMISSIVE FOR SELECT TO openpc_control_key_governor
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
DROP POLICY IF EXISTS wr_signing_installation_privacy_read ON control.privacy_domain;
CREATE POLICY wr_signing_installation_privacy_read ON control.privacy_domain AS PERMISSIVE FOR SELECT TO openpc_control_key_governor
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
GRANT USAGE ON SCHEMA control,openpc TO openpc_control_key_governor;
GRANT SELECT ON control.business_signing_key,control.business_signing_grant,control.business_signing_key_state,control.business_signing_selection,control.business_transition_profile,
 control.identity_envelope_signing_profile,control.identity_envelope_signing_grant,control.identity_envelope_signing_selection TO openpc_control_key_governor;
GRANT SELECT(participant_id,credential_id,principal_id,kind,credential_epoch,public_key_digest,state,valid_from,valid_until,audience,secret_fingerprint) ON control.credential TO openpc_control_key_governor;
GRANT SELECT(participant_id,principal_id,kind,state,authority_epoch) ON control.principal TO openpc_control_key_governor;
GRANT SELECT(participant_id,state,authority_epoch) ON control.participant TO openpc_control_key_governor;
GRANT UPDATE(state,row_version,changed_at_ns,change_reference,change_digest) ON control.business_signing_key_state TO openpc_control_key_governor;
GRANT UPDATE(signer_id,row_version,fence_generation,fenced_operation_id,changed_at_ns,change_reference,change_digest) ON control.business_signing_selection TO openpc_control_key_governor;
GRANT EXECUTE ON FUNCTION openpc.work_item_business_projection(control.work_item),openpc.assert_work_item_receipt(control.audit_occurrence)
 TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.configuration_step_up_receipt_input(control.audit_occurrence,control.mutation_evidence) TO openpc_control_runtime;
GRANT EXECUTE ON FUNCTION openpc.identity_runtime_cose_key_id(bytea,bytea),openpc.check_module_admission_receipt(control.audit_occurrence),openpc.check_governed_configuration_receipt(control.audit_occurrence) TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT EXECUTE ON FUNCTION openpc.business_cbor_item(bytea,integer,integer),openpc.business_cbor(bytea),openpc.business_bytes(bytea),openpc.business_uuid(uuid),openpc.business_request_digest(text[])
 TO openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_key_governor;
`
  : '';
const forceStatements = rlsTables
  .map((table) => `ALTER TABLE "control"."${table}" FORCE ROW LEVEL SECURITY;`)
  .join('\n');
const ownershipStatements = allTables
  .map((table) => `ALTER TABLE "control"."${table}" OWNER TO "openpc_control_owner";`)
  .join('\n');

const requestContextPreamble = `${preambleStart}
CREATE SCHEMA IF NOT EXISTS openpc;
CREATE OR REPLACE FUNCTION openpc.action_intent_semantic_digest(
  p_action_intent_id text, p_resource_type text, p_operation_class text, p_risk_class text,
  p_maker_checker_required boolean, p_step_up_required boolean, p_idempotency_required boolean,
  p_existence_disclosure text, p_payload_disclosure text, p_evidence_class text
) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog AS $$
  SELECT sha256(
    convert_to(p_action_intent_id, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_resource_type, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_operation_class, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_risk_class, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_maker_checker_required::text, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_step_up_required::text, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_idempotency_required::text, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_existence_disclosure, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_payload_disclosure, 'UTF8') || decode('00', 'hex') ||
    convert_to(p_evidence_class, 'UTF8')
  )
$$;
CREATE OR REPLACE FUNCTION openpc.require_uuid_setting(p_name text)
RETURNS uuid LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE value text; parsed uuid;
BEGIN
  value := current_setting(p_name, true);
  IF value IS NULL OR value = '' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6000-CONTEXT-MISSING', DETAIL = p_name;
  END IF;
  BEGIN parsed := value::uuid;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID', DETAIL = p_name;
  END;
  RETURN parsed;
END $$;
CREATE OR REPLACE FUNCTION openpc.current_participant_id()
RETURNS uuid LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, openpc
AS $$ SELECT openpc.require_uuid_setting('openpc.participant_id') $$;
CREATE OR REPLACE FUNCTION openpc.current_privacy_domain_id()
RETURNS uuid LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, openpc
AS $$ SELECT openpc.require_uuid_setting('openpc.privacy_domain_id') $$;
CREATE OR REPLACE FUNCTION openpc.current_operation_id()
RETURNS uuid LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, openpc
AS $$ SELECT openpc.require_uuid_setting('openpc.operation_id') $$;
CREATE OR REPLACE FUNCTION openpc.current_action_intent_id()
RETURNS text LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE value text;
BEGIN
  value := current_setting('openpc.action_intent_id', true);
  IF value IS NULL OR value !~ '^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID', DETAIL = 'openpc.action_intent_id';
  END IF;
  RETURN value;
END $$;
CREATE OR REPLACE FUNCTION openpc.set_request_context(
  p_mode text, p_participant_id uuid, p_privacy_domain_id uuid,
  p_operation_id uuid, p_action_intent_id text, p_require_privacy boolean DEFAULT true
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog, openpc AS $$
BEGIN
  IF p_mode NOT IN ('PARTICIPANT', 'PLATFORM') THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID', DETAIL = 'openpc.context_mode';
  END IF;
  IF p_operation_id::text !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_action_intent_id !~ '^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID';
  END IF;
  IF p_mode = 'PLATFORM' AND NOT (
    current_user = 'openpc_control_platform_runtime'
    OR pg_has_role(current_user, 'openpc_control_platform_runtime', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_migrator', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_maintenance', 'MEMBER')
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6002-PLATFORM-CONTEXT-FORBIDDEN';
  END IF;
  IF p_require_privacy AND p_privacy_domain_id IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6000-CONTEXT-MISSING', DETAIL = 'privacy_domain_id';
  END IF;
  PERFORM set_config('openpc.context_mode', p_mode, true);
  PERFORM set_config('openpc.participant_id', p_participant_id::text, true);
  PERFORM set_config('openpc.privacy_domain_id', coalesce(p_privacy_domain_id::text, ''), true);
  PERFORM set_config('openpc.operation_id', p_operation_id::text, true);
  PERFORM set_config('openpc.action_intent_id', p_action_intent_id, true);
  PERFORM set_config('openpc.context_scope', 'TRANSACTION_LOCAL', true);
END $$;
CREATE OR REPLACE FUNCTION openpc.assert_request_context(p_require_privacy boolean DEFAULT true)
RETURNS void LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = pg_catalog, openpc AS $$
DECLARE mode text;
BEGIN
  mode := current_setting('openpc.context_mode', true);
  IF current_setting('openpc.context_scope', true) <> 'TRANSACTION_LOCAL' OR mode NOT IN ('PARTICIPANT', 'PLATFORM') THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6001-CONTEXT-INVALID';
  END IF;
  PERFORM openpc.current_participant_id();
  PERFORM openpc.current_operation_id();
  PERFORM openpc.current_action_intent_id();
  IF p_require_privacy THEN PERFORM openpc.current_privacy_domain_id(); END IF;
  IF mode = 'PLATFORM' AND NOT (
    current_user = 'openpc_control_platform_runtime'
    OR pg_has_role(current_user, 'openpc_control_platform_runtime', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_migrator', 'MEMBER')
    OR pg_has_role(current_user, 'openpc_control_maintenance', 'MEMBER')
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6002-PLATFORM-CONTEXT-FORBIDDEN';
  END IF;
END $$;
CREATE OR REPLACE FUNCTION openpc.matches_participant(p_participant_id uuid)
RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY INVOKER SET search_path = pg_catalog, openpc
AS $$ SELECT p_participant_id = openpc.current_participant_id() $$;
CREATE OR REPLACE FUNCTION openpc.matches_privacy(p_privacy_domain_id uuid)
RETURNS boolean LANGUAGE sql STABLE STRICT SECURITY INVOKER SET search_path = pg_catalog, openpc
AS $$ SELECT p_privacy_domain_id = openpc.current_privacy_domain_id() $$;
${base.includes('openpc.platform_recovery_continuation_root_matches(') || base.includes('openpc.platform_history_') ? platformRecoveryContinuationRootPreambleSql : ''}
${base.includes('openpc.root_expiry_pending_ancestry(') ? rootExpiryAncestryPreambleSql : ''}
${
  base.includes('openpc.platform_recovery_installation_source_current(')
    ? `
-- Fail closed until the security tail installs the invoker/RLS predicate.
CREATE OR REPLACE FUNCTION openpc.platform_recovery_installation_source_current(p_enrollment uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN RETURN false; END $$;
REVOKE ALL ON FUNCTION openpc.platform_recovery_installation_source_current(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.platform_recovery_installation_source_current(uuid) TO openpc_control_owner;
`
    : ''
}
${
  base.includes('openpc.identity_envelope_recovery_installation_source_current(')
    ? `
-- Fail closed until the purpose-specific invoker/RLS predicate is installed.
CREATE OR REPLACE FUNCTION openpc.identity_envelope_recovery_installation_source_current(p_enrollment uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN RETURN false; END $$;
REVOKE ALL ON FUNCTION openpc.identity_envelope_recovery_installation_source_current(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.identity_envelope_recovery_installation_source_current(uuid) TO openpc_control_owner;
`
    : ''
}
${
  base.includes('openpc.root_expiry_recovery_installation_source_current(')
    ? `
CREATE OR REPLACE FUNCTION openpc.root_expiry_recovery_installation_source_current(p_enrollment uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$
BEGIN RETURN false; END $$;
REVOKE ALL ON FUNCTION openpc.root_expiry_recovery_installation_source_current(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.root_expiry_recovery_installation_source_current(uuid) TO openpc_control_owner;
`
    : ''
}
${
  base.includes('openpc.read_workload_credential_continuation_evidence(')
    ? `
CREATE OR REPLACE FUNCTION openpc.read_workload_credential_continuation_evidence(p_enrollment uuid)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on
AS $$ SELECT '[]'::jsonb $$;
REVOKE ALL ON FUNCTION openpc.read_workload_credential_continuation_evidence(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_workload_credential_continuation_evidence(uuid) TO openpc_control_owner;
`
    : ''
}
${
  base.includes('openpc.read_workload_credential_continuation_scope(')
    ? `
CREATE OR REPLACE FUNCTION openpc.read_workload_credential_continuation_scope()
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on
AS $$ SELECT '[]'::jsonb $$;
REVOKE ALL ON FUNCTION openpc.read_workload_credential_continuation_scope() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_workload_credential_continuation_scope() TO openpc_control_owner;
`
    : ''
}
${
  base.includes('openpc.read_workload_credential_continuation_ids(')
    ? `
CREATE OR REPLACE FUNCTION openpc.read_workload_credential_continuation_ids(p_enrollment uuid,p_kind text)
RETURNS uuid[] LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on
AS $$ SELECT ARRAY[]::uuid[] $$;
REVOKE ALL ON FUNCTION openpc.read_workload_credential_continuation_ids(uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.read_workload_credential_continuation_ids(uuid,text) TO openpc_control_owner;
`
    : ''
}
${base.includes('openpc.platform_context_scoped_read_current(') ? platformContextReadSql : ''}
${preambleEnd}`;

const securityTail = `${tailMarker}
INSERT INTO "control"."action_intent"
  ("action_intent_id","resource_type","operation_class","risk_class",
   "maker_checker_required","step_up_required","idempotency_required",
   "existence_disclosure","payload_disclosure","evidence_class")
VALUES
  ('${pendingDeliveryInternalActions.enqueue}','pending-delivery','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','PENDING_DELIVERY_MUTATION'),
  ('${pendingDeliveryInternalActions.transition}','pending-delivery','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','PENDING_DELIVERY_MUTATION')
ON CONFLICT ("action_intent_id") DO NOTHING;
DO $pending_delivery_actions$
BEGIN
  IF (SELECT count(*) FROM "control"."action_intent"
       WHERE ("action_intent_id","resource_type","operation_class","risk_class",
              "maker_checker_required","step_up_required","idempotency_required",
              "existence_disclosure","payload_disclosure","evidence_class") IN (
         ('${pendingDeliveryInternalActions.enqueue}','pending-delivery','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','PENDING_DELIVERY_MUTATION'),
         ('${pendingDeliveryInternalActions.transition}','pending-delivery','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','PENDING_DELIVERY_MUTATION')
       )) <> 2 THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'pending delivery internal action registration';
  END IF;
END
$pending_delivery_actions$;
CREATE OR REPLACE FUNCTION openpc.enforce_pending_delivery_lifecycle()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE captured_now timestamptz := clock_timestamp();
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.pending_delivery';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW."state" <> 'PENDING' OR NEW."lease_owner" IS NOT NULL
       OR NEW."lease_expires_at" IS NOT NULL OR NEW."next_retry_at" IS NOT NULL
       OR NEW."safe_reason" IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'pending delivery initial state';
    END IF;
    NEW."first_observed_at" := captured_now;
    NEW."last_observed_at" := captured_now;
    RETURN NEW;
  END IF;
  IF ${pendingDeliverySql.immutableReceiptChanged}
     OR ${pendingDeliverySql.immutableIdentityChanged} THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'pending delivery identity';
  END IF;
  IF NOT (${pendingDeliverySql.legalTransition})
     AND NOT (OLD."state" = 'LEASED' AND NEW."state" = 'LEASED'
              AND OLD."lease_expires_at" <= captured_now) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6022-INVALID-STATE-TRANSITION', DETAIL = 'pending delivery lifecycle';
  END IF;
  NEW."first_observed_at" := OLD."first_observed_at";
  NEW."last_observed_at" := captured_now;
  IF NEW."state" = 'LEASED' THEN
    IF NEW."lease_owner" IS NULL OR NEW."lease_expires_at" IS NULL
       OR NEW."lease_expires_at" <= captured_now THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'pending delivery lease';
    END IF;
    NEW."next_retry_at" := NULL;
    NEW."safe_reason" := NULL;
  ELSIF NEW."state" = 'RETRY_WAIT' THEN
    IF NEW."next_retry_at" IS NULL OR NEW."next_retry_at" <= captured_now THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'pending delivery retry';
    END IF;
    NEW."lease_owner" := NULL;
    NEW."lease_expires_at" := NULL;
    NEW."safe_reason" := NULL;
  ELSIF NEW."state" = 'QUARANTINED' THEN
    IF NEW."safe_reason" IS NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'pending delivery quarantine';
    END IF;
    NEW."lease_owner" := NULL;
    NEW."lease_expires_at" := NULL;
    NEW."next_retry_at" := NULL;
  ELSE
    NEW."lease_owner" := NULL;
    NEW."lease_expires_at" := NULL;
    NEW."next_retry_at" := NULL;
    NEW."safe_reason" := NULL;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS pending_delivery_lifecycle ON "control"."pending_delivery";
CREATE TRIGGER pending_delivery_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON "control"."pending_delivery"
FOR EACH ROW EXECUTE FUNCTION openpc.enforce_pending_delivery_lifecycle();
${workItemLifecycleGuardsSql}
CREATE OR REPLACE FUNCTION openpc.enforce_mutation_candidate_lifecycle()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.mutation_candidate';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW."state" <> 'PROPOSED' OR NEW."consumed_operation_id" IS NOT NULL THEN
      RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.mutation_candidate initial state';
    END IF;
    RETURN NEW;
  END IF;
  IF row(NEW."mutation_candidate_id",NEW."participant_id",NEW."privacy_domain_id",
         NEW."action_intent_id",NEW."catalog_operation_id",NEW."resource_type",
         NEW."operation_class",NEW."resource_id",NEW."candidate_digest",
         NEW."candidate_document",NEW."expected_revision",NEW."idempotency_key",
         NEW."maker_principal_id",NEW."maker_session_id",NEW."maker_session_epoch",
         NEW."maker_participant_epoch",NEW."maker_principal_epoch",NEW."maker_assignment_id",
         NEW."maker_assignment_row_version",NEW."maker_authority_envelope_id",
         NEW."maker_authority_epoch",NEW."maker_delegation_epoch",NEW."expires_at",NEW."created_at")
     IS DISTINCT FROM
     row(OLD."mutation_candidate_id",OLD."participant_id",OLD."privacy_domain_id",
         OLD."action_intent_id",OLD."catalog_operation_id",OLD."resource_type",
         OLD."operation_class",OLD."resource_id",OLD."candidate_digest",
         OLD."candidate_document",OLD."expected_revision",OLD."idempotency_key",
         OLD."maker_principal_id",OLD."maker_session_id",OLD."maker_session_epoch",
         OLD."maker_participant_epoch",OLD."maker_principal_epoch",OLD."maker_assignment_id",
         OLD."maker_assignment_row_version",OLD."maker_authority_envelope_id",
         OLD."maker_authority_epoch",OLD."maker_delegation_epoch",OLD."expires_at",OLD."created_at") THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = 'control.mutation_candidate identity';
  END IF;
  IF NOT ((OLD."state" = 'PROPOSED' AND NEW."state" IN ('APPROVAL_REQUESTED','CANCELLED'))
          OR (OLD."state" = 'APPROVAL_REQUESTED' AND NEW."state" IN ('APPROVAL_REQUESTED','APPROVED','CANCELLED'))
          OR (OLD."state" = 'APPROVED' AND NEW."state" = 'CONSUMED')) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6022-INVALID-STATE-TRANSITION', DETAIL = 'control.mutation_candidate lifecycle';
  END IF;
  IF NEW."updated_at" <= OLD."updated_at"
     OR ((NEW."state" = 'CONSUMED') <> (NEW."consumed_operation_id" IS NOT NULL)) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.mutation_candidate transition';
  END IF;
  RETURN NEW;
END $$;
${mutationResumeGuardsSql}
DROP TRIGGER IF EXISTS mutation_candidate_lifecycle ON "control"."mutation_candidate";
CREATE TRIGGER mutation_candidate_lifecycle BEFORE INSERT OR UPDATE OR DELETE ON "control"."mutation_candidate"
FOR EACH ROW EXECUTE FUNCTION openpc.enforce_mutation_candidate_lifecycle();
UPDATE "control"."idempotency_record" AS idempotency
SET "webauthn_assertion_binding_digest" = evidence."webauthn_assertion_binding_digest"
FROM "control"."mutation_evidence" AS evidence
WHERE idempotency."participant_id" = evidence."participant_id"
  AND idempotency."operation_id" = evidence."operation_id"
  AND idempotency."catalog_operation_id" = 'ID-OP-WEBAUTHN-VERIFY'
  AND idempotency."webauthn_assertion_binding_digest" IS NULL
  AND evidence."catalog_operation_id" = 'ID-OP-WEBAUTHN-VERIFY'
  AND evidence."webauthn_assertion_binding_digest" IS NOT NULL;
DO $binding_upgrade$
BEGIN
  IF EXISTS (
    SELECT 1 FROM "control"."idempotency_record" AS idempotency
    WHERE idempotency."catalog_operation_id" = 'ID-OP-WEBAUTHN-VERIFY'
      AND NOT EXISTS (
        SELECT 1 FROM "control"."mutation_evidence" AS evidence
        JOIN "control"."outbox_event" AS outbox
          ON outbox."participant_id" = evidence."participant_id"
         AND outbox."aggregate_type" = 'webauthn-verification'
         AND outbox."webauthn_assertion_binding_digest" = evidence."webauthn_assertion_binding_digest"
        WHERE evidence."participant_id" = idempotency."participant_id"
          AND evidence."operation_id" = idempotency."operation_id"
          AND evidence."catalog_operation_id" = idempotency."catalog_operation_id"
          AND evidence."webauthn_assertion_binding_digest" = idempotency."webauthn_assertion_binding_digest"
          AND octet_length(evidence."webauthn_assertion_binding_digest") = 32
      )
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = 'control.idempotency_record WebAuthn binding upgrade';
  END IF;
END
$binding_upgrade$;
DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'openpc_signing_authority_locker') THEN
    CREATE ROLE openpc_signing_authority_locker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'openpc_signing_continuation_issuer') THEN
    CREATE ROLE openpc_signing_continuation_issuer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'openpc_backup_operator') THEN
    CREATE ROLE openpc_backup_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT BYPASSRLS;
  END IF;
END
$roles$;
ALTER ROLE "openpc_control_owner" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_migrator" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT BYPASSRLS;
ALTER ROLE "openpc_control_runtime" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_worker" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_platform_runtime" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_reader" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_maintenance" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT BYPASSRLS;
ALTER ROLE "openpc_backup_operator" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT BYPASSRLS;
GRANT "openpc_control_owner" TO "openpc_control_migrator";
ALTER DATABASE "openpc_control" OWNER TO "openpc_control_owner";
ALTER SCHEMA openpc OWNER TO "openpc_control_owner";
ALTER SCHEMA control OWNER TO "openpc_control_owner";
REVOKE ALL ON DATABASE "openpc_control" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE "openpc_control" TO "openpc_control_migrator";
GRANT CONNECT ON DATABASE "openpc_control" TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
REVOKE ALL ON SCHEMA public, openpc, control FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA openpc, control TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
${forceStatements}
${ownershipStatements}
CREATE OR REPLACE FUNCTION openpc.reject_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
CREATE OR REPLACE FUNCTION openpc.require_complete_security_record()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE row_document jsonb := to_jsonb(NEW);
BEGIN
  IF TG_TABLE_NAME = 'idempotency_record' AND (
    row_document->>'catalog_operation_id' IN ('ID-OP-WEBAUTHN-VERIFY','POL-OP-ACTIVATE')
    AND row_document->>'webauthn_assertion_binding_digest' IS NULL
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
  END IF;
  IF TG_TABLE_NAME = 'approval_decision_record' AND (
    row_document->>'approver_principal_epoch' IS NULL
    OR row_document->>'approver_authority_envelope_id' IS NULL
    OR row_document->>'approver_envelope_epoch' IS NULL
    OR row_document->>'approver_assignment_id' IS NULL
    OR row_document->>'signer_credential_id' IS NULL
    OR row_document->>'aggregate_version' IS NULL
    OR row_document->>'candidate_digest' IS NULL OR row_document->>'evidence_cbor' IS NULL
    OR (row_document->>'mfa_challenge_id' IS NOT NULL AND (
      row_document->>'approver_participant_epoch' IS NULL
      OR row_document->>'approver_assignment_row_version' IS NULL
      OR row_document->>'approver_delegation_epoch' IS NULL
    ))
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
  END IF;
  IF TG_TABLE_NAME = 'mutation_evidence' AND (
    row_document->>'evidence_role'='IDENTITY_PROOF_INPUT' OR row_document->>'catalog_operation_id'='ID-OP-INVITATION-ACCEPT'
  ) THEN
    IF NOT coalesce((row_document->>'evidence_role'='IDENTITY_PROOF_INPUT'
      AND row_document->>'evidence_format'='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
      AND row_document->>'catalog_operation_id'='ID-OP-INVITATION-ACCEPT'
      AND row_document->>'action_intent_id'='ACT-PARTICIPANT_CREATE_MEMBER-V1'
      AND row_document->>'aggregate_type'='invitation-redemption'
      AND row_document->>'aggregate_version' IS NOT NULL
      AND row_document->>'bound_participant_epoch' IS NOT NULL AND row_document->>'bound_principal_epoch' IS NOT NULL
      AND octet_length((row_document->>'candidate_digest')::bytea)=32
      AND (row_document->>'evidence_digest')::bytea=sha256((row_document->>'evidence_cbor')::bytea)
      AND row_document->>'checker_principal_id' IS NULL AND row_document->>'approval_request_id' IS NULL
      AND row_document->>'mfa_challenge_id' IS NULL AND row_document->>'signer_credential_id' IS NULL
      AND row_document->>'webauthn_assertion_binding_digest' IS NULL
      AND row_document->>'bound_authority_envelope_id' IS NULL AND row_document->>'bound_envelope_epoch' IS NULL
      AND row_document->>'bound_assignment_id' IS NULL),false) THEN
      RAISE EXCEPTION 'DATA-6021-INCOMPLETE-IDENTITY-PROOF';
    END IF;
  ELSIF TG_TABLE_NAME = 'mutation_evidence' AND row_document->>'catalog_operation_id'='ID-OP-PARTICIPANT-FIRST-ADMIN-ACCEPT' THEN
    IF NOT coalesce((row_document->>'evidence_role'='AUTHORIZATION_INPUT'
      AND row_document->>'evidence_format'='IDENTITY_RUNTIME_ASSERTION_3002_2_13'
      AND row_document->>'action_intent_id'='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
      AND row_document->>'aggregate_type'='participant'
      AND row_document->>'aggregate_id'=row_document->>'participant_id'
      AND octet_length((row_document->>'webauthn_assertion_binding_digest')::bytea)=32
      AND (row_document->>'evidence_digest')::bytea=sha256((row_document->>'evidence_cbor')::bytea)
      AND row_document->>'bound_authority_envelope_id' IS NULL AND row_document->>'bound_assignment_id' IS NULL
      AND EXISTS (
        SELECT 1 FROM control.participant_bootstrap_custody custody
        JOIN control.mfa_challenge challenge ON challenge.participant_id=custody.participant_id
          AND challenge.principal_id=custody.candidate_membership_id AND challenge.session_id=custody.candidate_session_id
          AND challenge.mfa_challenge_id=(row_document->>'mfa_challenge_id')::uuid
          AND challenge.action_intent_id=row_document->>'action_intent_id'
          AND challenge.resource_digest=(row_document->>'candidate_digest')::bytea
          AND challenge.used_at IS NULL AND challenge.consumed_at IS NULL AND challenge.expires_at>clock_timestamp()
        JOIN control.credential credential ON credential.participant_id=custody.participant_id
          AND credential.principal_id=custody.candidate_membership_id AND credential.credential_id=(row_document->>'signer_credential_id')::uuid
          AND credential.kind='WEBAUTHN' AND credential.state='ACTIVE'
        WHERE custody.participant_id=(row_document->>'participant_id')::uuid
          AND custody.candidate_membership_id=(row_document->>'principal_id')::uuid
          AND custody.state='CLAIM_PENDING' AND custody.expires_at>clock_timestamp()
          AND custody.participant_epoch=(row_document->>'bound_participant_epoch')::numeric
          AND custody.participant_epoch=(row_document->>'aggregate_version')::numeric
      )),false) THEN RAISE EXCEPTION 'DATA-6021-INCOMPLETE-FIRST-ADMIN-CUSTODY'; END IF;
  ELSIF TG_TABLE_NAME = 'mutation_evidence' AND (
    row_document->>'catalog_operation_id' = 'LEGACY'
    OR row_document->>'aggregate_version' IS NULL
    OR row_document->>'bound_authority_envelope_id' IS NULL
    OR row_document->>'bound_envelope_epoch' IS NULL
    OR row_document->>'bound_assignment_id' IS NULL
    OR (row_document->>'catalog_operation_id' IN ('ID-OP-WEBAUTHN-VERIFY','POL-OP-ACTIVATE')
        AND (row_document->>'webauthn_assertion_binding_digest' IS NULL
             OR row_document->>'signer_credential_id' IS NULL))
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
  END IF;
  IF TG_TABLE_NAME = 'outbox_event' AND (
    row_document->>'aggregate_type' IN ('webauthn-verification','policy-activation')
    AND row_document->>'webauthn_assertion_binding_digest' IS NULL
  ) THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
  END IF;
  IF TG_TABLE_NAME = 'credential' AND row_document->>'kind' = 'WEBAUTHN'
     AND row_document->>'state' IN ('ACTIVE','ROTATING')
     AND row_document->>'public_key_spki_der' IS NULL THEN
    RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6021-INCOMPLETE-SECURITY-RECORD', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS approval_decision_immutable ON "control"."approval_decision_record";
CREATE TRIGGER approval_decision_immutable BEFORE UPDATE OR DELETE ON "control"."approval_decision_record"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS mutation_evidence_immutable ON "control"."mutation_evidence";
CREATE TRIGGER mutation_evidence_immutable BEFORE UPDATE OR DELETE ON "control"."mutation_evidence"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS approval_decision_complete ON "control"."approval_decision_record";
CREATE TRIGGER approval_decision_complete BEFORE INSERT ON "control"."approval_decision_record"
FOR EACH ROW EXECUTE FUNCTION openpc.require_complete_security_record();
DROP TRIGGER IF EXISTS idempotency_record_complete ON "control"."idempotency_record";
CREATE TRIGGER idempotency_record_complete BEFORE INSERT OR UPDATE ON "control"."idempotency_record"
FOR EACH ROW EXECUTE FUNCTION openpc.require_complete_security_record();
DROP TRIGGER IF EXISTS mutation_evidence_complete ON "control"."mutation_evidence";
CREATE TRIGGER mutation_evidence_complete BEFORE INSERT ON "control"."mutation_evidence"
FOR EACH ROW EXECUTE FUNCTION openpc.require_complete_security_record();
DROP TRIGGER IF EXISTS outbox_event_complete ON "control"."outbox_event";
CREATE TRIGGER outbox_event_complete BEFORE INSERT ON "control"."outbox_event"
FOR EACH ROW EXECUTE FUNCTION openpc.require_complete_security_record();
DROP TRIGGER IF EXISTS credential_webauthn_spki_complete ON "control"."credential";
CREATE TRIGGER credential_webauthn_spki_complete BEFORE INSERT OR UPDATE ON "control"."credential"
FOR EACH ROW EXECUTE FUNCTION openpc.require_complete_security_record();
${businessGuards}
${allTables.includes('authority_role') ? authorityRoleGuardsSql : ''}
${allTables.includes('directory_group_mapping') ? directoryGroupGuardsSql : ''}
${history.includes('authority_group_member_active_uq') ? authorityGroupGuardsSql(allTables.includes('directory_group_mapping')) : ''}
${allTables.includes('directory_connector') ? directoryGuardsSql : ''}
${allTables.includes('participant_invitation') ? invitationGuardsSql : ''}
${allTables.includes('participant_bootstrap_custody') ? bootstrapCustodyGuardsSql : ''}
${allTables.includes('participant_lifecycle_transition') ? participantLifecycleGuardsSql : ''}
${allTables.includes('platform_context') ? platformContextReadSql + platformContextGuardsSql : ''}
${allTables.includes('platform_envelope_scope') ? platformEnvelopeScopeGuardsSql : ''}
${allTables.includes('platform_scope_replacement') ? platformScopeReplacementGuardsSql : ''}
${discoveryPreapprovalReady ? discoveryApprovalResumeSourceSql + discoveryApprovalResumeGuardsSql + discoveryApprovalResumeTargetSql + discoveryPreapprovalTargetGuardsSql + discoveryPreapprovalFinalGuardsSql : ''}
${allTables.includes('platform_recovery_enrollment') ? platformRecoveryGuardsSql + (allTables.includes('discovery_certificate_issuance') ? discoveryCertificateRecoveryGuardsSql : '') + platformRecoveryLeaseProjectionSql(allTables.includes('discovery_certificate_issuance')) + platformRecoveryResourceSql + (allTables.includes('discovery_certificate_issuer_attempt') ? discoveryCertificateIssuerAttemptGuardsSql : '') : ''}
${allTables.includes('platform_recovery_enrollment') && allTables.includes('identity_envelope_proposal') ? platformRecoveryApprovalResumeGuardsSql : ''}
${allTables.includes('identity_envelope_recovery_enrollment') ? identityEnvelopeRecoveryGuardsSql + identityEnvelopeRecoveryLeaseGuardsSql + workloadCredentialContinuationReadSql : ''}
${allTables.includes('root_expiry_recovery_enrollment') ? rootExpiryRecoveryGuardsSql : ''}
${allTables.includes('identity_envelope_rotation_step') ? identityEnvelopeRotationGuardsSql + identityEnvelopeSelectionGuardsSql : ''}
${allTables.includes('identity_envelope_proposal') ? identityEnvelopeProposalGuardsSql : ''}
${allTables.includes('identity_envelope_activation') ? identityEnvelopeActivationGuardsSql : ''}
${history.includes('"mfa_challenge" ADD COLUMN "resource_id"') ? mfaChallengeResourceGuardsSql : ''}
${allTables.includes('wallet_binding') ? walletBindingGuardsSql : ''}
${allTables.includes('identity_subject') ? identitySubjectGuardsSql : ''}
${allTables.includes('identity_oidc_binding') ? identityOidcBindingGuardsSql : ''}
${(
  rotationDefinitions +
  (allTables.includes('signing_continuation')
    ? signingContinuationGuardsSql + signingOperationEvidenceGuardsSql + signingGovernanceSql
    : '')
).replace(
  /CREATE (?:CONSTRAINT )?TRIGGER ([a-z_]+)([\s\S]*?) ON control\.([a-z_]+)/gu,
  (match, name, _body, table) => `DROP TRIGGER IF EXISTS ${name} ON control.${table};\n${match}`,
)}
${allTables.includes('authentication_occurrence') ? authenticationOccurrenceGuardsSql : ''}
${allTables.includes('governed_initial_enrollment_profile') ? governedInitialEnrollmentGuardsSql : ''}
${allTables.includes('installed_secret_recipient') ? secretRecipientGuardsSql : ''}
${allTables.includes('notification_completion_phase_admission') ? notificationCompletionAdmissionSql : ''}
DO $ownership$
DECLARE owned_function record;
BEGIN
  FOR owned_function IN
    SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) arguments
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname IN ('openpc', 'control')
  LOOP
    EXECUTE format('ALTER FUNCTION %I.%I(%s) OWNER TO openpc_control_owner',
      owned_function.nspname, owned_function.proname, owned_function.arguments);
  END LOOP;
END
$ownership$;
REVOKE ALL ON ${quotedAllTables} FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM PUBLIC;
REVOKE ALL ON ${quotedAllTables} FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
GRANT EXECUTE ON FUNCTION openpc.require_uuid_setting(text), openpc.set_request_context(text,uuid,uuid,uuid,text,boolean), openpc.assert_request_context(boolean), openpc.matches_participant(uuid), openpc.matches_privacy(uuid), openpc.current_participant_id(), openpc.current_privacy_domain_id(), openpc.current_operation_id(), openpc.current_action_intent_id() TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_key_governor";
GRANT SELECT ON ${quotedAllTables} TO "openpc_control_runtime", "openpc_control_platform_runtime", "openpc_control_reader";
${allTables.includes('platform_context') ? platformContextGrantsSql : ''}
${allTables.includes('platform_scope_replacement') ? platformScopeReplacementGrantsSql + platformScopeReplacementSourcePoliciesSql : ''}
${allTables.includes('platform_recovery_enrollment') ? platformRecoveryGrantsSql + platformRecoveryLeaseGrantsSql + platformRecoveryResourceGrantsSql : ''}
${allTables.includes('discovery_certificate_issuance') ? discoveryCertificateRecoveryGrantsSql : ''}
${allTables.includes('discovery_certificate_issuer_attempt') ? discoveryCertificateIssuerAttemptGrantsSql : ''}
${administrationResourceScopeGrantsSql}
${allTables.includes('authority_role') ? authorityRoleGrantsSql : ''}
${history.includes('authority_group_member_active_uq') ? authorityGroupGrantsSql : ''}
${allTables.includes('directory_group_mapping') ? directoryGroupGrantsSql : ''}
GRANT INSERT, UPDATE ON ${quoteTables(mutableRuntimeTables)} TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT (participant_id, privacy_domain_id, chain_id, profile_id, profile_version,
  correlated_log_identity_hmac, entity_hmac, entity_scope_digest, delivery_surface,
  protected_delivery_reference_digest, subscription_reference_digest,
  session_reference_digest, state) ON "control"."pending_delivery"
  TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE (state, lease_owner, lease_expires_at, next_retry_at, safe_reason)
  ON "control"."pending_delivery"
  TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."approval_decision_record" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON "control"."authority_envelope", "control"."revocation" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE (state, checker_principal_id, cose_sign1, last_mutation_operation_id, row_version, updated_at) ON "control"."authority_envelope" TO "openpc_control_runtime", "openpc_control_platform_runtime";
${
  allTables.includes('identity_envelope_proposal')
    ? `GRANT INSERT ON control.identity_envelope_proposal TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT UPDATE(state,submission_operation_id,submission_intent_digest,submission_approval_id,submission_maker,submission_checker,submission_checker_authority,row_version)
 ON control.identity_envelope_proposal TO openpc_control_runtime,openpc_control_platform_runtime;`
    : ''
}
GRANT INSERT ON "control"."mutation_evidence", "control"."outbox_event" TO "openpc_control_runtime", "openpc_control_platform_runtime";
${
  allTables.includes('identity_envelope_activation')
    ? `GRANT INSERT ON control.identity_envelope_activation TO openpc_control_runtime,openpc_control_platform_runtime;
GRANT UPDATE(state,observation,cose_sign1,dispatched_at,observed_at,committed_at,row_version)
 ON control.identity_envelope_activation TO openpc_control_runtime,openpc_control_platform_runtime;
${identityEnvelopeActivationSourceGrantsSql}`
    : ''
}
GRANT INSERT ON "control"."mutation_candidate" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE (state, consumed_operation_id, updated_at) ON "control"."mutation_candidate" TO "openpc_control_runtime", "openpc_control_platform_runtime";
${hasBusinessReceipts ? workloadSigningHandoverAdmissionGrantsSql : ''}
GRANT INSERT, UPDATE (last_sequence, updated_at) ON "control"."outbox_aggregate_head" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT SELECT, INSERT, UPDATE ON "control"."idempotency_record", "control"."outbox_aggregate_head", "control"."outbox_event" TO "openpc_control_worker";
GRANT SELECT ON ${quotedAllTables} TO "openpc_control_worker";
GRANT SELECT, INSERT, UPDATE, DELETE ON ${quotedAllTables} TO "openpc_control_maintenance";
GRANT SELECT ON ${quotedAllTables} TO "openpc_backup_operator";
${businessGrants}
${discoveryPreapprovalReady ? discoveryApprovalResumeGrantsSql + discoveryApprovalResumeTargetGrantsSql + discoveryPreapprovalTargetGrantsSql : ''}
${allTables.includes('platform_recovery_enrollment') && allTables.includes('identity_envelope_proposal') ? platformRecoveryApprovalResumeGrantsSql : ''}
${mutationResumeGrantsSql}
${rotationGrants}
${allTables.includes('identity_envelope_rotation_step') ? identityEnvelopeRotationGrantsSql : ''}
${allTables.includes('signing_continuation') ? signingContinuationGrantsSql : ''}
${allTables.includes('signing_authorization_generation') ? signingGovernanceGrantsSql : ''}
${allTables.includes('signing_key_rotation') ? signingAttemptAuthorityGrantsSql : ''}
${
  allTables.includes('hardware_authenticator')
    ? `
REVOKE UPDATE, DELETE ON control.hardware_authenticator FROM openpc_control_runtime, openpc_control_platform_runtime;
DROP TRIGGER IF EXISTS hardware_authenticator_immutable ON control.hardware_authenticator;
CREATE TRIGGER hardware_authenticator_immutable BEFORE UPDATE OR DELETE ON control.hardware_authenticator FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
`
    : ''
}
${
  allTables.includes('identity_runtime_snapshot')
    ? `
GRANT INSERT ON control.identity_runtime_snapshot, control.identity_runtime_snapshot_content, control.identity_runtime_authority_set TO openpc_control_runtime, openpc_control_platform_runtime;
DROP TRIGGER IF EXISTS identity_runtime_snapshot_immutable ON control.identity_runtime_snapshot;
CREATE TRIGGER identity_runtime_snapshot_immutable BEFORE UPDATE OR DELETE ON control.identity_runtime_snapshot FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS identity_runtime_snapshot_content_immutable ON control.identity_runtime_snapshot_content;
CREATE TRIGGER identity_runtime_snapshot_content_immutable BEFORE UPDATE OR DELETE ON control.identity_runtime_snapshot_content FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
DROP TRIGGER IF EXISTS identity_runtime_authority_set_immutable ON control.identity_runtime_authority_set;
CREATE TRIGGER identity_runtime_authority_set_immutable BEFORE UPDATE OR DELETE ON control.identity_runtime_authority_set FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();
CREATE OR REPLACE FUNCTION openpc.guard_identity_runtime_scope_version() RETURNS trigger LANGUAGE plpgsql AS $scope_version$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'identity authority scope versions cannot be reset'; END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.version<>1 THEN RAISE EXCEPTION 'identity authority scopes start at version one'; END IF;
    RETURN NEW;
  END IF;
  IF (NEW.participant_id,NEW.domain_code,NEW.scope_digest,NEW.scope_cbor) IS DISTINCT FROM (OLD.participant_id,OLD.domain_code,OLD.scope_digest,OLD.scope_cbor)
    OR (NEW.source_state_digest=OLD.source_state_digest AND NEW.version<>OLD.version)
    OR (NEW.source_state_digest<>OLD.source_state_digest AND NEW.version<>OLD.version+1)
  THEN RAISE EXCEPTION 'identity authority scope version transition rejected'; END IF;
  RETURN NEW;
END $scope_version$;
ALTER FUNCTION openpc.guard_identity_runtime_scope_version() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.guard_identity_runtime_scope_version() FROM PUBLIC;
DROP TRIGGER IF EXISTS identity_runtime_scope_version_guard ON control.identity_runtime_authority_scope;
CREATE TRIGGER identity_runtime_scope_version_guard BEFORE INSERT OR UPDATE OR DELETE ON control.identity_runtime_authority_scope FOR EACH ROW EXECUTE FUNCTION openpc.guard_identity_runtime_scope_version();
`
    : ''
}
${allTables.includes('session') ? qaSessionDurationGuardsSql : ''}
${allTables.includes('root_expiry_recovery_enrollment') ? rootExpiryRecoveryGrantsSql : ''}
${allTables.includes('workload_renewal_intent') ? workloadRenewalGuardsSql : ''}
${allTables.includes('workload_renewal_policy_head') ? workloadRenewalPolicyGuardsSql : ''}
${allTables.includes('workload_renewal_signing_profile') ? workloadRenewalSigningGuardsSql : ''}
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA openpc REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC;
${allTables.includes('identity_oidc_binding') ? identityOidcBindingGrantsSql : ''}
${allTables.includes('authentication_occurrence') ? authenticationOccurrenceGrantsSql : ''}
${allTables.includes('governed_initial_enrollment_profile') ? governedInitialEnrollmentGrantsSql : ''}
${allTables.includes('installed_secret_recipient') ? secretRecipientGrantsSql : ''}
${allTables.includes('notification_completion_phase_admission') ? notificationCompletionAdmissionGrantsSql : ''}
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;`;

const priorDefinitions = (
  await Promise.all(migrations.slice(0, -1).map((name) => readMigration(name)))
).join('\n');
const unscopedSql = `${requestContextPreamble}\n${base}\n${securityTail}\n`;
const migrationSql = restoreFunctionGrantsAfterReset(
  scopeFunctionRevocations(unscopedSql, priorDefinitions),
);
verifyConditionCases(migrationSql);
const grantAcceptance = verifyFunctionGrants(priorDefinitions + migrationSql, migrationSql);
// Empty conditional SQL fragments must not leave whitespace-only generated lines.
await writeFile(path, `${migrationSql}\n${grantAcceptance}\n`.replace(/[\t ]+$/gmu, ''), 'utf8');
