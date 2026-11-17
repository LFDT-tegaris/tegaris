import { describe, expect, it } from 'vitest';
import { getTableConfig, PgDialect } from 'drizzle-orm/pg-core';
import {
  rootExpiryRecoveryEnrollments,
  rootExpiryRecoveryCases,
  rootExpiryRecoveryScopes,
  rootExpiryRecoveryTrust,
  rootExpiryRecoveryProofs,
} from './schema/root-expiry-recovery.js';
import { platformRecoveryEnrollments, platformRecoveryCases } from './schema/platform-recovery.js';
import { outboxEvents } from './schema/workflow.js';
import { platformRecoveryApprovalOwnerReadDefinitions } from './schema/platform-recovery-source.js';
import { controlOwnerRole } from './schema/common.js';
import { authorityRoles } from './schema/authority-roles.js';
import { platformEnvelopeScopes } from './schema/platform-envelope-scope.js';
import { platformEnvelopeScopeSuccessors } from './schema/platform-scope-replacement.js';
import { discoveryCertificateRecoveryGuardsSql } from './discovery-certificate-recovery-guards.mjs';
import {
  discoveryApprovalResumeSourceSql,
  discoveryApprovalResumeGuardsSql,
  discoveryApprovalResumeGrantsSql,
} from './discovery-approval-resume-guards.mjs';
import {
  platformRecoveryGuardsSql,
  platformRecoveryContinuationRootPreambleSql,
} from './platform-recovery-guards.mjs';
import { verifyConditionCases, verifyFunctionGrants } from './function-grants.js';
import { discoveryCertificateRecoveryActions } from '../domain/discovery-certificate-recovery.js';
import { platformRecoveryContinuationLeaseActions } from '../domain/platform-recovery-lease.js';
import { platformRecoveryResourceSql } from './platform-recovery-lease-guards.mjs';
import { platformContextReadSql } from './platform-context-guards.mjs';
import { platformContexts } from './schema/platform-context.js';

it('isolates historical pending preparation reads without changing their owner or receipt checks', () => {
  const policy = getTableConfig(outboxEvents).policies.find(
    (p) => p.name === 'root_expiry_pending_preparation_outbox_source_read',
  )!;
  expect(policy.to).toEqual([controlOwnerRole]);
  const leaf = new PgDialect().sqlToQuery(policy.using!).sql;
  expect(leaf).toContain('openpc.platform_history_outbox_event_pending_preparation_read(');
  expect(leaf).not.toContain('control.mutation_candidate');
  const definition = platformRecoveryApprovalOwnerReadDefinitions(outboxEvents).find(
    (d) => d.functionName === 'platform_history_outbox_event_pending_preparation_read',
  )!;
  for (const required of [
    "pending.state='WITHDRAWING'",
    "candidate.state='CONSUMED'",
    "approval.state='APPROVED'",
    "committed.terminal_state='COMMITTED'",
    'scope.admission_digest=pending.predecessor_digest',
    'pending.successor_digest=sha256(pending.successor_preimage)',
    'evidence.evidence_cbor',
    'evidence.evidence_digest',
    'evidence.cose_sign1',
  ])
    expect(new PgDialect().sqlToQuery(definition.predicate).sql).toContain(required);
  expect(definition.body).toContain('VOLATILE SECURITY INVOKER');
  expect(definition.body).toContain('SET row_security=on');
  expect(definition.body).toContain('TO openpc_control_owner;');
  expect(definition.body).not.toContain('SECURITY DEFINER');
  expect(definition.preamble).toContain('BEGIN RETURN false; END');
});

it('keeps Root visibility invoker-scoped behind a non-inline planning boundary', () => {
  const policy = getTableConfig(platformContexts).policies.find(
    (p) => p.name === 'platform_context_scoped_read',
  )!;
  const sql = new PgDialect().sqlToQuery(policy.using!).sql;
  expect(sql).toContain('openpc.platform_context_scoped_read_current(');
  expect(sql).not.toContain('authority_envelope');
  expect(platformContextReadSql).toContain('LANGUAGE plpgsql STABLE SECURITY INVOKER');
  expect(platformContextReadSql).toContain('SET row_security=on');
  expect(platformContextReadSql).toContain(
    "current_user='openpc_control_owner' AND openpc.matches_participant(p_owner)",
  );
  expect(platformContextReadSql).toContain(
    'envelope.platform_context_id=p_root AND openpc.matches_participant(envelope.participant_id)',
  );
  expect(platformContextReadSql).toContain('FROM PUBLIC');
  const grants = verifyFunctionGrants(platformContextReadSql, platformContextReadSql);
  expect(grants).toContain('openpc_control_runtime');
  expect(grants).not.toContain('openpc_backup_operator');
});

it('binds unused handoff bridge trust and proof reads to the exact live supersession', () => {
  for (const table of [rootExpiryRecoveryTrust, rootExpiryRecoveryProofs]) {
    const policy = getTableConfig(table).policies.find(
      (p) => p.name === 'root_expiry_admin_receipt_prerequisite_read',
    )!;
    expect(policy.for).toBe('select');
    const statement = new PgDialect().sqlToQuery(policy.using!).sql;
    for (const bound of [
      "source.source_purpose='ROOT_EXPIRY_RECOVERY'",
      "source.document#>>'{uneffectedPredecessor,schema}'='pc.identity.platform-expired-uneffected-recovery'",
      "source.document#>>'{uneffectedPredecessor,schemaVersion}'='1'",
      "lease.intent->'supersession'=jsonb_build_object(",
      "lease.state='ACTIVE'",
      'lease.valid_until>clock_timestamp()',
      "completed.state='COMPLETED'",
      "source.document#>>'{source,receiptDigest}'='sha256:'||encode(completed.evidence_digest,'hex')",
    ])
      expect(statement).toContain(bound);
  }
});

it('reads the unused handoff Root completion event only through its exact live lease', () => {
  const policy = getTableConfig(outboxEvents).policies.find(
    (p) => p.name === 'root_expiry_admin_receipt_prerequisite_read',
  )!;
  expect(policy.for).toBe('select');
  const statement = new PgDialect().sqlToQuery(policy.using!).sql;
  for (const bound of [
    'openpc.matches_participant(',
    'openpc.matches_privacy(',
    'openpc.local_qa_runtime',
    'ACT-IDENTITY_UPDATE_STEP_UP-V1',
    "source.source_purpose='ROOT_EXPIRY_RECOVERY'",
    "source.document#>>'{uneffectedPredecessor,schema}'='pc.identity.platform-expired-uneffected-recovery'",
    "source.document#>>'{uneffectedPredecessor,schemaVersion}'='1'",
    "lease.intent->'supersession'=jsonb_build_object(",
    "lease.state='ACTIVE'",
    'lease.valid_until>clock_timestamp()',
    'root.authority_epoch=source.root_epoch',
    'root.row_version=source.root_revision',
    'custody.document_digest=receipt.enrollment_digest',
    "receipt.state='COMPLETED'",
    "source.document#>>'{source,receiptDigest}'='sha256:'||encode(receipt.evidence_digest,'hex')",
    'local-root-expiry-recovery',
    'openpc.identity.local-root-expiry-recovery.completed.v1',
    'receipt.evidence_cbor',
    'receipt.evidence_digest',
    'receipt.evidence_cose',
  ])
    expect(statement).toContain(bound);
  expect(statement).not.toContain('platform_scope_pending_root_bridge_current(');
  expect(statement).not.toContain('platform_recovery_uneffected_source_current(');
  expect(statement).not.toContain('set_config(');
  const installation = platformRecoveryApprovalOwnerReadDefinitions(outboxEvents).find(
    (d) => d.functionName === 'platform_history_outbox_event_root_source_read',
  )!;
  expect(new PgDialect().sqlToQuery(installation.predicate).sql).toContain(
    "openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'",
  );
});

it('reads only the consumed preparation approval named by the current receiving continuation', () => {
  const branch = platformRecoveryResourceSql
    .split("IF action='ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1' AND EXISTS(")[1]!
    .split(') THEN RETURN true; END IF;')[0]!;
  expect(branch).toBeDefined();
  for (const bound of [
    'fresh.recovery_id=selected.recovery_case_id',
    'fresh.participant_id=participant AND openpc.matches_privacy(fresh.privacy_domain_id)',
    "fresh.intent ? 'continuation'",
    "source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' AND source.document->>'schemaVersion'='3'",
    "issuing.recovery_case_id::text=fresh.intent#>>'{continuation,recoveryId}'",
    "target=fresh.intent#>>'{continuation,preparationApprovalId}'",
    'replacement.replacement_id::text=ANY(resources)',
    "replacement.state='WITHDRAWING' AND replacement.row_version=1",
    "prepared.state='CONSUMED'",
    "prepared.consumed_operation_id::text=fresh.intent#>>'{continuation,preparationOperationId}'",
    "prepared.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' AND prepared.expected_revision=0",
    "prepared.candidate_document=fresh.intent->'preparation'",
    "prepared.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(prepared.candidate_document),'UTF8'))",
    'approval.subject_digest=prepared.candidate_digest AND approval.subject_version=prepared.expected_revision',
    "approval.state='APPROVED'",
    'approval.maker_principal_id<>approval.checker_principal_id',
    "approval.checker_principal_id::text=fresh.intent#>>'{preparation,administrators,1,principalId}'",
  ])
    expect(branch).toContain(bound);
  expect(
    platformRecoveryResourceSql.indexOf('NOT openpc.platform_recovery_envelope_current('),
  ).toBeLessThan(
    platformRecoveryResourceSql.indexOf(
      "IF action='ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1' AND EXISTS(",
    ),
  );
  expect(branch).not.toMatch(
    /\b(?:insert|update|delete)\s+control\.|ACT-APPROVAL_REQUESTS_UPDATE|ACT-POLICY_APPROVE/iu,
  );
  expect(branch).not.toContain('administration_resource_permits(');
});

it('separates the continuation Root comparison from historical witness policy expansion', () => {
  const leaf = platformRecoveryGuardsSql
    .split('CREATE OR REPLACE FUNCTION openpc.platform_recovery_continuation_root_matches(')[1]!
    .split('REVOKE ALL')[0]!;
  expect(leaf).toContain('LANGUAGE plpgsql STABLE SECURITY INVOKER');
  expect(leaf).toContain('SET row_security=on');
  expect([...leaf.matchAll(/\b(?:from|join) control\.([a-z_]+)\b/giu)].map((m) => m[1])).toEqual([
    'platform_context',
  ]);
  for (const binding of [
    'root.platform_context_id=p_root',
    'root.owner_participant_id=p_owner',
    "root.state='ACTIVE'",
    'root.authority_epoch=p_epoch',
    'root.row_version=p_revision',
  ])
    expect(leaf).toContain(binding);
  expect(leaf).not.toMatch(
    /security definer|\b(?:insert|update|delete)\b|set_config\(|platform_recovery_(?:source_root_current|continuation_current)\(/iu,
  );
  const grant = platformRecoveryGuardsSql.match(
    /GRANT EXECUTE ON FUNCTION openpc\.platform_recovery_continuation_root_matches\(uuid,uuid,numeric,numeric\) TO ([^;]+);/u,
  );
  expect(grant?.[1]).toBe('openpc_control_owner');
  expect(platformRecoveryGuardsSql).toContain(
    'REVOKE ALL ON FUNCTION openpc.platform_recovery_continuation_root_matches(uuid,uuid,numeric,numeric) FROM PUBLIC;',
  );
  expect(leaf).toContain('p_root uuid,p_owner uuid,p_epoch numeric,p_revision numeric)');
  expect(platformRecoveryContinuationRootPreambleSql).toContain('BEGIN RETURN false; END $$;');
  expect(platformRecoveryContinuationRootPreambleSql).toContain('SECURITY INVOKER');
  expect(platformRecoveryContinuationRootPreambleSql).toContain('SET row_security=on');
  expect(platformRecoveryContinuationRootPreambleSql.split('REVOKE ALL')[0]).not.toMatch(
    /\b(?:from|join)\b/iu,
  );
  expect(platformRecoveryContinuationRootPreambleSql).toContain(
    '(p_root uuid,p_owner uuid,p_epoch numeric,p_revision numeric)',
  );
});

it('admits Discovery intent v2 at the shared case guard without changing other version gates', () => {
  const guard = platformRecoveryGuardsSql
    .split('CREATE OR REPLACE FUNCTION openpc.guard_platform_recovery_case()')[1]!
    .split('REVOKE ALL')[0]!;
  expect(guard).toContain("OR (NEW.intent->>'schemaVersion' IS DISTINCT FROM '1'");
  expect(guard).toContain("AND NOT (NEW.intent->>'schemaVersion' IS NOT DISTINCT FROM '2'");
  expect(guard).toContain(
    "AND NEW.intent->>'schema' IS NOT DISTINCT FROM 'pc.identity.discovery-certificate-recovery-intent'",
  );
  expect(guard).toContain('AND NOT signer_repair))');
  expect(guard).toContain('NEW.intent_digest<>sha256');
  expect(guard).toContain('NEW.valid_until>source.valid_until');
  expect(discoveryCertificateRecoveryGuardsSql).toContain(
    "NEW.state NOT IN ('REVOKED','EXPIRED') and NEW.intent->>'schemaVersion'='2'",
  );
  expect(discoveryCertificateRecoveryGuardsSql).toContain(
    'and NOT openpc.discovery_certificate_resume_administrators_current(NEW.enrollment_id)',
  );
});

it('keeps discovery receipt source currentness at the existing exact Root and original-row owners', () => {
  verifyConditionCases(discoveryCertificateRecoveryGuardsSql);
  verifyConditionCases(platformRecoveryGuardsSql);
  const source = discoveryCertificateRecoveryGuardsSql.split(
    'CREATE OR REPLACE FUNCTION openpc.discovery_certificate_recovery_current',
  )[0]!;
  expect(source).toContain('openpc.platform_recovery_source_root_current(e)');
  expect(source).not.toContain('JOIN control.platform_envelope_scope_successor');
  expect(source).toContain(
    "e.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'",
  );
  const administrator = discoveryCertificateRecoveryGuardsSql
    .split(
      'CREATE OR REPLACE FUNCTION openpc.discovery_certificate_recovery_administrators_current',
    )[1]!
    .split('REVOKE ALL')[0]!;
  for (const binding of [
    'openpc.platform_recovery_original_administrators_current(e)',
    "'{source,originalAdministrators}'",
    "'{source,ancestorReceipts,-1,enrollmentId}'",
    'administrator->',
    "'{grantable,administration,actionIntentIds}'",
    'role.action_intent_ids',
    'principal.authority_epoch',
  ])
    expect(administrator).toContain(binding);
  expect(administrator).not.toMatch(/set_config\(|grant |bypassrls/iu);
});

it('admits only named source schemas and matching live lease purposes in receipt witness policy', () => {
  const constraint = getTableConfig(platformRecoveryEnrollments).checks.find(
    (check) => check.name === 'platform_recovery_enrollment_source_purpose_ck',
  );
  expect(constraint).toBeDefined();
  const purpose = new PgDialect().sqlToQuery(constraint!.value).sql;
  expect(purpose).toContain('pc.identity.discovery-certificate-recovery-enrollment');
  expect(purpose).toContain('ROOT_EXPIRY_RECOVERY');
  expect(purpose).toContain("->>'schemaVersion'='2'");
  for (const statement of statements) {
    expect(statement).toContain(
      "source.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'",
    );
    expect(statement).toContain(
      "lease.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'",
    );
  }
});

// Declaration/closure checks only. Actual INVOKER RLS and governed positive
// handoff remain operational gates; this never installs synthetic lease rows.
const requiredActions = [
  'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  'ACT-IDENTITY_UPDATE_STEP_UP-V1',
  'ACT-POLICY_APPROVE_REQUEST-V1',
  'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
  'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1',
  'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
  'ACT-IDENTITY_CREATE_SESSION-V1',
  'ACT-IDENTITY_DELETE_SESSION-V1',
  'ACT-OPERATIONS_READ_OPERATION-V1',
  'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
  'ACT-PARTICIPANT_CREATE_MEMBER-V1',
  'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
];
const tables = [rootExpiryRecoveryEnrollments, rootExpiryRecoveryCases, rootExpiryRecoveryScopes];
const statements = tables.map((table) => {
  const policy = getTableConfig(table).policies.find(
    (p) => p.name === 'root_expiry_admin_receipt_prerequisite_read',
  );
  if (!policy?.using) throw new Error('Missing exact prerequisite policy');
  expect(policy.for).toBe('select');
  return new PgDialect().sqlToQuery(policy.using).sql;
});
describe('exact historical receipt witness visibility declaration', () => {
  it.each([
    [platformEnvelopeScopes, 'platform_envelope_scope_read'],
    [platformEnvelopeScopeSuccessors, 'platform_scope_successor_read'],
    [rootExpiryRecoveryScopes, 'root_expiry_scope_read'],
  ] as const)(
    'binds shared Platform fact readers to envelope-covered request privacy',
    (table, name) => {
      const policy = getTableConfig(table).policies.find((p) => p.name === name);
      expect(policy?.for).toBe('select');
      expect(policy?.using).toBeDefined();
      const statement = new PgDialect().sqlToQuery(policy!.using!).sql;
      expect(statement).toContain('openpc.matches_participant(');
      expect(statement).toMatch(
        /openpc\.current_privacy_domain_id\(\)::text\s*=\s*any\((?:e|envelope)\.privacy_domain_ids\)/iu,
      );
      // Installation privacy records provenance; explicitly covered delegated
      // consumers may use another privacy domain. Historical metadata does not
      // require a currently active grant and must not call its consuming guard.
      const ordinary =
        name === 'root_expiry_scope_read' ? statement.split('then false else ')[1]! : statement;
      expect(ordinary).not.toContain('installation_privacy_domain_id');
      expect(ordinary).not.toMatch(/state\s*=|platform_recovery_envelope_current|set_config\(/iu);
    },
  );
  it('exposes and locks only exact enrolled administrator roles without permitting a role mutation', () => {
    const policies = getTableConfig(authorityRoles).policies.filter((p) =>
      p.name.startsWith('platform_recovery_installation_source_'),
    );
    expect(policies.map((p) => p.for).sort()).toEqual(['select', 'update']);
    for (const policy of policies) {
      expect(policy.to).toEqual([controlOwnerRole]);
      const statement = new PgDialect().sqlToQuery(policy.using!).sql;
      expect(statement).toContain("actor->>'roleId'");
      expect(statement).toContain("'{source,originalAdministrators}'");
      expect(statement).toContain("replacement.candidate->'administrators'");
      expect(statement).toContain('openpc.platform_recovery_installation_source_current(');
      expect(statement).not.toContain('platform_recovery_original_administrators_current(');
      expect(statement).toContain('openpc.matches_privacy(');
      expect(statement).toContain('enrollment.valid_until>clock_timestamp()');
      expect(statement).toContain('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1');
      if (policy.for === 'select') {
        expect(statement).toContain(
          "enrollment.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'",
        );
        expect(statement).toContain("enrollment.document->>'schemaVersion'='2'");
        for (const action of discoveryCertificateRecoveryActions)
          expect(statement).toContain(action);
        expect(statement).toContain(
          "enrollment.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION'",
        );
        expect(statement).toContain("enrollment.document->>'schemaVersion'='3'");
        expect(statement).toContain(
          "enrollment.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'",
        );
        expect(statement).toContain("current_setting('openpc.local_qa_runtime',true)");
        for (const action of platformRecoveryContinuationLeaseActions)
          expect(statement).toContain(action);
        expect(statement).not.toContain('ACT-PARTICIPANTS_CREATE_RESOURCE-V1');
      } else {
        expect(statement).not.toContain('ACT-PARTICIPANTS_READ_RESOURCE-V1');
        expect(statement).not.toContain('ACT-IDENTITY_UPDATE_STEP_UP-V1');
      }
      expect(statement).not.toContain('join control.authority_role');
      if (policy.for === 'update')
        expect(new PgDialect().sqlToQuery(policy.withCheck!).sql).toBe('false');
    }
  });
  it('provides only an exact live schema3 lease witness to the source owner', () => {
    const policy = getTableConfig(platformRecoveryCases).policies.find(
      (p) => p.name === 'platform_recovery_continuation_lease_source_read',
    )!;
    expect(policy.for).toBe('select');
    expect(policy.to).toEqual([controlOwnerRole]);
    const statement = new PgDialect().sqlToQuery(policy.using!).sql;
    for (const binding of [
      'openpc.matches_participant(',
      'openpc.matches_privacy(',
      'openpc.platform_recovery_continuation_root_matches(',
      "source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION'",
      "source.document->>'schemaVersion'='3'",
      "source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'",
      "current_setting('openpc.local_qa_runtime',true)",
      'source.enrollment_id=',
      'source.row_version=',
      'source.document_digest=',
      "='ACTIVE'",
      '>clock_timestamp()',
      '<=source.valid_until',
      "->'continuation'=source.document#>'{source,continuation}'",
      'activation_operation_id',
      'activation_evidence_digest',
      'activation_cose',
      'jsonb_array_length(',
    ])
      expect(statement).toContain(binding);
    for (const action of platformRecoveryContinuationLeaseActions)
      expect(statement).toContain(action);
    expect(statement).not.toMatch(
      /set_config\(|platform_recovery_(?:source_root_current|envelope_current|continuation_current)\(|\b(?:insert|update|delete)\b/iu,
    );
    const invoker = platformRecoveryGuardsSql
      .split('CREATE OR REPLACE FUNCTION openpc.platform_recovery_installation_source_current(')[1]!
      .split('REVOKE ALL')[0]!;
    expect(invoker).toContain('SECURITY INVOKER');
    expect(invoker).toContain('SET row_security=on');
    expect(invoker).toContain("current_user='openpc_control_owner'");
    expect(invoker).toContain("enrollment.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION'");
    expect(invoker).toContain("enrollment.document->>'schemaVersion'='3'");
    expect(invoker).toContain(
      "enrollment.document#>>'{uneffectedPredecessor,schema}'='pc.identity.platform-expired-uneffected-recovery'",
    );
    expect(invoker).toContain("enrollment.document#>>'{uneffectedPredecessor,schemaVersion}'='1'");
    expect(invoker).toContain('openpc.platform_recovery_source_root_current(enrollment)');
    for (const action of platformRecoveryContinuationLeaseActions)
      expect(invoker).toContain(action);
  });
  it('admits only the installation owner exact completed outbox prerequisite before a lease exists', () => {
    const policy = getTableConfig(outboxEvents).policies.find(
      (p) => p.name === 'root_expiry_admin_outbox_source_read',
    );
    expect(policy?.for).toBe('select');
    expect(policy?.to).toEqual([controlOwnerRole]);
    expect(policy?.using).toBeDefined();
    const definition = platformRecoveryApprovalOwnerReadDefinitions(outboxEvents).find(
      (d) => d.functionName === 'platform_history_outbox_event_root_source_read',
    )!;
    expect(new PgDialect().sqlToQuery(policy!.using!).sql).toContain(definition.functionName);
    const statement = new PgDialect().sqlToQuery(definition.predicate).sql;
    for (const required of [
      'openpc.matches_participant(',
      'openpc.matches_privacy(',
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      "source.source_purpose='ROOT_EXPIRY_RECOVERY'",
      "source.document->>'schemaVersion'='2'",
      'LOCAL_QA_VIRTUAL_AUTHENTICATOR',
      'source.valid_until>clock_timestamp()',
      "receipt.state='COMPLETED'",
      'root.authority_epoch=source.root_epoch',
      'root.row_version=source.root_revision',
      'source,activationOperationId',
      'source,receiptDigest',
      'local-root-expiry-recovery',
      'openpc.identity.local-root-expiry-recovery.completed.v1',
      'receipt.evidence_cbor',
      'receipt.evidence_digest',
      'receipt.evidence_cose',
    ])
      expect(statement).toContain(required);
    expect(statement).not.toContain('platform_recovery_case');
    expect(statement).not.toMatch(/from control.outbox_event|set_config\(|security definer/iu);
    expect(statement).not.toContain('receipt.valid_until');
  });
  it('authenticates the current V2 Root event and bounded ancestry before Source4 installation', () => {
    const policy = getTableConfig(outboxEvents).policies.find(
      (p) => p.name === 'root_expiry_admin_installation_receipt_read',
    );
    expect(policy?.for).toBe('select');
    expect(policy?.to).toEqual([controlOwnerRole]);
    const definition = platformRecoveryApprovalOwnerReadDefinitions(outboxEvents).find(
      (d) => d.functionName === 'platform_history_outbox_event_root_installation_read',
    )!;
    expect(new PgDialect().sqlToQuery(policy!.using!).sql).toContain(definition.functionName);
    const statement = new PgDialect().sqlToQuery(definition.predicate).sql;
    for (const required of [
      'openpc.matches_participant(',
      'openpc.matches_privacy(',
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'openpc.local_qa_runtime',
      'with recursive ancestry',
      'ancestry.depth<32',
      "completed.state='COMPLETED'",
      "completed.intent->>'schemaVersion'='2'",
      'LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY',
      "custody.document->>'purpose'='pc.installation.local-root-expiry-pending-recovery-custody.v2'",
      "trust.document->'pending'=custody.document->'pending'",
      "completed.intent->'pending'=custody.document->'pending'",
      'scope.admission_digest=sha256(scope.admission_preimage)',
      'root.authority_epoch=scope.platform_authority_epoch',
      'root.row_version=pending.expected_root_revision+1',
      "pending.state='WITHDRAWING' and pending.row_version=1 and pending.superseded_by is null",
      'openpc.platform_scope_pending_record_digest(pending)',
      "predecessor.result->>'rootDigest'=ancestry.intent->>'predecessorDigest'",
      "predecessor.result->>'rootRevision'=ancestry.intent->>'predecessorRevision'",
      'local-root-expiry-recovery',
      'receipt.evidence_cbor',
      'receipt.evidence_digest',
      'receipt.evidence_cose',
      'receipt.operation_id',
    ])
      expect(statement).toContain(required);
    expect(statement).not.toMatch(
      /platform_recovery_(?:enrollment|case)|from control.outbox_event|platform_scope_pending_root_bridge_current|set_config\(|security definer|\b(?:insert|update|delete)\s+control\./iu,
    );
  });
  it('keeps source and lease policy dependencies scoped and the historical branch read-only', () => {
    for (const table of [platformRecoveryEnrollments, platformRecoveryCases]) {
      const policies = getTableConfig(table).policies.filter(
        (policy) => policy.for === 'select' || policy.for === 'all',
      );
      expect(policies.length).toBeGreaterThan(0);
      for (const policy of policies) {
        if (!policy.using) throw new Error('Missing prerequisite visibility expression');
        const statement = new PgDialect().sqlToQuery(policy.using).sql;
        const pendingApprovalHistory =
          policy.name === 'platform_prepare_approval_continuation_history_read';
        const liveLease = policy.name === 'platform_recovery_continuation_lease_source_read';
        const scopedSource =
          policy.name.startsWith('platform_recovery_continuation_') || pendingApprovalHistory;
        if (scopedSource) {
          expect(table).toBe(platformRecoveryCases);
          expect(policy.to).toEqual([controlOwnerRole]);
          const dependencies = [
            ...statement.matchAll(/\b(?:from|join) control\.([a-z_]+)\b/giu),
          ].map((match) => match[1]);
          expect(dependencies).toEqual(['platform_recovery_enrollment']);
          expect(statement).toContain(
            'openpc.platform_recovery_continuation_root_matches(source.platform_context_id,source.participant_id,source.root_epoch,source.root_revision)',
          );
          expect(statement).toContain("source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION'");
          expect(statement).toContain("source.document->>'schemaVersion'='3'");
          if (policy.name === 'platform_recovery_continuation_history_read')
            expect(statement).toContain("source.document#>>'{source,continuation,recoveryId}'");
          else expect(statement).toContain('source.enrollment_id=');
          if (pendingApprovalHistory) {
            for (const required of [
              "source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY'",
              "source.document->>'schemaVersion'='4'",
              '"state"=\'EXPIRED\'',
              '"valid_until"<=clock_timestamp()',
              "\"intent\"->'pendingExpiry'=source.document#>'{source,pendingExpiry}'",
              'not ("control"."platform_recovery_case"."intent" ? \'approvalContinuation\')',
              'source.row_version=',
              'source.document_digest=',
              '"intent_digest"=sha256(convert_to(openpc.signing_canonical_json("control"."platform_recovery_case"."intent"),',
              '"activation_operation_id" is not null',
              'sha256("control"."platform_recovery_case"."activation_evidence_cbor")',
              'octet_length("control"."platform_recovery_case"."activation_cose")>0',
            ])
              expect(statement).toContain(required);
          }
          if (liveLease) {
            for (const required of [
              'source.row_version=',
              'source.document_digest=',
              '"state"=\'ACTIVE\'',
              '"valid_from"<=clock_timestamp()',
              '"valid_until">clock_timestamp()',
              '"valid_until"<=source.valid_until',
              "source.source_purpose='ROOT_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='2'",
              'uneffectedPredecessor,intentDigest',
              'uneffectedPredecessor,preparationOperationId',
              'uneffectedPredecessor,preparationApprovalId',
              '"intent_digest"=sha256(convert_to(openpc.signing_canonical_json(',
              '"activation_evidence_digest"=sha256(',
              'octet_length(',
              'jsonb_array_length(',
            ])
              expect(statement).toContain(required);
          }
          expect(statement).not.toMatch(
            /set_config\(|openpc\.platform_recovery_(?:envelope_current|continuation_current)\(/iu,
          );
          expect(statement).toContain('source.valid_until>clock_timestamp()');
        } else {
          expect(statement).not.toMatch(/\b(?:from|join)\b/iu);
        }
        const functions = [...statement.matchAll(/openpc\.([a-z_]+)\(/gu)].map((v) => v[1]);
        expect(functions.length).toBeGreaterThan(0);
        for (const name of functions)
          expect([
            'matches_participant',
            'matches_privacy',
            ...(scopedSource
              ? ['current_action_intent_id', 'platform_recovery_continuation_root_matches']
              : []),
            ...(pendingApprovalHistory || liveLease ? ['signing_canonical_json'] : []),
          ]).toContain(name);
      }
    }
  });
  it.each(requiredActions)(
    'retains required authorization context %s without inventing permission',
    (action) => {
      for (const statement of statements) expect(statement).toContain("'" + action + "'");
    },
  );
  it('has exactly the independently required action closure and no wildcard or additional action', () => {
    const discoveryActions = [
      ...requiredActions.filter(
        (action) =>
          ![
            'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1',
            'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
            'ACT-PARTICIPANT_CREATE_MEMBER-V1',
          ].includes(action),
      ),
      'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
    ];
    for (const statement of statements) {
      const closures = [...statement.matchAll(/current_action_intent_id\(\) in \(([^)]+)\)/gu)].map(
        (match) => [...match[1]!.matchAll(/'(ACT-[A-Z0-9_-]+)'/gu)].map((v) => v[1]).sort(),
      );
      expect(closures).toEqual([
        [...requiredActions].sort(),
        [...requiredActions, 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'].sort(),
        [...requiredActions].sort(),
        [...discoveryActions].sort(),
      ]);
      expect(statement).not.toContain('ACT-PARTICIPANTS_READ_COLLECTION-V1');
      expect(statement).not.toContain('ACT-PARTICIPANTS_DELETE_RESOURCE-V1');
      expect(statement).toContain(
        "openpc.current_action_intent_id()<>'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'",
      );
      expect(statement).toContain("or lease.intent->>'schemaVersion'='2'");
    }
  });
  it('requires exact same participant/privacy, active signed current source/case and local profile', () => {
    for (const statement of statements) {
      for (const expected of [
        'openpc.matches_participant(',
        'openpc.matches_privacy(',
        'source.participant_id=',
        'source.privacy_domain_id=',
        "source.source_purpose='ROOT_EXPIRY_RECOVERY'",
        'lease.enrollment_revision=source.row_version',
        'lease.enrollment_digest=source.document_digest',
        "source.state='ACTIVE'",
        "lease.state='ACTIVE'",
        'LOCAL_QA_VIRTUAL_AUTHENTICATOR',
        'source.valid_until>clock_timestamp()',
        'lease.valid_until>clock_timestamp()',
        'lease.activation_cose is not null',
        'jsonb_array_length(lease.lease_bindings)=2',
      ])
        expect(statement).toContain(expected);
      expect(statement).not.toContain('platform_recovery_envelope_current(');
      expect(statement).not.toContain('platform_recovery_source_root_current(');
      expect(statement).not.toContain('set_config(');
      expect(statement).not.toContain('current_principal');
      expect(statement).not.toContain('security definer');
      expect(statement).toContain('exists(select 1');
    }
  });
  it('binds each distinct immutable witness and does not demand historical ceremony freshness', () => {
    expect(statements[0]).toContain("source.document#>>'{source,enrollmentId}'");
    for (const expected of [
      'source.root_expiry_recovery_id=',
      'source,activationOperationId',
      'source,receiptDigest',
      "='COMPLETED'",
    ])
      expect(statements[1]).toContain(expected);
    for (const expected of [
      'source.root_expiry_recovery_id=',
      'source.root_epoch=',
      'source.root_digest=',
      'source.platform_context_id=',
    ])
      expect(statements[2]).toContain(expected);
    for (const statement of statements) {
      expect(statement).not.toContain('successorValidFrom');
      expect(statement).not.toContain('root_expiry_recovery_case.valid_until');
      expect(statement).not.toContain('root_expiry_recovery_enrollment.valid_until');
    }
  });
});

it('bounds each ancestor witness to an exact declared tuple and keeps the policies acyclic', () => {
  for (const statement of statements) {
    expect(statement).toContain('ancestorReceipts');
    expect(statement).toContain('between 1 and 31');
    expect(statement).toContain('declared->>');
    expect(statement).not.toContain('platform_recovery_envelope_current(');
    expect(statement).not.toContain('platform_recovery_original_administrators_current(');
  }
  expect(statements[0]).toContain("declared->>'enrollmentId'");
  for (const field of ['recoveryId', 'enrollmentId', 'activationOperationId', 'receiptDigest'])
    expect(statements[1]).toContain(`declared->>'${field}'`);
  expect(statements[2]).toContain('platform_authority_epoch');
});

// This verifies shared admission/ACL wiring. Executing the predicate against
// authenticated installed receipts remains a separate real-role requirement.
it('uses one installed Root lineage predicate for visibility and durable approved resume with closed invoker grants', () => {
  const predicate = discoveryApprovalResumeSourceSql
    .split('CREATE OR REPLACE FUNCTION openpc.discovery_approval_resume_enrollments_compatible')[1]!
    .split('REVOKE ALL')[0]!;
  expect(predicate).toContain('STABLE SECURITY INVOKER');
  expect(predicate).not.toMatch(/SECURITY DEFINER|INSERT INTO|UPDATE control|set_config/iu);
  expect(predicate).toContain(
    'openpc.platform_recovery_source_root_current(new_e) IS DISTINCT FROM true',
  );
  expect(predicate).toContain('IF suffix IS DISTINCT FROM old_refs THEN RETURN false;');
  expect(predicate).toContain(
    'new_e.root_revision-old_e.root_revision IS DISTINCT FROM new_e.root_epoch-old_e.root_epoch',
  );
  expect(predicate).toContain('receipt.admission_digest IS DISTINCT FROM old_e.root_digest');
  expect(discoveryApprovalResumeSourceSql).toContain(
    'openpc.discovery_approval_resume_enrollments_compatible(old_source.enrollment_id,source.enrollment_id)',
  );
  expect(discoveryApprovalResumeGuardsSql).toContain(
    'openpc.discovery_approval_resume_enrollments_compatible(old_enrollment.enrollment_id,new_enrollment.enrollment_id) IS DISTINCT FROM true',
  );
  verifyConditionCases(discoveryApprovalResumeSourceSql);
  verifyFunctionGrants(discoveryApprovalResumeSourceSql, discoveryApprovalResumeGrantsSql);
  for (const role of [
    'openpc_control_worker',
    'openpc_control_reader',
    'openpc_control_maintenance',
  ])
    expect(() =>
      verifyFunctionGrants(
        discoveryApprovalResumeSourceSql,
        discoveryApprovalResumeGrantsSql +
          '\nGRANT EXECUTE ON FUNCTION openpc.discovery_approval_resume_enrollments_compatible(uuid,uuid) TO ' +
          role +
          ';',
      ),
    ).toThrow('role mismatch');
});

it('adds only filtered V3 immutable outbox metadata and preserves the ordinary scope reader outside the complete owner context', () => {
  const dialect = new PgDialect();
  const policy = getTableConfig(outboxEvents).policies.find(
    (p) => p.name === 'root_expiry_pending_ancestry_receipt_read',
  )!;
  expect(policy.for).toBe('select');
  const statement = dialect.sqlToQuery(policy.using!).sql;
  expect(statement).toContain('case when "control"."outbox_event"."aggregate_type"=');
  expect(statement).toContain("current_user='openpc_control_owner'");
  expect(statement).toContain('openpc.root_expiry_pending_ancestry(');
  expect(statement).toContain("source.document->>'schemaVersion'='3'");
  expect(statement).toContain(
    "source.document->>'purpose'='pc.installation.local-root-expiry-pending-ancestry-custody.v3'",
  );
  for (const field of [
    'enrollmentId',
    'recoveryId',
    'activationOperationId',
    'enrollmentDigest',
    'intentDigest',
    'receiptDigest',
  ])
    expect(statement).toContain(`declared->>'${field}'`);
  expect(statement).not.toMatch(
    /from control.outbox_event|read_root_expiry_pending_ancestry_witness|root_expiry_recovery_source_current|\b(?:insert|update|delete)\s+control\./iu,
  );
  const scope = getTableConfig(rootExpiryRecoveryScopes).policies.find(
    (p) => p.name === 'root_expiry_scope_read',
  )!;
  const scopeSql = dialect.sqlToQuery(scope.using!).sql;
  expect(scopeSql).toContain("current_user='openpc_control_owner'");
  expect(scopeSql).toContain('openpc.matches_participant(');
  expect(scopeSql).toContain('openpc.matches_privacy(');
  expect(scopeSql).toContain('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1');
  expect(scopeSql).toContain('then false else exists(select 1 from control.authority_envelope');
});
