import { readFileSync } from 'node:fs';
import { getTableConfig } from 'drizzle-orm/pg-core';
import { expect, it } from 'vitest';
import { runtimeArtifactRetirements } from './runtime-artifact-retirement-schema.js';
// @ts-expect-error The migration declaration is checked against its owning contracts below.
import * as retirementDeclaration from './runtime-artifact-retirement-guards.mjs';
const {
  runtimeArtifactRetirementGuardsSql: sql,
  runtimeArtifactRetirementProfile: profile,
  runtimeArtifactRetirementRequiredOwners: owners,
} = retirementDeclaration;
const declaration = JSON.parse(
  readFileSync(
    new URL(
      '../../../../schemas/canonical/business-transition-profiles/evidence-deletion-runtime-artifact-v1.json',
      import.meta.url,
    ),
    'utf8',
  ),
);
const body = (name: string) => {
  const start = sql.indexOf(`CREATE OR REPLACE FUNCTION openpc.${name}(`);
  expect(start).toBeGreaterThanOrEqual(0);
  const end = sql.indexOf('END $$;', start);
  expect(end).toBeGreaterThan(start);
  return sql.slice(start, end);
};
it('binds the committed isolated receipt profile without registering or admitting it', () => {
  expect(profile).toEqual({
    profileId: declaration.profileId,
    profileVersion: declaration.profileVersion,
    profileDigest: declaration.definitionDigest,
    actionIntentId: declaration.actionIntentId,
    catalogOperationId: declaration.catalogOperationId,
  });
  expect(sql).not.toMatch(/INSERT INTO control\.(?:action_intent|business_transition_profile)/u);
  expect(sql).not.toMatch(/\bGRANT\b/u);
});
it('retains original identity per input and indexes digest across all module generations', () => {
  const table = getTableConfig(runtimeArtifactRetirements);
  expect(table.name).toBe('runtime_artifact_retirement');
  expect(table.enableRLS).toBe(true);
  expect(table.policies).toHaveLength(2);
  expect(table.columns.map((c) => c.name)).not.toContain('configuration_cbor');
  expect(table.columns.map((c) => c.name)).not.toContain('selected');
  expect(
    table.uniqueConstraints
      .find((u) => u.name === 'runtime_artifact_retirement_input_uq')
      ?.columns.map((c) => c.name),
  ).toEqual(['participant_id', 'privacy_domain_id', 'runtime_configuration_input_id']);
  expect(table.foreignKeys.map((f) => getTableConfig(f.reference().foreignTable).name)).toEqual([
    'deletion_job',
  ]);
  expect(
    table.indexes
      .find((i) => i.config.name === 'runtime_artifact_retirement_digest_ix')
      ?.config.columns.map((c) => ('name' in c ? c.name : null)),
  ).toEqual(['participant_id', 'privacy_domain_id', 'configuration_digest']);
});
it('rejects direct mutation and TRUNCATE, requiring actual OLD capture and scoped original job', () => {
  expect(body('guard_runtime_artifact_retirement_statement')).toContain("IF TG_OP<>'INSERT'");
  expect(body('guard_runtime_artifact_retirement')).toContain(
    "IF TG_OP<>'INSERT' OR pg_trigger_depth()<>2",
  );
  const capture = body('capture_runtime_artifact_retirement');
  for (const check of [
    "TG_TABLE_NAME<>'runtime_configuration_input'",
    "TG_OP<>'DELETE'",
    "TG_WHEN<>'BEFORE'",
    'pg_trigger_depth()<>1',
    'operation_id=openpc.current_operation_id()',
    'OLD.configuration_digest',
    'OLD.module_configuration_generation_id',
  ])
    expect(capture).toContain(check);
  expect(sql).not.toMatch(/CREATE TRIGGER[^;]+ON control\.runtime_configuration_input/u);
  expect(sql).not.toMatch(/DELETE FROM control\.runtime_configuration_input/u);
});
it('has no fallback admission for absent or mismatched native eligibility/effect owners', () => {
  expect(owners).toEqual({
    eligibility:
      'openpc.assert_runtime_artifact_retirement_eligible(control.deletion_job,control.runtime_configuration_input)',
    effect:
      'openpc.assert_runtime_artifact_retirement_effect(control.deletion_job,control.runtime_artifact_retirement)',
  });
  const required = body('assert_runtime_artifact_retirement_owner');
  for (const predicate of [
    'to_regprocedure(owner_signature)',
    "r.rolname='openpc_control_owner'",
    'NOT p.prosecdef',
    'NOT p.proisstrict',
    "p.prorettype='pg_catalog.void'::regtype",
    'p.pronargs=2',
    'RUNTIME-ARTIFACT-RETIREMENT-OWNER-UNAVAILABLE',
  ])
    expect(required).toContain(predicate);
  expect(sql).not.toContain(
    'CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_retirement_eligible(',
  );
  expect(sql).not.toContain(
    'CREATE OR REPLACE FUNCTION openpc.assert_runtime_artifact_retirement_effect(',
  );
  expect(body('capture_runtime_artifact_retirement')).toContain(
    'PERFORM openpc.assert_runtime_artifact_retirement_eligible(job,OLD)',
  );
  expect(body('guard_runtime_artifact_retirement')).not.toContain('source.configuration_cbor');
  expect(body('assert_runtime_artifact_retirement_committed')).toContain(
    'PERFORM openpc.assert_runtime_artifact_retirement_effect(job,r)',
  );
});
it('keeps late-reference serialization and exact signed effect mandatory at commit', () => {
  const context = body('assert_runtime_artifact_retirement_context');
  for (const check of [
    "'evidence-lifecycle:'",
    'l.pid=pg_backend_pid()',
    "l.mode='ExclusiveLock'",
    "current_setting('transaction_isolation')<>'read committed'",
    'rolbypassrls',
  ])
    expect(context).toContain(check);
  const committed = body('assert_runtime_artifact_retirement_committed');
  for (const check of [
    "state='SUCCEEDED' AND revision=1",
    "external_attempt_state='NOT_STARTED'",
    'deleted_bytes=(r).configuration_bytes',
    'runtime_configuration_input_id=(r).runtime_configuration_input_id',
    'openpc.assert_evidence_deletion_receipt(receipt)',
    "i.terminal_state='COMMITTED'",
    'e.payload_digest=sha256(e.payload_cbor)',
    'runtime_artifact_retirement_after_digest(r)',
  ])
    expect(committed).toContain(check);
  expect(sql).toContain('DEFERRABLE INITIALLY DEFERRED');
});
it('denies by scoped bytes even when a caller proposes another input or module generation', () => {
  const denied = body('runtime_artifact_digest_retired');
  expect(denied).toContain('r.participant_id=openpc.current_participant_id()');
  expect(denied).toContain('r.privacy_domain_id=openpc.current_privacy_domain_id()');
  expect(denied).toContain('r.configuration_digest=p_digest');
  expect(denied).not.toMatch(
    /module_configuration_generation_id|runtime_configuration_input_id|selected/u,
  );
});
