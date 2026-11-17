import { expect, it } from 'vitest';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';

it('parses connected archive, disposition and direct-input SQL conditions before database allocation', async () => {
  for (const [path, name] of [
    ['./runtime-artifact-archive-guards.mjs', 'runtimeArtifactArchiveGuardsSql'],
    ['./runtime-artifact-use-guards.mjs', 'runtimeArtifactUseGuardsSql'],
    ['./runtime-artifact-retirement-admission.mjs', 'runtimeArtifactRetirementAdmissionSql'],
    ['../configuration/runtime-input-guards.mjs', 'runtimeInputGuardsSql'],
  ]) {
    const declaration: Record<string, unknown> = await import(new URL(path!, import.meta.url).href);
    expect(typeof declaration[name!]).toBe('string');
    expect(() => verifyConditionCases(declaration[name!] as string)).not.toThrow();
  }
});

it('keeps archive-integrity access bound to exact disposition and physical-retirement actions', async () => {
  const declaration: Record<string, unknown> = await import(
    new URL('./runtime-artifact-archive-guards.mjs', import.meta.url).href
  );
  const sql = String(declaration.runtimeArtifactArchiveGuardsSql);
  for (const action of [
    'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1',
    'ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1',
    'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
    'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1',
  ])
    expect(sql).toContain(action);
  expect(sql).not.toContain('ACT-EVIDENCE_DELETIONS_READ_COLLECTION-V1');
  expect(sql).toContain("pg_has_role(session_user,'openpc_control_runtime','USAGE')");
  expect(sql).toContain("NOT pg_has_role(oid,'openpc_control_owner','MEMBER')");
});
