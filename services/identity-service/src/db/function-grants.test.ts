import { expect, it } from 'vitest';
import {
  workloadSigningHandoverAdmissionGuardsSql,
  workloadSigningHandoverAdmissionGrantsSql,
} from './workload-signing-handover-admission-guards.mjs';
import { readFile, readdir } from 'node:fs/promises';
import { businessTransitionProfiles } from '../../../../packages/security-kernel/src/business-transition/profiles.generated.js';
import { signingRoleProfiles } from '../../../../packages/security-kernel/src/signing-roles.js';
import { governedReceiptOperationIds } from './governed-receipt-inputs.js';
import { stepUpOnlyConfigurationOperations } from '../domain/configuration-step-up-admission.js';
import {
  platformRecoveryGuardsSql,
  platformRecoveryGrantsSql,
} from './platform-recovery-guards.mjs';
import {
  platformRecoveryLeaseProjectionSql,
  platformRecoveryLeaseGrantsSql,
} from './platform-recovery-lease-guards.mjs';
import {
  platformRecoveryApprovalResumeGuardsSql,
  platformRecoveryApprovalResumeGrantsSql,
} from './platform-recovery-approval-resume-guards.mjs';
import {
  scopeFunctionRevocations,
  repairFunctionRevocationOrder,
  restoreFunctionGrantsAfterReset,
  verifyConditionCases,
  verifyFunctionGrants,
} from './function-grants.js';

it('keeps pending Platform history and resume routines inside their exact generated role grants', () => {
  const definitions =
    platformRecoveryGuardsSql +
    platformRecoveryLeaseProjectionSql(false) +
    platformRecoveryApprovalResumeGuardsSql;
  const generated =
    definitions +
    platformRecoveryGrantsSql +
    platformRecoveryLeaseGrantsSql +
    platformRecoveryApprovalResumeGrantsSql;
  expect(() => verifyFunctionGrants(definitions, generated)).not.toThrow();
  for (const signature of [
    'openpc.platform_recovery_continuation_current(uuid,uuid,jsonb,jsonb)',
    'openpc.require_platform_recovery_continuation_enrollment()',
    'openpc.platform_recovery_proposal_history_current(uuid,uuid,uuid,uuid)',
    'openpc.platform_recovery_approval_resume_subject_visible(uuid,uuid,uuid,uuid,uuid)',
    'openpc.assert_platform_recovery_approval_resume(control.mutation_candidate)',
  ]) {
    expect(() =>
      verifyFunctionGrants(
        definitions,
        generated + `\nGRANT EXECUTE ON FUNCTION ${signature} TO openpc_control_worker;`,
      ),
    ).toThrow('Function grant role mismatch');
  }
});

it('rejects a declared runtime grant revoked later in generated SQL', () => {
  const definition =
    'CREATE FUNCTION openpc.recovery(p_id uuid) RETURNS boolean AS $$ SELECT true $$;';
  const grant =
    'GRANT EXECUTE ON FUNCTION openpc.recovery(uuid) TO openpc_control_runtime,openpc_control_platform_runtime;';
  const reset =
    'REVOKE ALL ON FUNCTION openpc.recovery(uuid) FROM openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance,openpc_backup_operator;';
  expect(() => verifyFunctionGrants(definition, grant + reset)).toThrow(
    'revoked after declaration',
  );
  const restored = restoreFunctionGrantsAfterReset(grant + reset);
  expect(verifyFunctionGrants(definition, restored)).toContain(
    "('openpc.recovery(uuid)','openpc_control_runtime')",
  );
  expect(restored.slice(restored.indexOf(reset) + reset.length)).not.toContain(
    'openpc_control_worker',
  );
  expect(restoreFunctionGrantsAfterReset(restored)).toBe(restored);
  expect(() =>
    verifyFunctionGrants(
      definition,
      restored + '\nREVOKE EXECUTE ON FUNCTION openpc.recovery(uuid) FROM openpc_control_runtime;',
    ),
  ).toThrow('revoked after declaration');
});

it('does not undo an explicit later revocation or include functions outside the owned reset', () => {
  const grant =
    'GRANT EXECUTE ON FUNCTION openpc.external(),openpc.owned() TO openpc_control_runtime;';
  const reset =
    'REVOKE ALL ON FUNCTION openpc.owned() FROM openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance,openpc_backup_operator;';
  const narrow =
    'REVOKE ALL ON FUNCTION openpc.owned() FROM openpc_control_runtime,openpc_control_platform_runtime;';
  expect(restoreFunctionGrantsAfterReset(grant + narrow)).toBe(grant + narrow);
  expect(
    restoreFunctionGrantsAfterReset(grant + reset).slice((grant + reset).length),
  ).not.toContain('openpc.external');
});

it('preserves installation-only grants and public revocations across the shared reset', () => {
  const installation = 'GRANT EXECUTE ON FUNCTION openpc.install(uuid) TO openpc_control_owner;';
  const publicReset = 'REVOKE ALL ON FUNCTION openpc.install(uuid) FROM PUBLIC;';
  const runtimeReset =
    'REVOKE ALL ON FUNCTION openpc.install(uuid) FROM openpc_control_runtime,openpc_control_platform_runtime;';
  const original = installation + publicReset + runtimeReset;
  expect(restoreFunctionGrantsAfterReset(original)).toBe(original);
});
it('does not restore grants revoked or dropped before a later reset', () => {
  const grant =
    'GRANT EXECUTE ON FUNCTION openpc.owned() TO openpc_control_runtime,openpc_control_reader;';
  const revoke = 'REVOKE EXECUTE ON FUNCTION openpc.owned() FROM openpc_control_runtime;';
  const reset =
    'REVOKE ALL ON FUNCTION openpc.owned() FROM openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance,openpc_backup_operator;';
  const restored = restoreFunctionGrantsAfterReset(grant + revoke + reset);
  expect(restored.slice((grant + revoke + reset).length)).toContain(
    'GRANT EXECUTE ON FUNCTION openpc.owned() TO openpc_control_reader;',
  );
  expect(restored.slice((grant + revoke + reset).length)).not.toContain('openpc_control_runtime');
  const recreated =
    grant +
    '\nDROP FUNCTION openpc.owned();\n' +
    'CREATE FUNCTION openpc.owned() RETURNS void AS $$ SELECT NULL $$;' +
    reset;
  expect(restoreFunctionGrantsAfterReset(recreated)).toBe(recreated);
  const publicOnly = 'GRANT EXECUTE ON FUNCTION openpc.owned() TO PUBLIC;' + reset;
  expect(restoreFunctionGrantsAfterReset(publicOnly)).toBe(publicOnly);
});

// SQL generators are JavaScript owners. Validate their exports instead of
// weakening the service's TypeScript settings or inventing declaration files.
async function sqlOwner(path: string, name: string): Promise<string> {
  const owner: Record<string, unknown> = await import(path);
  const sql = owner[name];
  if (typeof sql !== 'string') throw new Error(`Missing SQL owner: ${path}:${name}`);
  return sql;
}
const identityEnvelopeRotationGuardsSql = await sqlOwner(
  './identity-envelope-rotation-guards.mjs',
  'identityEnvelopeRotationGuardsSql',
);
const identityEnvelopeRotationGrantsSql = await sqlOwner(
  './identity-envelope-rotation-guards.mjs',
  'identityEnvelopeRotationGrantsSql',
);
const businessReceiptGuardsSql = await sqlOwner(
  './business-receipt-guards.mjs',
  'businessReceiptGuardsSql',
);
const receiptSigningAttemptGuardsSql = await sqlOwner(
  './receipt-signing-attempt-guards.mjs',
  'receiptSigningAttemptGuardsSql',
);
const signingAuthorizationGuardsSql = await sqlOwner(
  './signing-authorization-guards.mjs',
  'signingAuthorizationGuardsSql',
);

it('finds both cardinality and method CASE conditions before PostgreSQL stops at their inner THEN', () => {
  for (const condition of [
    'count<>CASE WHEN used THEN 2 ELSE 1 END',
    "target IS DISTINCT FROM CASE method WHEN 'PREPARE' THEN 'PREPARED' END",
  ])
    expect(() =>
      verifyConditionCases(
        `DO $$ BEGIN IF ${condition} THEN RAISE EXCEPTION 'rejected'; END IF; END $$;`,
      ),
    ).toThrow('Unparenthesized CASE');
  expect(() =>
    verifyConditionCases(
      `DO $$ BEGIN IF count<>(CASE WHEN used THEN 2 ELSE 1 END) THEN RAISE EXCEPTION 'IF CASE THEN'; END IF; END $$;`,
    ),
  ).not.toThrow();
});

const definition = `CREATE OR REPLACE FUNCTION openpc.check_signing_continuation_context(p_context jsonb)
RETURNS void LANGUAGE plpgsql AS $$ BEGIN RETURN; END $$;`;
const grant =
  'GRANT EXECUTE ON FUNCTION openpc.check_signing_continuation_context(jsonb) TO openpc_control_runtime;';
it('limits a populated-store privilege reset to the migration owner definitions', () => {
  const projected = scopeFunctionRevocations(
    'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM PUBLIC;\n' +
      'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM openpc_control_reader;',
    definition,
  );
  expect(projected).toBe(
    'REVOKE ALL ON FUNCTION openpc.check_signing_continuation_context(jsonb) FROM PUBLIC;\n' +
      'REVOKE ALL ON FUNCTION openpc.check_signing_continuation_context(jsonb) FROM openpc_control_reader;',
  );
});
it('resets only prior installed and already-created functions, preserving late explicit revocations', () => {
  const prior = 'CREATE FUNCTION openpc.installed() RETURNS void AS $$ SELECT NULL $$;';
  const early = 'CREATE FUNCTION openpc.early() RETURNS void AS $$ SELECT NULL $$;';
  const late = 'CREATE FUNCTION openpc.late() RETURNS void AS $$ SELECT NULL $$;';
  const reset = 'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM PUBLIC;';
  const explicit = 'REVOKE ALL ON FUNCTION openpc.late() FROM PUBLIC;';
  const projected = scopeFunctionRevocations(early + reset + late + explicit + reset, prior);
  expect(projected).toBe(
    early +
      'REVOKE ALL ON FUNCTION openpc.early(),openpc.installed() FROM PUBLIC;' +
      late +
      explicit +
      'REVOKE ALL ON FUNCTION openpc.early(),openpc.installed(),openpc.late() FROM PUBLIC;',
  );
  // A routine already installed by a previous migration remains available even
  // when this migration replaces its definition after the reset.
  expect(scopeFunctionRevocations(reset + late, prior + late)).toContain(
    'openpc.installed(),openpc.late() FROM PUBLIC;',
  );
  expect(() => scopeFunctionRevocations(reset + late, '')).toThrow(
    'No owned functions for privilege projection',
  );
});
it('repairs only complete generated resets in unapplied SQL, without changing DDL or narrow grants', () => {
  const prior = 'CREATE FUNCTION openpc.installed() RETURNS void AS $$ SELECT NULL $$;';
  const early = 'CREATE FUNCTION openpc.early() RETURNS void AS $$ SELECT NULL $$;';
  const late = 'CREATE FUNCTION openpc.late() RETURNS void AS $$ SELECT NULL $$;';
  const roles =
    'openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance,openpc_backup_operator';
  const full = 'openpc.early(),openpc.installed(),openpc.late()';
  const grant = 'GRANT EXECUTE ON FUNCTION openpc.early() TO openpc_control_runtime;';
  const explicit = 'REVOKE ALL ON FUNCTION openpc.late() FROM PUBLIC;';
  const unknown = 'REVOKE ALL ON FUNCTION openpc.external(),openpc.late() FROM PUBLIC;';
  const sql =
    early +
    `REVOKE ALL ON FUNCTION ${full} FROM PUBLIC;` +
    `REVOKE ALL ON FUNCTION ${full} FROM ${roles};` +
    grant +
    late +
    explicit +
    unknown;
  const expected =
    early +
    'REVOKE ALL ON FUNCTION openpc.early(),openpc.installed() FROM PUBLIC;' +
    `REVOKE ALL ON FUNCTION openpc.early(),openpc.installed() FROM ${roles};` +
    grant +
    late +
    explicit +
    unknown;
  expect(repairFunctionRevocationOrder(sql, prior)).toBe(expected);
  expect(repairFunctionRevocationOrder(expected, prior)).toBe(expected);
  expect(verifyFunctionGrants(prior + expected, expected)).toContain(
    "('openpc.early()','openpc_control_runtime')",
  );
  expect(
    repairFunctionRevocationOrder(
      sql.replace(`FROM ${roles};`, 'FROM openpc_control_runtime;'),
      prior,
    ),
  ).toContain(`REVOKE ALL ON FUNCTION ${full} FROM openpc_control_runtime;`);
});
it('tracks actual drops, overloads and defaulted identities before each generated reset', () => {
  const prior =
    'CREATE FUNCTION openpc.owned(a uuid) RETURNS void AS $$ SELECT NULL $$;\n' +
    'CREATE FUNCTION openpc.owned(a text,b integer DEFAULT 2) RETURNS void AS $$ SELECT NULL $$;';
  const reset = 'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM PUBLIC;';
  const drop = '\nDROP FUNCTION IF EXISTS openpc.owned(uuid) RESTRICT;\n';
  const created = 'CREATE FUNCTION openpc.owned(a uuid) RETURNS void AS $$ SELECT NULL $$;';
  const projected = scopeFunctionRevocations(drop + reset + created + reset, prior);
  expect(projected).toBe(
    drop +
      'REVOKE ALL ON FUNCTION openpc.owned(text,integer) FROM PUBLIC;' +
      created +
      'REVOKE ALL ON FUNCTION openpc.owned(text,integer),openpc.owned(uuid) FROM PUBLIC;',
  );
  expect(() =>
    scopeFunctionRevocations('\nDROP FUNCTION openpc.owned CASCADE;\n' + reset, prior),
  ).toThrow('Unsupported cascading function drop');
  expect(() => scopeFunctionRevocations('\nDROP FUNCTION openpc.owned;\n' + reset, prior)).toThrow(
    'Unsupported generated function drop signature',
  );
  expect(() =>
    verifyFunctionGrants(
      prior + drop,
      'GRANT EXECUTE ON FUNCTION openpc.owned(uuid) TO openpc_control_runtime;',
    ),
  ).toThrow('no matching definition');
});
it('rejects missing helpers, different signatures, and unintended continuation grantees before migration', () => {
  expect(() => verifyFunctionGrants('', grant)).toThrow('no matching definition');
  expect(() => verifyFunctionGrants(definition, grant.replace('(jsonb)', '(bytea)'))).toThrow(
    'no matching definition',
  );
  expect(() =>
    verifyFunctionGrants(
      definition,
      grant.replace('openpc_control_runtime', 'openpc_control_worker'),
    ),
  ).toThrow('role mismatch');
  expect(verifyFunctionGrants(definition, grant)).toContain('to_regprocedure(expected.signature)');
});
it('handles multiple signatures, roles and defaulted arguments without splitting argument lists', () => {
  const sql = `CREATE FUNCTION openpc.one(a uuid,b numeric DEFAULT NULL) RETURNS boolean AS $$ SELECT true $$;
  CREATE FUNCTION openpc.two() RETURNS void AS $$ SELECT NULL $$;`;
  const projected = verifyFunctionGrants(
    sql,
    `GRANT EXECUTE ON FUNCTION openpc.one(uuid,numeric),openpc.two() TO "openpc_control_runtime",openpc_control_worker;`,
  );
  expect(projected).toContain("('openpc.one(uuid,numeric)','openpc_control_worker')");
  expect(projected).toContain("('openpc.two()','openpc_control_runtime')");
});

it('preserves worker access to the shared pure encoder without granting signing authority', () => {
  const sql = `CREATE FUNCTION openpc.signing_canonical_json(p_value jsonb) RETURNS text AS $$ SELECT p_value::text $$;`;
  const partial = `GRANT EXECUTE ON FUNCTION openpc.signing_canonical_json(jsonb) TO openpc_control_runtime,openpc_control_platform_runtime;`;
  expect(() => verifyFunctionGrants(sql, partial)).toThrow('role mismatch');
  expect(
    verifyFunctionGrants(
      sql,
      partial +
        '\nGRANT EXECUTE ON FUNCTION openpc.signing_canonical_json(jsonb) TO openpc_control_worker;',
    ),
  ).toContain("('openpc.signing_canonical_json(jsonb)','openpc_control_worker')");
});

it('binds every canonical maker/checker receipt to governed input and attempt admission before PostgreSQL', () => {
  // Independent canonical authority declarations, not a second production allowlist.
  const governed = businessTransitionProfiles.filter((profile) => {
    const definition = JSON.parse(profile.definitionCanonicalJson);
    return definition.authority.evidence.some((evidence: { kind: number }) => evidence.kind === 3);
  });
  expect([...new Set(governed.map((profile) => profile.catalogOperationId))].sort()).toEqual(
    [...governedReceiptOperationIds].sort(),
  );
  expect(governed.length).toBeGreaterThan(0);
  for (const profile of governed) {
    expect(receiptSigningAttemptGuardsSql).toContain(
      `decode('${profile.profileDigest.slice(7)}','hex')`,
    );
    expect(businessReceiptGuardsSql).toContain(`'${profile.catalogOperationId}'`);
  }
  expect(businessReceiptGuardsSql).toMatch(
    /jsonb_array_length\(actual->'20'\)<>\(CASE WHEN continuation_used OR NEW.catalog_operation_id IN \([^)]+\) OR NEW.catalog_operation_id IN \([^)]+\) THEN 2 ELSE 1 END\)/u,
  );
  const stepUp = businessTransitionProfiles.filter((profile) => {
    const kinds = JSON.parse(profile.definitionCanonicalJson).authority.evidence.map(
      (evidence: { kind: number }) => evidence.kind,
    );
    return kinds.includes(4) && !kinds.includes(3);
  });
  expect(stepUp.map((profile) => profile.catalogOperationId).sort()).toEqual(
    [...stepUpOnlyConfigurationOperations].sort(),
  );
  for (const profile of stepUp) {
    expect(
      JSON.parse(profile.definitionCanonicalJson).authority.evidence.map(
        (evidence: { kind: number }) => evidence.kind,
      ),
    ).toEqual([2, 4]);
    expect(receiptSigningAttemptGuardsSql).toContain(
      `decode('${profile.profileDigest.slice(7)}','hex')`,
    );
  }
  expect(businessReceiptGuardsSql).toContain(
    'expected:=jsonb_build_array(proof,openpc.configuration_step_up_receipt_input(NEW,authorization_row));',
  );
});

it('keeps business signing grants, consumer eligibility and owning state checks connected without widening roles', () => {
  const consumer = signingAuthorizationGuardsSql.match(
    /signerRole'='BUSINESS_EFFECT' AND i.namespace='CONTROL_BUSINESS_TRANSITION_V1' AND a.aggregate_type IN \(([^)]+)\)/u,
  );
  expect(consumer).not.toBeNull();
  const consumerTypes = consumer![1]!.split(',').map((value) => value.trim().replaceAll("'", ''));
  const effectProfiles = businessTransitionProfiles.filter((profile) =>
    (signingRoleProfiles.BUSINESS_EFFECT as readonly string[]).includes(profile.profileId),
  );
  expect([...new Set(effectProfiles.map((profile) => profile.profileId))].sort()).toEqual(
    [...signingRoleProfiles.BUSINESS_EFFECT].sort(),
  );
  expect([...new Set(effectProfiles.map((profile) => profile.aggregateType))].sort()).toEqual(
    consumerTypes.sort(),
  );
  for (const [aggregate, count] of [
    ['evidence-hold', 4],
    ['retention-policy', 2],
    ['evidence-deletion', 9],
    ['store-retirement', 1],
    ['runtime-artifact-disposition', 1],
    ['work-item', 4],
    ['notification', 2],
    ['notification-endpoint', 3],
    ['workload-renewal-policy', 4],
  ] as const) {
    const profiles = businessTransitionProfiles.filter(
      (profile) => profile.aggregateType === aggregate,
    );
    expect(profiles).toHaveLength(count);
    for (const profile of profiles) {
      expect(signingRoleProfiles.BUSINESS_EFFECT).toContain(profile.profileId);
      expect(signingRoleProfiles.LIFECYCLE_EVIDENCE).not.toContain(profile.profileId);
    }
    expect(businessReceiptGuardsSql).toContain(
      `IF NEW.aggregate_type='${aggregate}' THEN\n  PERFORM openpc.assert_${aggregate.replaceAll('-', '_')}_receipt(NEW);`,
    );
  }
  // Module trust and lifecycle continuation retain their separate owners.
  expect(
    effectProfiles.some((profile) =>
      ['module-registration', 'signing-key-rotation'].includes(profile.aggregateType),
    ),
  ).toBe(false);
});

it('admits both indexer state versions as separate exact grants and atomic attempts with one authority input', () => {
  const indexers = businessTransitionProfiles.filter(
    (profile) => profile.aggregateType === 'indexer-profile',
  );
  expect(
    indexers.map((profile) => [profile.catalogOperationId, profile.profileVersion]).sort(),
  ).toEqual([
    ['CFG-OP-CREATE-INDEXER-PROFILE', 1],
    ['CFG-OP-CREATE-INDEXER-PROFILE', 2],
    ['CFG-OP-UPDATE-INDEXER-PROFILE', 1],
    ['CFG-OP-UPDATE-INDEXER-PROFILE', 2],
  ]);
  for (const profile of indexers) {
    const canonical = JSON.parse(profile.definitionCanonicalJson);
    expect(canonical.authority.evidence.map((input: { kind: number }) => input.kind)).toEqual([2]);
    expect(canonical.events).toHaveLength(1);
    expect(canonical.events[0].eventType).toBe('io.openpc.control.command.committed.v1');
    expect(signingRoleProfiles.BUSINESS_EFFECT).toContain(profile.profileId);
    expect(signingRoleProfiles.LIFECYCLE_EVIDENCE).not.toContain(profile.profileId);
    expect(receiptSigningAttemptGuardsSql).toContain(
      `decode('${profile.profileDigest.slice(7)}','hex')`,
    );
    expect(businessReceiptGuardsSql).toContain(
      Buffer.from(profile.definitionCanonicalJson).toString('hex'),
    );
    expect(governedReceiptOperationIds).not.toContain(profile.catalogOperationId);
    expect(canonical.state.projection['4'].type).toBe(profile.profileVersion === 1 ? 'H32' : 'U64');
    if (profile.profileVersion === 2)
      expect(canonical.state.projection['5'].presence).toBe('required iff field 4 is 1');
  }
});

it('checks the complete hold selector, source and participant governance SQL before database allocation', async () => {
  const sql = await sqlOwner(
    new URL('../../../control-api/src/evidence/hold-guards.mjs', import.meta.url).href,
    'evidenceHoldGuardsSql',
  );
  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(sql).toContain('ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1');
  expect(sql).toContain('ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1');
  for (const name of [
    'evidence_hold_selector_encoding',
    'evidence_hold_source_match',
    'evidence_hold_record_metadata',
    'evidence_hold_match_state',
  ]) {
    expect(sql).toContain(`FUNCTION openpc.${name}(`);
    expect(sql).toContain(`REVOKE ALL ON FUNCTION openpc.${name}(`);
    expect(sql).toContain(`GRANT EXECUTE ON FUNCTION openpc.${name}(`);
  }
});

it('keeps raw-proof deletion separate from audit custody and checks its complete SQL owner before database allocation', async () => {
  const sql = await sqlOwner(
    new URL('../../../control-api/src/evidence/raw-deletion-guards.mjs', import.meta.url).href,
    'rawProofDeletionGuardsSql',
  );
  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(sql).toContain("p.data_class='RAW_SOURCE_BODY'");
  expect(sql).toContain('control.protected_proof_checkpoint');
  expect(sql).toContain('control.protected_proof_payload');
  expect(sql).toContain('IS DISTINCT FROM false');
  expect(sql).toContain("h.selector_type='PARTICIPANT'");
  expect(sql).toContain('openpc.evidence_deletion_selection_plan(job.selection)');
  expect(sql).toContain("confrelid='control.protected_proof_payload'::regclass");
  expect(sql).toContain("a.profile_id='pc.control.evidence-deletion.raw-proof'");
  expect(sql).not.toContain("p.data_class='AUDIT_EVIDENCE'");
});

it('checks projection deletion admissions and retirement SQL before allocating PostgreSQL', async () => {
  const sql = await sqlOwner(
    new URL('../../../control-api/src/evidence/projection-deletion-guards.mjs', import.meta.url)
      .href,
    'projectionDeletionGuardsSql',
  );
  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(sql).toContain("'NORMALIZED_JSON_PROJECTION','SEARCH_PROJECTION'");
  expect(sql).toContain("'PRE_ADMISSION_DENIAL'");
  expect(sql).toContain('control.evidence_export_selection');
  expect(sql).toContain('control.protected_proof_object');
  expect(sql).toContain('openpc.evidence_deletion_selection_plan(job.selection)');
  expect(sql).toContain("a.profile_id='pc.control.evidence-deletion.projection'");
});

it('admits the four public work-item profiles with exact actions, one authority input and no worker signing role', async () => {
  const projection = businessTransitionProfiles.filter((p) => p.aggregateType === 'work-item');
  expect(projection).toHaveLength(4);
  for (const profile of projection) {
    const definition = JSON.parse(profile.definitionCanonicalJson);
    expect(receiptSigningAttemptGuardsSql).toContain(
      `decode('${profile.profileDigest.slice(7)}','hex')`,
    );
    expect(definition.authority.approval).toBe('NOT_REQUIRED');
    expect(definition.authority.stepUp).toBe('NOT_REQUIRED');
    expect(definition.authority.evidence).toHaveLength(1);
    expect(definition.events).toHaveLength(1);
    expect(definition.events[0].cardinality).toBe(1);
    expect(Object.keys(definition.state.projection)).toEqual([
      '0',
      '1',
      '2',
      '3',
      '4',
      '5',
      '6',
      '7',
      '8',
      '9',
      '10',
      '11',
    ]);
    expect(signingRoleProfiles.BUSINESS_EFFECT).toContain(profile.profileId);
    expect(signingRoleProfiles.LIFECYCLE_EVIDENCE).not.toContain(profile.profileId);
    expect(governedReceiptOperationIds).not.toContain(profile.catalogOperationId);
    expect(profile.resourceType).toBe(
      ['CFG-OP-CREATE-WORK-ITEM', 'CFG-OP-UPDATE-WORK-ITEM'].includes(profile.catalogOperationId)
        ? 'work-items'
        : 'work-item',
    );
  }
  const owner = await sqlOwner('./work-item-receipt-guards.mjs', 'workItemReceiptGuardsSql');
  verifyConditionCases(owner);
  const grant =
    'GRANT EXECUTE ON FUNCTION openpc.work_item_business_projection(control.work_item),openpc.assert_work_item_receipt(control.audit_occurrence) TO openpc_control_runtime;';
  expect(verifyFunctionGrants(owner, grant)).toContain('to_regprocedure');
  for (const role of [
    'openpc_control_worker',
    'openpc_control_reader',
    'openpc_control_platform_runtime',
  ])
    expect(() =>
      verifyFunctionGrants(owner, grant.replace('openpc_control_runtime', role)),
    ).toThrow('role mismatch');
  expect(owner).toContain('DEFERRABLE INITIALLY DEFERRED');
  expect(owner).toContain('openpc.work_item_business_projection(OLD)');
});

it('admits only notification create and user acknowledgement with one authority and exact state/outbox bindings', async () => {
  const profiles = businessTransitionProfiles.filter((p) => p.aggregateType === 'notification');
  expect(profiles.map((p) => p.catalogOperationId).sort()).toEqual([
    'CFG-OP-ACKNOWLEDGE-NOTIFICATION',
    'CFG-OP-CREATE-NOTIFICATION',
  ]);
  for (const profile of profiles) {
    const definition = JSON.parse(profile.definitionCanonicalJson);
    expect(definition.authority.evidence.map((v: { kind: number }) => v.kind)).toEqual([2]);
    expect(definition.authority.approval).toBe('NOT_REQUIRED');
    expect(definition.authority.stepUp).toBe('NOT_REQUIRED');
    expect(definition.events).toHaveLength(1);
    expect(definition.events[0]).toMatchObject({
      cardinality: 1,
      eventType: 'io.openpc.control.command.committed.v1',
    });
    expect(receiptSigningAttemptGuardsSql).toContain(
      `decode('${profile.profileDigest.slice(7)}','hex')`,
    );
    expect(businessReceiptGuardsSql).toContain(
      Buffer.from(profile.definitionCanonicalJson).toString('hex'),
    );
    expect(governedReceiptOperationIds).not.toContain(profile.catalogOperationId);
    expect(profile.resourceType).toBe(
      profile.catalogOperationId === 'CFG-OP-CREATE-NOTIFICATION'
        ? 'notifications'
        : 'notification',
    );
  }
  const sql = await sqlOwner(
    new URL('../../../control-api/src/notifications/receipt-guards.mjs', import.meta.url).href,
    'notificationReceiptGuardsSql',
  );
  verifyConditionCases(sql);
  expect(verifyFunctionGrants(sql, sql)).toContain('to_regprocedure');
  for (const role of [
    'openpc_control_worker',
    'openpc_control_reader',
    'openpc_control_platform_runtime',
  ]) {
    const grant = `GRANT EXECUTE ON FUNCTION openpc.notification_business_projection(control.notification),openpc.assert_notification_receipt(control.audit_occurrence) TO ${role};`;
    expect(() => verifyFunctionGrants(sql, grant)).toThrow('role mismatch');
  }
  expect(sql).toContain('ALTER TABLE control.notification FORCE ROW LEVEL SECURITY');
  expect(sql).toContain('openpc.notification_business_projection(OLD)');
  expect(sql).toContain('DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION');
});

it('carries every admitted business profile into the actual generated Identity migration before allocation', async () => {
  const directory = new URL('../../../../migrations/postgres/identity/', import.meta.url);
  const latest = (await readdir(directory))
    .filter((name) => /^[0-9]{4}_.*\.sql$/u.test(name))
    .sort()
    .at(-1);
  expect(latest).toBeDefined();
  const sql = await readFile(new URL(latest!, directory), 'utf8');
  for (const profile of businessTransitionProfiles) {
    expect(
      sql,
      `Missing generated admission for ${profile.profileId}@${profile.profileVersion}`,
    ).toContain(`decode('${Buffer.from(profile.definitionCanonicalJson).toString('hex')}','hex')`);
  }
});

it('restricts identity-envelope recovery admission to its two scoped runtime roles before migration', async () => {
  const sql = await sqlOwner(
    './identity-envelope-recovery-trust-guards.mjs',
    'identityEnvelopeRecoveryTrustGuardsSql',
  );
  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(verifyFunctionGrants(sql, sql)).toContain(
    "('openpc.admit_identity_envelope_recovery_trust(bytea,bytea)','openpc_control_platform_runtime')",
  );
  for (const changed of [
    sql.replaceAll('openpc_control_platform_runtime', 'openpc_control_worker'),
    sql.replaceAll(
      'openpc_control_runtime,openpc_control_platform_runtime',
      'openpc_control_runtime',
    ),
  ])
    expect(() => verifyFunctionGrants(sql, changed)).toThrow('role mismatch');
});

it('restricts identity-envelope recovery selection to its scoped runtime roles', async () => {
  const sql = await sqlOwner(
    './identity-envelope-selection-guards.mjs',
    'identityEnvelopeSelectionGuardsSql',
  );
  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(verifyFunctionGrants(sql, sql)).toContain(
    "('openpc.select_identity_envelope_recovery_trust()','openpc_control_platform_runtime')",
  );
  expect(() =>
    verifyFunctionGrants(
      sql,
      sql.replaceAll('openpc_control_platform_runtime', 'openpc_control_worker'),
    ),
  ).toThrow('role mismatch');
});

it('restricts identity-envelope predecessor revocation to the exact scoped runtime roles', async () => {
  const sql = await sqlOwner(
    './identity-envelope-rotation-retirement-guards.mjs',
    'identityEnvelopeRotationRetirementGuardsSql',
  );
  expect(() => verifyConditionCases(sql)).not.toThrow();
  expect(verifyFunctionGrants(sql, sql)).toContain(
    "('openpc.revoke_identity_envelope_recovery_trust()','openpc_control_platform_runtime')",
  );
  expect(() =>
    verifyFunctionGrants(
      sql,
      sql.replaceAll('openpc_control_platform_runtime', 'openpc_control_worker'),
    ),
  ).toThrow('role mismatch');
  expect(() => verifyFunctionGrants(sql, sql.replace(/GRANT EXECUTE[^;]+;/u, ''))).toThrow();
});

it('preserves the closed Discovery continuation role contract through resets', () => {
  const definitions = `CREATE FUNCTION openpc.assert_discovery_preapproval_continuation(n control.mutation_candidate) RETURNS void AS $$ SELECT 1 $$;
 CREATE FUNCTION openpc.guard_discovery_preapproval_target_claims() RETURNS trigger AS $$ SELECT 1 $$;`;
  const exact = `GRANT EXECUTE ON FUNCTION openpc.assert_discovery_preapproval_continuation(control.mutation_candidate) TO openpc_control_runtime,openpc_control_platform_runtime;
 GRANT EXECUTE ON FUNCTION openpc.guard_discovery_preapproval_target_claims() TO openpc_control_owner;`;
  expect(verifyFunctionGrants(definitions, exact)).toContain('openpc_control_owner');
  for (const role of [
    'openpc_control_reader',
    'openpc_control_worker',
    'openpc_control_maintenance',
    'openpc_control_runtime',
  ])
    expect(() =>
      verifyFunctionGrants(
        definitions,
        exact +
          `GRANT EXECUTE ON FUNCTION openpc.guard_discovery_preapproval_target_claims() TO ${role};`,
      ),
    ).toThrow('role mismatch');
  expect(() =>
    verifyFunctionGrants(definitions, exact.replace(',openpc_control_platform_runtime', '')),
  ).toThrow('role mismatch');
  const reset =
    'REVOKE ALL ON FUNCTION openpc.assert_discovery_preapproval_continuation(control.mutation_candidate),openpc.guard_discovery_preapproval_target_claims() FROM openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance,openpc_backup_operator;';
  expect(() => verifyFunctionGrants(definitions, exact + reset)).toThrow(
    'revoked after declaration',
  );
  expect(
    verifyFunctionGrants(definitions, restoreFunctionGrantsAfterReset(exact + reset)),
  ).toContain('openpc_control_platform_runtime');
});

it('requires the handover assertion grant only for its existing mutation runtime roles', () => {
  const definition = workloadSigningHandoverAdmissionGuardsSql;
  const generated = definition + workloadSigningHandoverAdmissionGrantsSql;
  expect(() => verifyFunctionGrants(definition, generated)).not.toThrow();
  expect(() => verifyFunctionGrants(definition, definition)).toThrow(
    'Function grant role mismatch',
  );
  for (const role of [
    'openpc_control_worker',
    'openpc_control_reader',
    'openpc_control_maintenance',
    'openpc_backup_operator',
    'openpc_control_key_governor',
  ]) {
    expect(() =>
      verifyFunctionGrants(
        definition,
        generated +
          `\nGRANT EXECUTE ON FUNCTION openpc.assert_handover_admission_candidate(control.mutation_candidate) TO ${role};`,
      ),
    ).toThrow('Function grant role mismatch');
  }
  expect(() =>
    verifyFunctionGrants(
      definition,
      generated +
        '\nGRANT EXECUTE ON FUNCTION openpc.assert_handover_admission_candidate(control.mutation_candidate) TO PUBLIC;',
    ),
  ).toThrow('Unexpected function grantee: public');
});

it('keeps envelope rotation definitions out of the post-reset ACL fragment', () => {
  const statements = identityEnvelopeRotationGrantsSql
    .split(';')
    .map((value) => value.trim())
    .filter(Boolean);
  expect(statements).toHaveLength(4);
  expect(statements.every((value) => /^(GRANT|REVOKE)\b/u.test(value))).toBe(true);
  expect(identityEnvelopeRotationGrantsSql).not.toMatch(
    /\b(CREATE|ALTER|DROP|DO|FUNCTION|TRIGGER)\b/u,
  );
  expect(identityEnvelopeRotationGrantsSql).not.toMatch(
    /GRANT[^;]*(?:DELETE|TO PUBLIC|UPDATE ON)/u,
  );
  expect(identityEnvelopeRotationGuardsSql).toContain(
    'CREATE OR REPLACE FUNCTION openpc.revoke_identity_envelope_recovery_trust()',
  );
  expect(identityEnvelopeRotationGuardsSql).toContain(
    'CREATE CONSTRAINT TRIGGER identity_envelope_rotation_step_effect',
  );
  expect(identityEnvelopeRotationGuardsSql).not.toContain(
    'GRANT INSERT ON control.identity_envelope_rotation_step',
  );
  for (const statement of statements.filter((value) => value.startsWith('GRANT'))) {
    expect(statement).toMatch(/TO openpc_control_runtime,openpc_control_platform_runtime$/u);
    expect(statement).not.toMatch(
      /openpc_control_worker|openpc_control_reader|openpc_backup_operator/u,
    );
  }
});
function assertEnvelopeRotationGrantOrder(sql: string, grants: string) {
  const resets = [
    ...sql.matchAll(
      /REVOKE ALL ON "control"\.[^;]+ FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";/gu,
    ),
  ].filter(
    (match) =>
      match[0].includes('"identity_envelope_rotation_step"') &&
      match[0].includes('"identity_envelope_rotation_attempt"'),
  );
  if (resets.length !== 1) throw new Error('Missing or ambiguous runtime table reset');
  const reset = resets[0]!;
  const end = reset.index! + reset[0].length;
  const definition = sql.indexOf(
    'CREATE OR REPLACE FUNCTION openpc.revoke_identity_envelope_recovery_trust()',
  );
  if (definition < 0 || definition >= reset.index!)
    throw new Error('Retirement definition must precede normalization/reset');
  for (const statement of grants
    .split(';')
    .map((value) => value.trim())
    .filter(Boolean)) {
    const at = sql.lastIndexOf(statement + ';');
    if (at < end) throw new Error('Envelope ACL precedes runtime table reset');
    if (!statement.startsWith('GRANT')) continue;
    for (const revoke of sql
      .slice(at + statement.length + 1)
      .matchAll(/(?:^|\n)(REVOKE [^;]+;)/gu)) {
      const value = revoke[1]!.replaceAll('"', '');
      if (/\bON FUNCTION\b/u.test(value)) continue;
      const privileges = value.split(/\bON\b/u)[0]!;
      const roles = value.split(/\bFROM\b/u)[1] ?? '';
      if (
        /\b(ALL|INSERT|UPDATE)\b/u.test(privileges) &&
        /\bopenpc_control_(?:platform_runtime|runtime)\b/u.test(roles) &&
        /\bidentity_envelope_rotation_(?:step|attempt)\b/u.test(value)
      )
        throw new Error('Later runtime revoke cancels envelope ACL');
    }
  }
}
it('places exact constrained envelope step/attempt writes after the complete runtime-role table reset', async () => {
  const directory = new URL('../../../../migrations/postgres/identity/', import.meta.url);
  const latest = (await readdir(directory))
    .filter((name) => /^\d{4}_[a-z0-9_]+\.sql$/u.test(name))
    .sort()
    .at(-1);
  expect(latest).toBeDefined();
  const sql = await readFile(new URL(latest!, directory), 'utf8');
  expect(() =>
    assertEnvelopeRotationGrantOrder(sql, identityEnvelopeRotationGrantsSql),
  ).not.toThrow();
});
it('rejects grants before the runtime reset, missing retirement definitions and later cancelling revokes', () => {
  const definition =
    'CREATE OR REPLACE FUNCTION openpc.revoke_identity_envelope_recovery_trust() RETURNS void AS $$ SELECT NULL $$;\n';
  const tables =
    '"control"."identity_envelope_rotation_step", "control"."identity_envelope_rotation_attempt"';
  const publicReset = 'REVOKE ALL ON ' + tables + ' FROM PUBLIC;\n';
  const runtimeReset =
    'REVOKE ALL ON ' +
    tables +
    ' FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";\n';
  const valid = definition + publicReset + runtimeReset + identityEnvelopeRotationGrantsSql;
  expect(() =>
    assertEnvelopeRotationGrantOrder(valid, identityEnvelopeRotationGrantsSql),
  ).not.toThrow();
  for (const invalid of [
    definition + publicReset + identityEnvelopeRotationGrantsSql + runtimeReset,
    publicReset + runtimeReset + identityEnvelopeRotationGrantsSql,
    valid +
      '\nREVOKE UPDATE(state) ON control.identity_envelope_rotation_step FROM openpc_control_runtime;',
  ])
    expect(() =>
      assertEnvelopeRotationGrantOrder(invalid, identityEnvelopeRotationGrantsSql),
    ).toThrow();
});
