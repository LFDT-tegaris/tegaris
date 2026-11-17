import { expect, it } from 'vitest';
import { getTableConfig } from 'drizzle-orm/pg-core';
import { PgDialect } from 'drizzle-orm/pg-core';
import { controlRuntimeRole } from './schema/common.js';
import {
  workloadRenewalSigningGrants,
  workloadRenewalSigningProfiles,
  workloadRenewalSigningSelections,
} from './schema/workload-renewal-signing.js';
import {
  workloadRenewalSigningProfileCanonicalJson,
  workloadRenewalSigningProfileDigest,
} from '@openpc/security-kernel';
import {
  workloadRenewalAttempts,
  workloadRenewalIntents,
  workloadRenewalObservations,
  workloadRenewalIssueAuthorizations,
  workloadRenewalPolicies,
  workloadRenewalPolicyHeads,
  workloadCredentialFamilies,
} from './schema/workload-renewal.js';

/** Drizzle source regressions. Real migration/runtime-role behavior is still
 * required; metadata inspection never claims SQL or operational acceptance. */
it('binds an issuance authorization to the same scope, original, attempt and observation', () => {
  const fk = getTableConfig(workloadRenewalIssueAuthorizations)
    .foreignKeys.find((key) => key.getName() === 'wr_authorization_observation_fk')!
    .reference();
  const columns = [
    'participant_id',
    'privacy_domain_id',
    'renewal_id',
    'attempt_id',
    'observation_id',
  ];
  expect(fk.columns.map((column) => column.name)).toEqual(columns);
  expect(fk.foreignColumns.map((column) => column.name)).toEqual(columns);
});
it('admits only generated trust v2 and keeps purpose376 grants separate from ordinary receipt and envelope grants', () => {
  const profile = getTableConfig(workloadRenewalSigningProfiles);
  const sql = new PgDialect().sqlToQuery(
    profile.checks.find((c) => c.name === 'wr_signing_profile_exact_ck')!.value,
  ).sql;
  expect(sql).toContain(workloadRenewalSigningProfileDigest.slice(7));
  expect(sql).toContain('=2');
  expect(sql).toContain('=376');
  // Drizzle's generated CHECK extraction cannot safely retain semicolons in
  // an embedded SQL string. Bind the exact original canonical UTF8 as bytea.
  const definition = /"definition_canonical_json"=decode\('([0-9a-f]+)','hex'\)/u.exec(sql)?.[1];
  expect(definition).toBeDefined();
  expect(Buffer.from(definition!, 'hex').toString('utf8')).toBe(
    workloadRenewalSigningProfileCanonicalJson,
  );
  expect(sql).not.toContain(';');
  const grant = getTableConfig(workloadRenewalSigningGrants),
    selection = getTableConfig(workloadRenewalSigningSelections);
  const key = grant.foreignKeys.find((k) => k.getName() === 'wr_signing_grant_key_fk')!.reference();
  expect(key.columns.map((c) => c.name)).toEqual([
    'participant_id',
    'privacy_domain_id',
    'signer_id',
    'signing_purpose_code',
  ]);
  expect(key.foreignColumns.map((c) => c.name)).toEqual(key.columns.map((c) => c.name));
  const family = grant.foreignKeys
    .find((k) => k.getName() === 'wr_signing_grant_family_fk')!
    .reference();
  expect(family.columns.map((c) => c.name)).toEqual([
    'participant_id',
    'privacy_domain_id',
    'family_id',
  ]);
  expect(selection.foreignKeys[0]!.reference().foreignTable).toBe(workloadRenewalSigningGrants);
});
it('binds observations to their exact original attempt rather than another tenant or intent', () => {
  const fk = getTableConfig(workloadRenewalObservations)
    .foreignKeys.find((key) => key.getName() === 'wr_observation_attempt_fk')!
    .reference();
  expect(fk.columns.map((column) => column.name)).toEqual([
    'participant_id',
    'privacy_domain_id',
    'renewal_id',
    'attempt_id',
  ]);
  expect(fk.foreignColumns.map((column) => column.name)).toEqual(
    fk.columns.map((column) => column.name),
  );
});
it('keeps failed or ambiguous originals in the unique pending-family reservation', () => {
  const index = getTableConfig(workloadRenewalIntents).indexes.find(
    (i) => i.config.name === 'wr_intent_pending_uq',
  )!;
  expect(index.config.unique).toBe(true);
  expect(new PgDialect().sqlToQuery(index.config.where!).sql).toContain("<>'COMPLETE'");
});
it.each([
  workloadCredentialFamilies,
  workloadRenewalIntents,
  workloadRenewalAttempts,
  workloadRenewalObservations,
  workloadRenewalIssueAuthorizations,
])(
  'grants no application mutation policy before authoritative installation admission is connected %#',
  (table) => {
    const config = getTableConfig(table);
    expect(config.enableRLS).toBe(true);
    expect(config.policies.map((p) => p.for)).toEqual(['select']);
    const read = new PgDialect().sqlToQuery(config.policies[0]!.using!).sql;
    expect(read).toContain('openpc.matches_participant');
    expect(read).toContain('openpc.matches_privacy');
  },
);
it('allows only human policy insertion and current-head CAS, leaving worker writes closed', () => {
  const policy = getTableConfig(workloadRenewalPolicies);
  const head = getTableConfig(workloadRenewalPolicyHeads);
  expect(policy.policies.map((p) => p.for)).toEqual(['select', 'insert']);
  expect(head.policies.map((p) => p.for)).toEqual(['select', 'insert', 'update']);
  for (const config of [policy, head])
    for (const p of config.policies.filter((p) => p.for !== 'select')) {
      expect(p.to).toEqual([controlRuntimeRole]);
      expect(new PgDialect().sqlToQuery(p.withCheck!).sql).toContain(
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      );
    }
  const fk = head.foreignKeys
    .find((k) => k.getName() === 'wr_policy_head_revision_fk')!
    .reference();
  expect(fk.columns.map((c) => c.name)).toEqual([
    'participant_id',
    'privacy_domain_id',
    'policy_id',
    'current_revision',
  ]);
  expect(fk.foreignColumns.map((c) => c.name)).toEqual([
    'participant_id',
    'privacy_domain_id',
    'policy_id',
    'revision',
  ]);
});
