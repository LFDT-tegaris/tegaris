import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  contractCounts,
  errorIds,
  eventTypes,
  frozenModuleContractInventory,
  installEdges,
  installOrder,
  migrationIds,
  testIds,
} from '../../../services/module-registry/src/index.js';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

describe('I03 authored and generated contract boundaries', () => {
  it('exposes the exact TypeScript module and policy inventory', () => {
    expect(frozenModuleContractInventory.counts).toBe(contractCounts);
    expect(contractCounts).toEqual({
      modules: 33,
      dagNodes: 33,
      dagEdges: 69,
      types: 16,
      states: 26,
      operations: 15,
      errors: 16,
      events: 10,
      configuration: 3,
      migrations: 2,
      tests: 14,
    });
    expect(installOrder).toHaveLength(33);
    expect(installEdges).toHaveLength(69);
    expect(errorIds).toHaveLength(16);
    expect(eventTypes).toHaveLength(10);
    expect(migrationIds).toHaveLength(2);
    expect(testIds).toHaveLength(14);
  });

  it('keeps generated Rust inventories aligned with the same frozen identifiers', async () => {
    const moduleRust = await readFile(
      path.join(repositoryRoot, 'crates/pc-module-sdk/src/generated.rs'),
      'utf8',
    );
    const policyRust = await readFile(
      path.join(repositoryRoot, 'crates/pc-policy-core/src/generated.rs'),
      'utf8',
    );
    for (const moduleId of frozenModuleContractInventory.moduleIds) {
      expect(moduleRust).toContain(JSON.stringify(moduleId));
    }
    for (const operationId of frozenModuleContractInventory.operationIds) {
      expect(policyRust).toContain(JSON.stringify(operationId));
    }
  });

  it('preserves a generated-only policy migration boundary', async () => {
    const migrationRoot = path.join(repositoryRoot, 'migrations/postgres/policy');
    const migrationFiles = (await readdir(migrationRoot)).sort();
    expect(migrationFiles).toEqual([
      '0000_yummy_plazm.sql',
      '0001_vengeful_human_torch.sql',
      '0002_clumsy_lady_mastermind.sql',
      '0003_motionless_lilandra.sql',
      '0004_empty_tempest.sql',
      '0005_third_albert_cleary.sql',
      '0006_pale_shape.sql',
      '0007_fancy_skreet.sql',
      '0008_black_madelyne_pryor.sql',
      '0009_parched_nekra.sql',
      '0010_policy_generation_fence.sql',
      '0011_chubby_talkback.sql',
      '0012_policy_set_generation_revision.sql',
      '0013_module_disable_reference_fences.sql',
      '0014_module_installation_direct_assignment_epoch.sql',
      'README.md',
      'meta',
    ]);
    const metadataFiles = (await readdir(path.join(migrationRoot, 'meta'))).sort();
    expect(metadataFiles).toEqual([
      '0000_snapshot.json',
      '0001_snapshot.json',
      '0002_snapshot.json',
      '0003_snapshot.json',
      '0004_snapshot.json',
      '0005_snapshot.json',
      '0006_snapshot.json',
      '0007_snapshot.json',
      '0008_snapshot.json',
      '0009_snapshot.json',
      '0010_snapshot.json',
      '0011_snapshot.json',
      '0012_snapshot.json',
      '0013_snapshot.json',
      '0014_snapshot.json',
      '_journal.json',
    ]);
    const journal = JSON.parse(
      await readFile(path.join(migrationRoot, 'meta/_journal.json'), 'utf8'),
    ) as { entries: { idx: number; tag: string }[] };
    expect(journal.entries).toHaveLength(15);
    expect(journal.entries.map(({ idx, tag }) => ({ idx, tag }))).toEqual(
      migrationFiles
        .filter((name) => name.endsWith('.sql'))
        .map((name, idx) => ({ idx, tag: name.slice(0, -4) })),
    );
    const drizzleConfig = await readFile(
      path.join(repositoryRoot, 'services/module-registry/drizzle.config.ts'),
      'utf8',
    );
    expect(drizzleConfig).toContain("schema: './src/db/schema/index.ts'");
    expect(drizzleConfig).toContain("out: '../../migrations/postgres/policy'");
    const packageJson = JSON.parse(
      await readFile(path.join(repositoryRoot, 'services/module-registry/package.json'), 'utf8'),
    ) as { scripts: Record<string, string> };
    expect(packageJson.scripts['db:generate']).toBe(
      'drizzle-kit generate --config drizzle.config.ts && node src/db/generate-policy-security-tail.mjs && node src/db/verify-policy-security.mjs',
    );
    const securityVerifier = await readFile(
      path.join(repositoryRoot, 'services/module-registry/src/db/verify-policy-security.mjs'),
      'utf8',
    );
    expect(securityVerifier).toContain('OPENPC GENERATED POLICY SECURITY TAIL; DO NOT EDIT');
    expect(securityVerifier).not.toContain('writeFile');
    const generated = await readFile(path.join(migrationRoot, '0000_yummy_plazm.sql'), 'utf8');
    expect(generated).toContain('"participant_id" uuid NOT NULL');
    expect(generated).toContain(
      'CREATE UNIQUE INDEX "policy_generation_one_active_uq" ON "control"."policy_generation" USING btree ("participant_id","privacy_domain_id","scope_digest")',
    );
    expect(generated).toContain('CREATE POLICY "privacy_domain_isolation"');
    expect(generated).not.toContain('OPENPC GENERATED I03 POLICY SECURITY TAIL');
    const binding = await readFile(
      path.join(migrationRoot, '0001_vengeful_human_torch.sql'),
      'utf8',
    );
    expect(binding).toContain('"webauthn_assertion_binding_digest" "bytea" NOT NULL');
    expect(binding).not.toContain('OPENPC GENERATED I03 POLICY SECURITY TAIL');
    const proofBinding = await readFile(
      path.join(migrationRoot, '0002_clumsy_lady_mastermind.sql'),
      'utf8',
    );
    expect(proofBinding).toContain('policy_activation_webauthn_one_use_uq');
    expect(proofBinding).toContain('OPENPC GENERATED POLICY SECURITY TAIL; DO NOT EDIT');
    expect(proofBinding).toContain('FORCE ROW LEVEL SECURITY');
    expect(proofBinding).toContain('OWNER TO "openpc_control_owner"');
    expect(proofBinding).not.toContain('ALTER ROLE');
  });
});
