import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const moduleRoot = path.join(repositoryRoot, 'policies/modules/generated');

async function readJson(relativePath: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(path.join(moduleRoot, relativePath), 'utf8')) as Record<
    string,
    unknown
  >;
}

function sha256(value: Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}

describe('frozen module contract projection', () => {
  it('preserves the exact generated source index', async () => {
    const index = await readJson('generated-source-index.json');
    const files = index.files as Array<{ path: string; sha256: string }>;
    expect(files).toHaveLength(50);
    const projected = files.filter(({ path: sourcePath }) =>
      sourcePath.startsWith('SPECIFICATIONS/MODULES/'),
    );
    expect(projected.length).toBeGreaterThan(0);
    for (const file of projected) {
      const sourcePath = path.join(moduleRoot, file.path.replace('SPECIFICATIONS/MODULES/', ''));
      expect(sha256(await readFile(sourcePath))).toBe(file.sha256);
    }
    expect(index.denominator).toEqual({
      manifests: 33,
      dagNodes: 33,
      dagEdges: 69,
      traceRows: 5470,
      negativeCases: 264,
    });
  });

  it('validates all 33 closed manifests and their registry digests', async () => {
    const frozenSchema = await readJson('module-manifest.schema.json');
    const schema = await readJson('module-manifest.compat.schema.json');
    const registry = await readJson('module-registry.json');
    expect((frozenSchema.properties as Record<string, Record<string, unknown>>).$schema.const).toBe(
      'pkg://modules/module-manifest.schema.json',
    );
    expect((schema.properties as Record<string, Record<string, unknown>>).$schema.const).toBe(
      '../module-manifest.schema.json',
    );
    const certification = (schema.properties as Record<string, Record<string, unknown>>)
      .certification.properties as Record<string, Record<string, unknown>>;
    const targetProfiles = certification.targetProfiles;
    expect(targetProfiles.items).toBe(false);
    expect(targetProfiles.prefixItems).toHaveLength(5);

    // The authenticated schema closes this tuple with `items: false` but
    // intentionally omits redundant min/max bounds. Keep every other AJV
    // strictness check while accepting that valid Draft 2020-12 tuple form.
    const ajv = new Ajv2020({ allErrors: true, strict: true, strictTuples: false });
    addFormats(ajv);
    const validate = ajv.compile(schema);
    const modules = registry.modules as Array<{
      manifestPath: string;
      manifestSha256: string;
      moduleId: string;
    }>;
    expect(modules).toHaveLength(33);
    for (const module of modules) {
      const bytes = await readFile(path.join(moduleRoot, module.manifestPath));
      const manifest = JSON.parse(bytes.toString('utf8')) as Record<string, unknown>;
      expect(validate(manifest), JSON.stringify(validate.errors)).toBe(true);
      expect(sha256(bytes)).toBe(module.manifestSha256);
      expect((manifest.metadata as Record<string, unknown>).id).toBe(module.moduleId);
    }
  });

  it('preserves the deterministic 33-node and 69-edge acyclic install order', async () => {
    const registry = await readJson('module-registry.json');
    const nodes = registry.nodes as Array<{ nodeId: string }>;
    const edges = registry.edges as Array<{ edgeId: string; from: string; to: string }>;
    const installOrder = registry.installOrder as string[];
    expect(nodes).toHaveLength(33);
    expect(edges).toHaveLength(69);
    expect(new Set(installOrder)).toEqual(new Set(nodes.map(({ nodeId }) => nodeId)));
    const position = new Map(installOrder.map((moduleId, index) => [moduleId, index]));
    for (const edge of edges) {
      expect(edge.edgeId).toBe(`INSTALL-${edge.from}-BEFORE-${edge.to}`);
      expect(position.get(edge.from)).toBeLessThan(position.get(edge.to) as number);
    }
    expect(registry.cyclePolicy).toBe('FORBIDDEN');
  });

  it('preserves the full catalog, trace and conformance denominators', async () => {
    const catalog = await readJson('module-contract-catalog.json');
    const fixtures = await readJson('module-conformance-fixtures.json');
    const traceRows = (await readFile(path.join(moduleRoot, 'module-traceability.jsonl'), 'utf8'))
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect((catalog.types as unknown[]).length).toBe(16);
    expect((catalog.states as unknown[]).length).toBe(26);
    expect((catalog.operations as unknown[]).length).toBe(15);
    expect((catalog.errors as unknown[]).length).toBe(16);
    expect((catalog.events as unknown[]).length).toBe(10);
    expect((catalog.configuration as unknown[]).length).toBe(3);
    expect((catalog.migrations as unknown[]).length).toBe(2);
    expect((catalog.tests as unknown[]).length).toBe(14);
    expect(traceRows).toHaveLength(5470);
    expect((fixtures.positiveCases as unknown[]).length).toBe(4);
    expect((fixtures.negativeProfiles as unknown[]).length).toBe(8);
    expect((fixtures.negativeCases as unknown[]).length).toBe(264);
  });
});
