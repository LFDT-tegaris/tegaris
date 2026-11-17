import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

// Select exact dependency closure; public admission still authenticates every release.
export function selectModuleReleases(releases, roots) {
  assert.ok(releases.length > 0);
  const byId = new Map();
  for (const [index, release] of releases.entries()) {
    assert.ok(!byId.has(release.manifest.metadata.id), 'Ambiguous module release');
    byId.set(release.manifest.metadata.id, { ...release, index });
  }
  const active = new Set(),
    selected = new Set();
  function visit(id) {
    const entry = byId.get(id);
    assert.ok(entry, `Missing module dependency: ${id}`);
    assert.ok(!active.has(id), 'Cyclic module dependency');
    if (selected.has(entry.index)) return;
    active.add(id);
    for (const dependency of entry.manifest.dependencies) {
      const target = byId.get(dependency.moduleId);
      assert.ok(target, `Missing module dependency: ${dependency.moduleId}`);
      assert.equal(dependency.providerModuleId, dependency.moduleId);
      assert.equal(
        target.manifest.metadata.version,
        dependency.version,
        'Exact dependency version',
      );
      assert.equal(target.manifestDigest, dependency.manifestDigest, 'Exact dependency digest');
      visit(dependency.moduleId);
    }
    active.delete(id);
    selected.add(entry.index);
  }
  assert.ok(Array.isArray(roots) && roots.length > 0);
  assert.equal(new Set(roots).size, roots.length, 'Duplicate module roots');
  for (const root of roots) visit(root);
  return [...selected];
}

export async function moduleReleaseSelection(
  catalogPath,
  rootsText = process.env.OPENPC_LOCAL_MODULE_ROOTS,
) {
  const catalog = JSON.parse(await readFile(catalogPath, 'utf8'));
  const releases = await Promise.all(
    catalog.releases.map(async (entry) => ({
      ...entry,
      manifest: JSON.parse(await readFile(join(dirname(catalogPath), entry.manifestBytes), 'utf8')),
    })),
  );
  const roots =
    rootsText === undefined
      ? releases.map((entry) => entry.manifest.metadata.id)
      : JSON.parse(rootsText);
  return selectModuleReleases(releases, roots);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  process.stdout.write((await moduleReleaseSelection(process.argv[2])).join(' ') + '\n');
