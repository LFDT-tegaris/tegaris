import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';

import { writeValidatedJsonAtomically } from '../../../../scripts/evidence/atomic-json.mjs';

const root = process.cwd();
const inputs = [
  'Cargo.lock',
  'pnpm-lock.yaml',
  'package.json',
  'tests/conformance/bootstrap/contract-manifest.json',
];
const artifacts = resolve(root, 'artifacts/i01');

const files = await Promise.all(
  inputs.map(async (path) => {
    const contents = await readFile(resolve(root, path));
    return {
      path,
      sha256: createHash('sha256').update(contents).digest('hex'),
    };
  }),
);

await writeValidatedJsonAtomically(resolve(artifacts, 'sbom-input-index.json'), {
  schemaVersion: '1.0',
  scope: 'Dependency and interface input inventory',
  files,
  deferred: 'Generate a release SBOM and build provenance from the actual distributed artifacts.',
  repositoryRelativePath: relative(root, artifacts),
});
