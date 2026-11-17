import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { expect, it } from 'vitest';

import { writeValidatedJsonAtomically } from '../../../scripts/evidence/atomic-json.mjs';
import { validatePrivacyExplorerOpenApiSource } from './scripts/privacy-explorer-contract-closure';

const fixtureDirectory = resolve(import.meta.dirname, 'fixtures');

it('keeps projection delivery and occurrence metadata in their separate closed public contracts', async () => {
  const source = await readFile(
    resolve(import.meta.dirname, '../../../schemas/openapi/openpc-privacy-explorer.openapi.yaml'),
    'utf8',
  );
  expect(validatePrivacyExplorerOpenApiSource(source)).toEqual({
    operations: 2,
    paths: 2,
    statuses: 12,
  });
  for (const altered of [
    source.replace('operationId: readPrivacyExplorerOccurrence', 'operationId: unknownOccurrence'),
    source.replace('PrivacyExplorerOccurrenceV1', 'PrivacyExplorerResultV1'),
    source.replace('PrivacyExplorerResultV1', 'ExplorerProjectionResultV1'),
    `${source}\n  /v1/privacy-explorer/extra:\n    post:\n      operationId: extra\n`,
  ])
    expect(() => validatePrivacyExplorerOpenApiSource(altered)).toThrow();
});

it('parses every bootstrap conformance fixture', async () => {
  const files = (await readdir(fixtureDirectory)).filter((file) => file.endsWith('.json')).sort();
  const fixtures = await Promise.all(
    files.map(async (file) => JSON.parse(await readFile(resolve(fixtureDirectory, file), 'utf8'))),
  );

  expect(files.length).toBeGreaterThan(0);
  expect(fixtures.every((fixture) => typeof fixture === 'object' && fixture !== null)).toBe(true);
});

it('uses the strongest compatible Buf lint profile', async () => {
  const configuration = await readFile(
    resolve(import.meta.dirname, '../../../proto/buf.yaml'),
    'utf8',
  );

  expect(configuration).toContain('    - BASIC');
  expect(configuration).not.toContain('    - MINIMAL');
});

it('keeps quoted digest header patterns valid under Unicode regular expressions', async () => {
  const openApi = await readFile(
    resolve(import.meta.dirname, '../../../schemas/openapi/openpc-control-api.openapi.yaml'),
    'utf8',
  );

  expect(openApi.match(/pattern: \^"sha256:\[0-9a-f\]\{64\}"\$/g)).toHaveLength(2);
  expect(openApi).not.toContain('pattern: ^\\"sha256:');
});

it('routes contract TypeScript tools through the workspace-safe temporary root', async () => {
  const repositoryRoot = resolve(import.meta.dirname, '../../..');
  const packageManifest = JSON.parse(
    await readFile(resolve(repositoryRoot, 'package.json'), 'utf8'),
  ) as { scripts: Record<string, string> };
  const wrapper = await readFile(
    resolve(repositoryRoot, 'scripts/contracts/run-with-toolchain.mjs'),
    'utf8',
  );
  const scriptNames = [
    'contracts:generate',
    'contracts:install',
    'contracts:lint',
    'contracts:manifest',
    'contracts:validate',
    'contracts:verify-generated',
    'contracts:dependencies',
    'licenses',
    'sbom',
  ];

  for (const scriptName of scriptNames) {
    expect(packageManifest.scripts[scriptName]).toContain(
      'scripts/contracts/run-with-toolchain.mjs',
    );
  }
  expect(wrapper).toContain('TMPDIR: temporaryRoot');
  expect(wrapper).toContain("['--import', 'tsx'");
  expect(wrapper).toContain("CI: 'true'");
  expect(wrapper).toContain('ASYNCAPI_METRICS_CONFIG_PATH');
  expect(wrapper).toContain('OPENPC_PNC_TMP_ROOT must not use /tmp.');
  expect(packageManifest.scripts.licenses).not.toContain('>');
});

it('does not expose a nonexistent workspace TMPDIR to clean CI setup actions', async () => {
  const repositoryRoot = resolve(import.meta.dirname, '../../..');
  const workflow = await readFile(resolve(repositoryRoot, '.github/workflows/ci.yml'), 'utf8');
  const packageManifest = JSON.parse(
    await readFile(resolve(repositoryRoot, 'package.json'), 'utf8'),
  ) as { scripts: Record<string, string> };

  expect(workflow).toContain('OPENPC_PNC_TMP_ROOT: ${{ github.workspace }}/.openpc-tmp');
  expect(workflow).not.toMatch(/^\s+TMPDIR:/mu);
  expect(workflow).toContain('run: pnpm run contracts:install');
  expect(packageManifest.scripts['contracts:install']).toContain(
    '--dir tests/conformance/bootstrap/asyncapi-cli --ignore-workspace install --frozen-lockfile',
  );
});

it('preserves prior evidence when an atomic JSON write fails before rename', async () => {
  const configuredRoot = process.env.OPENPC_PNC_TMP_ROOT;
  if (!configuredRoot) {
    throw new Error('OPENPC_PNC_TMP_ROOT is required for atomic evidence tests.');
  }
  await mkdir(resolve(configuredRoot), { recursive: true });
  const directory = await mkdtemp(join(resolve(configuredRoot), 'atomic-json-test-'));
  const destination = resolve(directory, 'evidence.json');
  const priorEvidence = '{"status":"prior-pass"}\n';

  try {
    await writeFile(destination, priorEvidence, 'utf8');
    await expect(
      writeValidatedJsonAtomically(
        destination,
        { status: 'replacement' },
        {
          beforeRename: () => {
            throw new Error('injected pre-rename failure');
          },
        },
      ),
    ).rejects.toThrow('injected pre-rename failure');
    expect(await readFile(destination, 'utf8')).toBe(priorEvidence);
    expect((await readdir(directory)).sort()).toEqual(['evidence.json']);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});
