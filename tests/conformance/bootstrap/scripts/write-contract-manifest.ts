import { readFile, rename, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { format, resolveConfig } from 'prettier';

import { repositoryRoot } from './contract-paths.js';
import {
  byteCompare,
  signingChangedContractOutputs,
  generatorDescriptors,
  privacyApiClientOutputs,
  privacyRustOutputs,
  privacyTypeScriptOutputs,
  protectedOpenApiOutputs,
  rustStagedOutputs,
  sha256,
} from './privacy-explorer-contract-closure.js';
import { generatedClosure } from './generate-typescript-contracts.js';

const jsonSchemaNames = [
  'action-intent-registry',
  'adapter-interface',
  'authority-context',
  'control-api',
  'error-registry',
  'event-envelope',
  'event-payloads',
  'jsonrpc-runtime',
  'problem',
  'shared-primitives',
  'sse-subscription',
  'ui-bff',
  'signing-key-rotation',
] as const;
const jsonSchemaSources = [
  ...jsonSchemaNames.map((name) => `schemas/json/${name}.schema.json`),
  'schemas/json/privacy-explorer.schema.json',
] as const;
const protoSources = [
  'proto/openpc/common/v1/common.proto',
  'proto/openpc/control/v1/control.proto',
  'proto/openpc/evidence/v1/evidence.proto',
  'proto/openpc/facts/v1/facts.proto',
  'proto/openpc/fleet/v1/fleet.proto',
  'proto/openpc/runtime/v1/runtime.proto',
] as const;
const fixedPaths = [
  'schemas/openapi/OPENAPI_REGISTRY.json',
  'schemas/openapi/openpc-control-api.openapi.yaml',
  'schemas/openapi/openpc-legacy-compatibility-v1.openapi.json',
  'schemas/openapi/openpc-privacy-explorer.openapi.yaml',
  'schemas/asyncapi/openpc-events.asyncapi.yaml',
  'proto/openpc/README.md',
  ...protoSources,
  'tests/conformance/bootstrap/test-obligations.yaml',
] as const;

const hash = async (path: string) => sha256(await readFile(resolve(repositoryRoot, path)));
const outputRows = async (paths: readonly string[]) =>
  Promise.all(paths.map(async (path) => ({ path, sha256: await hash(path) })));
const sourceDigest = async (paths: readonly string[]) =>
  sha256(
    `${(await Promise.all(paths.map(async (path) => ({ path, sha256: await hash(path) }))))
      .sort((left, right) => byteCompare(left.path, right.path))
      .map(({ path, sha256: digest }) => `${digest}  ${path}`)
      .join('\n')}\n`,
  );

type Descriptor = Readonly<{ name: string; version: string; argv: readonly string[] }>;
const row = async (
  source: string,
  sourceSha256: string,
  descriptor: Descriptor,
  preservationMode: string,
  outputs: readonly string[],
) => ({
  source,
  sourceSha256,
  generator: descriptor.name,
  generatorVersion: descriptor.version,
  argv: descriptor.argv,
  preservationMode,
  outputs: await outputRows(outputs),
});

export const buildContractManifest = async () => {
  const files = await Promise.all(
    [...fixedPaths, ...jsonSchemaSources]
      .sort(byteCompare)
      .map(async (path) => ({ path, sha256: await hash(path) })),
  );
  const sourceOutputs = [];
  for (const source of jsonSchemaSources) {
    const output = `generated/typescript/json-schema/${source.slice('schemas/json/'.length, -'.schema.json'.length)}.d.ts`;
    sourceOutputs.push(
      await row(
        source,
        await hash(source),
        generatorDescriptors.json2ts,
        signingChangedContractOutputs.includes(output) || output === privacyTypeScriptOutputs[0]
          ? 'PUBLISH_EXACT_ALLOWLIST'
          : 'VERIFY_ONLY_IMMUTABLE_PREDECESSOR',
        [output],
      ),
    );
  }
  sourceOutputs.push(
    await row(
      'generated/typescript/README.md',
      await hash('generated/typescript/README.md'),
      {
        name: 'I01 immutable generated-contract notice',
        version: '1.0',
        argv: ['NOT_RUN_BY_I07'],
      },
      'VERIFY_ONLY_IMMUTABLE_PREDECESSOR',
      ['generated/typescript/README.md'],
    ),
    await row(
      'schemas/json/privacy-explorer.schema.json',
      await hash('schemas/json/privacy-explorer.schema.json'),
      {
        name: 'I07 Privacy Explorer extension generator',
        version: '1.0',
        argv: generatorDescriptors.contractTree.argv,
      },
      'PUBLISH_EXACT_ALLOWLIST',
      [privacyTypeScriptOutputs[1], privacyTypeScriptOutputs[2]],
    ),
    await row(
      'schemas/openapi/openpc-control-api.openapi.yaml',
      await hash('schemas/openapi/openpc-control-api.openapi.yaml'),
      generatorDescriptors.openapiControl,
      'PUBLISH_SIGNING_ALLOWLIST_PRESERVE_UNRELATED_OUTPUTS',
      protectedOpenApiOutputs,
    ),
    await row(
      'schemas/openapi/openpc-privacy-explorer.openapi.yaml',
      await hash('schemas/openapi/openpc-privacy-explorer.openapi.yaml'),
      generatorDescriptors.openapiPrivacy,
      'PUBLISH_EXACT_ALLOWLIST',
      privacyApiClientOutputs,
    ),
    await row(
      'schemas/json',
      await sourceDigest(jsonSchemaSources),
      generatorDescriptors.rust,
      'PUBLISH_EXACT_ALLOWLIST',
      privacyRustOutputs,
    ),
    await row(
      'proto/openpc',
      await sourceDigest(protoSources),
      generatorDescriptors.rust,
      'VERIFY_ONLY_IMMUTABLE_PREDECESSOR',
      rustStagedOutputs.filter((path) => path.startsWith('generated/rust/proto/')),
    ),
    await row(
      'generated',
      await sourceDigest(generatedClosure),
      {
        name: 'I07 generated-tree closure',
        version: generatorDescriptors.contractTree.version,
        argv: generatorDescriptors.contractTree.argv,
      },
      'PUBLISH_CHECKSUM_AFTER_ATOMIC_OUTPUTS',
      ['generated/contract-tree.sha256'],
    ),
  );
  return { schemaVersion: '1.1', files, sourceOutputs };
};

if (resolve(process.argv[1] ?? '') === resolve(import.meta.filename)) {
  const manifest = await buildContractManifest();
  const destination = resolve(repositoryRoot, 'tests/conformance/bootstrap/contract-manifest.json');
  const temporary = `${destination}.i07-${process.pid}`;
  const formatted = await format(JSON.stringify(manifest), {
    ...(await resolveConfig(destination)),
    filepath: destination,
  });
  await writeFile(temporary, formatted, { flag: 'wx' });
  await rename(temporary, destination);
}
