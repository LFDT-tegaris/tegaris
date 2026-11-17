import { spawnSync } from 'node:child_process';
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  rmdir,
  writeFile,
} from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

import { listFiles, repositoryRoot } from './contract-paths.js';
import {
  assertExactHashes,
  assertExactSet,
  assertSafeRelativePath,
  byteCompare,
  existingTypeScriptJsonSchemaOutputs,
  signingTypeScriptOutputs,
  signingChangedContractOutputs,
  hashRows,
  privacyApiClientOutputs,
  privacyRustOutputs,
  privacyTypeScriptOutputs,
  protectedOpenApiOutputs,
  protectedOpenApiSha256ByPath,
  rustStagedOutputs,
  sha256,
  validateExecutionRegistry,
  validatePrivacyExplorerProblemUnion,
} from './privacy-explorer-contract-closure.js';

export type GenerationMode = 'generate' | 'verify';

const privacySchemaPath = 'schemas/json/privacy-explorer.schema.json';
const preservedRustOutputs = rustStagedOutputs.filter(
  (path) => !privacyRustOutputs.includes(path as (typeof privacyRustOutputs)[number]),
);
export const generatedClosure = [
  'generated/typescript/README.md',
  ...existingTypeScriptJsonSchemaOutputs,
  ...signingTypeScriptOutputs,
  ...protectedOpenApiOutputs,
  ...privacyTypeScriptOutputs,
  ...rustStagedOutputs,
] as const;
const publishOutputs = [
  ...signingChangedContractOutputs,
  ...privacyTypeScriptOutputs,
  ...privacyRustOutputs,
  ...privacyApiClientOutputs,
] as const;
const contractTreePath = 'generated/contract-tree.sha256';
export const publicationEntryCount = publishOutputs.length + 1;

type PublicationEntry = Readonly<{ path: string; bytes: Uint8Array }>;

const execute = (program: string, args: string[], environment = process.env) => {
  const result = spawnSync(program, args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: environment,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${program} ${args.join(' ')} failed:\n${result.stderr || result.stdout}`);
  }
};

const walk = async (directory: string): Promise<string[]> => {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = await Promise.all(
    entries
      .sort((left, right) => byteCompare(left.name, right.name))
      .map(async (entry) => {
        const path = join(directory, entry.name);
        if (entry.isSymbolicLink()) throw new Error(`staged symbolic link is forbidden: ${path}`);
        return entry.isDirectory() ? walk(path) : [path];
      }),
  );
  return paths.flat();
};

const relativeFiles = async (root: string) =>
  (await walk(root)).map((path) => relative(root, path).split(sep).join('/'));

const readRows = async (root: string, paths: readonly string[]) =>
  hashRows(
    await Promise.all(
      paths.map(async (path) => ({ path, bytes: await readFile(resolve(root, path)) })),
    ),
  );

const compareBytes = async (stagedRoot: string, paths: readonly string[], label: string) => {
  for (const path of paths) {
    const staged = await readFile(resolve(stagedRoot, path));
    const live = await readFile(resolve(repositoryRoot, path));
    if (!staged.equals(live)) throw new Error(`${label}: byte drift for ${path}`);
  }
};

const isWithin = (candidate: string, owner: string) =>
  candidate === owner || candidate.startsWith(`${owner}${sep}`);

const nearestExistingAncestor = async (path: string) => {
  let candidate = path;
  for (;;) {
    try {
      await lstat(candidate);
      return candidate;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      const parent = dirname(candidate);
      if (parent === candidate) throw new Error(`no existing ancestor for ${path}`);
      candidate = parent;
    }
  }
};

export const validateApprovedTemporaryRoot = async (temporaryRoot: string) => {
  if (!isAbsolute(temporaryRoot) || resolve(temporaryRoot).startsWith('/tmp'))
    throw new Error('OPENPC_PNC_TMP_ROOT must be an absolute non-/tmp directory');
  const workspaceReal = await realpath(repositoryRoot);
  const ancestorReal = await realpath(await nearestExistingAncestor(temporaryRoot));
  if (isWithin(ancestorReal, workspaceReal))
    throw new Error('OPENPC_PNC_TMP_ROOT must not resolve inside the repository');
  await mkdir(temporaryRoot, { recursive: true });
  const temporaryReal = await realpath(temporaryRoot);
  if (isWithin(temporaryReal, workspaceReal))
    throw new Error('OPENPC_PNC_TMP_ROOT must not resolve inside the repository');
  return { temporaryReal, workspaceReal };
};

const assertExternalRunRoot = async (
  runRoot: string,
  temporaryReal: string,
  workspaceReal: string,
) => {
  const runReal = await realpath(runRoot);
  if (isWithin(runReal, workspaceReal) || !isWithin(runReal, temporaryReal)) {
    throw new Error(`staging root escaped the approved external temporary root: ${runReal}`);
  }
};

const writePrivacyValidator = async (stagedRoot: string, schema: Record<string, unknown>) => {
  const path = resolve(
    stagedRoot,
    'generated/typescript/json-schema/privacy-explorer.validator.mjs',
  );
  await mkdir(dirname(path), { recursive: true });
  const definitions = Object.keys((schema.$defs ?? {}) as Record<string, unknown>).sort(
    byteCompare,
  );
  const aliases = definitions
    .map(
      (name) =>
        `const baseValidate${name} = ajv.compile({ $ref: ${JSON.stringify(`${String(schema.$id)}#/$defs/${name}`)} });\nexport const validate${name} = withChecks(baseValidate${name}, extraChecks.${name});`,
    )
    .join('\n');
  await writeFile(
    path,
    `// @generated from ${privacySchemaPath}; do not edit.\nimport Ajv2020 from 'ajv/dist/2020.js';\nimport addFormats from 'ajv-formats';\n\nexport const privacyExplorerSchema = ${JSON.stringify(schema, null, 2)};\nconst ajv = new Ajv2020({ allErrors: true, strict: true });\najv.addKeyword({ keyword: 'x-openpc-executionRegistry', schemaType: 'object', valid: true });\naddFormats(ajv);\najv.addSchema(privacyExplorerSchema);\nconst orderedUnique = (values, key) => Array.isArray(values) && values.every((value, index) => index === 0 || key(values[index - 1]) < key(value));\nconst canonicalScalar = (value) => JSON.stringify(value);\nconst filterKey = (entry) => \`\${entry.fieldId}\\u0000\${entry.filterId}\\u0000\${canonicalScalar(entry.value)}\`;\nconst profileRelations = (value) => value.operationVersions.length === 9 && orderedUnique(value.operationVersions, (entry) => entry.operationId) && value.operationVersions.every((entry) => orderedUnique(entry.acceptedDataClassIds, (dataClassId) => dataClassId)) && orderedUnique(value.allowedFieldIds, (entry) => entry) && orderedUnique(value.allowedFilterIds, (entry) => entry) && value.retryBackoffMilliseconds.length === value.maximumReadAttempts - 1 && value.retryBackoffMilliseconds.every((delay, index) => index === 0 || value.retryBackoffMilliseconds[index - 1] <= delay);\nconst requestRelations = (value) => {\n  const operation = value.exportProfile.operationVersions.find((entry) => entry.operationId === value.operationId && entry.version === value.semanticOperationVersion);\n  return profileRelations(value.exportProfile) && value.scope.action === value.action && Boolean(operation?.acceptedDataClassIds.includes(value.dataClassId)) && value.page.limit <= value.exportProfile.maximumPageSize && orderedUnique(value.filters, filterKey) && orderedUnique(value.projectionFields, (entry) => entry) && value.projectionFields.every((fieldId) => value.exportProfile.allowedFieldIds.includes(fieldId)) && value.filters.every((filter) => value.projectionFields.includes(filter.fieldId) && value.exportProfile.allowedFilterIds.includes(filter.filterId));\n};\nconst recordOrder = (value) => orderedUnique(value.records, (entry) => entry.id) && value.records.every((record) => orderedUnique(record.fields, (entry) => entry.fieldId));\nconst outcomeTruth = { COMPLETE: 'TRUE', PARTIAL: 'PARTIAL', UNKNOWN: 'UNKNOWN', UNAVAILABLE: 'UNAVAILABLE' };\nconst resultRelations = (value) => {\n  if (!recordOrder(value) || outcomeTruth[value.outcome] !== value.truthState) return false;\n  if (value.outcome === 'COMPLETE') return value.page.gapFree === true && value.page.cursor === null;\n  if (value.outcome === 'PARTIAL') return value.page.gapFree === false || value.page.cursor !== null;\n  return value.records.length === 0 && value.page.gapFree === false && value.page.cursor === null;\n};\nconst extraChecks = {\n  PrivacyExplorerExportProfileV1: profileRelations,\n  ExplorerProjectionRequestV1: requestRelations,\n  AdapterCallContextV1: (value) => orderedUnique(value.accessClassIds, (entry) => entry) && value.cancellation.occurrenceId === value.occurrenceId && value.reconciliation.occurrenceId === value.occurrenceId,\n  ExplorerProjectionResultV1: recordOrder,\n  PrivacyExplorerResultV1: resultRelations,\n};\nconst withChecks = (base, extra = () => true) => {\n  const validate = (value) => {\n    const valid = base(value) && extra(value);\n    validate.errors = valid ? null : (base.errors ?? [{ keyword: 'x-openpc-order-or-relation', message: 'ordering or cross-field relation failed' }]);\n    return valid;\n  };\n  validate.errors = null;\n  return validate;\n};\nconst baseValidatePrivacyExplorerDocument = ajv.getSchema(${JSON.stringify(String(schema.$id))});\nif (!baseValidatePrivacyExplorerDocument) throw new Error('Privacy Explorer root validator was not compiled');\nexport const validatePrivacyExplorerDocument = withChecks(baseValidatePrivacyExplorerDocument, (value) => (!value.request || requestRelations(value.request)) && (!value.result || resultRelations(value.result)) && (!value.request || !value.result || (value.request.exportProfile.digest === value.result.profileDigest && value.request.queryDigest === value.result.queryDigest)));\n${aliases}\n`,
  );
};

const stageAll = async (runRoot: string) => {
  const schemaPaths = await listFiles(resolve(repositoryRoot, 'schemas/json'), '.schema.json');
  const expectedSchemas = [
    ...existingTypeScriptJsonSchemaOutputs.map((path) => basename(path, '.d.ts')),
    ...signingTypeScriptOutputs.map((path) => basename(path, '.d.ts')),
    'privacy-explorer',
  ].sort(byteCompare);
  assertExactSet(
    schemaPaths.map((path) => basename(path, '.schema.json')),
    expectedSchemas,
    'JSON Schema source inventory',
  );

  for (const schemaPath of schemaPaths) {
    const name = basename(schemaPath, '.schema.json');
    const output = resolve(runRoot, `generated/typescript/json-schema/${name}.d.ts`);
    await mkdir(dirname(output), { recursive: true });
    const args = [
      'exec',
      'json2ts',
      '--input',
      schemaPath,
      '--output',
      output,
      '--cwd',
      resolve(repositoryRoot, 'schemas/json'),
      '--unknownAny',
    ];
    if (name === 'event-payloads' || name === 'signing-key-rotation')
      args.push('--unreachableDefinitions');
    execute('pnpm', args);
  }

  const controlOutput = resolve(runRoot, 'generated/typescript/openapi');
  const privacyOutput = resolve(runRoot, 'packages/api-client/generated/privacy-explorer');
  execute('pnpm', [
    'exec',
    'openapi-ts',
    '--input',
    'schemas/openapi/openpc-control-api.openapi.yaml',
    '--output',
    controlOutput,
    '--client',
    '@hey-api/client-fetch',
    '--no-log-file',
    '--silent',
  ]);
  execute('pnpm', [
    'exec',
    'openapi-ts',
    '--input',
    'schemas/openapi/openpc-privacy-explorer.openapi.yaml',
    '--output',
    privacyOutput,
    '--client',
    '@hey-api/client-fetch',
    '--no-log-file',
    '--silent',
  ]);

  const schema = JSON.parse(
    await readFile(resolve(repositoryRoot, privacySchemaPath), 'utf8'),
  ) as Record<string, unknown>;
  const registry = schema['x-openpc-executionRegistry'];
  validateExecutionRegistry(registry);
  validatePrivacyExplorerProblemUnion(schema, registry);
  await writePrivacyValidator(runRoot, schema);
  const registryOutput = resolve(
    runRoot,
    'generated/typescript/privacy-explorer/execution-registry.ts',
  );
  await mkdir(dirname(registryOutput), { recursive: true });
  await writeFile(
    registryOutput,
    `// @generated from ${privacySchemaPath}; do not edit.\nexport const privacyExplorerExecutionRegistry = ${JSON.stringify(registry, null, 2)} as const;\n`,
  );

  const toolchainBin = process.env.OPENPC_C17_TOOLCHAIN_BIN;
  if (!toolchainBin || !isAbsolute(toolchainBin)) {
    throw new Error('OPENPC_C17_TOOLCHAIN_BIN must be an absolute directory');
  }
  const protoc = resolve(toolchainBin, 'protoc');
  if (!(await lstat(protoc)).isFile()) throw new Error(`protoc is unavailable: ${protoc}`);
  execute(
    'cargo',
    [
      'run',
      '--locked',
      '-p',
      'pc-contracts',
      '--bin',
      'generate-rust-contracts',
      '--',
      '--output-root',
      runRoot,
    ],
    { ...process.env, PATH: `${toolchainBin}:${process.env.PATH ?? ''}`, PROTOC: protoc },
  );
};

const validateStage = async (runRoot: string) => {
  assertExactSet(
    await relativeFiles(resolve(runRoot, 'generated/typescript/json-schema')),
    [
      ...[...existingTypeScriptJsonSchemaOutputs, ...signingTypeScriptOutputs].map((path) =>
        path.replace('generated/typescript/json-schema/', ''),
      ),
      ...privacyTypeScriptOutputs
        .filter((path) => path.includes('/json-schema/'))
        .map((path) => path.replace('generated/typescript/json-schema/', '')),
    ],
    'staged TypeScript JSON Schema outputs',
  );
  assertExactSet(
    (await relativeFiles(resolve(runRoot, 'generated/typescript/openapi'))).map(
      (path) => `generated/typescript/openapi/${path}`,
    ),
    protectedOpenApiOutputs,
    'staged protected OpenAPI outputs',
  );
  assertExactSet(
    (await relativeFiles(resolve(runRoot, 'packages/api-client/generated/privacy-explorer'))).map(
      (path) => `packages/api-client/generated/privacy-explorer/${path}`,
    ),
    privacyApiClientOutputs,
    'staged Privacy Explorer API outputs',
  );
  assertExactSet(
    (await relativeFiles(resolve(runRoot, 'generated/rust'))).map(
      (path) => `generated/rust/${path}`,
    ),
    rustStagedOutputs,
    'staged Rust outputs',
  );
  assertExactHashes(
    await readRows(
      runRoot,
      protectedOpenApiOutputs.filter((path) => !signingChangedContractOutputs.includes(path)),
    ),
    Object.fromEntries(
      Object.entries(protectedOpenApiSha256ByPath).filter(
        ([path]) => !signingChangedContractOutputs.includes(path),
      ),
    ),
    'staged protected OpenAPI outputs',
  );
  await compareBytes(
    runRoot,
    existingTypeScriptJsonSchemaOutputs.filter(
      (path) => !signingChangedContractOutputs.includes(path),
    ),
    'preserved JSON Schema output',
  );
  await compareBytes(
    runRoot,
    protectedOpenApiOutputs.filter((path) => !signingChangedContractOutputs.includes(path)),
    'protected OpenAPI output',
  );
  await compareBytes(runRoot, preservedRustOutputs, 'preserved Rust proto output');
};

const exists = async (path: string) => {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
};

type OwnedIdentity = Readonly<{
  path: string;
  device: number;
  inode: number;
  mode: number;
  kind: 'directory' | 'file';
}>;

const readIdentity = async (
  path: string,
  expectedKind: OwnedIdentity['kind'],
): Promise<OwnedIdentity> => {
  const status = await lstat(path);
  if (status.isSymbolicLink()) throw new Error(`symbolic link is forbidden: ${path}`);
  if (
    (expectedKind === 'directory' && !status.isDirectory()) ||
    (expectedKind === 'file' && !status.isFile())
  )
    throw new Error(`unexpected publication path kind: ${path}`);
  return {
    path,
    device: status.dev,
    inode: status.ino,
    mode: status.mode,
    kind: expectedKind,
  };
};

const sameIdentity = (left: OwnedIdentity, right: OwnedIdentity) =>
  left.path === right.path &&
  left.device === right.device &&
  left.inode === right.inode &&
  left.mode === right.mode &&
  left.kind === right.kind;

const recheckIdentities = async (identities: readonly OwnedIdentity[], label: string) => {
  for (const expected of identities) {
    const actual = await readIdentity(expected.path, expected.kind);
    if (!sameIdentity(actual, expected)) throw new Error(`${label}: path identity changed`);
  }
};

const assertAbsent = async (path: string, label: string) => {
  if (await exists(path)) throw new Error(`${label}: path unexpectedly exists`);
};

const resolveOwnedDestination = async (
  destinationRoot: string,
  relativePath: string,
  createdDirectories: OwnedIdentity[],
) => {
  const safePath = assertSafeRelativePath(relativePath);
  const rootPath = resolve(destinationRoot);
  const rootIdentity = await readIdentity(rootPath, 'directory');
  const rootReal = await realpath(rootPath);
  if (rootReal !== rootPath)
    throw new Error(`publication root is not a canonical real directory: ${destinationRoot}`);

  const components = safePath.split('/');
  let parent = rootPath;
  const parentIdentities: OwnedIdentity[] = [rootIdentity];
  for (const component of components.slice(0, -1)) {
    parent = resolve(parent, component);
    if (!isWithin(parent, rootPath))
      throw new Error(`publication destination escaped owner: ${relativePath}`);
    if (!(await exists(parent))) {
      let createdByThisTransaction = false;
      try {
        await mkdir(parent);
        createdByThisTransaction = true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      }
      const created = await readIdentity(parent, 'directory');
      if (createdByThisTransaction) createdDirectories.push(created);
      parentIdentities.push(created);
    } else {
      parentIdentities.push(await readIdentity(parent, 'directory'));
    }
  }

  const destination = resolve(parent, components.at(-1)!);
  if (!isWithin(destination, rootPath))
    throw new Error(`publication destination escaped owner: ${relativePath}`);
  const destinationIdentity = (await exists(destination))
    ? await readIdentity(destination, 'file')
    : undefined;
  await recheckIdentities(parentIdentities, `${relativePath} parent`);
  return { destination, destinationIdentity, parentIdentities };
};

const removeOwnedFile = async (identity: OwnedIdentity, label: string) => {
  if (!(await exists(identity.path))) return;
  const actual = await readIdentity(identity.path, 'file');
  if (!sameIdentity(actual, identity)) throw new Error(`${label}: file identity changed`);
  await rm(identity.path);
};

const removeOwnedDirectory = async (identity: OwnedIdentity, label: string) => {
  if (!(await exists(identity.path))) return;
  const actual = await readIdentity(identity.path, 'directory');
  if (!sameIdentity(actual, identity)) throw new Error(`${label}: directory identity changed`);
  try {
    await rmdir(identity.path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOTEMPTY') throw error;
  }
};

const writeOwnedFileExclusive = async (
  path: string,
  bytes: Uint8Array,
  label: string,
): Promise<OwnedIdentity> => {
  const handle = await open(path, 'wx');
  let identity: OwnedIdentity | undefined;
  let failure: unknown;
  try {
    const status = await handle.stat();
    if (!status.isFile()) throw new Error(`${label}: opened publication path is not a file`);
    identity = {
      path,
      device: status.dev,
      inode: status.ino,
      mode: status.mode,
      kind: 'file',
    };
    const visible = await readIdentity(path, 'file');
    if (!sameIdentity(visible, identity))
      throw new Error(`${label}: opened publication path identity mismatch`);
    await handle.writeFile(bytes);
    await handle.sync();
  } catch (error) {
    failure = error;
  }
  try {
    await handle.close();
  } catch (error) {
    failure = failure
      ? new AggregateError([failure, error], `${label}: write and close failed`)
      : error;
  }
  if (failure) {
    if (identity)
      try {
        await removeOwnedFile(identity, `${label} failed-write cleanup`);
      } catch (cleanupError) {
        throw new AggregateError([failure, cleanupError], `${label}: write cleanup failed`);
      }
    throw failure;
  }
  return identity!;
};

export type PublicationPreparedEntry = Readonly<{
  index: number;
  relativePath: string;
  destination: string;
  temporary: string;
  backup: string;
}>;

export const transactionalReplace = async ({
  destinationRoot,
  entries,
  failAfter,
  failDuringPreparation,
  beforeRename,
}: {
  destinationRoot: string;
  entries: readonly PublicationEntry[];
  failAfter?: number;
  failDuringPreparation?: number;
  beforeRename?: (entry: PublicationPreparedEntry) => Promise<void>;
}) => {
  const normalizedPaths = entries.map((entry) => assertSafeRelativePath(entry.path));
  uniquePublicationPaths(normalizedPaths);

  const prepared: Array<{
    index: number;
    relativePath: string;
    destination: string;
    temporary: string;
    backup: string;
    destinationIdentity?: OwnedIdentity;
    destinationSha256?: string;
    temporaryIdentity: OwnedIdentity;
    backupIdentity?: OwnedIdentity;
    parentIdentities: OwnedIdentity[];
    published: boolean;
  }> = [];
  const createdDirectories: OwnedIdentity[] = [];
  let failure: unknown;
  try {
    for (const [index, entry] of entries.entries()) {
      const relativePath = normalizedPaths[index];
      const { destination, destinationIdentity, parentIdentities } = await resolveOwnedDestination(
        destinationRoot,
        relativePath,
        createdDirectories,
      );
      await recheckIdentities(parentIdentities, `${relativePath} before preparation`);
      if (destinationIdentity) {
        const actual = await readIdentity(destination, 'file');
        if (!sameIdentity(actual, destinationIdentity))
          throw new Error(`${relativePath}: destination identity changed before backup`);
      } else {
        await assertAbsent(destination, `${relativePath} destination`);
      }

      const temporary = resolve(
        dirname(destination),
        `.${basename(destination)}.i07-${process.pid}-${index}`,
      );
      const backup = `${temporary}.backup`;
      await assertAbsent(temporary, `${relativePath} temporary`);
      await assertAbsent(backup, `${relativePath} backup`);

      let backupIdentity: OwnedIdentity | undefined;
      let destinationSha256: string | undefined;
      if (destinationIdentity) {
        const destinationBytes = await readFile(destination);
        destinationSha256 = sha256(destinationBytes);
        backupIdentity = await writeOwnedFileExclusive(
          backup,
          destinationBytes,
          `${relativePath} backup`,
        );
      }
      let temporaryIdentity: OwnedIdentity;
      try {
        temporaryIdentity = await writeOwnedFileExclusive(
          temporary,
          entry.bytes,
          `${relativePath} temporary`,
        );
      } catch (error) {
        if (backupIdentity)
          try {
            await removeOwnedFile(backupIdentity, `${relativePath} backup preparation cleanup`);
          } catch (cleanupError) {
            throw new AggregateError(
              [error, cleanupError],
              `${relativePath}: preparation cleanup failed`,
            );
          }
        throw error;
      }
      prepared.push({
        index,
        relativePath,
        destination,
        temporary,
        backup,
        destinationIdentity,
        destinationSha256,
        temporaryIdentity,
        backupIdentity,
        parentIdentities,
        published: false,
      });
      if (failDuringPreparation === index)
        throw new Error(`injected publication preparation failure at ${index}`);
    }

    for (const item of prepared) {
      await beforeRename?.({
        index: item.index,
        relativePath: item.relativePath,
        destination: item.destination,
        temporary: item.temporary,
        backup: item.backup,
      });
      await recheckIdentities(item.parentIdentities, `${item.relativePath} before rename`);
      await recheckIdentities([item.temporaryIdentity], `${item.relativePath} temporary`);
      if (item.destinationIdentity) {
        const actual = await readIdentity(item.destination, 'file');
        if (!sameIdentity(actual, item.destinationIdentity))
          throw new Error(`${item.relativePath}: destination identity changed before rename`);
      } else {
        await assertAbsent(item.destination, `${item.relativePath} destination`);
      }
      await rename(item.temporary, item.destination);
      item.published = true;
      const publishedIdentity = await readIdentity(item.destination, 'file');
      if (!sameIdentity({ ...publishedIdentity, path: item.temporary }, item.temporaryIdentity))
        throw new Error(`${item.relativePath}: published identity mismatch`);
      if (failAfter === item.index)
        throw new Error(`injected publication failure after ${item.index}`);
    }
  } catch (error) {
    failure = error;
    const rollbackErrors: unknown[] = [];
    for (const item of [...prepared].reverse()) {
      try {
        if (!item.published) continue;
        await recheckIdentities(item.parentIdentities, `${item.relativePath} rollback parent`);
        const publishedIdentity = await readIdentity(item.destination, 'file');
        if (!sameIdentity({ ...publishedIdentity, path: item.temporary }, item.temporaryIdentity))
          throw new Error(`${item.relativePath}: published identity changed before rollback`);
        if (item.destinationIdentity && item.backupIdentity) {
          await recheckIdentities([item.backupIdentity], `${item.relativePath} backup`);
          await rename(item.backup, item.destination);
          const restored = await readIdentity(item.destination, 'file');
          if (
            restored.mode !== item.destinationIdentity.mode ||
            sha256(await readFile(item.destination)) !== item.destinationSha256
          )
            throw new Error(`${item.relativePath}: restored identity mismatch`);
        } else {
          await rm(item.destination);
        }
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError);
      }
    }
    if (rollbackErrors.length > 0)
      failure = new AggregateError([error, ...rollbackErrors], 'publication and rollback failed');
  } finally {
    const cleanupErrors: unknown[] = [];
    for (const item of [...prepared].reverse()) {
      try {
        await removeOwnedFile(item.temporaryIdentity, `${item.relativePath} temporary cleanup`);
      } catch (error) {
        cleanupErrors.push(error);
      }
      if (item.backupIdentity)
        try {
          await removeOwnedFile(item.backupIdentity, `${item.relativePath} backup cleanup`);
        } catch (error) {
          cleanupErrors.push(error);
        }
    }
    for (const directory of [...createdDirectories].reverse())
      try {
        await removeOwnedDirectory(directory, 'created-directory cleanup');
      } catch (error) {
        cleanupErrors.push(error);
      }
    if (cleanupErrors.length > 0) {
      if (failure)
        failure = new AggregateError(
          [failure, ...cleanupErrors],
          'publication rollback cleanup failed',
        );
      else failure = new AggregateError(cleanupErrors, 'publication cleanup failed');
    }
  }
  if (failure) throw failure;
};

const uniquePublicationPaths = (paths: readonly string[]) => {
  uniquePathSet(paths, (path) => path, 'duplicate publication path');
  uniquePathSet(paths, (path) => path.toLowerCase(), 'case-colliding publication path');
};

const uniquePathSet = (paths: readonly string[], key: (path: string) => string, label: string) => {
  const seen = new Set<string>();
  for (const path of paths) {
    const normalized = key(path);
    if (seen.has(normalized)) throw new Error(`${label}: ${path}`);
    seen.add(normalized);
  }
};

const contractTreeBytes = async (runRoot: string) => {
  const stagedGeneratedOutputs = new Set<string>(
    publishOutputs.filter((path) => path.startsWith('generated/')),
  );
  assertExactSet(
    (await relativeFiles(resolve(repositoryRoot, 'generated')))
      .map((path) => `generated/${path}`)
      .filter((path) => path !== contractTreePath && !stagedGeneratedOutputs.has(path)),
    generatedClosure.filter((path) => !stagedGeneratedOutputs.has(path)),
    'preserved live generated closure',
  );
  const files = await Promise.all(
    generatedClosure.map(async (path) => ({
      path,
      bytes: await readFile(
        resolve(stagedGeneratedOutputs.has(path) ? runRoot : repositoryRoot, path),
      ),
    })),
  );
  const rows = hashRows(files);
  for (const { path, bytes } of files) {
    const text = Buffer.from(bytes).toString('utf8');
    if (/\/home\/|[A-Z]:\\\\|generated at|generated on|build timestamp/i.test(text)) {
      throw new Error(`generated output contains nondeterministic metadata: ${path}`);
    }
  }
  return Buffer.from(
    `${rows.map(({ path, sha256: digest }) => `${digest}  ${path}`).join('\n')}\n`,
  );
};

export const runContractGeneration = async ({
  mode,
  failAfterPublication,
  failPhase,
}: {
  mode: GenerationMode;
  failAfterPublication?: number;
  failPhase?: 'after-run-root' | 'after-generation' | 'after-validation' | 'after-comparison';
}) => {
  const temporaryRoot = process.env.OPENPC_PNC_TMP_ROOT;
  if (!temporaryRoot) throw new Error('OPENPC_PNC_TMP_ROOT is required');
  const { temporaryReal, workspaceReal } = await validateApprovedTemporaryRoot(temporaryRoot);
  const runRoot = await mkdtemp(resolve(temporaryReal, `i07-b1-${mode}-`));
  try {
    await assertExternalRunRoot(runRoot, temporaryReal, workspaceReal);
    if (failPhase === 'after-run-root') throw new Error('injected failure after run-root setup');
    await stageAll(runRoot);
    if (failPhase === 'after-generation') throw new Error('injected failure after generation');
    await validateStage(runRoot);
    if (failPhase === 'after-validation') throw new Error('injected failure after validation');
    if (mode === 'verify') {
      await compareBytes(runRoot, publishOutputs, 'generated output');
      if (failPhase === 'after-comparison') throw new Error('injected failure after comparison');
    } else {
      const entries = await Promise.all(
        publishOutputs.map(async (path) => ({
          path,
          bytes: await readFile(resolve(runRoot, path)),
        })),
      );
      entries.push({ path: contractTreePath, bytes: await contractTreeBytes(runRoot) });
      await transactionalReplace({
        destinationRoot: repositoryRoot,
        entries,
        failAfter: failAfterPublication,
      });
    }
    return { runRoot, published: mode === 'generate' ? publishOutputs.length : 0 };
  } finally {
    await rm(runRoot, { force: true, recursive: true });
  }
};

if (resolve(process.argv[1] ?? '') === resolve(import.meta.filename)) {
  await runContractGeneration({ mode: 'generate' });
}
