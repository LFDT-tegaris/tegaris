import { spawnSync } from 'node:child_process';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { repositoryRoot } from './contract-paths.js';
import {
  generatedClosure,
  publicationEntryCount,
  runContractGeneration,
  transactionalReplace,
  validateApprovedTemporaryRoot,
} from './generate-typescript-contracts.js';
import {
  assertExactSet,
  byteCompare,
  expectedExecutionRegistrySha256,
  sha256,
  validateExecutionRegistry,
  validateExecutionRegistryRelations,
  validatePrivacyExplorerProblemUnion,
  validatePrivacyExplorerOpenApiSource,
} from './privacy-explorer-contract-closure.js';
import { buildContractManifest } from './write-contract-manifest.js';

const git = (args: string[]) => {
  const result = spawnSync('git', args, {
    cwd: repositoryRoot,
    encoding: 'buffer',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr.toString('utf8')}`);
  }
  return result.stdout;
};

const snapshotRepository = async () => {
  const paths = git(['ls-files', '-co', '--exclude-standard', '-z'])
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .sort(byteCompare);
  const files = await Promise.all(
    paths.map(async (path) => {
      const absolute = resolve(repositoryRoot, path);
      const status = await lstat(absolute);
      const bytes = status.isSymbolicLink()
        ? Buffer.from(await readlink(absolute))
        : await readFile(absolute);
      return { path, mode: status.mode, sha256: sha256(bytes) };
    }),
  );
  return {
    files,
    status: sha256(git(['status', '--porcelain=v1', '-z', '--untracked-files=all'])),
    index: sha256(git(['diff', '--cached', '--binary'])),
    worktree: sha256(git(['diff', '--binary'])),
  };
};

const snapshotDirectory = async (root: string) => {
  const visit = async (
    directory: string,
  ): Promise<Array<{ path: string; kind: 'directory' | 'file'; sha256: string }>> => {
    const entries = await readdir(directory, { withFileTypes: true });
    const rows = await Promise.all(
      entries
        .sort((left, right) => byteCompare(left.name, right.name))
        .map(async (entry) => {
          const path = join(directory, entry.name);
          return entry.isDirectory()
            ? [
                { path: relative(root, path), kind: 'directory' as const, sha256: '' },
                ...(await visit(path)),
              ]
            : [
                {
                  path: relative(root, path),
                  kind: 'file' as const,
                  sha256: sha256(await readFile(path)),
                },
              ];
        }),
    );
    return rows.flat();
  };
  return visit(root);
};

const expectFailure = async (action: () => Promise<unknown>, label: string) => {
  try {
    await action();
  } catch {
    return;
  }
  throw new Error(`${label}: expected failure`);
};

const existsForTest = async (path: string) => {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
};
const temporaryRoot = process.env.OPENPC_PNC_TMP_ROOT;
if (!temporaryRoot) throw new Error('OPENPC_PNC_TMP_ROOT is required');
const { temporaryReal } = await validateApprovedTemporaryRoot(temporaryRoot);
const safetyRoot = await mkdtemp(resolve(temporaryReal, 'i07-b1-safety-'));
let publicationRollbackCases = 0;
let publicationPreparationCases = 0;
let publicationSymlinkCases = 0;
let publicationOwnershipCases = 0;
try {
  const badRoot = resolve(safetyRoot, 'repository-symlink');
  await symlink(repositoryRoot, badRoot, 'dir');
  await expectFailure(
    () => validateApprovedTemporaryRoot(badRoot),
    'repository-resolving temporary root',
  );

  const realPublicationRoot = resolve(safetyRoot, 'real-publication-root');
  const publicationRootSymlink = resolve(safetyRoot, 'publication-root-symlink');
  await mkdir(realPublicationRoot);
  await symlink(realPublicationRoot, publicationRootSymlink, 'dir');
  await expectFailure(
    () =>
      transactionalReplace({
        destinationRoot: publicationRootSymlink,
        entries: [{ path: 'owned/file.bin', bytes: Buffer.from('replacement') }],
      }),
    'symbolic publication root',
  );
  publicationSymlinkCases += 1;

  const transactionEntries = Array.from({ length: publicationEntryCount }, (_, index) => ({
    path: index % 2 === 0 ? `existing/${index}.bin` : `created/nested/${index}.bin`,
    bytes: Buffer.from(`replacement-${index}`),
  }));
  const prepareTransactionRoot = async (name: string) => {
    const destinationRoot = resolve(safetyRoot, name);
    await mkdir(destinationRoot);
    for (const [index, entry] of transactionEntries.entries()) {
      if (index % 2 === 0) {
        await mkdir(dirname(resolve(destinationRoot, entry.path)), { recursive: true });
        await writeFile(resolve(destinationRoot, entry.path), `original-${index}`);
      }
    }
    return destinationRoot;
  };

  for (let failurePosition = 0; failurePosition < publicationEntryCount; failurePosition += 1) {
    const destinationRoot = await prepareTransactionRoot(`transaction-rename-${failurePosition}`);
    const beforeFailure = await snapshotDirectory(destinationRoot);
    await expectFailure(
      () =>
        transactionalReplace({
          destinationRoot,
          entries: transactionEntries,
          failAfter: failurePosition,
        }),
      `publication rename position ${failurePosition}`,
    );
    const afterFailure = await snapshotDirectory(destinationRoot);
    if (JSON.stringify(beforeFailure) !== JSON.stringify(afterFailure))
      throw new Error(`publication rename position ${failurePosition}: rollback drift`);
    publicationRollbackCases += 1;
  }

  for (let failurePosition = 0; failurePosition < publicationEntryCount; failurePosition += 1) {
    const destinationRoot = await prepareTransactionRoot(
      `transaction-preparation-${failurePosition}`,
    );
    const beforeFailure = await snapshotDirectory(destinationRoot);
    await expectFailure(
      () =>
        transactionalReplace({
          destinationRoot,
          entries: transactionEntries,
          failDuringPreparation: failurePosition,
        }),
      `publication preparation position ${failurePosition}`,
    );
    const afterFailure = await snapshotDirectory(destinationRoot);
    if (JSON.stringify(beforeFailure) !== JSON.stringify(afterFailure))
      throw new Error(`publication preparation position ${failurePosition}: cleanup drift`);
    publicationPreparationCases += 1;
  }

  for (const targetKind of ['internal', 'external'] as const) {
    for (const componentIndex of [0, 1] as const) {
      const destinationRoot = resolve(safetyRoot, `symlink-parent-${targetKind}-${componentIndex}`);
      await mkdir(destinationRoot);
      const internalTarget = resolve(destinationRoot, 'internal-target');
      const externalTarget = resolve(safetyRoot, `external-target-${targetKind}-${componentIndex}`);
      const target = targetKind === 'internal' ? internalTarget : externalTarget;
      await mkdir(target);
      if (componentIndex === 0) {
        await symlink(target, resolve(destinationRoot, 'level-one'), 'dir');
      } else {
        await mkdir(resolve(destinationRoot, 'level-one'));
        await symlink(target, resolve(destinationRoot, 'level-one/level-two'), 'dir');
      }
      await expectFailure(
        () =>
          transactionalReplace({
            destinationRoot,
            entries: [
              {
                path:
                  componentIndex === 0
                    ? 'level-one/level-two/file.bin'
                    : 'level-one/level-two/file.bin',
                bytes: Buffer.from('must-not-publish'),
              },
            ],
          }),
        `${targetKind} symlink parent component ${componentIndex}`,
      );
      if (
        await existsForTest(
          resolve(target, componentIndex === 0 ? 'level-two/file.bin' : 'file.bin'),
        )
      )
        throw new Error(`${targetKind} symlink parent received publication`);
      publicationSymlinkCases += 1;
    }
  }

  for (const targetKind of ['internal', 'external'] as const) {
    const destinationRoot = resolve(safetyRoot, `symlink-destination-${targetKind}`);
    const internalTarget = resolve(destinationRoot, 'internal-target.bin');
    const externalTarget = resolve(safetyRoot, `external-target-${targetKind}.bin`);
    await mkdir(resolve(destinationRoot, 'owned'), { recursive: true });
    const target = targetKind === 'internal' ? internalTarget : externalTarget;
    await writeFile(target, 'original-target');
    await symlink(target, resolve(destinationRoot, 'owned/file.bin'), 'file');
    await expectFailure(
      () =>
        transactionalReplace({
          destinationRoot,
          entries: [{ path: 'owned/file.bin', bytes: Buffer.from('must-not-publish') }],
        }),
      `${targetKind} symbolic destination`,
    );
    if ((await readFile(target, 'utf8')) !== 'original-target')
      throw new Error(`${targetKind} symbolic destination target changed`);
    publicationSymlinkCases += 1;
  }

  for (const [label, entries] of [
    [
      'duplicate',
      [
        { path: 'owned/file.bin', bytes: Buffer.from('a') },
        { path: 'owned/file.bin', bytes: Buffer.from('b') },
      ],
    ],
    [
      'case-collision',
      [
        { path: 'owned/File.bin', bytes: Buffer.from('a') },
        { path: 'owned/file.bin', bytes: Buffer.from('b') },
      ],
    ],
    ['traversal', [{ path: '../file.bin', bytes: Buffer.from('a') }]],
  ] as const) {
    const destinationRoot = resolve(safetyRoot, `unsafe-${label}`);
    await mkdir(destinationRoot);
    await expectFailure(
      () => transactionalReplace({ destinationRoot, entries }),
      `unsafe publication path ${label}`,
    );
    if ((await snapshotDirectory(destinationRoot)).length !== 0)
      throw new Error(`unsafe publication path ${label}: residue`);
    publicationOwnershipCases += 1;
  }

  const identityRoot = resolve(safetyRoot, 'identity-change');
  await mkdir(resolve(identityRoot, 'owned'), { recursive: true });
  await writeFile(resolve(identityRoot, 'owned/file.bin'), 'original');
  const identityBefore = await snapshotDirectory(identityRoot);
  let identityHookRan = false;
  await expectFailure(
    () =>
      transactionalReplace({
        destinationRoot: identityRoot,
        entries: [{ path: 'owned/file.bin', bytes: Buffer.from('replacement') }],
        beforeRename: async () => {
          if (identityHookRan) return;
          identityHookRan = true;
          const owned = resolve(identityRoot, 'owned');
          const parked = resolve(identityRoot, 'parked');
          await rename(owned, parked);
          await mkdir(owned);
          for (const name of await readdir(parked))
            await rename(resolve(parked, name), resolve(owned, name));
          await rm(parked, { recursive: true });
        },
      }),
    'publication parent identity change',
  );
  if (!identityHookRan) throw new Error('publication parent identity hook did not run');
  const identityAfter = await snapshotDirectory(identityRoot);
  if (JSON.stringify(identityBefore) !== JSON.stringify(identityAfter))
    throw new Error('publication parent identity change: byte or cleanup drift');
  publicationOwnershipCases += 1;
} finally {
  await rm(safetyRoot, { force: true, recursive: true });
}

const manifestPath = resolve(repositoryRoot, 'tests/conformance/bootstrap/contract-manifest.json');
const actualManifest = JSON.parse(await readFile(manifestPath, 'utf8')) as unknown;
const expectedManifest = await buildContractManifest();
if (JSON.stringify(actualManifest) !== JSON.stringify(expectedManifest)) {
  throw new Error('contract manifest is not the exact recomputable source/output closure');
}

const checksumPath = resolve(repositoryRoot, 'generated/contract-tree.sha256');
const checksumLines = (await readFile(checksumPath, 'utf8')).trimEnd().split('\n');
const checksumRows = checksumLines.map((line) => {
  const match = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
  if (!match) throw new Error(`invalid generated checksum row: ${line}`);
  return { sha256: match[1], path: match[2] };
});
assertExactSet(
  checksumRows.map(({ path }) => path),
  generatedClosure,
  'contract-tree paths',
);
if (
  JSON.stringify(checksumRows.map(({ path }) => path)) !==
  JSON.stringify([...generatedClosure].sort(byteCompare))
) {
  throw new Error('contract-tree rows are not repository-path byte ordered');
}
for (const row of checksumRows) {
  if (sha256(await readFile(resolve(repositoryRoot, row.path))) !== row.sha256) {
    throw new Error(`contract-tree hash drift: ${row.path}`);
  }
}

const before = await snapshotRepository();
for (const failPhase of [
  'after-run-root',
  'after-generation',
  'after-validation',
  'after-comparison',
] as const) {
  await expectFailure(
    () => runContractGeneration({ mode: 'verify', failPhase }),
    `generator cleanup phase ${failPhase}`,
  );
}
await expectFailure(
  () =>
    runContractGeneration({
      mode: 'generate',
      failAfterPublication: publicationEntryCount - 1,
    }),
  'contract-tree publication rollback',
);
await runContractGeneration({ mode: 'verify' });
const after = await snapshotRepository();
if (JSON.stringify(before) !== JSON.stringify(after)) {
  throw new Error('read-only regeneration changed repository bytes, status, or index');
}

const remainingRunRoots = (await readdir(temporaryReal)).filter((name) =>
  name.startsWith('i07-b1-'),
);
if (remainingRunRoots.length > 0)
  throw new Error(`generator run-root cleanup failed: ${remainingRunRoots.join(', ')}`);

const privacySchema = JSON.parse(
  await readFile(resolve(repositoryRoot, 'schemas/json/privacy-explorer.schema.json'), 'utf8'),
) as Record<string, unknown>;
const registry = privacySchema['x-openpc-executionRegistry'] as Record<string, unknown>;
if (sha256(JSON.stringify(registry)) !== expectedExecutionRegistrySha256)
  throw new Error('source registry semantic digest drift');
const problemUnionSummary = validatePrivacyExplorerProblemUnion(privacySchema, registry);
let problemUnionNegatives = 0;
for (const [id, mutate] of [
  [
    'missing-http-boundary-tuple',
    (candidate: Record<string, unknown>) => {
      const definitions = candidate.$defs as Record<string, unknown>;
      const problem = definitions.PrivacyExplorerProblemV1 as Record<string, unknown>;
      (problem.oneOf as unknown[]).shift();
    },
  ],
  [
    'cross-condition-tuple',
    (candidate: Record<string, unknown>) => {
      const definitions = candidate.$defs as Record<string, unknown>;
      const problem = definitions.PrivacyExplorerProblemV1 as Record<string, unknown>;
      const variant = (problem.oneOf as Array<Record<string, unknown>>)[2]!;
      const properties = variant.properties as Record<string, Record<string, unknown>>;
      properties.httpStatus!.const = 503;
    },
  ],
] as const) {
  const candidate = structuredClone(privacySchema);
  try {
    mutate(candidate);
    validatePrivacyExplorerProblemUnion(candidate, registry);
  } catch {
    problemUnionNegatives += 1;
    continue;
  }
  throw new Error(`problem union negative accepted: ${id}`);
}
const registryNegativeIds: string[] = [];
const relationalNegativeIds: string[] = [];
const integrityNegativeIds: string[] = [];
const rejectRelational = (id: string, mutate: (candidate: Record<string, unknown>) => void) => {
  const candidate = structuredClone(registry);
  mutate(candidate);
  try {
    validateExecutionRegistryRelations(candidate);
  } catch {
    registryNegativeIds.push(id);
    relationalNegativeIds.push(id);
    return;
  }
  throw new Error(`relational registry negative accepted: ${id}`);
};
const rejectIntegrityOnly = (id: string, mutate: (candidate: Record<string, unknown>) => void) => {
  const candidate = structuredClone(registry);
  mutate(candidate);
  try {
    validateExecutionRegistryRelations(candidate);
  } catch (error) {
    throw new Error(`integrity-only negative rejected relationally: ${id}: ${String(error)}`);
  }
  try {
    validateExecutionRegistry(candidate);
  } catch {
    registryNegativeIds.push(id);
    integrityNegativeIds.push(id);
    return;
  }
  throw new Error(`integrity-only registry negative accepted: ${id}`);
};
for (const sourcePath of [
  resolve(
    repositoryRoot,
    'tests/conformance/bootstrap/scripts/privacy-explorer-contract-closure.ts',
  ),
  resolve(repositoryRoot, 'tests/conformance/bootstrap/scripts/verify-generated-contracts.ts'),
])
  if (
    (await readFile(sourcePath, 'utf8')).includes(['EXPECTED', 'EXECUTION', 'REGISTRY'].join('_'))
  )
    throw new Error(`duplicate authored registry oracle remains: ${sourcePath}`);
rejectIntegrityOnly('integrity-only-identity-drift', (candidate) => {
  (candidate.nonGoals as string[])[0] = 'ExternalDecisionAdapterV2';
});
const registryFamilies = [
  'sourceAnchors',
  'resultDefinitions',
  'operationDefinitions',
  'conditionDefinitions',
  'lifecycleApplications',
  'conditionApplications',
  'cancellationApplications',
  'contributionApplications',
] as const;
for (const family of registryFamilies) {
  const rows = registry[family] as Array<Record<string, unknown>>;
  for (const [rowIndex, row] of rows.entries()) {
    for (const key of Object.keys(row)) {
      rejectRelational(`${family}[${rowIndex}].${key}`, (candidate) => {
        const target = (candidate[family] as Array<Record<string, unknown>>)[rowIndex];
        const value = target[key];
        target[key] =
          typeof value === 'boolean'
            ? !value
            : typeof value === 'number'
              ? value + 1
              : typeof value === 'string'
                ? `${value}-SOURCE-FALSE`
                : Array.isArray(value)
                  ? [...value, 'SOURCE-FALSE']
                  : { ...(value as Record<string, unknown>), unexpected: true };
      });
    }
  }
}
const resultLawFields = ['outcome', 'truthState', 'recordLawId', 'cursorLawId'] as const;
for (const [rowIndex, row] of (
  registry.resultDefinitions as Array<Record<string, unknown>>
).entries())
  for (const key of resultLawFields)
    rejectRelational(`resultDefinitions[${rowIndex}].${key}.valid-swap`, (candidate) => {
      const target = (candidate.resultDefinitions as Array<Record<string, unknown>>)[rowIndex];
      const replacement = (registry.resultDefinitions as Array<Record<string, unknown>>).find(
        (entry) => entry[key] !== row[key],
      );
      if (!replacement) throw new Error(`missing valid ${key} replacement`);
      target[key] = replacement[key];
    });
for (const [rowIndex] of (
  registry.operationDefinitions as Array<Record<string, unknown>>
).entries())
  rejectRelational(
    `operationDefinitions[${rowIndex}].outputDispositionKinds.valid-swap`,
    (candidate) => {
      (candidate.operationDefinitions as Array<Record<string, unknown>>)[
        rowIndex
      ].outputDispositionKinds = ['NONE'];
    },
  );
for (const family of [
  'lifecycleApplications',
  'conditionApplications',
  'cancellationApplications',
  'contributionApplications',
] as const) {
  const rows = registry[family] as Array<Record<string, unknown>>;
  const applicationRows = [
    ...(registry.lifecycleApplications as Array<Record<string, unknown>>),
    ...(registry.conditionApplications as Array<Record<string, unknown>>),
    ...(registry.cancellationApplications as Array<Record<string, unknown>>),
    ...(registry.contributionApplications as Array<Record<string, unknown>>),
  ];
  for (const [rowIndex, row] of rows.entries()) {
    for (const key of ['eventId', 'guardId', 'retainedFactId', 'noEffectId'] as const)
      rejectRelational(`${family}[${rowIndex}].${key}.valid-swap`, (candidate) => {
        const target = (candidate[family] as Array<Record<string, unknown>>)[rowIndex];
        const replacement = applicationRows.find((entry) => entry[key] !== row[key]);
        if (!replacement) throw new Error(`missing valid ${family}.${key} replacement`);
        target[key] = replacement[key];
      });
    for (const key of ['id', 'mutatedFieldId', 'expectedRejectingBranchId'] as const)
      rejectRelational(`${family}[${rowIndex}].negativeVector.${key}`, (candidate) => {
        const target = (candidate[family] as Array<Record<string, unknown>>)[rowIndex]
          .negativeVector as Record<string, unknown>;
        target[key] =
          key === 'mutatedFieldId'
            ? row.negativeVector &&
              (row.negativeVector as Record<string, unknown>).mutatedFieldId === 'eventId'
              ? 'guardId'
              : 'eventId'
            : `${target[key]}-SOURCE-FALSE`;
      });
  }
}
for (const family of ['states', 'rawStates', 'deliveryStates'] as const) {
  for (const index of (registry[family] as string[]).keys())
    rejectRelational(`${family}[${index}]`, (candidate) => {
      (candidate[family] as string[])[index] += '-SOURCE-FALSE';
    });
}
rejectRelational('extra-lifecycle-row', (candidate) => {
  (candidate.lifecycleApplications as unknown[]).push({
    ...(candidate.lifecycleApplications as Array<Record<string, unknown>>)[0],
    id: 'PXT-999',
  });
});
rejectRelational('source-hash-drift', (candidate) => {
  (candidate.sourceAnchors as Array<Record<string, unknown>>)[0].artifactSha256 = '0'.repeat(64);
});
rejectRelational('garbage-effect', (candidate) => {
  (candidate.lifecycleApplications as Array<Record<string, unknown>>)[0].rawStateEffectId =
    'GARBAGE';
});
rejectRelational('cross-family-duplicate', (candidate) => {
  (candidate.lifecycleApplications as Array<Record<string, unknown>>)[0].id = String(
    (candidate.operationDefinitions as Array<Record<string, unknown>>)[0].id,
  );
});
rejectRelational('invented-reachable-state', (candidate) => {
  (candidate.states as string[]).push('INVENTED');
  (candidate.lifecycleApplications as unknown[]).push({
    ...(candidate.lifecycleApplications as Array<Record<string, unknown>>)[0],
    id: 'PXT-999',
    toStateId: 'INVENTED',
  });
});
rejectRelational('circular-condition-disposition', (candidate) => {
  (candidate.conditionApplications as Array<Record<string, unknown>>)[0].disposition = {
    kind: 'CONDITION',
    conditionApplicationId: 'CA-001',
  };
});
rejectRelational('missing-condition-disposition-reference', (candidate) => {
  (candidate.conditionApplications as Array<Record<string, unknown>>)[0].disposition = {
    kind: 'CONDITION',
  };
});
rejectRelational('multiple-disposition-references', (candidate) => {
  (candidate.conditionApplications as Array<Record<string, unknown>>)[0].disposition = {
    kind: 'CONDITION',
    conditionDefinitionId: 'EXP-COND-001',
    resultDefinitionId: 'RESULT-COMPLETE',
  };
});
rejectRelational('condition-to-public-success', (candidate) => {
  (candidate.conditionApplications as Array<Record<string, unknown>>)[0].disposition = {
    kind: 'RESULT',
    resultDefinitionId: 'RESULT-COMPLETE',
  };
});
rejectRelational('orphan-condition-definition', (candidate) => {
  (candidate.conditionDefinitions as unknown[]).push({
    ...(candidate.conditionDefinitions as Array<Record<string, unknown>>)[0],
    id: 'EXP-ORPHAN',
  });
});
rejectRelational('missing-ca006', (candidate) => {
  candidate.conditionApplications = (
    candidate.conditionApplications as Array<Record<string, unknown>>
  ).filter((row) => row.id !== 'CA-006');
});
rejectRelational('contradictory-redaction-source-state', (candidate) => {
  const row = (candidate.conditionApplications as Array<Record<string, unknown>>).find(
    (entry) => entry.id === 'CA-006',
  );
  if (!row) throw new Error('fixture CA-006 missing');
  row.fromStateId = 'PREAUTHORIZED';
  row.rawStateEffectId = 'NEVER_CREATED';
  row.adapterEffectId = 'NOT_STARTED';
});
rejectRelational('old-pxt014-restored', (candidate) => {
  (candidate.lifecycleApplications as unknown[]).push({
    ...(candidate.lifecycleApplications as Array<Record<string, unknown>>)[0],
    id: 'PXT-014',
    operationId: 'PXI-REDACT-PROJECTION/v1',
    fromStateId: 'PROJECTION_VALIDATED_RAW_LIVE',
    eventId: 'REDACTION_FAILURE',
    toStateId: 'OUTCOME_SELECTED_RAW_LIVE',
  });
});
rejectRelational('orphan-operation-application-set', (candidate) => {
  (candidate.lifecycleApplications as Array<Record<string, unknown>>)[0].operationId =
    'PXI-RELEASE-RESULT/v1';
});
rejectRelational('dangling-condition-definition', (candidate) => {
  (
    (candidate.conditionApplications as Array<Record<string, unknown>>)[0].disposition as Record<
      string,
      unknown
    >
  ).conditionDefinitionId = 'EXP-MISSING';
});
if (JSON.stringify(integrityNegativeIds) !== JSON.stringify(['integrity-only-identity-drift']))
  throw new Error(
    `unexpected integrity-only registry negatives: ${integrityNegativeIds.join(', ')}`,
  );

const validators = (await import(
  pathToFileURL(
    resolve(repositoryRoot, 'generated/typescript/json-schema/privacy-explorer.validator.mjs'),
  ).href
)) as Record<string, (value: unknown) => boolean>;
const digest = `sha256:${'a'.repeat(64)}`;
const parityFixture = JSON.parse(
  await readFile(
    resolve(repositoryRoot, 'tests/fixtures/privacy-explorer/i07-gate2-b3-parity-vectors.json'),
    'utf8',
  ),
) as Record<string, Record<string, unknown>>;
const request = parityFixture.request;
const adapterContext = {
  authorizationDigest: digest,
  profileDigest: digest,
  authorizationContextId: '123e4567-e89b-42d3-a456-426614174002',
  authorizationContextEpoch: 7,
  accessClassIds: ['ACCESS-PRIVATE'],
  scopeDigest: digest,
  deadlineAt: '2026-09-04T10:00:00Z',
  idempotencyDigest: digest,
  occurrenceId: '123e4567-e89b-42d3-a456-426614174000',
  auditCorrelationId: '123e4567-e89b-42d3-a456-426614174001',
  cancellation: {
    mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION',
    occurrenceId: '123e4567-e89b-42d3-a456-426614174000',
  },
  reconciliation: {
    mode: 'EXACT_OCCURRENCE',
    occurrenceId: '123e4567-e89b-42d3-a456-426614174000',
  },
};
const releasedResult = {
  schemaVersion: '1.0',
  outcome: 'COMPLETE',
  truthState: 'TRUE',
  requestDigest: parityFixture.expected.requestDigest,
  profileDigest: digest,
  queryDigest: digest,
  resultDigest: digest,
  records: [{ id: 'record-a', fields: [{ fieldId: 'PEF-A', value: 'redacted' }] }],
  page: { cursor: null, gapFree: true },
};
const unauthenticatedProblem = {
  code: 'PC-AUTH-0001',
  httpStatus: 401,
  jsonRpcCode: -32041,
  grpcStatus: 'UNAUTHENTICATED',
  truthState: 'DENIED',
  retryable: false,
  disclosure: 'NON_LEAKING_INVARIANT',
  publicTitle: 'Resource is unavailable',
};
const terminalDenialProblem = {
  code: 'PC-RUNTIME-3001',
  httpStatus: 403,
  jsonRpcCode: -32001,
  grpcStatus: 'PERMISSION_DENIED',
  truthState: 'DENIED',
  retryable: false,
  disclosure: 'NON_LEAKING_INVARIANT',
  publicTitle: 'Resource is unavailable',
};
if (!validators.validateExplorerProjectionRequestV1(request))
  throw new Error('valid projection request rejected');
if (!validators.validateAdapterCallContextV1(adapterContext))
  throw new Error('valid adapter context rejected');
if (!validators.validatePrivacyExplorerResultV1(releasedResult))
  throw new Error('valid released result rejected');
if (
  !validators.validatePrivacyExplorerProblemV1(unauthenticatedProblem) ||
  !validators.validatePrivacyExplorerProblemV1(terminalDenialProblem)
)
  throw new Error('valid exact HTTP-boundary problem rejected');
const schemaNegatives = [
  [
    { ...request, projectionFields: ['arbitrary.unregistered.field'] },
    'validateExplorerProjectionRequestV1',
  ],
  [{ ...request, endpoint: 'https://forbidden.invalid' }, 'validateExplorerProjectionRequestV1'],
  [{ ...request, provider: 'forbidden' }, 'validateExplorerProjectionRequestV1'],
  [{ ...request, fallback: true }, 'validateExplorerProjectionRequestV1'],
  [
    {
      ...request,
      scope: { ...(request.scope as Record<string, unknown>), action: 'different-action' },
    },
    'validateExplorerProjectionRequestV1',
  ],
  [
    {
      ...request,
      exportProfile: {
        ...(request.exportProfile as Record<string, unknown>),
        operationVersions: [
          ...((request.exportProfile as Record<string, unknown>).operationVersions as unknown[]),
        ].reverse(),
      },
    },
    'validateExplorerProjectionRequestV1',
  ],
  [
    {
      ...request,
      exportProfile: {
        ...(request.exportProfile as Record<string, unknown>),
        maximumPageSize: 1,
      },
    },
    'validateExplorerProjectionRequestV1',
  ],
  [
    {
      ...request,
      filters: [
        { fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: 'z' },
        { fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: 'a' },
      ],
    },
    'validateExplorerProjectionRequestV1',
  ],
  [
    { ...releasedResult, outcome: 'SUPPRESSED', truthState: 'FAILED' },
    'validatePrivacyExplorerResultV1',
  ],
  [
    { ...releasedResult, outcome: 'COMPLETE', truthState: 'PARTIAL' },
    'validatePrivacyExplorerResultV1',
  ],
  [
    { ...releasedResult, page: { cursor: 'next', gapFree: true } },
    'validatePrivacyExplorerResultV1',
  ],
  [
    {
      ...releasedResult,
      outcome: 'PARTIAL',
      truthState: 'PARTIAL',
      page: { cursor: null, gapFree: true },
    },
    'validatePrivacyExplorerResultV1',
  ],
  [
    {
      ...releasedResult,
      outcome: 'UNKNOWN',
      truthState: 'UNKNOWN',
      records: [],
      page: { cursor: null, gapFree: true },
    },
    'validatePrivacyExplorerResultV1',
  ],
  [
    {
      schemaVersion: '1.0',
      requestDigest: digest,
      profileDigest: digest,
      records: [],
      page: { cursor: null, gapFree: true },
      completeness: 'COMPLETE',
      freshness: 'FRESH',
      conflict: 'NONE',
    },
    'validatePrivacyExplorerResultV1',
  ],
  [
    {
      ...adapterContext,
      cancellation: {
        ...adapterContext.cancellation,
        occurrenceId: adapterContext.auditCorrelationId,
      },
    },
    'validateAdapterCallContextV1',
  ],
  [
    { ...unauthenticatedProblem, httpStatus: 403, grpcStatus: 'PERMISSION_DENIED' },
    'validatePrivacyExplorerProblemV1',
  ],
  [
    { ...terminalDenialProblem, code: 'PC-AUTH-0001', jsonRpcCode: -32041 },
    'validatePrivacyExplorerProblemV1',
  ],
] as const;
for (const [value, validatorName] of schemaNegatives)
  if (validators[validatorName](value))
    throw new Error(`${validatorName}: adversarial value accepted`);

const openApiSource = await readFile(
  resolve(repositoryRoot, 'schemas/openapi/openpc-privacy-explorer.openapi.yaml'),
  'utf8',
);
const openApiSummary = validatePrivacyExplorerOpenApiSource(openApiSource);
const generatedClientTypes = await readFile(
  resolve(repositoryRoot, 'packages/api-client/generated/privacy-explorer/types.gen.ts'),
  'utf8',
);
if (
  !generatedClientTypes.includes('PrivacyExplorerResultV1') ||
  generatedClientTypes.includes('ExplorerProjectionResultV1')
)
  throw new Error('generated client exposes the wrong response boundary');

process.stdout.write(
  `${JSON.stringify({
    registry: validateExecutionRegistry(registry),
    registryNegatives: registryNegativeIds.length,
    relationalRegistryNegatives: relationalNegativeIds.length,
    integrityRegistryNegatives: integrityNegativeIds.length,
    schemaNegatives: schemaNegatives.length,
    problemUnion: problemUnionSummary,
    problemUnionNegatives,
    publicationPreparationCases,
    publicationRollbackCases,
    publicationSymlinkCases,
    publicationOwnershipCases,
    openApi: openApiSummary,
  })}\n`,
);
