import { createHash } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { z } from 'zod';
import {
  recoveryPrivateFiles,
  recoveryBytes as bytes,
  recoveryHash as hash,
  recoveryTargetPort,
} from './postgres-component-recovery.js';

const absolute = z.string().refine(isAbsolute);
const uuid = z.uuidv7();
export const candidateRecoveryImage =
  'docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7';
const caseCluster = z.strictObject({
  containerId: z.string().regex(/^[0-9a-f]{64}$/u),
  dataDirectory: absolute,
  port: z.number().int().min(1024).max(65535),
  // The canonical roles-only installer supplies these exact identities. This
  // fixture never creates roles, installs trust or changes passwords.
  passwords: z.strictObject({
    openpc_candidate_index: absolute,
    openpc_indexer_manager: absolute,
    openpc_indexer_writer: absolute,
    openpc_candidate_index_reader: absolute,
  }),
});
const common = {
  version: z.literal(1),
  project: z.string().regex(/^openpc-[a-z0-9][a-z0-9_-]{0,100}$/u),
  backupDirectory: absolute,
  source: caseCluster,
  target: caseCluster,
  control: z.strictObject({
    port: z.number().int().min(1024).max(65535),
    adminPasswordFile: absolute,
    workerPasswordFile: absolute,
  }),
  participantId: uuid,
  privacyDomainId: uuid,
};

/** A fixture selection is not product authority. Every state below is read back
 * from its original owner before dumping, and again after restoring. */
export const candidateDatabaseRecoveryCase = z.discriminatedUnion('phase', [
  z.strictObject({ ...common, phase: z.literal('PRISTINE'), projectionPlanId: uuid }),
  z.strictObject({
    ...common,
    phase: z.literal('RETIRED'),
    custodyCaseFile: absolute,
    nativeBeforeFile: absolute,
    terminalReadbackFile: absolute,
    nativeConfigurationFile: absolute,
    // Existing compiled installation executable; canonical owns its provenance
    // and build. No shell command, wrapper arguments or new execution mode.
    nativeExecutable: absolute,
  }),
]);
export type CandidateDatabaseRecoveryCase = z.infer<typeof candidateDatabaseRecoveryCase>;

export function requireDistinctCandidateClusters(input: CandidateDatabaseRecoveryCase) {
  if (
    input.source.containerId === input.target.containerId ||
    input.source.port === input.target.port ||
    input.source.dataDirectory === input.target.dataDirectory ||
    input.source.dataDirectory.startsWith(`${input.target.dataDirectory}/`) ||
    input.target.dataDirectory.startsWith(`${input.source.dataDirectory}/`) ||
    [input.source.port, input.target.port].includes(input.control.port)
  )
    throw new Error('BLOCKED: Candidate recovery requires distinct source, target and Control');
}

const hex = z.string().regex(/^[a-f0-9]{64}$/u);
const decimal = z.string().regex(/^[1-9][0-9]{0,19}$/u);
const path = z.string().max(4096).refine(isAbsolute);
const cluster = z.strictObject({
  containerId: hex,
  imageId: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
  dataDirectory: path,
  port: z.number().int().min(1024).max(65535),
  systemIdentifier: decimal,
  databaseOid: decimal,
});
export const candidateRecoveryProvenance = z.strictObject({
  project: z.string().regex(/^openpc-local-e2e-[a-f0-9]{12}$/u),
  ownerDigest: hex,
  selectionDigest: hex,
  phase: z.enum(['PRISTINE', 'RETIRED']),
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  database: z.literal('openpc_candidate_index'),
  databaseOwner: z.literal('openpc_candidate_index_owner'),
  source: cluster,
  target: cluster,
});
export type CandidateRecoveryProvenance = z.infer<typeof candidateRecoveryProvenance>;
const fingerprint = z.strictObject({ count: z.number().int().min(0), sha256: hex });
const entries = z
  .array(
    z.strictObject({
      name: z.string().regex(/^(?:candidate|openpc_local|sequence|control)\.[a-z][a-z0-9_]*$/u),
      ...fingerprint.shape,
    }),
  )
  .max(4096)
  .refine((rows) => rows.every((row, index) => index === 0 || rows[index - 1]!.name < row.name));
const security = z.strictObject({
  relations: fingerprint,
  policies: fingerprint,
  functions: fingerprint,
  triggers: fingerprint,
  constraints: fingerprint,
  schemas: fingerprint,
  defaults: fingerprint,
  roles: fingerprint,
  databases: fingerprint,
  settings: fingerprint,
});
export const candidateRecoveryComparison = z.strictObject({
  data: entries.refine((rows) =>
    [
      'candidate.schema_migration',
      'candidate.store_retirement_attempt',
      'openpc_local.migration',
    ].every((name) => rows.some((row) => row.name === name)),
  ),
  security,
  control: entries.refine(
    (rows) => rows.length > 0 && rows.every((row) => row.name.startsWith('control.')),
  ),
  vault: z
    .array(
      z.strictObject({
        name: z.string().regex(/^[a-f0-9]{64}\.(?:segment|hold-[12])$/u),
        bytes: z.number().int().positive(),
        digest: hex,
      }),
    )
    .max(100000)
    .nullable(),
});
export type CandidateRecoveryComparison = z.infer<typeof candidateRecoveryComparison>;
const originalSchema = z
  .strictObject({
    version: z.literal(1),
    kind: z.literal('OPENPC-CANDIDATE-RECOVERY-ORIGINAL-1'),
    provenance: candidateRecoveryProvenance,
    epoch: z.strictObject({
      exportedSnapshot: z.string().regex(/^[A-F0-9]{8}-[A-F0-9]{8}-[1-9][0-9]*$/u),
      snapshot: z
        .string()
        .regex(/^[0-9]+:[0-9]+:(?:[0-9]+(?:,[0-9]+)*)?$/u)
        .max(65536),
      backendPid: z.number().int().positive(),
      observedAt: z.iso.datetime(),
      connectionLimit: z
        .number()
        .int()
        .min(-1)
        .max(2147483647)
        .refine((n) => n !== 0),
    }),
    comparison: candidateRecoveryComparison,
  })
  .refine((value) =>
    value.provenance.phase === 'RETIRED'
      ? value.comparison.vault !== null && value.comparison.vault.length > 0
      : value.comparison.vault === null,
  );
export type CandidateRecoveryOriginal = z.infer<typeof originalSchema>;
const reference = z.strictObject({ bytes: z.number().int().positive(), sha256: hex });
const sealSchema = z.strictObject({
  version: z.literal(1),
  kind: z.literal('OPENPC-CANDIDATE-RECOVERY-SEALED-1'),
  original: reference,
  archive: reference,
});
const names = {
  original: 'candidate-database-recovery.original.json',
  seal: 'candidate-database-recovery.binding.json',
  archive: 'candidate-database-recovery.dump',
} as const;
const archiveLimit = 64 * 1024 * 1024;
const fail = () =>
  new Error('UNKNOWN: Candidate recovery original/archive binding unavailable or changed');

// Hashes are integrity comparisons within the authenticated owned backup root,
// never signing authority. Persist only fingerprints, not SQL payloads or keys.
export function candidateRecoveryFingerprint(value: unknown, count: number) {
  return fingerprint.parse({ count, sha256: hash(bytes(value)) });
}
export function candidateRecoveryData(rows: Record<string, string[]>, prefix = '') {
  return entries.parse(
    Object.entries(rows)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([name, values]) => ({
        name: `${prefix}${name}`,
        ...candidateRecoveryFingerprint(values, values.length),
      })),
  );
}
export function candidateRecoverySecurity(value: Record<string, unknown>) {
  return security.parse(
    Object.fromEntries(
      Object.entries(value).map(([key, rows]) => [
        key,
        candidateRecoveryFingerprint(
          rows,
          Array.isArray(rows) ? rows.length : Object.keys(rows as object).length,
        ),
      ]),
    ),
  );
}
export function assertCandidateRecoveryComparison(
  expected: CandidateRecoveryComparison,
  actual: CandidateRecoveryComparison,
) {
  if (
    !bytes(candidateRecoveryComparison.parse(expected)).equals(
      bytes(candidateRecoveryComparison.parse(actual)),
    )
  )
    throw fail();
}

const {
  privateDirectory,
  privateFile,
  verifyFileEnd,
  syncDirectory,
  readMetadata,
  decode,
  writeImmutable,
} = recoveryPrivateFiles(fail);
async function archiveReference(directory: string, durable: boolean) {
  const file = await privateFile(directory, names.archive, archiveLimit, durable);
  try {
    const buffer = Buffer.alloc(65536);
    const digest = createHash('sha256');
    let position = 0;
    try {
      while (position < file.stat.size) {
        const { bytesRead } = await file.handle.read(
          buffer,
          0,
          Math.min(buffer.length, file.stat.size - position),
          position,
        );
        if (!bytesRead || (position === 0 && buffer.subarray(0, 5).toString() !== 'PGDMP'))
          throw fail();
        digest.update(buffer.subarray(0, bytesRead));
        position += bytesRead;
      }
    } finally {
      buffer.fill(0);
    }
    if (position <= 5) throw fail();
    await verifyFileEnd(directory, file);
    if (durable) {
      await file.handle.sync();
      await syncDirectory(directory);
    }
    return { bytes: position, sha256: digest.digest('hex') };
  } finally {
    await file.handle.close();
  }
}
export async function requireUnusedCandidateRecoveryBinding(directory: string) {
  await privateDirectory(directory);
  for (const name of Object.values(names)) {
    try {
      await lstat(join(directory, name));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw fail();
    }
    throw fail();
  }
}
export async function retainCandidateRecoveryOriginal(
  directory: string,
  original: CandidateRecoveryOriginal,
) {
  await writeImmutable(directory, names.original, originalSchema.parse(original));
}
export async function retainCandidateRecoveryCase(
  directory: string,
  value: CandidateDatabaseRecoveryCase,
) {
  const input = candidateDatabaseRecoveryCase.parse(value);
  requireDistinctCandidateClusters(input);
  if (input.backupDirectory !== directory) throw fail();
  await writeImmutable(directory, 'case.json', input);
}
export async function sealCandidateRecoveryBinding(
  directory: string,
  expected: CandidateRecoveryProvenance,
) {
  const data = await readMetadata(directory, names.original);
  const original = decode(data, originalSchema);
  if (!bytes(original.provenance).equals(bytes(candidateRecoveryProvenance.parse(expected))))
    throw fail();
  const archive = await archiveReference(directory, true);
  await writeImmutable(
    directory,
    names.seal,
    sealSchema.parse({
      version: 1,
      kind: 'OPENPC-CANDIDATE-RECOVERY-SEALED-1',
      original: { bytes: data.length, sha256: hash(data) },
      archive,
    }),
  );
  return readCandidateRecoveryBinding(directory, expected);
}
async function readCandidateRecoveryArtifacts(directory: string) {
  try {
    const sealBytes = await readMetadata(directory, names.seal);
    const seal = decode(sealBytes, sealSchema);
    const data = await readMetadata(directory, names.original);
    if (data.length !== seal.original.bytes || hash(data) !== seal.original.sha256) throw fail();
    const original = decode(data, originalSchema);
    const archive = await archiveReference(directory, false);
    if (!bytes(archive).equals(bytes(seal.archive))) throw fail();
    return { original, archive, archivePath: join(directory, names.archive) };
  } catch {
    throw fail();
  }
}

export async function readCandidateRecoveryBinding(
  directory: string,
  expected: CandidateRecoveryProvenance,
) {
  const bound = await readCandidateRecoveryArtifacts(directory);
  if (!bytes(bound.original.provenance).equals(bytes(candidateRecoveryProvenance.parse(expected))))
    throw fail();
  return bound;
}

export function candidateRecoveryRunnerMode(args: string[], continuation?: string) {
  if (
    args.length > 1 ||
    (args.length && !['--fresh', '--retained'].includes(args[0]!)) ||
    (continuation !== undefined && !['0', '1'].includes(continuation)) ||
    (args[0] === '--fresh' && continuation === '1') ||
    (args[0] === '--retained' && continuation === '0')
  )
    throw fail();
  return args[0] === '--retained' || continuation === '1' ? 'retained' : 'fresh';
}

/** Read the original case and seal, never create or repair either. Live database
 * identities and source fencing still require the runner/fixture's real reads. */
export async function readCandidateRecoveryContinuation(root: string, project: string) {
  const directory = join(root, 'data/candidate-database-recovery');
  const marker = await readMetadata(root, '.openpc-local-runtime-owner');
  const ownership = /^openpc-local-runtime:(openpc-local-e2e-[a-f0-9]{12}):([a-f0-9]{64})\n$/u.exec(
    marker.toString(),
  );
  if (
    !ownership ||
    ownership[1] !== project ||
    project !== `openpc-local-e2e-${ownership[2]!.slice(0, 12)}`
  )
    throw fail();
  const caseBytes = await readMetadata(directory, 'case.json');
  const raw = JSON.parse(caseBytes.toString());
  if (JSON.stringify(raw) !== caseBytes.toString()) throw fail();
  const input = candidateDatabaseRecoveryCase.parse(raw);
  requireDistinctCandidateClusters(input);
  if (
    input.phase !== 'RETIRED' ||
    input.project !== project ||
    input.backupDirectory !== directory ||
    input.source.dataDirectory !== join(root, 'data/candidate-index-pg') ||
    input.target.dataDirectory !== join(directory, 'postgres') ||
    input.nativeExecutable !== join(directory, 'candidate_retirement_owner')
  )
    throw fail();
  const bound = await readCandidateRecoveryArtifacts(directory);
  const expected = {
    ...bound.original.provenance,
    project,
    ownerDigest: hash(marker),
    selectionDigest: hash(Buffer.from(JSON.stringify(input))),
    phase: input.phase,
    participantId: input.participantId,
    privacyDomainId: input.privacyDomainId,
    source: {
      ...bound.original.provenance.source,
      containerId: input.source.containerId,
      dataDirectory: input.source.dataDirectory,
      port: input.source.port,
    },
    target: {
      ...bound.original.provenance.target,
      containerId: input.target.containerId,
      dataDirectory: input.target.dataDirectory,
      port: input.target.port,
    },
  };
  if (!bytes(expected).equals(bytes(bound.original.provenance))) throw fail();
  return { input, bound, caseFile: join(directory, 'case.json') };
}

/** Docker inspection supplies a transport locator, never replacement authority.
 * The original case and its recorded port remain unchanged in the sealed proof. */
export function candidateRecoveryTargetPort(
  input: CandidateDatabaseRecoveryCase,
  root: string,
  imageId: string,
  inspection: unknown,
) {
  return recoveryTargetPort(
    input,
    root,
    imageId,
    inspection,
    candidateRecoveryImage,
    'candidate-target',
    fail,
  );
}

/** The runner retains the first failure even if stopping its exact target fails.
 * PASS is emitted by the caller only after this returns; no removal is allowed. */
export async function finishCandidateRecoveryRunner(
  run: () => Promise<void>,
  stop: () => Promise<void>,
) {
  let failed = false;
  let primary: unknown;
  try {
    await run();
  } catch (error) {
    failed = true;
    primary = error;
  }
  try {
    await stop();
  } catch (error) {
    if (!failed) {
      failed = true;
      primary = error;
    }
  }
  if (failed)
    throw new Error('UNKNOWN: Candidate recovery runner failed; all originals retained', {
      cause: primary,
    });
}
