import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { z } from 'zod';
import {
  candidateRecoveryImage,
  candidateRecoveryProvenance,
  candidateRecoveryComparison,
  candidateRecoveryFingerprint,
  candidateRecoveryRunnerMode,
  finishCandidateRecoveryRunner,
} from './candidate-recovery-binding.js';
import {
  recoveryBytes,
  recoveryHash,
  recoveryPrivateFiles,
  recoveryTargetPort,
} from './postgres-component-recovery.js';

export const factRecoveryImage = candidateRecoveryImage;
export function factRecoveryRunnerMode(args: string[], continuation?: string) {
  if (args.length === 1 && args[0] === '--preflight') {
    candidateRecoveryRunnerMode(['--fresh'], continuation);
    return 'preflight' as const;
  }
  return candidateRecoveryRunnerMode(args, continuation);
}
export const finishFactRecoveryRunner = finishCandidateRecoveryRunner;
const path = z.string().max(4096).refine(isAbsolute);
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const cluster = z.strictObject({
  containerId: digest,
  dataDirectory: path,
  port: z.number().int().min(1024).max(65535),
  passwords: z.strictObject({
    openpc_facts: path,
    openpc_fact_runtime: path,
    openpc_policy_fact_runtime: path,
  }),
});
export const factDatabaseRecoveryCase = z.strictObject({
  version: z.literal(1),
  phase: z.literal('RETIRED'),
  project: z.string().regex(/^openpc-local-e2e-[a-f0-9]{12}$/u),
  backupDirectory: path,
  source: cluster,
  target: cluster,
  control: z.strictObject({
    port: z.number().int().min(1024).max(65535),
    adminPasswordFile: path,
    workerPasswordFile: path,
  }),
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  selectionFile: path,
  originalFactFile: path,
  originalCustodyFile: path,
  protectedFactsFile: path,
  terminalReadbackFile: path,
  installationFile: path,
  nativeConfigurationFile: path,
  workerConfigurationFile: path,
  nativeExecutable: path,
});
export type FactDatabaseRecoveryCase = z.infer<typeof factDatabaseRecoveryCase>;
// Source-only observations confer no dump/restore authority and allocate no
// target or durable recovery case. The ordinary runner supplies these inputs.
export const factRecoverySourceCase = factDatabaseRecoveryCase.omit({ target: true });
export type FactRecoverySourceCase = z.infer<typeof factRecoverySourceCase>;
export const factRecoveryProvenance = candidateRecoveryProvenance.extend({
  phase: z.literal('RETIRED'),
  database: z.literal('openpc_facts'),
  databaseOwner: z.literal('openpc_facts'),
});
export type FactRecoveryProvenance = z.infer<typeof factRecoveryProvenance>;
const fingerprint = z.strictObject({ count: z.number().int().nonnegative(), sha256: digest });
const entries = z
  .array(
    z.strictObject({
      name: z.string().regex(/^(?:facts|openpc_local|sequence|control)\.[a-z][a-z0-9_]*$/u),
      ...fingerprint.shape,
    }),
  )
  .max(4096)
  .refine((rows) => rows.every((row, i) => i === 0 || rows[i - 1]!.name < row.name));
export const factRecoveryComparison = z.strictObject({
  data: entries.refine((rows) =>
    [
      'openpc_local.migration',
      'facts.canonical_fact',
      'facts.retained_fact_identity',
      'facts.signed_fact_custody',
      'facts.store_retirement_attempt',
      'facts.retired_fact_payload',
      'facts.store_retirement_outbox',
      'facts.control_admission_custody_ack',
      'facts.fleet_admission_ack',
    ].every((name) => rows.some((row) => row.name === name)),
  ),
  security: candidateRecoveryComparison.shape.security.extend({
    indexes: fingerprint,
    extensions: fingerprint,
  }),
  control: entries.refine(
    (rows) => rows.length > 0 && rows.every((row) => row.name.startsWith('control.')),
  ),
  vault: candidateRecoveryComparison.shape.vault.unwrap().refine((rows) => rows.length > 0),
  inputs: z
    .array(
      z.strictObject({
        name: z.string().min(1).max(160),
        bytes: z.number().int().positive(),
        sha256: digest,
      }),
    )
    .min(8)
    .max(64)
    .refine((rows) => rows.every((row, i) => i === 0 || rows[i - 1]!.name < row.name)),
});
export type FactRecoveryComparison = z.infer<typeof factRecoveryComparison>;
const epoch = z.strictObject({
  exportedSnapshot: z.string().regex(/^[A-F0-9]{8}-[A-F0-9]{8}-[1-9][0-9]*$/u),
  snapshot: z
    .string()
    .regex(/^[0-9]+:[0-9]+:(?:[0-9]+(?:,[0-9]+)*)?$/u)
    .max(65536),
  timelineId: z.number().int().positive(),
  walLsn: z.string().regex(/^[0-9A-F]+\/[0-9A-F]+$/u),
  backendPid: z.number().int().positive(),
  observedAt: z.iso.datetime(),
  connectionLimit: z
    .number()
    .int()
    .min(-1)
    .max(2147483647)
    .refine((n) => n !== 0),
});
const reference = z.strictObject({ bytes: z.number().int().positive(), sha256: digest });
const originalSchema = z.strictObject({
  version: z.literal(1),
  kind: z.literal('OPENPC-FACT-RECOVERY-ORIGINAL-1'),
  provenance: factRecoveryProvenance,
  epoch,
  comparison: factRecoveryComparison,
  key: reference.refine((value) => value.bytes === 32),
});
export type FactRecoveryOriginal = z.infer<typeof originalSchema>;
const sealSchema = z.strictObject({
  version: z.literal(1),
  kind: z.literal('OPENPC-FACT-RECOVERY-SEALED-1'),
  original: reference,
  archive: reference,
});
export const factRecoveryFiles = {
  original: 'fact-database-recovery.original.json',
  seal: 'fact-database-recovery.binding.json',
  archive: 'fact-database-recovery.encrypted',
  key: 'fact-database-recovery.key',
} as const;
export const factRecoveryArchiveLimit = 64 * 1024 * 1024;
const magic = Buffer.from('OPENPC-FACT-PG-RECOVERY-1\n');
const envelopeLimit = factRecoveryArchiveLimit + magic.length + 28;
const fail = () =>
  new Error(
    'UNKNOWN: original Fact recovery binding, encrypted archive or key unavailable or changed',
  );
const io = recoveryPrivateFiles(fail);
const ref = (value: Buffer) => ({ bytes: value.length, sha256: recoveryHash(value) });
const equal = (a: unknown, b: unknown) => recoveryBytes(a).equals(recoveryBytes(b));

export function requireDistinctFactClusters(input: FactDatabaseRecoveryCase) {
  if (
    input.source.containerId === input.target.containerId ||
    input.source.port === input.target.port ||
    input.source.dataDirectory === input.target.dataDirectory ||
    input.source.dataDirectory.startsWith(input.target.dataDirectory + '/') ||
    input.target.dataDirectory.startsWith(input.source.dataDirectory + '/') ||
    [input.source.port, input.target.port].includes(input.control.port)
  )
    throw fail();
}
export function factRecoveryData(rows: Record<string, string[]>, prefix = '') {
  return entries.parse(
    Object.entries(rows)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([name, values]) => ({
        name: prefix + name,
        ...candidateRecoveryFingerprint(values, values.length),
      })),
  );
}
export function factRecoverySecurity(value: Record<string, unknown>) {
  return factRecoveryComparison.shape.security.parse(
    Object.fromEntries(
      Object.entries(value).map(([name, rows]) => [
        name,
        candidateRecoveryFingerprint(
          rows,
          Array.isArray(rows) ? rows.length : Object.keys(rows as object).length,
        ),
      ]),
    ),
  );
}
export function assertFactRecoveryComparison(
  expected: FactRecoveryComparison,
  actual: FactRecoveryComparison,
) {
  if (!equal(factRecoveryComparison.parse(expected), factRecoveryComparison.parse(actual)))
    throw fail();
}
export function factRecoveryInputPaths(root: string) {
  const evidence = join(root, 'evidence/runtime-bootstrap/store-retirement');
  const privateRoot = join(root, 'data/runtime-bootstrap/store-retirement/private');
  return {
    selectionFile: join(evidence, 'selection-input.json'),
    originalFactFile: join(evidence, 'original-fact.json'),
    originalCustodyFile: join(evidence, 'original-custody.json'),
    protectedFactsFile: join(evidence, 'protected-facts.json'),
    terminalReadbackFile: join(evidence, 'terminal-readback.json'),
    installationFile: join(privateRoot, 'installation.json'),
    nativeConfigurationFile: join(privateRoot, 'target.json'),
    workerConfigurationFile: join(privateRoot, 'worker.json'),
  };
}
export async function retainFactRecoveryCase(directory: string, value: FactDatabaseRecoveryCase) {
  const input = factDatabaseRecoveryCase.parse(value);
  requireDistinctFactClusters(input);
  if (input.backupDirectory !== directory) throw fail();
  await io.writeImmutable(directory, 'case.json', input);
}
export async function readFactRecoveryCase(directory: string) {
  const input = io.decode(await io.readMetadata(directory, 'case.json'), factDatabaseRecoveryCase);
  requireDistinctFactClusters(input);
  if (input.backupDirectory !== directory) throw fail();
  return input;
}
export async function requireUnusedFactRecoveryBinding(directory: string) {
  await io.privateDirectory(directory);
  for (const name of Object.values(factRecoveryFiles)) {
    try {
      await lstat(join(directory, name));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw fail();
    }
    throw fail();
  }
}
/** The local rehearsal key is independent of product signer/capability/archive
 * keys. No KMS authority or production recovery qualification is created. */
export async function retainFactRecoveryOriginal(
  directory: string,
  value: Omit<FactRecoveryOriginal, 'key'>,
) {
  await requireUnusedFactRecoveryBinding(directory);
  const key = randomBytes(32);
  try {
    const original = originalSchema.parse({ ...value, key: ref(key) });
    await io.writeBytes(directory, factRecoveryFiles.key, key, 32);
    await io.writeImmutable(directory, factRecoveryFiles.original, original);
    return original;
  } finally {
    key.fill(0);
  }
}
async function readOriginal(directory: string, expected: FactRecoveryProvenance) {
  const data = await io.readMetadata(directory, factRecoveryFiles.original);
  const original = io.decode(data, originalSchema);
  if (!equal(original.provenance, factRecoveryProvenance.parse(expected))) throw fail();
  return { data, original };
}
async function readKey(directory: string, original: FactRecoveryOriginal) {
  const key = await io.readBytes(directory, factRecoveryFiles.key, 32);
  if (!equal(ref(key), original.key)) {
    key.fill(0);
    throw fail();
  }
  return key;
}
/** Original metadata must already be durable before invoking pg_dump. Plaintext
 * is bounded to 64MiB and never written to a host/container file. Buffer wiping
 * is best effort: JS/native crypto/process copies are not a secure-memory claim. */
export async function captureFactRecoveryArchive(
  directory: string,
  expected: FactRecoveryProvenance,
  dump: () => Promise<Buffer>,
) {
  const { data, original } = await readOriginal(directory, expected);
  for (const name of [factRecoveryFiles.archive, factRecoveryFiles.seal]) {
    try {
      await lstat(join(directory, name));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw fail();
    }
    throw fail();
  }
  const key = await readKey(directory, original);
  let plaintext: Buffer | undefined;
  let ciphertext: Buffer | undefined;
  try {
    plaintext = await dump();
    if (
      plaintext.length <= 5 ||
      plaintext.length > factRecoveryArchiveLimit ||
      plaintext.subarray(0, 5).toString() !== 'PGDMP'
    )
      throw fail();
    const nonce = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(data);
    const body = cipher.update(plaintext),
      tail = cipher.final();
    try {
      ciphertext = Buffer.concat([magic, nonce, cipher.getAuthTag(), body, tail]);
    } finally {
      body.fill(0);
      tail.fill(0);
    }
    if (!data.equals((await readOriginal(directory, expected)).data)) throw fail();
    const checkedKey = await readKey(directory, original);
    checkedKey.fill(0);
    await io.writeBytes(directory, factRecoveryFiles.archive, ciphertext, envelopeLimit);
  } catch {
    throw fail();
  } finally {
    key.fill(0);
    plaintext?.fill(0);
    ciphertext?.fill(0);
  }
  // Only the caller can seal after post-dump sequence/role/related-state checks.
}
function decryptEnvelope(key: Buffer, data: Buffer, encrypted: Buffer) {
  let part: Buffer | undefined, tail: Buffer | undefined;
  try {
    if (!encrypted.subarray(0, magic.length).equals(magic) || encrypted.length <= magic.length + 33)
      throw fail();
    const decipher = createDecipheriv(
      'aes-256-gcm',
      key,
      encrypted.subarray(magic.length, magic.length + 12),
    );
    decipher.setAAD(data);
    decipher.setAuthTag(encrypted.subarray(magic.length + 12, magic.length + 28));
    part = decipher.update(encrypted.subarray(magic.length + 28));
    tail = decipher.final();
    const plaintext = Buffer.concat([part, tail]);
    if (
      plaintext.length > factRecoveryArchiveLimit ||
      plaintext.subarray(0, 5).toString() !== 'PGDMP'
    ) {
      plaintext.fill(0);
      throw fail();
    }
    return plaintext;
  } finally {
    part?.fill(0);
    tail?.fill(0);
  }
}
export async function sealFactRecoveryBinding(directory: string, expected: FactRecoveryProvenance) {
  const { data, original } = await readOriginal(directory, expected);
  const key = await readKey(directory, original);
  let encrypted: Buffer | undefined;
  try {
    encrypted = await io.readBytes(directory, factRecoveryFiles.archive, envelopeLimit);
    const plaintext = decryptEnvelope(key, data, encrypted);
    plaintext.fill(0);
    await io.writeImmutable(
      directory,
      factRecoveryFiles.seal,
      sealSchema.parse({
        version: 1,
        kind: 'OPENPC-FACT-RECOVERY-SEALED-1',
        original: ref(data),
        archive: ref(encrypted),
      }),
    );
  } catch {
    throw fail();
  } finally {
    key.fill(0);
    encrypted?.fill(0);
  }
  return readFactRecoveryBinding(directory, expected);
}
async function authenticatedArchive(directory: string, expected: FactRecoveryProvenance) {
  let key: Buffer | undefined, encrypted: Buffer | undefined;
  try {
    const seal = io.decode(await io.readMetadata(directory, factRecoveryFiles.seal), sealSchema);
    const { data, original } = await readOriginal(directory, expected);
    if (!equal(ref(data), seal.original)) throw fail();
    key = await readKey(directory, original);
    encrypted = await io.readBytes(directory, factRecoveryFiles.archive, envelopeLimit);
    if (
      !equal(ref(encrypted), seal.archive) ||
      !encrypted.subarray(0, magic.length).equals(magic) ||
      encrypted.length <= magic.length + 33
    )
      throw fail();
    const plaintext = decryptEnvelope(key, data, encrypted);
    return { original, archive: seal.archive, plaintext };
  } catch {
    throw fail();
  } finally {
    key?.fill(0);
    encrypted?.fill(0);
  }
}
export async function readFactRecoveryBinding(directory: string, expected: FactRecoveryProvenance) {
  const bound = await authenticatedArchive(directory, expected);
  bound.plaintext.fill(0);
  return { original: bound.original, archive: bound.archive };
}
/** Callback cannot run until GCM final authentication and complete bindings pass. */
export async function withFactRecoveryArchive<T>(
  directory: string,
  expected: FactRecoveryProvenance,
  restore: (bytes: Buffer) => Promise<T>,
) {
  const bound = await authenticatedArchive(directory, expected);
  try {
    return await restore(bound.plaintext);
  } finally {
    bound.plaintext.fill(0);
  }
}
export async function readFactRecoveryContinuation(root: string, project: string) {
  const directory = join(root, 'data/fact-database-recovery');
  const marker = await io.readMetadata(root, '.openpc-local-runtime-owner');
  const ownership = /^openpc-local-runtime:(openpc-local-e2e-[a-f0-9]{12}):([a-f0-9]{64})\n$/u.exec(
    marker.toString(),
  );
  if (
    !ownership ||
    ownership[1] !== project ||
    project !== `openpc-local-e2e-${ownership[2]!.slice(0, 12)}`
  )
    throw fail();
  const input = await readFactRecoveryCase(directory);
  if (
    input.project !== project ||
    input.source.dataDirectory !== join(root, 'data/fact-pg') ||
    input.target.dataDirectory !== join(directory, 'postgres') ||
    input.nativeExecutable !== join(directory, 'fact_retirement_owner')
  )
    throw fail();
  for (const [name, value] of Object.entries(factRecoveryInputPaths(root)))
    if (input[name as keyof typeof input] !== value) throw fail();
  const metadata = io.decode(
    await io.readMetadata(directory, factRecoveryFiles.original),
    originalSchema,
  );
  const expected = {
    ...metadata.provenance,
    project,
    ownerDigest: recoveryHash(marker),
    selectionDigest: recoveryHash(Buffer.from(JSON.stringify(input))),
    participantId: input.participantId,
    privacyDomainId: input.privacyDomainId,
    source: {
      ...metadata.provenance.source,
      containerId: input.source.containerId,
      dataDirectory: input.source.dataDirectory,
      port: input.source.port,
    },
    target: {
      ...metadata.provenance.target,
      containerId: input.target.containerId,
      dataDirectory: input.target.dataDirectory,
      port: input.target.port,
    },
  };
  const bound = await readFactRecoveryBinding(directory, expected);
  return { input, bound, caseFile: join(directory, 'case.json') };
}

export function factRecoveryTargetPort(
  input: FactDatabaseRecoveryCase,
  root: string,
  imageId: string,
  inspection: unknown,
) {
  return recoveryTargetPort(
    input,
    root,
    imageId,
    inspection,
    factRecoveryImage,
    'fact-target',
    fail,
  );
}
