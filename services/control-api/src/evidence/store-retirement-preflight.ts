import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import {
  parseRetirementWire,
  retirementAttempt,
  retirementAttemptDigest,
  retirementHost,
  retirementWireDigest,
  type StoreRetirementHost,
  retirementSelection,
  retirementWireBytes,
  type StoreRetirementAttempt,
} from './store-retirement-wire.js';

const hash = z.string().regex(/^[0-9a-f]{64}$/u);
const response = z.strictObject({
  identity: z.literal('OPENPC-FACT-RETIREMENT-PREFLIGHT-1'),
  authority: z.literal('ADVISORY_ONLY'),
  attemptDigest: hash,
  selectionDigest: hash,
  result: z.discriminatedUnion('state', [
    z.strictObject({
      state: z.literal('CLEAR'),
      checkedAtMs: z.string().regex(/^[1-9][0-9]{0,18}$/u),
      selection: retirementSelection,
    }),
    z.strictObject({
      state: z.literal('BLOCKED'),
      blocker: z.enum([
        'SOURCE_CHANGED',
        'GENERATION_CHANGED',
        'REORG_FENCED',
        'CHECKPOINT_INCOMPLETE',
        'READINESS_PROTECTED',
        'PUBLICATION_PROTECTED',
        'REFERENCES_PROTECTED',
        'RETENTION_NOT_ELAPSED',
        'ARCHIVE_MISMATCH',
        'GOVERNANCE_CHANGED',
      ]),
    }),
    z.strictObject({ state: z.literal('UNAVAILABLE') }),
  ]),
});

/** Only validates a native observation. No surviving lease, signing capability
 * or caller-provided eligibility is obtained from this result. */
export function parseFactRetirementPreflight(bytes: Buffer, original: StoreRetirementAttempt) {
  const attempt = retirementAttempt.parse(original);
  if (attempt.store !== 'openpc_facts') throw new ConfigurationRepositoryError('PC-DATA-6007');
  const parsed = response.parse(parseRetirementWire(bytes));
  if (
    parsed.attemptDigest !== retirementAttemptDigest(attempt) ||
    parsed.selectionDigest !== attempt.selection_digest ||
    (parsed.result.state === 'CLEAR' &&
      (!retirementWireBytes(parsed.result.selection).equals(
        retirementWireBytes(attempt.selection),
      ) ||
        BigInt(parsed.result.checkedAtMs) > 9223372036854775807n))
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  return parsed.result;
}

/** Database connection, native executable and signature trust are service
 * configuration. Neither an HTTP input nor the native result can replace them. */
export async function readFactRetirementPreflight(original: StoreRetirementAttempt) {
  const attempt = retirementAttempt.parse(structuredClone(original));
  if (attempt.store !== 'openpc_facts') throw new ConfigurationRepositoryError('PC-DATA-6007');
  const keyFile = process.env.POLICY_FACT_VERIFY_KEY_FILE,
    keyId = process.env.POLICY_FACT_VERIFY_KEY_ID;
  if (!keyFile || !keyId) throw new ConfigurationRepositoryError('PC-DATA-6007');
  const key = await readFile(keyFile);
  if (key.length !== 33 || ![2, 3].includes(key[0]!))
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const input = retirementWireBytes({
    participantId: attempt.scope.participant_id,
    privacyDomainId: attempt.scope.privacy_domain_id,
    attempt,
  });
  const executable =
    process.env.OPENPC_POLICY_FACT_READER_BIN ??
    fileURLToPath(new URL('../../../../target/debug/policy_fact_reader', import.meta.url));
  const bytes = await new Promise<Buffer>((resolve, reject) => {
    const child = execFile(
      executable,
      ['--retirement-preflight'],
      { timeout: 11000, maxBuffer: 1048576, encoding: 'buffer' },
      (error, stdout) => {
        if (error) reject(new ConfigurationRepositoryError('PC-DATA-6007'));
        else resolve(stdout);
      },
    );
    child.stdin?.on('error', () => reject(new ConfigurationRepositoryError('PC-DATA-6007')));
    if (!child.stdin) reject(new ConfigurationRepositoryError('PC-DATA-6007'));
    else child.stdin.end(input);
  });
  return {
    result: parseFactRetirementPreflight(bytes, attempt),
    verificationKeyDigest: sha256(key),
    verificationKeyId: keyId,
  };
}

const candidateResponse = response.extend({
  identity: z.literal('OPENPC-CANDIDATE-RETIREMENT-PREFLIGHT-1'),
  hostDigest: hash,
});
export function parseCandidateRetirementPreflight(
  bytes: Buffer,
  original: StoreRetirementAttempt,
  installedHost: StoreRetirementHost,
) {
  const attempt = retirementAttempt.parse(original),
    host = retirementHost.parse(installedHost);
  const parsed = candidateResponse.parse(parseRetirementWire(bytes));
  if (
    attempt.store !== 'openpc_candidate_index' ||
    host.store !== attempt.store ||
    host.scope.participant_id !== attempt.scope.participant_id ||
    host.scope.privacy_domain_id !== attempt.scope.privacy_domain_id ||
    parsed.hostDigest !== retirementWireDigest(host) ||
    parsed.attemptDigest !== retirementAttemptDigest(attempt) ||
    parsed.selectionDigest !== attempt.selection_digest ||
    (parsed.result.state === 'CLEAR' &&
      (!retirementWireBytes(parsed.result.selection).equals(
        retirementWireBytes(attempt.selection),
      ) ||
        BigInt(parsed.result.checkedAtMs) > 9223372036854775807n))
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  return parsed.result;
}

/** Installed target owns the source observation; no public input can choose its
 * connection or host. CLEAR is advisory only and the native executor rechecks. */
export async function readCandidateRetirementPreflight(
  original: StoreRetirementAttempt,
  installedHost: StoreRetirementHost,
  configurationFile: string,
) {
  const attempt = retirementAttempt.parse(structuredClone(original));
  const host = retirementHost.parse(structuredClone(installedHost));
  if (
    attempt.store !== 'openpc_candidate_index' ||
    host.store !== attempt.store ||
    !configurationFile.startsWith('/')
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const executable =
    process.env.OPENPC_CANDIDATE_RETIREMENT_OWNER_BIN ??
    fileURLToPath(new URL('../../../../target/debug/candidate_retirement_owner', import.meta.url));
  const bytes = await new Promise<Buffer>((resolve, reject) => {
    const child = execFile(
      executable,
      [],
      {
        env: { ...process.env, OPENPC_RETIREMENT_CANDIDATE_CONFIGURATION_FILE: configurationFile },
        timeout: 22000,
        maxBuffer: 1048576,
        encoding: 'buffer',
      },
      (error, stdout) =>
        error ? reject(new ConfigurationRepositoryError('PC-DATA-6007')) : resolve(stdout),
    );
    child.stdin?.on('error', () => reject(new ConfigurationRepositoryError('PC-DATA-6007')));
    if (!child.stdin) reject(new ConfigurationRepositoryError('PC-DATA-6007'));
    else child.stdin.end(retirementWireBytes({ mode: 'PREFLIGHT', attempt }));
  });
  return { result: parseCandidateRetirementPreflight(bytes, attempt, host) };
}
