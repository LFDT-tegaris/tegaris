import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import type { MutationCommitFence } from '../configuration/persistence/atomic-mutation.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import {
  factEvidenceBatch,
  factProvenance,
  type FactProvenance,
} from './fact-provenance-contract.js';
import { readFactProvenance } from './fact-provenance.js';
import { projectionDeletionSelection } from './projection-deletion-contracts.js';

const unavailable = () => new ConfigurationRepositoryError('PC-DATA-6007');
const identity = 'OPENPC-FACT-EVIDENCE-LEASE-1';
const factRetirementBlocker = z.enum(['INCOMPLETE_CHECKPOINT', 'REFERENCES']);
export class FactRetirementBlocked extends ConfigurationRepositoryError {
  constructor(readonly blocker: z.infer<typeof factRetirementBlocker>) {
    super('PC-DATA-6007');
  }
}

/** The service-configured Fact owner re-verifies original COSE and the full
 * historical reference closure. No request can supply database or trust pins. */
export function verifyFactRetirementBatch(
  value: unknown,
  expected: FactProvenance,
  verificationKeyDigest: string,
  verificationKeyId: string,
) {
  const { batch, retirementBlocker } = z
    .strictObject({
      identity: z.literal(identity),
      batch: factEvidenceBatch,
      retirementBlocker: factRetirementBlocker.nullable(),
    })
    .parse(value);
  const entry = batch.records[0];
  if (
    !entry ||
    (batch.checkpointState !== 'COMPLETE' && retirementBlocker !== 'INCOMPLETE_CHECKPOINT') ||
    batch.verificationKeyDigest !== verificationKeyDigest ||
    batch.sourceProfileId !== expected.sourceProfileId ||
    BigInt(batch.checkpointSequence) < BigInt(expected.sourceSequence)
  )
    throw unavailable();
  const { receiptBase64, ...record } = entry;
  delete record.admissionDelivery;
  const receipt = Buffer.from(receiptBase64, 'base64');
  const projection = factProvenance.parse({
    ...record,
    sourceProfileId: batch.sourceProfileId,
    verificationKeyDigest,
    verificationKeyId,
    integrity: 'FACT_COSE_VERIFIED_AT_CUSTODY',
    authority: 'NONE',
    currentReadiness: 'NOT_ESTABLISHED',
  });
  if (
    receipt.toString('base64') !== receiptBase64 ||
    sha256(receipt) !== record.receiptDigest ||
    sha256(projection) !== sha256(expected)
  )
    throw unavailable();
  if (retirementBlocker !== null) throw new FactRetirementBlocked(retirementBlocker);
}

export async function acquireFactRetirementFence(
  client: PoolClient,
  selection: z.infer<typeof projectionDeletionSelection>,
): Promise<MutationCommitFence> {
  if (
    selection.sourceKind !== 'FACT_PROVENANCE' ||
    selection.dataClass !== 'NORMALIZED_JSON_PROJECTION'
  )
    throw unavailable();
  const participantId = selection.participantId.slice(-36),
    privacyDomainId = selection.privacyDomainId;
  const selected = await client.query<{
    recordId: string;
    recordDigest: string;
    occurredAt: string;
    sequence: string;
  }>(
    `select record_id as "recordId",receipt_digest as "recordDigest",sequence::text,
     to_char(occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt"
     from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and evidence_id=$3
      and stream_id=$4 and source_format='OPENPC_CANONICAL_FACT_V1' and evidence_class='EFFECT'`,
    [participantId, privacyDomainId, selection.evidenceId.slice(-36), selection.streamId],
  );
  const record = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !record ||
    record.recordId !== selection.recordId ||
    record.sequence !== selection.sequence ||
    record.recordDigest !== selection.sourceReceiptDigest
  )
    throw unavailable();
  const projection = await readFactProvenance(client, {
    ...record,
    participantId,
    privacyDomainId,
    streamId: selection.streamId,
  });
  if (!projection || sha256(projection) !== selection.projectionDigest) throw unavailable();
  const keyFile = process.env.POLICY_FACT_VERIFY_KEY_FILE,
    keyId = process.env.POLICY_FACT_VERIFY_KEY_ID;
  if (!keyFile || !keyId) throw unavailable();
  const key = await readFile(keyFile);
  if (key.length !== 33 || ![2, 3].includes(key[0]!)) throw unavailable();
  const started = performance.now();
  const child = execFile(
    process.env.OPENPC_POLICY_FACT_READER_BIN ??
      fileURLToPath(new URL('../../../../target/debug/policy_fact_reader', import.meta.url)),
    ['--evidence-lease'],
    { timeout: 10000, maxBuffer: 4 * 1024 * 1024 },
  );
  let buffered = '',
    failed = false;
  let pending: { resolve: (line: string) => void; reject: (error: Error) => void } | undefined;
  const fail = () => {
    failed = true;
    pending?.reject(unavailable());
    pending = undefined;
  };
  const receive = () =>
    new Promise<string>((resolve, reject) => {
      if (failed || pending) {
        reject(unavailable());
        return;
      }
      pending = { resolve, reject };
    });
  child.stdout?.setEncoding('utf8');
  child.stdout?.on('data', (chunk: string) => {
    buffered += chunk;
    const end = buffered.indexOf('\n');
    if (
      buffered.length > 4 * 1024 * 1024 ||
      (end >= 0 && (!pending || end !== buffered.length - 1))
    ) {
      fail();
      child.kill();
      return;
    }
    if (end < 0) return;
    const waiter = pending!;
    pending = undefined;
    const line = buffered.slice(0, end);
    buffered = '';
    waiter.resolve(line);
  });
  child.on('error', fail);
  child.stdin?.on('error', fail);
  child.on('close', fail);
  const completed = new Promise<void>((resolve) => child.once('close', () => resolve()));
  const release = async () => {
    fail();
    child.stdin?.end('RELEASE\n');
    await completed;
  };
  const assertHeld = () => {
    if (
      failed ||
      child.exitCode !== null ||
      child.signalCode !== null ||
      performance.now() - started >= 5000
    )
      throw unavailable();
  };
  try {
    const ready = receive();
    child.stdin?.write(
      `${JSON.stringify({
        participantId,
        privacyDomainId,
        sourceProfileId: projection.sourceProfileId,
        afterSequence: (BigInt(projection.sourceSequence) - 1n).toString(),
      })}\n`,
    );
    verifyFactRetirementBatch(JSON.parse(await ready), projection, sha256(key), keyId);
    assertHeld();
    return {
      release,
      revalidate: async () => {
        assertHeld();
        const checked = receive();
        child.stdin?.write('CHECK\n');
        z.strictObject({ identity: z.literal(identity), state: z.literal('HELD') }).parse(
          JSON.parse(await checked),
        );
        assertHeld();
      },
    };
  } catch (error) {
    await release();
    if (error instanceof FactRetirementBlocked) throw error;
    throw unavailable();
  }
}
