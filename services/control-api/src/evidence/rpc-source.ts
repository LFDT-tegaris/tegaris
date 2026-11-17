import {
  rpcProvenance,
  rpcTransitionProjection,
  type RpcProvenance,
} from './rpc-provenance-contract.js';
import { spawnSync } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import { EvidenceCustodyError, type EvidenceScope, type SourceReceipt } from './segment.js';

const reference = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u);
const absolute = z.string().refine(isAbsolute);
const digest = z.string().regex(/^[0-9a-f]{64}$/u);
const ordinal = z.string().regex(/^[1-9][0-9]{0,19}$/u);
export const rpcEvidenceSource = z.strictObject({
  directory: absolute,
  targetRuntimeId: z.uuid(),
  spoolId: reference,
  keyId: reference,
  keyFile: absolute,
  activationPublicKeyFile: absolute,
  activationSignerId: reference,
});
export type RpcEvidenceSource = z.infer<typeof rpcEvidenceSource>;
export const RPC_EVIDENCE_FORMAT = 'OPENPC_RPC_DECISION_TRANSITION_V1';
const sourceRecords = z
  .array(
    z.strictObject({
      sequence: ordinal,
      decision_id: z.uuid(),
      capsule_digest: digest,
      reserved_at_ns: ordinal,
      occurred_at_ns: ordinal,
      source_digest: digest,
      provenance: z.preprocess((value) => {
        if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
        const normalized = { ...value } as Record<string, unknown>;
        for (const field of [
          'requestDigest',
          'decisionDigest',
          'responseDigest',
          'authorityBindingDigest',
          'sourceScopeDigest',
          'sourceRecordDigest',
        ]) {
          const hash = normalized[field];
          if (typeof hash === 'string' && /^[0-9a-f]{64}$/u.test(hash))
            normalized[field] = `sha256:${hash}`;
        }
        return normalized;
      }, rpcTransitionProjection),
      source_bytes: z.array(z.number().int().min(0).max(255)).min(1).max(131072),
    }),
  )
  .max(8);

const maximumReaderOutput = 4 * 1024 * 1024;
const unavailableProcessCodes = new Set([
  'ENOENT',
  'EACCES',
  'EAGAIN',
  'EMFILE',
  'ENFILE',
  'ENOMEM',
  'ETIMEDOUT',
]);
const diagnosticVersion = '"version"[ \\t]*:[ \\t]*1';
const diagnosticCode = '"code"[ \\t]*:[ \\t]*"(UNAVAILABLE|REJECTED)"';
// One bounded JSON diagnostic, in either key order. Reject duplicate keys,
// extra fields, multiple diagnostics and legacy free-form stderr explicitly.
const readerDiagnostic = new RegExp(
  `^[ \\t]*\\{[ \\t]*(?:${diagnosticVersion}[ \\t]*,[ \\t]*${diagnosticCode}|${diagnosticCode}[ \\t]*,[ \\t]*${diagnosticVersion})[ \\t]*\\}[ \\t]*\\n?$`,
  'u',
);

/** Internal subprocess boundary: unavailability does not assert transience,
 * journal integrity or an empty batch. Every failure aborts source admission. */
export function parseRpcReaderResult<T>(
  result: {
    stdout: string | null | undefined;
    stderr: string | null | undefined;
    status: number | null;
    signal: NodeJS.Signals | null;
    error?: Error & { code?: string };
  },
  schema: z.ZodType<T>,
): T {
  if (
    result.status === 0 &&
    !result.error &&
    result.signal === null &&
    result.stderr === '' &&
    typeof result.stdout === 'string' &&
    Buffer.byteLength(result.stdout) <= maximumReaderOutput
  ) {
    try {
      return schema.parse(JSON.parse(result.stdout));
    } catch {
      throw new EvidenceCustodyError('INTEGRITY');
    }
  }
  if (result.stdout === '' || result.stdout === null || result.stdout === undefined) {
    if (
      result.status === null &&
      (result.stderr === '' || result.stderr === null || result.stderr === undefined) &&
      (result.signal === null || ['SIGTERM', 'SIGKILL', 'SIGINT'].includes(result.signal)) &&
      result.error &&
      unavailableProcessCodes.has(result.error.code ?? '')
    )
      throw new EvidenceCustodyError('UNAVAILABLE');
    if (
      result.stdout === '' &&
      result.status === 1 &&
      !result.error &&
      result.signal === null &&
      typeof result.stderr === 'string' &&
      Buffer.byteLength(result.stderr) <= 128
    ) {
      const diagnostic = readerDiagnostic.exec(result.stderr);
      if (diagnostic?.[0] === result.stderr && (diagnostic[1] ?? diagnostic[2]) === 'UNAVAILABLE')
        throw new EvidenceCustodyError('UNAVAILABLE');
    }
  }
  throw new EvidenceCustodyError('INTEGRITY');
}

function core<T>(command: string, value: unknown, schema: z.ZodType<T>): T {
  const executable =
    process.env.OPENPC_RUNTIME_EVIDENCE_READER_BIN ??
    fileURLToPath(new URL('../../../../target/debug/runtime_evidence_reader', import.meta.url));
  let result;
  try {
    result = spawnSync(executable, [], {
      encoding: 'utf8',
      input: JSON.stringify({ command, value }),
      timeout: 10000,
      maxBuffer: maximumReaderOutput,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch {
    throw new EvidenceCustodyError('INTEGRITY');
  }
  return parseRpcReaderResult(result, schema);
}

/** Historical activation is evidence of installed runtime identity only. It
 * never grants a current workload permission, proves a provider effect, or
 * substitutes a claimed scope for the actual immutable Control owner joins. */
export async function readRpcEvidenceBatch(
  client: PoolClient,
  scope: EvidenceScope,
  input: RpcEvidenceSource,
  reconcile = false,
): Promise<{ source: SourceReceipt; provenance: RpcProvenance }[]> {
  const source = rpcEvidenceSource.parse(input);
  // Rebuild only missing minimized projections. Original catalogue, encrypted
  // segments and serving journal remain untouched; no new business admission.
  const gap = reconcile
    ? await client.query<{ sequence: string }>(
        `select c.sequence::text from control.evidence_catalogue c
     left join control.evidence_rpc_provenance p using(participant_id,privacy_domain_id,stream_id,record_id)
     where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3
      and p.record_id is null and not exists(select 1 from control.evidence_projection_retirement r
       where r.participant_id=c.participant_id and r.privacy_domain_id=c.privacy_domain_id and r.stream_id=c.stream_id
        and r.record_id=c.record_id and r.data_class='NORMALIZED_JSON_PROJECTION') order by c.sequence limit 1`,
        [scope.participantId, scope.privacyDomainId, scope.streamId],
      )
    : undefined;
  const tail = await client.query<{
    sequence: string;
    receipt_digest: string;
    source_format: string;
  }>(
    `select catalogue.sequence::text,receipt_digest,source_format from control.evidence_catalogue catalogue
     where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and ($4::numeric is null or catalogue.sequence<$4) order by catalogue.sequence desc limit 1`,
    [scope.participantId, scope.privacyDomainId, scope.streamId, gap?.rows[0]?.sequence ?? null],
  );
  const previous = tail.rows[0];
  if (previous && previous.source_format !== RPC_EVIDENCE_FORMAT)
    throw new EvidenceCustodyError('CONFLICT');
  const after = previous ? Number(previous.sequence) : 0;
  if (!Number.isSafeInteger(after) || after < 0) throw new EvidenceCustodyError('INTEGRITY');
  const records = core(
    'Read',
    {
      directory: source.directory,
      binding: {
        participant_id: scope.participantId,
        privacy_domain_id: scope.privacyDomainId,
        target_runtime_id: source.targetRuntimeId,
        spool_id: source.spoolId,
        key_id: source.keyId,
      },
      key_file: source.keyFile,
      after_sequence: after,
      prior_source_digest: previous?.receipt_digest.slice(7) ?? null,
    },
    sourceRecords,
  );
  if (records.length === 0) return [];
  const capsules = [...new Set(records.map((record) => `sha256:${record.capsule_digest}`))];
  const activated = await client.query<{
    capsule_digest: string;
    signed_bytes: string;
    operationId: string;
    attemptId: string;
    configurationWorkId: string;
    generationId: string;
    generationDigest: string;
  }>(
    `select observation.capsule_digest,observation.activation_receipt->>'activationReceiptCoseHex' signed_bytes,
      observation.operation_id::text as "operationId",observation.execution_attempt_id::text as "attemptId",
      observation.configuration_work_id::text as "configurationWorkId",
      observation.runtime_configuration_generation_id::text as "generationId",observation.generation_digest as "generationDigest"
     from control.runtime_activation_observation observation
     join control.configuration_work work on work.configuration_work_id=observation.configuration_work_id
      and work.participant_id=observation.participant_id and work.privacy_domain_id=observation.privacy_domain_id
      and work.runtime_target_id=observation.runtime_target_id
      and work.runtime_configuration_generation_id=observation.runtime_configuration_generation_id
      and work.operation_id=observation.operation_id and work.execution_attempt_id=observation.execution_attempt_id
      and work.generation_digest=observation.generation_digest and work.state='COMPLETED'
     where observation.participant_id=$1 and observation.privacy_domain_id=$2
      and observation.runtime_target_id=$3 and observation.capsule_digest=any($4::text[])
     order by observation.capsule_digest`,
    [scope.participantId, scope.privacyDomainId, source.targetRuntimeId, capsules],
  );
  if (
    activated.rows.length !== capsules.length ||
    new Set(activated.rows.map((row) => row.capsule_digest)).size !== capsules.length
  )
    throw new EvidenceCustodyError('INTEGRITY');
  const verification = core(
    'VerifyActivations',
    {
      target_runtime_id: source.targetRuntimeId,
      signer_id: source.activationSignerId,
      public_key_file: source.activationPublicKeyFile,
      receipts: Object.fromEntries(
        activated.rows.map((row) => [row.capsule_digest.slice(7), row.signed_bytes]),
      ),
      records: records.map((record) => ({
        capsule_digest: record.capsule_digest,
        reserved_at_ns: record.reserved_at_ns,
      })),
    },
    z.strictObject({
      verified: z.literal(true),
      authority: z.literal('NONE'),
      verificationKeyDigest: digest,
    }),
  );
  return records.map((record, index) => {
    const bytes = Buffer.from(record.source_bytes);
    if (
      record.sequence !== String(after + index + 1) ||
      sha256(bytes) !== `sha256:${record.source_digest}`
    )
      throw new EvidenceCustodyError('INTEGRITY');
    const occurred = BigInt(record.occurred_at_ns);
    const occurredAt = `${new Date(Number(occurred / 1000000n)).toISOString().slice(0, 19)}.${String((occurred % 1000000000n) / 1000n).padStart(6, '0')}Z`;
    const activation = activated.rows.find(
      (row) => row.capsule_digest === `sha256:${record.capsule_digest}`,
    )!;
    const {
      signed_bytes,
      operationId,
      attemptId,
      configurationWorkId,
      generationId,
      generationDigest,
    } = activation;
    const binding = { operationId, attemptId, configurationWorkId, generationId, generationDigest };
    if (!/^[0-9a-f]+$/u.test(signed_bytes) || signed_bytes.length % 2 !== 0)
      throw new EvidenceCustodyError('INTEGRITY');
    const provenance = rpcProvenance.parse({
      integrity: 'AEAD_CHAIN_VERIFIED_AT_CUSTODY',
      activationIntegrity: 'ACTIVATION_COSE_VERIFIED_AT_CUSTODY',
      authority: 'NONE',
      currentAuthority: 'NOT_ESTABLISHED',
      providerEffect: 'NOT_ESTABLISHED',
      chainFinality: 'NOT_ESTABLISHED',
      decisionId: record.decision_id,
      targetRuntimeId: source.targetRuntimeId,
      spoolId: source.spoolId,
      sourceSequence: record.sequence,
      sourceDigest: `sha256:${record.source_digest}`,
      capsuleDigest: activation.capsule_digest,
      reservedAtNs: record.reserved_at_ns,
      occurredAtNs: record.occurred_at_ns,
      transition: record.provenance,
      activation: {
        ...binding,
        receiptDigest: sha256(Buffer.from(signed_bytes, 'hex')),
        signerId: source.activationSignerId,
        verificationKeyDigest: `sha256:${verification.verificationKeyDigest}`,
      },
    });
    return {
      provenance,
      source: {
        recordId: `rpc:${sha256([source.targetRuntimeId, source.spoolId]).slice(7)}:${record.sequence}`,
        evidenceClass: 'EFFECT',
        sourceFormat: RPC_EVIDENCE_FORMAT,
        occurredAt,
        receiptDigest: `sha256:${record.source_digest}`,
        receiptBase64: bytes.toString('base64'),
      },
    };
  });
}

export async function readRpcEvidenceSources(
  client: PoolClient,
  scope: EvidenceScope,
  input: RpcEvidenceSource,
): Promise<SourceReceipt[]> {
  return (await readRpcEvidenceBatch(client, scope, input)).map((row) => row.source);
}
