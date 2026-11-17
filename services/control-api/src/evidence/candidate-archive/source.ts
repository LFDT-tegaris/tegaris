import { execFile } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../../configuration/digest.js';
import { lockEvidenceLifecycle } from '../lifecycle-fence.js';
import { LocalEvidenceVault } from '../local-vault.js';
import { readArchivedSourceRecords as originals } from '../archive-source-readback.js';
import {
  digest,
  sequence,
  evidenceScope,
  EvidenceCustodyError,
  type EvidenceScope,
  type SourceReceipt,
} from '../segment.js';
import {
  candidateArchiveRequest,
  candidateArchiveManifest,
  candidateManifestRecordId,
  parseCandidateArchiveSource,
  prepareCandidateArchive,
  reconstructCandidateArchive,
  type CandidateArchiveManifest,
  type PreparedCandidateArchive,
} from './contract.js';

export const candidateArchiveSource = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  sourceProfileId: z.uuidv7(),
  configurationFile: z.string().refine(isAbsolute),
});
export type CandidateArchiveSource = z.infer<typeof candidateArchiveSource>;
export type CandidateArchiveKeyResolver = (keyId: string) => Promise<Buffer>;

/** Configuration and executable are installed service inputs. Public requests
 * cannot choose them. Native output is scoped again before any bytes are admitted. */
export async function readCandidateArchiveSource(
  configuration: CandidateArchiveSource,
  input: z.infer<typeof candidateArchiveRequest>,
) {
  const config = candidateArchiveSource.parse(configuration),
    request = candidateArchiveRequest.parse(input);
  if (
    config.participantId !== request.participantId ||
    config.privacyDomainId !== request.privacyDomainId ||
    config.sourceProfileId !== request.sourceProfileId
  )
    throw new EvidenceCustodyError('INTEGRITY');
  const executable =
    process.env.OPENPC_CANDIDATE_ARCHIVE_READER_BIN ??
    fileURLToPath(new URL('../../../../../target/debug/candidate_archive_reader', import.meta.url));
  const bytes = await new Promise<Buffer>((resolve, reject) => {
    const child = execFile(
      executable,
      [],
      {
        env: {
          ...process.env,
          OPENPC_CANDIDATE_ARCHIVE_CONFIGURATION_FILE: config.configurationFile,
        },
        timeout: 16000,
        maxBuffer: 2_200_000,
        encoding: 'buffer',
      },
      (error, stdout) =>
        error ? reject(new EvidenceCustodyError('UNAVAILABLE')) : resolve(stdout),
    );
    child.stdin?.on('error', () => reject(new EvidenceCustodyError('UNAVAILABLE')));
    if (!child.stdin) reject(new EvidenceCustodyError('UNAVAILABLE'));
    else child.stdin.end(JSON.stringify(request));
  });
  const result = parseCandidateArchiveSource(bytes, request);
  try {
    return prepareCandidateArchive(result.identity, result.payload);
  } finally {
    result.payload.fill(0);
  }
}

function bind(scopeInput: EvidenceScope, input: CandidateArchiveManifest) {
  const scope = evidenceScope.parse(scopeInput),
    manifest = candidateArchiveManifest.parse(input);
  if (
    scope.participantId !== manifest.identity.participantId ||
    scope.privacyDomainId !== manifest.identity.privacyDomainId
  )
    throw new EvidenceCustodyError('INTEGRITY');
  return { scope, manifest, recordId: candidateManifestRecordId(manifest.identityDigest) };
}
const values = (scope: EvidenceScope) => [
  scope.participantId,
  scope.privacyDomainId,
  scope.streamId,
];

/** Existing EvidenceCustody.admitSource integration hook. Call inside its
 * lifecycle + stream transaction; admit one returned batch atomically and call
 * retainCandidateArchive after admission. No durable cursor can skip a hole. */
export async function nextCandidateArchiveRecords(
  client: PoolClient,
  scopeInput: EvidenceScope,
  prepared: PreparedCandidateArchive,
  resolveKey: CandidateArchiveKeyResolver,
): Promise<readonly SourceReceipt[]> {
  const { scope, manifest } = bind(scopeInput, prepared.manifest);
  const payload = reconstructCandidateArchive(manifest, prepared.batches.flat());
  let checked: PreparedCandidateArchive;
  try {
    checked = prepareCandidateArchive(manifest.identity, payload);
  } finally {
    payload.fill(0);
  }
  await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
  const all = checked.batches.flat();
  const retired = await client.query(
    `select 1 from control.evidence_projection_retirement where participant_id=$1 and privacy_domain_id=$2
     and stream_id=$3 and data_class='SEARCH_PROJECTION' and record_id=any($4::text[]) limit 1`,
    [...values(scope), all.map((record) => record.recordId)],
  );
  if (retired.rowCount) throw new EvidenceCustodyError('CONFLICT');
  const retained = await originals(
    client,
    scope,
    all.map((record) => record.recordId),
    resolveKey,
  );
  let pending: SourceReceipt[] | undefined;
  for (const batch of checked.batches) {
    const count = batch.filter((record) => retained.has(record.recordId)).length;
    if (count !== 0 && (count !== batch.length || pending))
      throw new EvidenceCustodyError('INTEGRITY');
    if (count === 0) {
      pending ??= batch;
      continue;
    }
    if (
      batch.some((record) => canonicalJson(retained.get(record.recordId)) !== canonicalJson(record))
    )
      throw new EvidenceCustodyError('INTEGRITY');
  }
  return pending ?? [];
}

/** A metadata row is not archive completion. The guard requires all local
 * chunk/manifest bytes, then atomically indexes every catalogue reference. */
export async function retainCandidateArchive(
  client: PoolClient,
  scopeInput: EvidenceScope,
  input: CandidateArchiveManifest,
  resolveKey: CandidateArchiveKeyResolver,
) {
  const { scope, manifest, recordId } = bind(scopeInput, input);
  await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
  const ids = [...manifest.chunks.map((chunk) => chunk.recordId), recordId];
  const found = await originals(client, scope, ids, resolveKey);
  if (found.size !== ids.length) return false;
  const payload = reconstructCandidateArchive(
    manifest,
    ids.map((id) => found.get(id)!),
  );
  payload.fill(0);
  await client.query(
    `insert into control.evidence_candidate_archive(participant_id,privacy_domain_id,stream_id,record_id,candidate_id,manifest,manifest_digest)
     values($1,$2,$3,$4,$5,$6,$7) on conflict do nothing`,
    [...values(scope), recordId, manifest.identity.candidateId, manifest, sha256(manifest)],
  );
  const existing = await client.query<{ manifest: unknown; manifest_digest: string }>(
    `select manifest,manifest_digest from control.evidence_candidate_archive
     where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4 and candidate_id=$5`,
    [...values(scope), recordId, manifest.identity.candidateId],
  );
  if (
    existing.rowCount !== 1 ||
    existing.rows[0]!.manifest_digest !== sha256(manifest) ||
    canonicalJson(existing.rows[0]!.manifest) !== canonicalJson(manifest)
  )
    throw new EvidenceCustodyError('CONFLICT');
  return true;
}

const coverage = z.discriminatedUnion('state', [
  z.strictObject({
    state: z.literal('PENDING'),
    authority: z.literal('NONE'),
    manifestDigest: digest,
  }),
  z.strictObject({
    state: z.literal('COMPLETE'),
    authority: z.literal('NONE'),
    manifestDigest: digest,
    segments: z
      .array(
        z.strictObject({
          segmentId: z.uuid(),
          objectDigest: digest,
          firstSequence: sequence,
          throughSequence: sequence,
          sinkReceipts: z
            .array(
              z.strictObject({
                sinkId: z.string().min(1).max(160),
                checkpointDigest: digest,
                receiptDigest: digest,
              }),
            )
            .min(1)
            .max(8),
        }),
      )
      .min(1)
      .max(17),
  }),
]);
/** Required sinks come from the installed/governed archive owner, never a
 * caller's custody claim. All segments and current hold revisions are required. */
export async function readCandidateArchiveCoverage(
  client: PoolClient,
  scopeInput: EvidenceScope,
  input: CandidateArchiveManifest,
  requiredSinkIds: readonly string[],
) {
  const { scope, manifest, recordId } = bind(scopeInput, input);
  const sinks = z
    .array(z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u))
    .min(1)
    .max(8)
    .parse(requiredSinkIds);
  if (new Set(sinks).size !== sinks.length) throw new EvidenceCustodyError('INVALID');
  await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
  const result = await client.query<{ value: unknown }>(
    'select openpc.candidate_archive_coverage($1,$2,$3,$4,$5) value',
    [...values(scope), recordId, sinks],
  );
  const parsed = coverage.parse(result.rows[0]?.value);
  if (parsed.manifestDigest !== sha256(manifest)) throw new EvidenceCustodyError('INTEGRITY');
  return parsed;
}

/** Restore/readback of original archived bytes; never re-acquire a candidate or
 * resurrect a native payload. Remote callers use their existing exact-version
 * reader and reconstructCandidateArchive with the same manifest contract. */
export async function readArchivedCandidatePayload(
  client: PoolClient,
  scopeInput: EvidenceScope,
  input: CandidateArchiveManifest,
  sink: LocalEvidenceVault,
  resolveKey: CandidateArchiveKeyResolver,
) {
  const { scope, manifest, recordId } = bind(scopeInput, input);
  const status = await readCandidateArchiveCoverage(client, scope, manifest, [sink.sinkId]);
  if (status.state !== 'COMPLETE') throw new EvidenceCustodyError('UNAVAILABLE');
  const ids = [...manifest.chunks.map((chunk) => chunk.recordId), recordId];
  const records = await originals(client, scope, ids, resolveKey, sink);
  if (records.size !== ids.length) throw new EvidenceCustodyError('INTEGRITY');
  return reconstructCandidateArchive(
    manifest,
    ids.map((id) => records.get(id)!),
  );
}
