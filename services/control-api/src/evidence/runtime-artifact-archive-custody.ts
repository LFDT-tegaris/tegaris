import type { PoolClient } from 'pg';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { readArchivedSourceRecords, type ArchiveKeyResolver } from './archive-source-readback.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import {
  evidenceScope,
  EvidenceCustodyError,
  type EvidenceScope,
  type SourceReceipt,
} from './segment.js';
import {
  prepareRuntimeArtifactArchive,
  reconstructRuntimeArtifactArchive,
  runtimeArtifactArchiveManifest,
  runtimeArtifactManifestRecordId,
  type RuntimeArtifactArchiveManifest,
} from './runtime-artifact-archive-contract.js';

type Prepared = ReturnType<typeof prepareRuntimeArtifactArchive>;
const values = (scope: EvidenceScope) => [
  scope.participantId,
  scope.privacyDomainId,
  scope.streamId,
];
function bind(scopeInput: EvidenceScope, value: RuntimeArtifactArchiveManifest) {
  const scope = evidenceScope.parse(scopeInput),
    manifest = runtimeArtifactArchiveManifest.parse(value);
  if (
    scope.participantId !== manifest.identity.participantId ||
    scope.privacyDomainId !== manifest.identity.privacyDomainId
  )
    throw new EvidenceCustodyError('INTEGRITY');
  return { scope, manifest, recordId: runtimeArtifactManifestRecordId(manifest.identityDigest) };
}

/** Within the existing custody transaction, return the first wholly absent
 * group. Retained bytes, partial groups and gaps are checked before progress.
 * A caller's packet remains data; the final SQL owner rechecks the native row. */
export async function nextRuntimeArtifactArchiveRecords(
  client: PoolClient,
  scopeInput: EvidenceScope,
  prepared: Prepared,
  resolveKey: ArchiveKeyResolver,
): Promise<readonly SourceReceipt[]> {
  const { scope, manifest } = bind(scopeInput, prepared.manifest);
  const { payload } = reconstructRuntimeArtifactArchive(manifest.identity, prepared.groups.flat());
  let checked: Prepared;
  try {
    checked = prepareRuntimeArtifactArchive(manifest.identity, payload);
  } finally {
    payload.fill(0);
  }
  await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
  const all = checked.groups.flat();
  const retired = await client.query(
    `select 1 from control.evidence_projection_retirement where participant_id=$1 and privacy_domain_id=$2
     and stream_id=$3 and data_class='SEARCH_PROJECTION' and record_id=any($4::text[]) limit 1`,
    [...values(scope), all.map((record) => record.recordId)],
  );
  if (retired.rowCount) throw new EvidenceCustodyError('CONFLICT');
  const retained = await readArchivedSourceRecords(
    client,
    scope,
    all.map((record) => record.recordId),
    resolveKey,
  );
  let pending: SourceReceipt[] | undefined;
  for (const group of checked.groups) {
    const count = group.filter((record) => retained.has(record.recordId)).length;
    if (count !== 0 && (count !== group.length || pending))
      throw new EvidenceCustodyError('INTEGRITY');
    if (count === 0) {
      pending ??= group;
      continue;
    }
    if (
      group.some((record) => canonicalJson(retained.get(record.recordId)) !== canonicalJson(record))
    )
      throw new EvidenceCustodyError('INTEGRITY');
  }
  return pending ?? [];
}

/** Index only a complete reconstructed archive. Every record retains an actual
 * catalogue foreign key. This is custody metadata, never deletion or serving authority. */
export async function retainRuntimeArtifactArchive(
  client: PoolClient,
  scopeInput: EvidenceScope,
  value: RuntimeArtifactArchiveManifest,
  resolveKey: ArchiveKeyResolver,
  pendingOriginal?: Buffer,
) {
  const { scope, manifest, recordId } = bind(scopeInput, value);
  await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
  const ids = [...manifest.chunks.map((chunk) => chunk.recordId), recordId];
  const found = await readArchivedSourceRecords(client, scope, ids, resolveKey);
  if (found.size !== ids.length) return false;
  reconstructRuntimeArtifactArchive(
    manifest.identity,
    ids.map((id) => found.get(id)!),
  ).payload.fill(0);
  await client.query(
    `insert into control.evidence_runtime_artifact_archive(participant_id,privacy_domain_id,stream_id,record_id,
     runtime_configuration_input_id,manifest,manifest_digest,source_pending_original) values($1,$2,$3,$4,$5,$6,$7,$8) on conflict do nothing`,
    [
      ...values(scope),
      recordId,
      manifest.identity.runtimeConfigurationInputId,
      manifest,
      sha256(manifest),
      pendingOriginal ?? null,
    ],
  );
  const existing = await client.query<{ manifest: unknown; manifest_digest: string }>(
    `select manifest,manifest_digest from control.evidence_runtime_artifact_archive where participant_id=$1
     and privacy_domain_id=$2 and stream_id=$3 and record_id=$4 and runtime_configuration_input_id=$5`,
    [...values(scope), recordId, manifest.identity.runtimeConfigurationInputId],
  );
  if (
    existing.rowCount !== 1 ||
    existing.rows[0]!.manifest_digest !== sha256(manifest) ||
    canonicalJson(existing.rows[0]!.manifest) !== canonicalJson(manifest)
  )
    throw new EvidenceCustodyError('CONFLICT');
  return true;
}

/** Read only the complete original group. This is custody verification and does
 * not issue source-read authority or append native completion. */
export async function verifyRuntimeArtifactArchiveReadback(
  client: PoolClient,
  scopeInput: EvidenceScope,
  value: unknown,
  resolveKey: ArchiveKeyResolver,
) {
  const manifest = runtimeArtifactArchiveManifest.parse(value);
  const { scope, recordId } = bind(scopeInput, manifest);
  const ids = [...manifest.chunks.map((chunk) => chunk.recordId), recordId];
  const found = await readArchivedSourceRecords(client, scope, ids, resolveKey);
  if (found.size !== ids.length) throw new EvidenceCustodyError('INTEGRITY');
  reconstructRuntimeArtifactArchive(
    manifest.identity,
    ids.map((id) => found.get(id)!),
  ).payload.fill(0);
}
