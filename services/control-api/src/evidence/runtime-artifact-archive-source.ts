import type { PoolClient } from 'pg';
import { z } from 'zod';
import {
  authorizeRuntimeArtifactRead,
  authorizeRuntimeArtifactArchiveRead,
} from '../../../module-registry/src/db/runtime-artifact-materialization.js';
import { sha256 } from '../configuration/digest.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { EvidenceCustodyError } from './segment.js';
import {
  prepareRuntimeArtifactArchive,
  runtimeArtifactArchiveIdentity,
} from './runtime-artifact-archive-contract.js';

export const runtimeArtifactArchiveRequest = runtimeArtifactArchiveIdentity.pick({
  participantId: true,
  privacyDomainId: true,
  runtimeConfigurationInputId: true,
});
type SourceRow = {
  identity: unknown;
  payload: Buffer;
  resource_bindings: unknown;
};

/** Native historical source read inside the existing custody transaction.
 * Request fields are locators only. The original immutable database row supplies
 * every archive identity field and the complete bytes. This does not publish
 * custody, release references, establish sink coverage or authorize retirement.
 */
export async function readRuntimeArtifactArchiveSource(
  client: PoolClient,
  input: z.infer<typeof runtimeArtifactArchiveRequest>,
  streamId?: string,
) {
  const request = runtimeArtifactArchiveRequest.parse(input);
  const context = await client.query<{ admitted: boolean }>(
    `select openpc.current_participant_id()=$1::uuid
      and openpc.current_privacy_domain_id()=$2::uuid
      and openpc.current_action_intent_id()='ACT-EVIDENCE_EXPORT_RECORDS-V1'
      and current_setting('row_security')='on'
      and current_setting('transaction_isolation')='read committed'
      and current_setting('session_replication_role')='origin'
      and (pg_has_role(current_user,'openpc_control_runtime','USAGE')
        or pg_has_role(current_user,'openpc_control_worker','USAGE'))
      and exists(select 1 from pg_roles where rolname=current_user and not rolsuper and not rolbypassrls)
      admitted`,
    [request.participantId, request.privacyDomainId],
  );
  if (context.rowCount !== 1 || context.rows[0]?.admitted !== true)
    throw new EvidenceCustodyError('INTEGRITY');
  await client.query('select openpc.assert_request_context(true)');
  await lockEvidenceLifecycle(client, request.participantId, request.privacyDomainId);
  const installed = await client.query<{ rooted: boolean }>(
    "select (openpc.runtime_artifact_materialization_source()).custody_root->>'consumer_profile'='openpc:local-runtime-source-consumers:v2' rooted",
  );
  const rooted = installed.rows[0]?.rooted === true;
  if (rooted) {
    if (!streamId) throw new EvidenceCustodyError('INTEGRITY');
    await authorizeRuntimeArtifactArchiveRead(
      client,
      request.runtimeConfigurationInputId,
      streamId,
    );
  } else await authorizeRuntimeArtifactRead(client, request.runtimeConfigurationInputId);
  const result = await client.query<SourceRow>(
    `select jsonb_build_object('participantId',participant_id::text,
      'privacyDomainId',privacy_domain_id::text,'runtimeConfigurationInputId',runtime_configuration_input_id::text,
      'moduleInstallationId',module_installation_id::text,
      'moduleConfigurationGenerationId',module_configuration_generation_id::text,
      'configurationDigest','sha256:'||encode(configuration_digest,'hex'),
      'configurationBytes',(openpc.runtime_artifact_input_information(runtime_configuration_input_id)->>'byteLength')::integer,
      'createdAt',to_char(created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) identity,
      ${rooted ? 'openpc.runtime_artifact_archive_payload(runtime_configuration_input_id,$4::text)' : 'openpc.runtime_artifact_input_payload(runtime_configuration_input_id)'} payload,resource_bindings
     from control.runtime_configuration_input where participant_id=$1 and privacy_domain_id=$2
      and runtime_configuration_input_id=$3 for share`,
    [
      request.participantId,
      request.privacyDomainId,
      request.runtimeConfigurationInputId,
      ...(rooted ? [streamId] : []),
    ],
  );
  if (result.rowCount !== 1) throw new EvidenceCustodyError('UNAVAILABLE');
  const row = result.rows[0]!;
  try {
    const fields = z.record(z.string(), z.unknown()).parse(row.identity);
    const identity = runtimeArtifactArchiveIdentity.parse({
      ...fields,
      resourceBindingsDigest: sha256(row.resource_bindings),
    });
    if (
      identity.participantId !== request.participantId ||
      identity.privacyDomainId !== request.privacyDomainId ||
      identity.runtimeConfigurationInputId !== request.runtimeConfigurationInputId
    )
      throw new EvidenceCustodyError('INTEGRITY');
    const pending = rooted
      ? await client.query<{ original: Buffer }>(
          "select decode(openpc.runtime_artifact_archive_permit($1::uuid,$2::text)->>'original','hex') original",
          [request.runtimeConfigurationInputId, streamId],
        )
      : undefined;
    if (rooted && pending?.rowCount !== 1) throw new EvidenceCustodyError('INTEGRITY');
    return {
      ...prepareRuntimeArtifactArchive(identity, row.payload),
      pendingOriginal: pending?.rows[0]?.original,
    };
  } finally {
    // Packaging owns independent encoded strings; do not retain the raw source
    // buffer alongside them in the database driver's result object.
    if (Buffer.isBuffer(row.payload)) row.payload.fill(0);
  }
}
