import { readFileSync, statSync } from 'node:fs';
import { z } from 'zod';
import type { PoolClient } from 'pg';
import { configurationCoreCommand } from '../core-command.js';
import { ConfigurationRepositoryError } from '../persistence/types.js';
import { ciglProfileReadbackSchema, verifiedCiglProfileSchema } from './profile-contract.js';
import { digestSchema } from '../resource-contracts.js';
import { readPublicationSources } from './publication-sources.js';

interface ProfileRow {
  profile_id: string;
  revision: string;
  state: 'PENDING' | 'COMPILED';
  work_state: string;
  profile_cbor: Buffer | null;
  compilation_receipt: Buffer | null;
  expected: Record<string, unknown>;
  result_receipt: { compilationReceiptDigest?: string } | null;
  compiled_at: string | null;
}

/** Historical compilation proves no current activation. Reverify the exact
 * artifact and retained sources against current deployment-owned signer trust. */
export async function readCiglProfile(
  client: PoolClient,
  analysisId: string,
  participant: string,
  privacy: string,
  includeCurrentSources = false,
) {
  const selected = await client.query<ProfileRow>(
    `select version.profile_id::text,version.revision::text,version.state,
    work.state work_state,version.profile_cbor,version.compilation_receipt,version.compiled_at::text,work.result_receipt,
    jsonb_build_object('schemaVersion','1.0','configurationWorkId',work.configuration_work_id::text,
      'operationId',work.operation_id::text,'analysisId',job.analysis_id::text,'profileId',version.profile_id::text,
      'profileRevision',version.revision::text,'participantId',job.participant_id::text,'privacyDomainId',job.privacy_domain_id::text,
      'targetRuntimeId',job.runtime_target_id::text,'capsuleDigest',substring(job.capsule_digest from 8),
      'reviewDigest',substring(version.review_digest from 8),'analysisDigest',substring(job.analysis_digest from 8),
      'policyGenerationDigest',substring(job.policy_generation_digest from 8),'profileDigest',substring(version.profile_digest from 8),
      'dependencyPathsDigest',substring(version.dependency_paths_digest from 8),
      'artifactDigest',substring(version.artifact_digest from 8),'compiledAtMs',floor(extract(epoch from version.compiled_at)*1000),
      'signerId',version.compilation_signer_id) expected
    from control.cigl_profile_version version
    join control.cigl_analysis job on job.analysis_id=version.analysis_id and job.participant_id=version.participant_id and job.privacy_domain_id=version.privacy_domain_id
    join control.configuration_work work on work.configuration_work_id=version.configuration_work_id and work.participant_id=version.participant_id and work.privacy_domain_id=version.privacy_domain_id
    where version.analysis_id=$1 and version.participant_id=$2 and version.privacy_domain_id=$3`,
    [analysisId, participant, privacy],
  );
  if (selected.rowCount === 0) return undefined;
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw new ConfigurationRepositoryError('PC-FACT-4001');
  let result = null;
  let currentSources = null;
  if (row.state === 'COMPILED') {
    try {
      if (row.work_state !== 'COMPLETED' || !row.profile_cbor || !row.compilation_receipt)
        throw new Error('incomplete compilation');
      const path = process.env.OPENPC_CIGL_PROFILE_PUBLIC_KEY_FILE;
      if (!path || statSync(path).size > 1024) throw new Error('missing signer trust');
      const key = readFileSync(path, 'utf8').trim();
      if (!/^(02|03)[0-9a-f]{64}$/u.test(key)) throw new Error('invalid signer trust');
      const parameters = [row.profile_id, row.revision, participant, privacy];
      const methods = await client.query<{ source: unknown }>(
        `select jsonb_build_object(
        'methodId',contract_method_policy_id::text,'runtimeBindingId',runtime_binding_id::text,
        'methodRevision',method_revision::text,'bindingRevision',binding_revision::text) source
        from control.cigl_profile_method_source where profile_id=$1 and profile_revision=$2 and participant_id=$3 and privacy_domain_id=$4
        order by contract_method_policy_id limit 2050`,
        parameters,
      );
      const grants = await client.query<{ source: unknown }>(
        `select jsonb_build_object(
        'grantId',grant_id::text,'revision',grant_revision::text,'digest',substring(grant_digest from 8)) source
        from control.cigl_profile_grant_source where profile_id=$1 and profile_revision=$2 and participant_id=$3 and privacy_domain_id=$4
        order by grant_id limit 4097`,
        parameters,
      );
      const dependencies = await client.query<{ document: unknown }>(
        `select document from control.cigl_profile_dependency_path where profile_id=$1 and profile_revision=$2 and participant_id=$3 and privacy_domain_id=$4 order by ordinal limit 2049`,
        parameters,
      );
      const publication = includeCurrentSources
        ? await readPublicationSources(client, row.profile_id, row.revision, participant, privacy)
        : null;
      const { currentGrantSourcesDigest, ...verified } = z
        .strictObject({
          ...verifiedCiglProfileSchema.shape,
          currentGrantSourcesDigest: digestSchema.nullable(),
        })
        .parse(
          configurationCoreCommand('READ_CIGL_PROFILE', {
            signedBytes: `0x${row.compilation_receipt.toString('hex')}`,
            profileBytes: `0x${row.profile_cbor.toString('hex')}`,
            verificationKey: `0x${key}`,
            expected: row.expected,
            methods: methods.rows.map((m) => m.source),
            grants: grants.rows.map((g) => g.source),
            dependencies: dependencies.rows.map((p) => p.document),
            ...(publication === null ? {} : { currentGrants: publication.grants }),
          }),
        );
      result = verifiedCiglProfileSchema.parse(verified);
      if (publication !== null && currentGrantSourcesDigest !== null) {
        currentSources = {
          targetRuntimeId: `urn:openpc:resource:${publication.target.target_id}`,
          targetRevision: publication.target.target_revision,
          installedCapsuleDigest: publication.target.capsule_digest,
          participantEpoch: publication.target.participant_epoch,
          grantSourcesDigest: currentGrantSourcesDigest,
        };
      }
      if (row.result_receipt?.compilationReceiptDigest !== result.receiptDigest)
        throw new Error('work receipt mismatch');
    } catch {
      throw new ConfigurationRepositoryError('PC-FACT-4001');
    }
  } else if (!['PENDING', 'LEASED', 'FAILED'].includes(row.work_state))
    throw new ConfigurationRepositoryError('PC-FACT-4001');
  return ciglProfileReadbackSchema.parse({
    profileId: `urn:openpc:resource:${row.profile_id}`,
    revision: row.revision,
    state:
      row.state === 'COMPILED'
        ? 'COMPILED'
        : row.work_state === 'LEASED'
          ? 'RUNNING'
          : row.work_state,
    runtimePermission: 'NONE',
    compiledAt: row.compiled_at === null ? null : new Date(row.compiled_at).toISOString(),
    result,
    currentSources,
  });
}
