import type { PoolClient } from 'pg';
import { z } from 'zod';
import { ConfigurationRepositoryError, type MutationContext } from '../persistence/types.js';
import { configurationCoreCommand } from '../core-command.js';
import { digestSchema } from '../resource-contracts.js';
import { readCiglProfile } from './profile-readback.js';
import { ciglGrantDefinitionSchema, type CiglGrantDefinition } from './grant-contract.js';
import type { CiglDependencyBundle } from './dependency-contract.js';
import { ciglDependencyClaimSchema } from './dependency-contract.js';
import { selectPage, type ListRequest } from '../pagination.js';

export async function readCiglDependencies(client: PoolClient, request: ListRequest) {
  const result = await selectPage(client, request, {
    table: `(select claim.*,coalesce(claim.released_at,claim.created_at) updated_at,path.document path,required.origin required_origin,version.analysis_id
      from control.cigl_method_grant_dependency_claims claim
      join control.cigl_profile_dependency_path path on path.profile_id=claim.profile_id and path.profile_revision=claim.profile_revision and path.ordinal=claim.ordinal
      join control.cigl_profile_version version on version.profile_id=claim.profile_id and version.revision=claim.profile_revision
      join control.cigl_method_access_grants required on required.grant_id=claim.required_grant_id) dependency`,
    idColumn: 'claim_id',
    projection: `claim_id::text,analysis_id::text,participant_id::text,privacy_domain_id::text,updated_at::text,
      jsonb_build_object('claimId','urn:openpc:resource:'||claim_id::text,'sourceGrantId','urn:openpc:resource:'||source_grant_id::text,
       'sourceGrantRevision',source_grant_revision::text,'requiredGrantId','urn:openpc:resource:'||required_grant_id::text,'requiredGrantRevision',required_grant_revision::text,
       'profileId','urn:openpc:resource:'||profile_id::text,'profileRevision',profile_revision::text,'capability',capability,'graphDigest',graph_digest,
       'policyGenerationDigest',policy_generation_digest,'participantEpoch',participant_epoch::text,'state',state,'ownership','UPSTREAM_SOURCE_GRANT',
       'requiredGrantOrigin',required_origin,'path',path,'createdAt',created_at,'releasedAt',released_at) document`,
    filterColumns: {
      state: 'state',
      sourceGrantId: "'urn:openpc:resource:'||source_grant_id::text",
      requiredGrantId: "'urn:openpc:resource:'||required_grant_id::text",
      profileId: "'urn:openpc:resource:'||profile_id::text",
    },
    rowId: (row: {
      claim_id: string;
      analysis_id: string;
      participant_id: string;
      privacy_domain_id: string;
      updated_at: string;
      document: Record<string, unknown>;
    }) => row.claim_id,
    rowUpdatedAt: (row) => new Date(row.updated_at).toISOString(),
    map: (row) => row,
  });
  const checked = new Set<string>();
  for (const row of result.items) {
    if (!checked.has(row.analysis_id)) {
      const verified = await readCiglProfile(
        client,
        row.analysis_id,
        row.participant_id,
        row.privacy_domain_id,
      );
      if (!verified?.result?.dependencyPaths)
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      checked.add(row.analysis_id);
    }
  }
  return {
    ...result,
    items: result.items.map(({ document }) =>
      ciglDependencyClaimSchema.parse({
        ...document,
        createdAt: new Date(String(document.createdAt)).toISOString(),
        releasedAt:
          document.releasedAt === null ? null : new Date(String(document.releasedAt)).toISOString(),
      }),
    ),
  };
}

const resourceId = (urn: string) => urn.slice('urn:openpc:resource:'.length);
type Grant = {
  grant_id: string;
  definition: CiglGrantDefinition;
  revision: string;
  status: 'ACTIVE' | 'DISABLED';
  binding_revision: string;
  method_revision: string;
  grant_digest: string;
};
const coreGrant = (grant: Grant) => ({
  grantId: grant.grant_id,
  ...grant.definition,
  runtimeBindingId: resourceId(grant.definition.runtimeBindingId),
  selector: [...Buffer.from(grant.definition.selector.slice(2), 'hex')],
  status: grant.status,
});

/** Runs in the same independently approved source-grant mutation and shared
 * grant fence. This only imports nested authority; activation has its own owner. */
export async function materializeCiglDependencies(
  client: PoolClient,
  context: MutationContext,
  sourceGrantId: string,
  operationId: string,
  bundle: CiglDependencyBundle,
) {
  const participant = context.authorization.participantId;
  const privacy = context.authorization.privacyDomainId;
  const profileId = resourceId(bundle.profileId);
  const source = (
    await client.query<Grant>(
      `select grant_id::text,definition,revision::text,status,binding_revision::text,method_revision::text,grant_digest
    from control.cigl_method_access_grants where grant_id=$1 and participant_id=$2 and privacy_domain_id=$3 and publication_operation_id=$4 and status='ACTIVE' and origin='SHARED'`,
      [sourceGrantId, participant, privacy, operationId],
    )
  ).rows[0];
  if (!source) throw new ConfigurationRepositoryError('PC-AUTH-0005');
  source.definition = ciglGrantDefinitionSchema.parse(source.definition);
  const version = await client.query<{ analysis_id: string }>(
    `select version.analysis_id::text from control.cigl_profile_version version
    join control.cigl_analysis analysis on analysis.analysis_id=version.analysis_id and analysis.participant_id=version.participant_id and analysis.privacy_domain_id=version.privacy_domain_id
    join control.runtime_target target on target.runtime_target_id=analysis.runtime_target_id and target.participant_id=analysis.participant_id and target.privacy_domain_id=analysis.privacy_domain_id
    join control.contract_method_policy method on method.contract_method_policy_id=analysis.contract_method_policy_id and method.participant_id=analysis.participant_id and method.privacy_domain_id=analysis.privacy_domain_id
    join control.participant participant on participant.participant_id=analysis.participant_id
    where version.profile_id=$1 and version.revision=$2 and version.participant_id=$3 and version.privacy_domain_id=$4 and version.state='COMPILED'
      and version.profile_digest=$5 and analysis.analysis_digest=$6 and analysis.policy_generation_digest=$7
      and target.policy_generation_digest=$7 and target.active_generation_digest=analysis.definition->>'expectedGenerationDigest'
      and target.active_generation_digest=target.desired_generation_digest and target.state='ACTIVE_MATCHED'
      and participant.state='ACTIVE' and participant.archived_at is null and participant.authority_epoch=$8
      and method.runtime_binding_id=$9 and method.selector=$10 and method.revision=$11 and method.state='ACTIVE'
      and ((method.effect='READ' and $12='SIMULATE_CALL') or (method.effect='WRITE' and $12='EXECUTE_TRANSACTION'))
      and not exists(select 1 from control.cigl_profile_method_source retained
        left join control.contract_method_policy live on live.contract_method_policy_id=retained.contract_method_policy_id and live.participant_id=retained.participant_id and live.privacy_domain_id=retained.privacy_domain_id
        left join control.contract_runtime_binding binding on binding.runtime_binding_id=retained.runtime_binding_id and binding.participant_id=retained.participant_id and binding.privacy_domain_id=retained.privacy_domain_id
        where retained.profile_id=version.profile_id and retained.profile_revision=version.revision
          and (live.contract_method_policy_id is null or live.state<>'ACTIVE' or live.revision<>retained.method_revision or binding.runtime_binding_id is null or binding.state<>'BOUND' or binding.revision<>retained.binding_revision))
    for share of target,method,participant`,
    [
      profileId,
      bundle.profileRevision,
      participant,
      privacy,
      bundle.profileDigest,
      bundle.graphDigest,
      bundle.policyGenerationDigest,
      bundle.participantEpoch,
      resourceId(source.definition.runtimeBindingId),
      source.definition.selector,
      source.method_revision,
      bundle.capability,
    ],
  );
  if (version.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
  const verified = await readCiglProfile(
    client,
    version.rows[0]!.analysis_id,
    participant,
    privacy,
  );
  const paths = verified?.result?.dependencyPaths;
  if (verified?.state !== 'COMPILED' || !paths || paths.length !== bundle.dependencies.length)
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  const methods = await client.query<{
    method_id: string;
    runtime_binding_id: string;
    selector: string;
    method_revision: string;
    binding_revision: string;
  }>(
    `select method.contract_method_policy_id::text method_id,binding.runtime_binding_id::text,method.selector,retained.method_revision::text,retained.binding_revision::text
     from control.cigl_profile_method_source retained join control.contract_method_policy method
      on method.contract_method_policy_id=retained.contract_method_policy_id and method.participant_id=retained.participant_id and method.privacy_domain_id=retained.privacy_domain_id
     join control.contract_runtime_binding binding on binding.runtime_binding_id=retained.runtime_binding_id and binding.participant_id=retained.participant_id and binding.privacy_domain_id=retained.privacy_domain_id
     where retained.profile_id=$1 and retained.profile_revision=$2 and method.state='ACTIVE' and binding.state='BOUND'
      and method.revision=retained.method_revision and binding.revision=retained.binding_revision order by method.contract_method_policy_id for share of method,binding`,
    [profileId, bundle.profileRevision],
  );
  if (methods.rowCount !== verified.result!.methodCount)
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const byMethod = new Map(methods.rows.map((method) => [method.method_id, method]));
  const sourceMethod = methods.rows.find(
    (method) =>
      method.runtime_binding_id === resourceId(source.definition.runtimeBindingId) &&
      method.selector === source.definition.selector,
  );
  if (
    !sourceMethod ||
    sourceMethod.binding_revision !== source.binding_revision ||
    sourceMethod.method_revision !== source.method_revision
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const byAction = new Map(paths.map((path) => [`sha256:${path.actionDigest}`, path]));
  const current = await client.query<Grant>(
    `select grant_row.grant_id::text,grant_row.definition,grant_row.revision::text,grant_row.status,grant_row.binding_revision::text,grant_row.method_revision::text,grant_row.grant_digest
    from control.cigl_method_access_grants grant_row where grant_row.participant_id=$3 and grant_row.privacy_domain_id=$4 and exists(
      select 1 from control.cigl_profile_method_source retained join control.contract_method_policy method on method.contract_method_policy_id=retained.contract_method_policy_id
      where retained.profile_id=$1 and retained.profile_revision=$2 and retained.runtime_binding_id=grant_row.runtime_binding_id and method.selector=grant_row.selector)
    order by grant_row.grant_id limit 4097`,
    [profileId, bundle.profileRevision, participant, privacy],
  );
  const grants = new Map(
    current.rows.map((grant) => [
      grant.grant_id,
      { ...grant, definition: ciglGrantDefinitionSchema.parse(grant.definition) },
    ]),
  );
  const generated = new Map<string, Grant>();
  const selections: {
    ordinal: number;
    actionDigest: string;
    requiredGrantId: string;
    revision: string;
  }[] = [];
  const newIds = (
    await client.query<{ id: string }>(
      'select uuidv7()::text id from generate_series(1,$1::integer)',
      [bundle.dependencies.filter((d) => d.grant.kind === 'GENERATE').length],
    )
  ).rows;
  for (const choice of bundle.dependencies) {
    const path = byAction.get(choice.actionDigest);
    if (!path) throw new ConfigurationRepositoryError('PC-DATA-6004');
    byAction.delete(choice.actionDigest);
    let required: Grant;
    if (choice.grant.kind === 'SHARED') {
      const grant = grants.get(resourceId(choice.grant.grantId));
      if (!grant || grant.revision !== choice.grant.expectedRevision)
        throw new ConfigurationRepositoryError('PC-DATA-6007');
      const method = byMethod.get(path.contractMethodPolicyId);
      if (
        !method ||
        grant.method_revision !== method.method_revision ||
        grant.binding_revision !== method.binding_revision
      )
        throw new ConfigurationRepositoryError('PC-DATA-6007');
      required = grant;
    } else {
      const key = `${path.runtimeBindingId}:${Buffer.from(path.selector).toString('hex')}`;
      let grant = generated.get(key);
      if (!grant) {
        const method = byMethod.get(path.contractMethodPolicyId);
        if (!method) throw new ConfigurationRepositoryError('PC-DATA-6007');
        grant = {
          grant_id: newIds.pop()!.id,
          definition: {
            runtimeBindingId: `urn:openpc:resource:${path.runtimeBindingId}`,
            selector: `0x${Buffer.from(path.selector).toString('hex')}`,
            subject: source.definition.subject,
            surface: source.definition.surface,
            effect: 'ALLOW',
          },
          revision: '1',
          status: 'ACTIVE',
          ...method,
          grant_digest: '',
        };
        generated.set(key, grant);
        grants.set(grant.grant_id, grant);
      }
      required = grant;
    }
    selections.push({
      ordinal: path.ordinal,
      actionDigest: path.actionDigest,
      requiredGrantId: required.grant_id,
      revision: required.revision,
    });
  }
  const validated = z
    .strictObject({
      identity: z.literal('PC-CIGL-DEPENDENCY-BUNDLE-1'),
      authority: z.literal('NONE'),
      grants: z.array(z.strictObject({ grantId: z.uuidv7(), digest: digestSchema })).max(4096),
    })
    .safeParse(
      configurationCoreCommand('VALIDATE_CIGL_DEPENDENCIES', {
        dependencies: paths,
        source: coreGrant(source),
        capability: bundle.capability,
        reviewed: selections.map(({ actionDigest, requiredGrantId }) => ({
          actionDigest,
          requiredGrantId,
        })),
        currentGrants: [...grants.values()].map(coreGrant),
      }),
    );
  if (!validated.success) throw new ConfigurationRepositoryError('PC-DATA-6004');
  const digests = new Map(validated.data.grants.map((grant) => [grant.grantId, grant.digest]));
  for (const grant of grants.values()) {
    if (grant.grant_digest && digests.get(grant.grant_id) !== grant.grant_digest)
      throw new ConfigurationRepositoryError('PC-DATA-6004');
  }
  await client.query(
    `insert into control.cigl_method_access_grants(grant_id,participant_id,privacy_domain_id,runtime_binding_id,selector,binding_revision,method_revision,definition,status,grant_digest,publication_operation_id,publication_authority_digest,origin,generated_by_grant_id)
    select (row->>'grant_id')::uuid,$2,$3,substring(row->'definition'->>'runtimeBindingId' from 21)::uuid,row->'definition'->>'selector',(row->>'binding_revision')::numeric,(row->>'method_revision')::numeric,row->'definition','ACTIVE',row->>'grant_digest',$4,$5,'GENERATED',$6
    from jsonb_array_elements($1::jsonb) row`,
    [
      JSON.stringify(
        [...generated.values()].map((g) => ({ ...g, grant_digest: digests.get(g.grant_id) })),
      ),
      participant,
      privacy,
      operationId,
      `sha256:${context.authorization.evidenceDigest.toString('hex')}`,
      sourceGrantId,
    ],
  );
  await client.query(
    `insert into control.cigl_method_grant_dependency_claims(participant_id,privacy_domain_id,source_grant_id,source_grant_revision,required_grant_id,required_grant_revision,profile_id,profile_revision,ordinal,capability,graph_digest,policy_generation_digest,participant_epoch,publication_operation_id)
    select $1,$2,$3,$4,(selection->>'requiredGrantId')::uuid,(selection->>'revision')::numeric,$5,$6,(selection->>'ordinal')::integer,$7,$8,$9,$10,$11 from jsonb_array_elements($12::jsonb) selection`,
    [
      participant,
      privacy,
      sourceGrantId,
      source.revision,
      profileId,
      bundle.profileRevision,
      bundle.capability,
      bundle.graphDigest,
      bundle.policyGenerationDigest,
      bundle.participantEpoch,
      operationId,
      JSON.stringify(selections),
    ],
  );
}

/** Reconcile only generated grants whose last upstream claim was released by
 * this approved operation. Shared grants and still-referenced generated grants
 * are untouched. The SQL guards independently enforce this causal boundary. */
export async function reconcileGeneratedCiglGrants(
  client: PoolClient,
  context: MutationContext,
  operationId: string,
) {
  await client.query(
    `with orphan as (
    select grant_row.grant_id,grant_row.definition-ARRAY['runtimeBindingId','selector'] || jsonb_build_object(
      'grantId',grant_row.grant_id::text,'runtimeBindingId',grant_row.runtime_binding_id::text,'status','DISABLED',
      'selector',jsonb_build_array(get_byte(decode(substr(grant_row.selector,3),'hex'),0),get_byte(decode(substr(grant_row.selector,3),'hex'),1),get_byte(decode(substr(grant_row.selector,3),'hex'),2),get_byte(decode(substr(grant_row.selector,3),'hex'),3))) canonical
    from control.cigl_method_access_grants grant_row where participant_id=$1 and privacy_domain_id=$2 and origin='GENERATED' and status='ACTIVE'
      and not exists(select 1 from control.cigl_method_grant_dependency_claims claim where claim.required_grant_id=grant_row.grant_id and claim.state='ACTIVE')
      and exists(select 1 from control.cigl_method_grant_dependency_claims claim where claim.required_grant_id=grant_row.grant_id and claim.released_operation_id=$3)
  ) update control.cigl_method_access_grants grant_row set status='DISABLED',revision=revision+1,publication_operation_id=$3,publication_authority_digest=$4,
    grant_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(orphan.canonical),'UTF8')),'hex') from orphan where grant_row.grant_id=orphan.grant_id`,
    [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      operationId,
      `sha256:${context.authorization.evidenceDigest.toString('hex')}`,
    ],
  );
}
