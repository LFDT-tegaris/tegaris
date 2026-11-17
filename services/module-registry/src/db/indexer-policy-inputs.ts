import type { PoolClient } from 'pg';

import { ContractError } from '../domain/errors.js';
import { authorizeRuntimeArtifactRead } from './runtime-artifact-materialization.js';
import type {
  IndexerCompilationInput,
  PolicySemanticDocument,
} from '../domain/policy-semantics.js';

/** Authoring binds current immutable source bytes, not live qualification or permission. */
export async function loadPolicyIndexerInputs(
  client: PoolClient,
  document: PolicySemanticDocument,
): Promise<readonly IndexerCompilationInput[]> {
  const policies = document.indexerPolicies ?? [];
  if (policies.length === 0) return [];
  const references = [
    ...new Map(policies.map((policy) => [policy.projectionPlanId, policy])).values(),
  ].sort((a, b) => a.projectionPlanId.localeCompare(b.projectionPlanId));
  const sources = await client.query<{
    projection_plan_id: string;
    indexer_profile_id: string;
    plan_digest: string;
    method_profile_digest: string;
  }>(
    `select plan.projection_plan_id::text,profile.indexer_profile_id::text,
            plan.plan_digest,profile.method_profile_digest
       from control.projection_plan plan
       join control.indexer_profile profile on profile.participant_id=plan.participant_id
        and profile.privacy_domain_id=plan.privacy_domain_id
        and profile.indexer_profile_id=plan.indexer_profile_id
      where plan.participant_id=$1 and plan.privacy_domain_id=$2
        and plan.projection_plan_id=any($3::uuid[])
        and plan.state<>'RETIRED' and profile.state<>'RETIRED'
      order by plan.projection_plan_id for share of plan,profile`,
    [
      document.participantId,
      document.privacyDomainId,
      references.map((policy) => policy.projectionPlanId),
    ],
  );
  if (
    sources.rowCount !== references.length ||
    policies.some(
      (policy) =>
        !sources.rows.some(
          (source) =>
            source.projection_plan_id === policy.projectionPlanId &&
            source.indexer_profile_id === policy.indexerProfileId &&
            source.method_profile_digest === policy.profileArtifactDigest &&
            source.plan_digest === policy.planArtifactDigest,
        ),
    )
  )
    throw new ContractError('PC-POLICY-2003', 'policy source references unavailable');
  const selected = await client.query<{ input_id: string; configuration_digest: Buffer }>(
    `select runtime_configuration_input_id::text input_id,configuration_digest
       from control.runtime_configuration_input_current_metadata
      where participant_id=$1 and privacy_domain_id=$2`,
    [document.participantId, document.privacyDomainId],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    !Buffer.isBuffer(row.configuration_digest) ||
    row.configuration_digest.length !== 32
  )
    throw new ContractError('PC-POLICY-2003', 'current policy source bytes unavailable');
  await authorizeRuntimeArtifactRead(client, row.input_id);
  const payload = await client.query<{ configuration_cbor: Buffer }>(
    'select openpc.runtime_artifact_input_payload($1::uuid) configuration_cbor',
    [row.input_id],
  );
  if (payload.rowCount !== 1 || !Buffer.isBuffer(payload.rows[0]?.configuration_cbor))
    throw new ContractError('PC-POLICY-2003', 'current policy source bytes unavailable');
  // The Rust compiler authenticates the bytes, exact profile/plan/acquisition
  // tuple, workload binding and limits. It selects no caller-supplied payload.
  return [
    {
      configurationCbor: [...payload.rows[0]!.configuration_cbor],
      configurationDigest: row.configuration_digest.toString('hex'),
    },
  ];
}
