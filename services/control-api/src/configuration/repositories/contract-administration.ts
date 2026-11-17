import type { PoolClient } from 'pg';
import { createHash } from 'node:crypto';
import { canonicalJson } from '../digest.js';
import { ConfigurationRepositoryError } from '../persistence/types.js';

type Document = Record<string, unknown>;
export interface ContractAdministrationSource {
  readonly logicalContract: Document;
  readonly bindings: readonly Document[];
  readonly abiArtifacts: readonly Document[];
  readonly priorRules: readonly Document[];
  readonly contentDigest: string;
}
/** Called after the Participant root fence; original records remain historical evidence. */
export async function readContractAdministration(
  client: PoolClient,
  participant: string,
  privacy: string,
  contract: string,
): Promise<ContractAdministrationSource> {
  const logical = await client.query<{ document: Document }>(
    `select (to_jsonb(asset)||jsonb_build_object('revision',asset.revision::text)) document from control.logical_contract_asset asset
    where participant_id=$1 and privacy_domain_id=$2 and logical_contract_id=$3 for update`,
    [participant, privacy, contract],
  );
  if (logical.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6001');
  const bindings = await client.query<{ document: Document }>(
    `select (to_jsonb(binding)||jsonb_build_object('revision',binding.revision::text)) document from control.contract_runtime_binding binding
    where participant_id=$1 and privacy_domain_id=$2 and logical_contract_id=$3 order by runtime_binding_id limit 65 for update`,
    [participant, privacy, contract],
  );
  if (
    !bindings.rowCount ||
    bindings.rowCount > 64 ||
    bindings.rows.some(({ document }) => document.state !== 'BOUND')
  )
    throw new ConfigurationRepositoryError('PC-DATA-6001');
  const ids = bindings.rows.map(({ document }) => String(document.runtime_binding_id));
  const abi = await client.query<{ document: Document }>(
    `select (to_jsonb(artifact)||jsonb_build_object('revision',artifact.revision::text)) document from control.abi_artifact artifact
    where participant_id=$1 and privacy_domain_id=$2 and abi_artifact_id=any($3::uuid[]) order by abi_artifact_id for share`,
    [participant, privacy, bindings.rows.map(({ document }) => String(document.abi_artifact_id))],
  );
  const rules = await client.query<{ document: Document }>(
    `select (to_jsonb(policy)||jsonb_build_object('revision',policy.revision::text)) document from control.contract_method_policy policy
    where participant_id=$1 and privacy_domain_id=$2 and runtime_binding_id=any($3::uuid[]) order by contract_method_policy_id limit 1025 for share`,
    [participant, privacy, ids],
  );
  if ((rules.rowCount ?? 0) > 1024) throw new ConfigurationRepositoryError('PC-DATA-6001');
  const value = {
    logicalContract: logical.rows[0]!.document,
    bindings: bindings.rows.map((r) => r.document),
    abiArtifacts: abi.rows.map((r) => r.document),
    priorRules: rules.rows.map((r) => r.document),
  };
  return {
    ...value,
    contentDigest: `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`,
  };
}

export interface ContractAdministrationTransfer {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly logicalContractId: string;
  readonly contentDigest: string;
  readonly successorParticipantId: string;
  readonly successorPrivacyDomainId: string;
  readonly successorLogicalContractId: string;
  readonly expectedSuccessorEpoch: string;
}

/** The registered Participant governance transaction supplies live Platform maker/checker authority. */
export async function transferContractAdministration(
  client: PoolClient,
  candidate: ContractAdministrationTransfer,
  operationId: string,
  evidence: {
    readonly evidenceCbor: Buffer;
    readonly evidenceDigest: Buffer;
    readonly coseSign1: Buffer;
    readonly webauthnAssertionBindingDigest?: Buffer;
  },
) {
  const source = await readContractAdministration(
    client,
    candidate.participantId,
    candidate.privacyDomainId,
    candidate.logicalContractId,
  );
  if (
    source.contentDigest !== candidate.contentDigest ||
    candidate.participantId === candidate.successorParticipantId
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const scope = async (participant: string, privacy: string) =>
    client.query(
      `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,current_setting('openpc.action_intent_id'),true)`,
      [participant, privacy, operationId],
    );
  await scope(candidate.successorParticipantId, candidate.successorPrivacyDomainId);
  const provenance = await client.query<{ digest: string | null }>(
    'select openpc.configuration_policy_provenance($1::uuid,$2::uuid) as digest',
    [candidate.successorParticipantId, candidate.successorPrivacyDomainId],
  );
  if (provenance.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6001');
  const successorPolicyDigest = provenance.rows[0]!.digest;
  const successor = await client.query(
    `select participant_id from control.participant where participant_id=$1 and root_privacy_domain_id=$2
    and state='ACTIVE' and archived_at is null and authority_epoch=$3 for update`,
    [
      candidate.successorParticipantId,
      candidate.successorPrivacyDomainId,
      candidate.expectedSuccessorEpoch,
    ],
  );
  if (successor.rowCount !== 1 || BigInt(candidate.expectedSuccessorEpoch) >= 18446744073709551615n)
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  // Copy only inert definitions. The successor must author and approve its own policy and grants.
  await client.query(
    `insert into control.logical_contract_asset(logical_contract_id,participant_id,privacy_domain_id,logical_name,display_name,policy_generation_digest)
    values($1,$2,$3,$4,$5,$6)`,
    [
      candidate.successorLogicalContractId,
      candidate.successorParticipantId,
      candidate.successorPrivacyDomainId,
      source.logicalContract.logical_name,
      source.logicalContract.display_name,
      successorPolicyDigest,
    ],
  );
  const abiIds = new Map<string, string>();
  for (const artifact of source.abiArtifacts) {
    const created = await client.query<{ abi_artifact_id: string }>(
      `insert into control.abi_artifact(participant_id,privacy_domain_id,provenance_source,provenance_locator,
      provenance_retrieved_at,provenance_source_digest,canonical_abi,abi_digest,policy_generation_digest,canonical_abi_bytes)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::bytea) returning abi_artifact_id`,
      [
        candidate.successorParticipantId,
        candidate.successorPrivacyDomainId,
        artifact.provenance_source,
        artifact.provenance_locator,
        artifact.provenance_retrieved_at,
        artifact.provenance_source_digest,
        JSON.stringify(artifact.canonical_abi),
        artifact.abi_digest,
        successorPolicyDigest,
        artifact.canonical_abi_bytes,
      ],
    );
    abiIds.set(String(artifact.abi_artifact_id), created.rows[0]!.abi_artifact_id);
  }
  const bindings: {
    sourceBindingId: string;
    successorBindingId: string;
    successorAbiArtifactId: string;
  }[] = [];
  for (const binding of source.bindings) {
    const abi = abiIds.get(String(binding.abi_artifact_id));
    if (!abi) throw new ConfigurationRepositoryError('PC-DATA-6001');
    const created = await client.query<{ runtime_binding_id: string }>(
      `insert into control.contract_runtime_binding(participant_id,privacy_domain_id,logical_contract_id,
      chain_id,network_id,genesis_digest,contract_address,code_digest,proxy_address,implementation_address,implementation_code_digest,
      abi_artifact_id,abi_version,policy_generation_digest,state,transaction_policy)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'BOUND',$15::jsonb) returning runtime_binding_id`,
      [
        candidate.successorParticipantId,
        candidate.successorPrivacyDomainId,
        candidate.successorLogicalContractId,
        binding.chain_id,
        binding.network_id,
        binding.genesis_digest,
        binding.contract_address,
        binding.code_digest,
        binding.proxy_address,
        binding.implementation_address,
        binding.implementation_code_digest,
        abi,
        binding.abi_version,
        successorPolicyDigest,
        binding.transaction_policy === null || binding.transaction_policy === undefined
          ? null
          : JSON.stringify(binding.transaction_policy),
      ],
    );
    bindings.push({
      sourceBindingId: String(binding.runtime_binding_id),
      successorBindingId: created.rows[0]!.runtime_binding_id,
      successorAbiArtifactId: abi,
    });
  }
  await client.query(
    `update control.participant set authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1`,
    [candidate.successorParticipantId],
  );
  await client.query(
    `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='CONTRACT_ADMINISTRATION_TRANSFER',
    session_epoch=session_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and state='ACTIVE'`,
    [candidate.successorParticipantId],
  );
  await client.query(
    `with head as (insert into control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence)
    values($1,'participant',$1,1) on conflict(participant_id,aggregate_type,aggregate_id) do update
      set last_sequence=control.outbox_aggregate_head.last_sequence+1,updated_at=clock_timestamp() returning last_sequence)
    insert into control.outbox_event(participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,aggregate_sequence,
      payload_cbor,payload_digest,cose_sign1,webauthn_assertion_binding_digest,occurred_at)
    select $1,$2,uuidv7(),'openpc.identity.participant.epoch.advanced.v1','participant',$1,last_sequence,$3,$4,$5,$6,clock_timestamp() from head`,
    [
      candidate.successorParticipantId,
      candidate.successorPrivacyDomainId,
      evidence.evidenceCbor,
      evidence.evidenceDigest,
      evidence.coseSign1,
      evidence.webauthnAssertionBindingDigest,
    ],
  );
  await scope(candidate.participantId, candidate.privacyDomainId);
  await client.query(
    `update control.contract_runtime_binding set state='QUARANTINED',revision=revision+1 where participant_id=$1 and privacy_domain_id=$2
    and logical_contract_id=$3 and state='BOUND'`,
    [candidate.participantId, candidate.privacyDomainId, candidate.logicalContractId],
  );
  await client.query(
    `insert into control.contract_administration_transfer(participant_id,privacy_domain_id,logical_contract_id,operation_id,
    successor_participant_id,successor_privacy_domain_id,successor_logical_contract_id,source_digest,prior_definition,binding_map,successor_epoch)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      candidate.participantId,
      candidate.privacyDomainId,
      candidate.logicalContractId,
      operationId,
      candidate.successorParticipantId,
      candidate.successorPrivacyDomainId,
      candidate.successorLogicalContractId,
      candidate.contentDigest,
      source,
      JSON.stringify(bindings),
      String(BigInt(candidate.expectedSuccessorEpoch) + 1n),
    ],
  );
  return {
    logicalContractId: candidate.logicalContractId,
    successorParticipantId: candidate.successorParticipantId,
    successorLogicalContractId: candidate.successorLogicalContractId,
    successorEpoch: String(BigInt(candidate.expectedSuccessorEpoch) + 1n),
    bindings,
  };
}
