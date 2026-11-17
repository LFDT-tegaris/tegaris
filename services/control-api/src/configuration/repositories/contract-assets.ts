import { transactionPolicySchema, type TransactionPolicy } from '../transaction-policy.js';
import type { Pool, PoolClient, QueryResultRow } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';

import {
  assertAbiContainsFunction,
  assertArgumentRulesMatchAbi,
  canonicalAbiBytes,
  ruleDigest,
  selectorFor,
} from '../contract-assets.js';
import { sha256 } from '../digest.js';
import { selectPage, type ListRequest, type PageResult } from '../pagination.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
  type OperationRecord,
} from '../persistence/types.js';

export interface AbiArtifactRecord {
  readonly abiArtifactId: string;
  readonly abiDigest: string;
  readonly provenance: {
    readonly source: string;
    readonly locator: string;
    readonly retrievedAt: string;
    readonly sourceDigest: string;
  };
  readonly canonicalAbi: readonly unknown[];
  readonly policyGenerationDigest: string | null;
  readonly revision: string;
  readonly createdAt: string;
}

export interface LogicalContractRecord {
  readonly logicalContractId: string;
  readonly logicalName: string;
  readonly displayName: string;
  readonly policyGenerationDigest: string | null;
  readonly revision: string;
  readonly createdAt: string;
}

export interface RuntimeBindingRecord {
  readonly runtimeBindingId: string;
  readonly logicalContractId: string;
  readonly abiArtifactId: string;
  readonly chainId: string;
  readonly networkId: string;
  readonly contractAddress: string;
  readonly codeDigest: string;
  readonly genesisDigest: string;
  readonly proxyAddress: string | null;
  readonly implementationAddress: string | null;
  readonly implementationCodeDigest: string | null;
  readonly abiDigest: string;
  readonly abiVersion: string;
  readonly transactionPolicy: TransactionPolicy | null;
  readonly state: string;
  readonly policyGenerationDigest: string | null;
  readonly revision: string;
  readonly createdAt: string;
}

export interface ArgumentRuleVersionRecord {
  readonly argumentRuleVersionId: string;
  readonly runtimeBindingId: string;
  readonly abiArtifactId: string;
  readonly canonicalSignature: string;
  readonly version: string;
  readonly ruleDigest: string;
  readonly state: string;
  readonly namedSetVersions: readonly {
    readonly ownerId: string;
    readonly setId: string;
    readonly version: string;
    readonly digest: string;
  }[];
  readonly rules: readonly {
    readonly parameterPath: string;
    readonly operandType: string;
    readonly operator: string;
    readonly values: readonly (string | boolean)[];
  }[];
  readonly policyGenerationDigest: string | null;
  readonly revision: string;
  readonly createdAt: string;
}

export interface ContractMethodPolicyRecord {
  readonly contractMethodPolicyId: string;
  readonly runtimeBindingId: string;
  readonly abiArtifactId: string;
  readonly canonicalSignature: string;
  readonly selector: string;
  readonly effect: string;
  readonly requiredRoles: readonly string[];
  readonly approvalRequirement: string;
  readonly mfaRequirement: string;
  readonly environments: readonly string[];
  readonly argumentRuleVersionId: string | null;
  readonly rpcMethodPolicyDigest: string;
  readonly nestedCallSetDigest: string;
  readonly state: string;
  readonly policyGenerationDigest: string | null;
  readonly revision: string;
  readonly createdAt: string;
}

const urn = (value: string) => `urn:openpc:resource:${value}`;
const timestamp = (value: string) =>
  new Date(value).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');

async function configurationPolicyProvenance(
  client: PoolClient,
  context: MutationContext,
): Promise<string | null> {
  const result = await client.query<{ digest: string | null }>(
    'select openpc.configuration_policy_provenance($1::uuid,$2::uuid) as digest',
    [context.authorization.participantId, context.authorization.privacyDomainId],
  );
  if (result.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6001');
  return result.rows[0]!.digest;
}

function abiRecord(row: {
  readonly abiArtifactId: string;
  readonly abiDigest: string;
  readonly provenanceSource: string;
  readonly provenanceLocator: string;
  readonly provenanceRetrievedAt: string;
  readonly provenanceSourceDigest: string;
  readonly canonicalAbi: readonly unknown[];
  readonly policyGenerationDigest: string | null;
  readonly revision: string;
  readonly createdAt: string;
}): AbiArtifactRecord {
  return {
    abiArtifactId: urn(row.abiArtifactId),
    abiDigest: row.abiDigest,
    provenance: {
      source: row.provenanceSource,
      locator: row.provenanceLocator,
      retrievedAt: timestamp(row.provenanceRetrievedAt),
      sourceDigest: row.provenanceSourceDigest,
    },
    canonicalAbi: row.canonicalAbi,
    policyGenerationDigest: row.policyGenerationDigest,
    revision: row.revision,
    createdAt: timestamp(row.createdAt),
  };
}

const abiProjection = `abi_artifact_id as "abiArtifactId",abi_digest as "abiDigest",
  provenance_source as "provenanceSource",provenance_locator as "provenanceLocator",
  provenance_retrieved_at::text as "provenanceRetrievedAt",
  provenance_source_digest as "provenanceSourceDigest",canonical_abi as "canonicalAbi",
  policy_generation_digest as "policyGenerationDigest",revision::text,
  created_at::text as "createdAt"`;

function logicalRecord(row: LogicalContractRecord): LogicalContractRecord {
  return {
    ...row,
    logicalContractId: urn(row.logicalContractId),
    createdAt: timestamp(row.createdAt),
  };
}

function bindingRecord(row: RuntimeBindingRecord): RuntimeBindingRecord {
  return {
    ...row,
    runtimeBindingId: urn(row.runtimeBindingId),
    logicalContractId: urn(row.logicalContractId),
    abiArtifactId: urn(row.abiArtifactId),
    createdAt: timestamp(row.createdAt),
  };
}

function methodRecord(row: ContractMethodPolicyRecord): ContractMethodPolicyRecord {
  return {
    ...row,
    contractMethodPolicyId: urn(row.contractMethodPolicyId),
    runtimeBindingId: urn(row.runtimeBindingId),
    abiArtifactId: urn(row.abiArtifactId),
    argumentRuleVersionId:
      row.argumentRuleVersionId === null ? null : urn(row.argumentRuleVersionId),
    createdAt: timestamp(row.createdAt),
  };
}

export class ContractAssetRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;

  constructor(
    private readonly pool: Pool,
    identityRuntimeVerifier?: IdentityRuntimeVerifier,
  ) {
    this.mutations = new AtomicConfigurationMutation(pool, identityRuntimeVerifier);
    this.reads = new ScopedConfigurationRead(pool);
  }

  private catalogue<Row extends QueryResultRow, Output>(
    context: ReadContext,
    request: ListRequest,
    resourceType: string,
    actionIntentId: string,
    specification: Parameters<typeof selectPage<Row, Output>>[2],
  ): Promise<PageResult<Output>> {
    // A resource-limited read must never become a collection read. Native
    // selection rechecks the complete wildcard authority in the SQL snapshot.
    if (
      context.resourceId !== '*' ||
      context.resourceType !== resourceType ||
      context.actionIntentId !== actionIntentId
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    return this.reads.execute(context, (client) => selectPage(client, request, specification));
  }

  listAbiArtifacts(context: ReadContext, request: ListRequest) {
    return this.catalogue<Parameters<typeof abiRecord>[0], AbiArtifactRecord>(
      context,
      request,
      'abi-artifact',
      'ACT-ABI_ARTIFACTS_READ_RESOURCE-V1',
      {
        table: '(select *,created_at as updated_at from control.abi_artifact) abi_artifact',
        visibilityAlias: 'abi_artifact',
        idColumn: 'abi_artifact_id',
        projection: abiProjection,
        filterColumns: { abiDigest: 'abi_digest' },
        rowId: (row) => row.abiArtifactId,
        rowUpdatedAt: (row) => row.createdAt,
        map: abiRecord,
      },
    );
  }

  listLogicalContracts(context: ReadContext, request: ListRequest) {
    return this.catalogue<LogicalContractRecord, LogicalContractRecord>(
      context,
      request,
      'logical-contract-asset',
      'ACT-LOGICAL_CONTRACT_ASSETS_READ_RESOURCE-V1',
      {
        table:
          '(select *,created_at as updated_at from control.logical_contract_asset) logical_contract_asset',
        visibilityAlias: 'logical_contract_asset',
        idColumn: 'logical_contract_id',
        projection: `logical_contract_id as "logicalContractId",logical_name as "logicalName",
          display_name as "displayName",policy_generation_digest as "policyGenerationDigest",
          revision::text,created_at::text as "createdAt"`,
        filterColumns: { logicalName: 'logical_name', displayName: 'display_name' },
        rowId: (row) => row.logicalContractId,
        rowUpdatedAt: (row) => row.createdAt,
        map: logicalRecord,
      },
    );
  }

  listRuntimeBindings(context: ReadContext, request: ListRequest) {
    return this.catalogue<RuntimeBindingRecord, RuntimeBindingRecord>(
      context,
      request,
      'contract-runtime-binding',
      'ACT-CONTRACT_RUNTIME_BINDINGS_READ_RESOURCE-V1',
      {
        table: `(select binding.*,artifact.abi_digest as binding_abi_digest,
            binding.created_at as updated_at from control.contract_runtime_binding binding
          join control.abi_artifact artifact on artifact.participant_id=binding.participant_id
           and artifact.privacy_domain_id=binding.privacy_domain_id
           and artifact.abi_artifact_id=binding.abi_artifact_id) contract_runtime_binding`,
        visibilityAlias: 'contract_runtime_binding',
        idColumn: 'runtime_binding_id',
        projection: `runtime_binding_id as "runtimeBindingId",logical_contract_id as "logicalContractId",
          abi_artifact_id as "abiArtifactId",chain_id as "chainId",network_id as "networkId",
          genesis_digest as "genesisDigest",contract_address as "contractAddress",code_digest as "codeDigest",
          proxy_address as "proxyAddress",implementation_address as "implementationAddress",
          implementation_code_digest as "implementationCodeDigest",binding_abi_digest as "abiDigest",
          abi_version as "abiVersion",state,transaction_policy as "transactionPolicy",
          policy_generation_digest as "policyGenerationDigest",revision::text,created_at::text as "createdAt"`,
        filterColumns: {
          state: 'state',
          networkId: 'network_id',
          chainId: 'chain_id',
          contractAddress: 'contract_address',
          logicalContractId: 'logical_contract_id::text',
        },
        rowId: (row) => row.runtimeBindingId,
        rowUpdatedAt: (row) => row.createdAt,
        map: bindingRecord,
      },
    );
  }

  listContractMethodPolicies(context: ReadContext, request: ListRequest) {
    return this.catalogue<ContractMethodPolicyRecord, ContractMethodPolicyRecord>(
      context,
      request,
      'contract-method-policy',
      'ACT-CONTRACT_METHOD_POLICIES_READ_RESOURCE-V1',
      {
        table:
          '(select *,created_at as updated_at from control.contract_method_policy) contract_method_policy',
        visibilityAlias: 'contract_method_policy',
        idColumn: 'contract_method_policy_id',
        projection: `contract_method_policy_id as "contractMethodPolicyId",runtime_binding_id as "runtimeBindingId",
          abi_artifact_id as "abiArtifactId",canonical_signature as "canonicalSignature",selector,effect,
          required_roles as "requiredRoles",approval_requirement as "approvalRequirement",
          mfa_requirement as "mfaRequirement",environments,argument_rule_version_id as "argumentRuleVersionId",
          rpc_method_policy_digest as "rpcMethodPolicyDigest",nested_call_set_digest as "nestedCallSetDigest",state,
          policy_generation_digest as "policyGenerationDigest",revision::text,created_at::text as "createdAt"`,
        filterColumns: {
          state: 'state',
          effect: 'effect',
          canonicalSignature: 'canonical_signature',
          runtimeBindingId: 'runtime_binding_id::text',
        },
        rowId: (row) => row.contractMethodPolicyId,
        rowUpdatedAt: (row) => row.createdAt,
        map: methodRecord,
      },
    );
  }

  async createAbiArtifact(
    context: MutationContext,
    input: {
      readonly abi: readonly unknown[];
      readonly sourceDocument: string;
      readonly provenance: {
        readonly source: string;
        readonly locator: string;
        readonly retrievedAt: string;
        readonly sourceDigest: string;
      };
      readonly abiDigest: string;
    },
  ): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client, abiArtifactId) => {
      const policyDigest = await configurationPolicyProvenance(client, context);
      const canonicalBytes = canonicalAbiBytes(input.abi);
      const sourceBytes = Buffer.from(input.sourceDocument, 'base64');
      let sourceAbi: unknown;
      try {
        sourceAbi = JSON.parse(sourceBytes.toString('utf8'));
      } catch {
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      }
      if (
        sha256(canonicalBytes) !== input.abiDigest ||
        sha256(sourceBytes) !== input.provenance.sourceDigest ||
        !Array.isArray(sourceAbi) ||
        !canonicalAbiBytes(sourceAbi).equals(canonicalBytes)
      ) {
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      }
      await client.query(
        `insert into control.abi_artifact
          (abi_artifact_id,participant_id,privacy_domain_id,provenance_source,provenance_locator,
           provenance_retrieved_at,provenance_source_digest,canonical_abi_bytes,canonical_abi,
           abi_digest,policy_generation_digest)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)`,
        [
          abiArtifactId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          input.provenance.source,
          input.provenance.locator,
          input.provenance.retrievedAt,
          input.provenance.sourceDigest,
          canonicalBytes,
          JSON.stringify(input.abi),
          input.abiDigest,
          policyDigest,
        ],
      );
      return { result: undefined, revision: '1', outboxEventType: 'abi-artifact.imported.v1' };
    });
  }

  async getAbiArtifact(context: ReadContext): Promise<AbiArtifactRecord> {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query(
        `select ${abiProjection} from control.abi_artifact where abi_artifact_id=$1`,
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return abiRecord(selected.rows[0] as Parameters<typeof abiRecord>[0]);
    });
  }

  async getLogicalContract(context: ReadContext): Promise<LogicalContractRecord> {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<LogicalContractRecord>(
        `select logical_contract_id as "logicalContractId",logical_name as "logicalName",
                display_name as "displayName",policy_generation_digest as "policyGenerationDigest",
                revision::text,created_at::text as "createdAt"
           from control.logical_contract_asset where logical_contract_id=$1`,
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return logicalRecord(selected.rows[0]!);
    });
  }

  async getRuntimeBinding(context: ReadContext): Promise<RuntimeBindingRecord> {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<RuntimeBindingRecord>(
        `select binding.runtime_binding_id as "runtimeBindingId",
                binding.logical_contract_id as "logicalContractId",
                binding.abi_artifact_id as "abiArtifactId",binding.chain_id as "chainId",
                binding.network_id as "networkId",binding.genesis_digest as "genesisDigest",
                binding.contract_address as "contractAddress",binding.code_digest as "codeDigest",
                binding.proxy_address as "proxyAddress",
                binding.implementation_address as "implementationAddress",
                binding.implementation_code_digest as "implementationCodeDigest",
                artifact.abi_digest as "abiDigest",binding.abi_version as "abiVersion",binding.state,
                binding.transaction_policy as "transactionPolicy",
                binding.policy_generation_digest as "policyGenerationDigest",binding.revision::text,
                binding.created_at::text as "createdAt"
           from control.contract_runtime_binding binding
           join control.abi_artifact artifact on artifact.participant_id=binding.participant_id
            and artifact.privacy_domain_id=binding.privacy_domain_id
            and artifact.abi_artifact_id=binding.abi_artifact_id
          where binding.runtime_binding_id=$1`,
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return bindingRecord(selected.rows[0]!);
    });
  }

  async getArgumentRuleVersion(context: ReadContext): Promise<ArgumentRuleVersionRecord> {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<
        Omit<ArgumentRuleVersionRecord, 'namedSetVersions' | 'rules'>
      >(
        `select argument_rule_version_id as "argumentRuleVersionId",
                runtime_binding_id as "runtimeBindingId",abi_artifact_id as "abiArtifactId",
                canonical_signature as "canonicalSignature",version,rule_digest as "ruleDigest",state,
                policy_generation_digest as "policyGenerationDigest",revision::text,
                created_at::text as "createdAt"
           from control.typed_argument_rule_version where argument_rule_version_id=$1`,
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      const namedSets = await client.query<{
        readonly ownerId: string;
        readonly setId: string;
        readonly version: string;
        readonly digest: string;
      }>(
        `select owner_id as "ownerId",set_id as "setId",version,version_digest as digest
           from control.argument_rule_named_set_binding
          where argument_rule_version_id=$1 order by owner_id,set_id,version`,
        [context.resourceId],
      );
      const rules = await client.query<{
        readonly parameterPath: string;
        readonly operandType: string;
        readonly operator: string;
        readonly values: readonly string[];
      }>(
        `select parameter_path as "parameterPath",operand_type as "operandType",operator,
                scalar_values as values
           from control.typed_argument_rule where argument_rule_version_id=$1
          order by ordinal::integer`,
        [context.resourceId],
      );
      const row = selected.rows[0]!;
      return {
        ...row,
        argumentRuleVersionId: urn(row.argumentRuleVersionId),
        runtimeBindingId: urn(row.runtimeBindingId),
        abiArtifactId: urn(row.abiArtifactId),
        namedSetVersions: namedSets.rows.map((value) => ({
          ...value,
          ownerId: urn(value.ownerId),
        })),
        rules: rules.rows.map((rule) => ({
          ...rule,
          values:
            rule.operandType === 'BOOLEAN'
              ? rule.values.map((value) => value === 'true')
              : rule.values,
        })),
        createdAt: timestamp(row.createdAt),
      };
    });
  }

  async getContractMethodPolicy(context: ReadContext): Promise<ContractMethodPolicyRecord> {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<ContractMethodPolicyRecord>(
        `select contract_method_policy_id as "contractMethodPolicyId",
                runtime_binding_id as "runtimeBindingId",abi_artifact_id as "abiArtifactId",
                canonical_signature as "canonicalSignature",selector,effect,
                required_roles as "requiredRoles",approval_requirement as "approvalRequirement",
                mfa_requirement as "mfaRequirement",environments,
                argument_rule_version_id as "argumentRuleVersionId",
                rpc_method_policy_digest as "rpcMethodPolicyDigest",
                nested_call_set_digest as "nestedCallSetDigest",state,
                policy_generation_digest as "policyGenerationDigest",revision::text,
                created_at::text as "createdAt"
           from control.contract_method_policy where contract_method_policy_id=$1`,
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return methodRecord(selected.rows[0]!);
    });
  }

  async createLogicalContract(
    context: MutationContext,
    input: { readonly logicalName: string; readonly displayName: string },
  ): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client, logicalContractId) => {
      const policyDigest = await configurationPolicyProvenance(client, context);
      await client.query(
        `insert into control.logical_contract_asset
          (logical_contract_id,participant_id,privacy_domain_id,logical_name,display_name,policy_generation_digest)
         values ($1,$2,$3,$4,$5,$6)`,
        [
          logicalContractId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          input.logicalName,
          input.displayName,
          policyDigest,
        ],
      );
      return { result: undefined, revision: '1', outboxEventType: 'logical-contract.created.v1' };
    });
  }

  async createRuntimeBinding(
    context: MutationContext,
    input: {
      readonly logicalContractId: string;
      readonly chainId: string;
      readonly networkId: string;
      readonly genesisDigest: string;
      readonly contractAddress: string;
      readonly codeDigest: string;
      readonly proxyAddress?: string;
      readonly implementationAddress?: string;
      readonly implementationCodeDigest?: string;
      readonly abiArtifactId: string;
      readonly abiDigest: string;
      readonly abiVersion: string;
      readonly transactionPolicy?: TransactionPolicy;
    },
  ): Promise<OperationRecord> {
    const transactionPolicy =
      input.transactionPolicy === undefined
        ? null
        : transactionPolicySchema.parse(input.transactionPolicy);
    return this.mutations.execute(context, async (client, runtimeBindingId) => {
      const policyDigest = await configurationPolicyProvenance(client, context);
      const inserted = await client.query(
        `insert into control.contract_runtime_binding
          (runtime_binding_id,participant_id,privacy_domain_id,logical_contract_id,chain_id,network_id,
           genesis_digest,contract_address,code_digest,proxy_address,implementation_address,
           implementation_code_digest,abi_artifact_id,abi_version,policy_generation_digest,transaction_policy)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,artifact.abi_artifact_id,$14,$15,$17::jsonb
           from control.abi_artifact artifact
          where artifact.abi_artifact_id=$13 and artifact.abi_digest=$16`,
        [
          runtimeBindingId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          input.logicalContractId,
          input.chainId,
          input.networkId,
          input.genesisDigest,
          input.contractAddress,
          input.codeDigest,
          input.proxyAddress ?? null,
          input.implementationAddress ?? null,
          input.implementationCodeDigest ?? null,
          input.abiArtifactId,
          input.abiVersion,
          policyDigest,
          input.abiDigest,
          transactionPolicy === null ? null : JSON.stringify(transactionPolicy),
        ],
      );
      if (inserted.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return {
        result: undefined,
        revision: '1',
        outboxEventType: 'contract-runtime-binding.created.v1',
      };
    });
  }

  async createArgumentRuleVersion(
    context: MutationContext,
    input: {
      readonly runtimeBindingId: string;
      readonly abiArtifactId: string;
      readonly abiDigest: string;
      readonly canonicalSignature: string;
      readonly version: string;
      readonly namedSetVersions: readonly {
        readonly ownerId: string;
        readonly setId: string;
        readonly version: string;
        readonly digest: string;
      }[];
      readonly rules: readonly {
        readonly parameterPath: string;
        readonly operandType: string;
        readonly operator: string;
        readonly values: readonly (string | boolean)[];
      }[];
    },
  ): Promise<OperationRecord> {
    const digest = ruleDigest({
      canonicalSignature: input.canonicalSignature,
      namedSetVersions: input.namedSetVersions,
      rules: input.rules,
      version: input.version,
    });
    return this.mutations.execute(context, async (client, argumentRuleVersionId) => {
      const policyDigest = await configurationPolicyProvenance(client, context);
      const owner = await client.query<{ readonly canonicalAbi: readonly unknown[] }>(
        `select artifact.canonical_abi as "canonicalAbi"
           from control.contract_runtime_binding binding
           join control.abi_artifact artifact on artifact.participant_id=binding.participant_id
            and artifact.privacy_domain_id=binding.privacy_domain_id
            and artifact.abi_artifact_id=binding.abi_artifact_id
          where binding.runtime_binding_id=$1 and binding.abi_artifact_id=$2
            and artifact.abi_digest=$3 and binding.state='BOUND' for share of binding,artifact`,
        [input.runtimeBindingId, input.abiArtifactId, input.abiDigest],
      );
      if (owner.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      try {
        assertArgumentRulesMatchAbi(
          owner.rows[0]!.canonicalAbi,
          input.canonicalSignature,
          input.rules,
        );
      } catch {
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      }
      await client.query(
        `insert into control.typed_argument_rule_version
          (argument_rule_version_id,participant_id,privacy_domain_id,runtime_binding_id,
           abi_artifact_id,canonical_signature,version,rule_digest,policy_generation_digest,state)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,'ACTIVE')`,
        [
          argumentRuleVersionId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          input.runtimeBindingId,
          input.abiArtifactId,
          input.canonicalSignature,
          input.version,
          digest,
          policyDigest,
        ],
      );
      for (const namedSet of input.namedSetVersions) {
        await client.query(
          `insert into control.argument_rule_named_set_binding
            (participant_id,privacy_domain_id,argument_rule_version_id,owner_id,set_id,version,version_digest)
           values ($1,$2,$3,$4,$5,$6,$7)`,
          [
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            argumentRuleVersionId,
            namedSet.ownerId,
            namedSet.setId,
            namedSet.version,
            namedSet.digest,
          ],
        );
      }
      for (const [ordinal, rule] of input.rules.entries()) {
        await client.query(
          `insert into control.typed_argument_rule
            (participant_id,privacy_domain_id,argument_rule_version_id,ordinal,parameter_path,
             operand_type,operator,scalar_values)
           values ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            argumentRuleVersionId,
            String(ordinal),
            rule.parameterPath,
            rule.operandType,
            rule.operator,
            rule.values.map(String),
          ],
        );
      }
      return {
        result: undefined,
        revision: '1',
        outboxEventType: 'typed-argument-rule-version.activated.v1',
      };
    });
  }

  async createContractMethodPolicy(
    context: MutationContext,
    input: {
      readonly runtimeBindingId: string;
      readonly abiArtifactId: string;
      readonly abiDigest: string;
      readonly canonicalSignature: string;
      readonly selector: string;
      readonly effect: string;
      readonly requiredRoles: readonly string[];
      readonly approvalRequirement: string;
      readonly mfaRequirement: string;
      readonly environments: readonly string[];
      readonly argumentRuleVersionId?: string;
      readonly rpcMethodPolicyDigest: string;
      readonly nestedCallSetDigest: string;
    },
  ): Promise<OperationRecord> {
    return this.mutations.execute(context, async (client, contractMethodPolicyId) => {
      const policyDigest = await configurationPolicyProvenance(client, context);
      const owner = await client.query<{ readonly canonicalAbi: readonly unknown[] }>(
        `select artifact.canonical_abi as "canonicalAbi"
           from control.contract_runtime_binding binding
           join control.abi_artifact artifact on artifact.participant_id=binding.participant_id
            and artifact.privacy_domain_id=binding.privacy_domain_id
            and artifact.abi_artifact_id=binding.abi_artifact_id
          where binding.runtime_binding_id=$1 and binding.abi_artifact_id=$2
            and artifact.abi_digest=$3 and binding.state='BOUND' for share of binding,artifact`,
        [input.runtimeBindingId, input.abiArtifactId, input.abiDigest],
      );
      if (owner.rowCount !== 1 || selectorFor(input.canonicalSignature) !== input.selector) {
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      }
      try {
        assertAbiContainsFunction(owner.rows[0]!.canonicalAbi, input.canonicalSignature);
      } catch {
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      }
      const collision = await client.query(
        `select 1 from control.contract_method_policy
          where runtime_binding_id=$1 and selector=$2 and canonical_signature<>$3
            and state in ('PREPARED','ACTIVE')`,
        [input.runtimeBindingId, input.selector, input.canonicalSignature],
      );
      if (collision.rowCount !== 0) throw new ConfigurationRepositoryError('PC-DATA-6001');
      if (input.argumentRuleVersionId !== undefined) {
        const rules = await client.query(
          `select 1 from control.typed_argument_rule_version
            where argument_rule_version_id=$1 and runtime_binding_id=$2 and abi_artifact_id=$3
              and canonical_signature=$4 and state='ACTIVE'`,
          [
            input.argumentRuleVersionId,
            input.runtimeBindingId,
            input.abiArtifactId,
            input.canonicalSignature,
          ],
        );
        if (rules.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      }
      await client.query(
        `insert into control.contract_method_policy
          (contract_method_policy_id,participant_id,privacy_domain_id,runtime_binding_id,abi_artifact_id,
           canonical_signature,selector,effect,required_roles,approval_requirement,mfa_requirement,
           environments,argument_rule_version_id,rpc_method_policy_digest,nested_call_set_digest,
           policy_generation_digest,state)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'ACTIVE')`,
        [
          contractMethodPolicyId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          input.runtimeBindingId,
          input.abiArtifactId,
          input.canonicalSignature,
          input.selector,
          input.effect,
          input.requiredRoles,
          input.approvalRequirement,
          input.mfaRequirement,
          input.environments,
          input.argumentRuleVersionId ?? null,
          input.rpcMethodPolicyDigest,
          input.nestedCallSetDigest,
          policyDigest,
        ],
      );
      return {
        result: undefined,
        revision: '1',
        outboxEventType: 'contract-method-policy.activated.v1',
      };
    });
  }
}
