import type { Pool, PoolClient } from 'pg';

import { fenceBoundAuthorities } from '../../../identity-service/src/db/authority-fence.js';
import { readWorkloadPolicyPrediction } from '../../../identity-service/src/domain/workload-policy-prediction.js';
import type { PublicApprovalScope } from './public-approval-store.js';
import { validatePolicySemantics } from '../domain/policy-semantics.js';
import { ContractError } from '../domain/errors.js';
import {
  listContractSimulationAuthorities,
  listSimulationWorkloads,
} from './policy-simulation-authority.js';

export const rpcAccessMethods = {
  eth_call: 'CALL_RESULT_DISCLOSURE',
  eth_sendRawTransaction: 'SIGNED_TRANSACTION_SUBMISSION',
} as const;

type RpcMethod = keyof typeof rpcAccessMethods;

async function scopedRead<T>(
  pool: Pool,
  scope: PublicApprovalScope,
  operation: (client: PoolClient) => Promise<T>,
): Promise<T> {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const client = await pool.connect();
    let open = false;
    let committing = false;
    let discard = false;
    try {
      // Each attempt rechecks the same authority in a fresh snapshot. No
      // provider calls or writes belong inside this read-only operation.
      await client.query('begin isolation level repeatable read');
      open = true;
      await client.query('set local row_security=on');
      await client.query(`set local statement_timeout='5s'`);
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
        [scope.participantId, scope.privacyDomainId, scope.operationId, scope.actionIntentId],
      );
      await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
      const result = await operation(client);
      await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
      committing = true;
      await client.query('commit');
      open = false;
      return result;
    } catch (error) {
      if (open) {
        try {
          await client.query('rollback');
          open = false;
        } catch {
          discard = true;
          throw new ContractError('PC-POLICY-2005', 'RPC access rollback unavailable');
        }
      }
      if (
        !committing &&
        attempt < 2 &&
        error instanceof Error &&
        'code' in error &&
        (error.code === '40001' || error.code === '40P01')
      )
        continue;
      if (error instanceof ContractError) throw error;
      throw new ContractError('PC-POLICY-2005', 'RPC access read unavailable');
    } finally {
      client.release(discard);
    }
  }
  throw new ContractError('PC-POLICY-2005', 'RPC access read unavailable');
}

export function readPolicyAuthoringContext(pool: Pool, scope: PublicApprovalScope) {
  return scopedRead(pool, scope, async (client) => {
    const rows = await client.query<{
      moduleId: string;
      semanticVersion: string;
      manifestDigest: string;
      configurationDigest: string;
      installationId: string;
      revision: string;
    }>(
      `select version.module_id as "moduleId",version.semantic_version as "semanticVersion",
              'sha256:'||encode(version.manifest_digest,'hex') as "manifestDigest",
              'sha256:'||encode(configuration.configuration_digest,'hex') as "configurationDigest",
              installation.module_installation_id::text as "installationId",
              installation.aggregate_version::text as revision
         from control.module_installation installation
         join control.module_version version using(module_version_id)
         join control.module_configuration_generation configuration
           on configuration.participant_id=installation.participant_id
          and configuration.privacy_domain_id=installation.privacy_domain_id
          and configuration.module_installation_id=installation.module_installation_id
        where installation.participant_id=$1 and installation.privacy_domain_id=$2
          and installation.state='ENABLED' and configuration.active=true
          and installation.active_manifest_digest=version.manifest_digest
        order by version.module_id limit 34`,
      [scope.participantId, scope.privacyDomainId],
    );
    if (rows.rows.length > 33) throw new ContractError('PC-POLICY-2005');
    const simulationAuthorities = await listContractSimulationAuthorities(
      client,
      scope.participantId,
      scope.privacyDomainId,
    );
    const simulationWorkloads = await listSimulationWorkloads(client, scope.participantId);
    return {
      moduleBindings: rows.rows,
      simulationAuthorities,
      simulationWorkloads,
      observedAt: new Date().toISOString(),
      completeness: 'COMPLETE' as const,
      authorizedEmpty: rows.rows.length === 0,
    };
  });
}

interface AssignmentRow {
  readonly assignmentId: string;
  readonly assignmentState: string;
  readonly assignmentRevision: string;
  readonly roleId: string | null;
  readonly envelopeId: string;
  readonly envelopeState: string;
  readonly validFrom: Date;
  readonly validUntil: Date | null;
  readonly capabilities: string[];
}

export function readRpcAccessPreview(
  pool: Pool,
  scope: PublicApprovalScope,
  input: {
    readonly workloadId: string;
    readonly methods: readonly RpcMethod[];
    readonly scopeDigest: Buffer;
  },
) {
  return scopedRead(pool, scope, async (client) => {
    const prediction = await readWorkloadPolicyPrediction(
      client,
      scope.participantId,
      scope.privacyDomainId,
      input.workloadId,
      Date.now(),
    );
    const active = await client.query<{
      policyGenerationId: string;
      generation: string;
      generationDigest: Buffer;
      policyVersionId: string;
      semanticCbor: Buffer;
    }>(
      `select generation.policy_generation_id::text as "policyGenerationId",
              generation.generation::text,generation.generation_digest as "generationDigest",
              version.policy_version_id::text as "policyVersionId",version.semantic_cbor as "semanticCbor"
         from control.policy_generation generation
         join control.policy_version version
           on (version.participant_id,version.privacy_domain_id,version.policy_version_id)=
              (generation.participant_id,generation.privacy_domain_id,generation.policy_version_id)
        where generation.participant_id=$1 and generation.privacy_domain_id=$2
          and generation.scope_digest=$3 and generation.state='ACTIVE' and generation.active=true
        for share of generation`,
      [scope.participantId, scope.privacyDomainId, input.scopeDigest],
    );
    const generation = active.rows[0];
    if (active.rowCount !== 1 || !generation) throw new ContractError('PC-POLICY-2001');
    const document = validatePolicySemantics(
      Array.from(generation.semanticCbor),
      'DECODE_SEMANTICS',
    ).document;
    const assignments = await client.query<AssignmentRow>(
      `select assignment.assignment_id::text as "assignmentId",assignment.state as "assignmentState",
              assignment.row_version::text as "assignmentRevision",assignment.role_id as "roleId",
              envelope.authority_envelope_id::text as "envelopeId",envelope.state as "envelopeState",
              lower(assignment.valid_during) as "validFrom",upper(assignment.valid_during) as "validUntil",
              assignment.runtime_capability_ids as capabilities
         from control.assignment assignment
         join control.authority_envelope envelope
           on envelope.participant_id=assignment.participant_id
          and envelope.authority_envelope_id=assignment.authority_envelope_id
         left join control.authority_role role
           on role.participant_id=assignment.participant_id and role.role_id=assignment.role_id
        where assignment.participant_id=$1 and assignment.principal_id=$2
          and $3::text=any(assignment.privacy_domain_ids)
          and assignment.state='ACTIVE' and assignment.valid_during @> clock_timestamp()
          and envelope.state='ACTIVE' and envelope.valid_from<=clock_timestamp()
          and (envelope.valid_until is null or envelope.valid_until>clock_timestamp())
          and (assignment.role_id is null or role.state='ACTIVE')
        order by assignment.assignment_id limit 257`,
      [scope.participantId, prediction.principalId, scope.privacyDomainId],
    );
    if (assignments.rows.length > 256) throw new ContractError('PC-POLICY-2005');
    const credentialCurrent = BigInt(prediction.input.credentialValidUntilNs) > 0n;
    const rules = document.rpcPolicies.flatMap((policy) => policy.rules);
    const methods = input.methods.map((method) => {
      const capabilityId = rpcAccessMethods[method];
      const methodRules = rules.filter((rule) => rule.method === method);
      const allowRules = methodRules.filter((rule) => rule.effect === 'ALLOW');
      const denyRules = methodRules.filter((rule) => rule.effect === 'DENY');
      const matching = assignments.rows.filter(
        (assignment) =>
          assignment.capabilities.includes(capabilityId) &&
          allowRules.some(
            (rule) =>
              rule.requiredRoles.length === 0 ||
              (assignment.roleId !== null && rule.requiredRoles.includes(assignment.roleId)),
          ),
      );
      const deniedByPolicy = denyRules.some(
        (rule) =>
          rule.requiredRoles.length === 0 ||
          assignments.rows.some(
            (assignment) =>
              assignment.roleId !== null && rule.requiredRoles.includes(assignment.roleId),
          ),
      );
      const reasons = [
        ...(methodRules.length === 0 ? ['POLICY_RULE_MISSING'] : []),
        ...(allowRules.length > 0 && matching.length === 0 ? ['ROLE_OR_CAPABILITY_MISSING'] : []),
        ...(deniedByPolicy ? ['POLICY_DENY'] : []),
        ...(!credentialCurrent ? ['WORKLOAD_CREDENTIAL_NOT_CURRENT'] : []),
      ];
      return {
        method,
        capabilityId,
        configured: methodRules.length > 0,
        truthState:
          reasons.length === 0 && matching.length > 0 ? ('SUCCESS' as const) : ('DENIED' as const),
        reasons,
        assignments: matching.map((assignment) => ({
          assignmentId: assignment.assignmentId,
          assignmentState: assignment.assignmentState,
          assignmentRevision: assignment.assignmentRevision,
          roleId: assignment.roleId,
          envelopeId: assignment.envelopeId,
          envelopeState: assignment.envelopeState,
          validFrom: assignment.validFrom.toISOString(),
          validUntil: assignment.validUntil?.toISOString() ?? null,
        })),
      };
    });
    return {
      authoritative: false as const,
      workloadId: input.workloadId,
      workloadSourceDigest: `sha256:${prediction.input.sourceDigest}`,
      credentialCurrent,
      policyGenerationId: generation.policyGenerationId,
      policyGeneration: generation.generation,
      policyGenerationDigest: `sha256:${generation.generationDigest.toString('hex')}`,
      policyVersionId: generation.policyVersionId,
      methods,
      observedAt: new Date().toISOString(),
    };
  });
}
