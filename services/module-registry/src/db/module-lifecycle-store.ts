import { controlMutationForAction } from '@openpc/security-kernel';
import {
  moduleDisableReplacementDigest,
  moduleLifecycleInputDigest,
} from '../module-command-contract.js';
import { acquireModuleDisableFence, type ModuleDisableFence } from './module-disable-fence.js';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import type { Pool, PoolClient } from 'pg';
import { AtomicConfigurationMutation } from '../../../control-api/src/configuration/persistence/atomic-mutation.js';
import type { ConfigurationBusinessEvidence } from '../../../control-api/src/configuration/persistence/business-receipt-writer.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../../../control-api/src/configuration/persistence/types.js';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import { ContractError } from '../domain/errors.js';
import { readModuleAdmissionState } from './module-admission-state.js';
import { bindModuleLifecycleTransition } from './module-lifecycle-state.js';
import { dependencyClosure, type ModuleReleaseVerifier } from './module-release-store.js';

const hex = (value: Buffer) => `sha256:${value.toString('hex')}`;
export { readVerifiedModuleLifecycleSnapshot } from './module-lifecycle-snapshot.js';
import { readVerifiedModuleLifecycleSnapshot } from './module-lifecycle-snapshot.js';

export { moduleLifecycleInputDigest } from '../module-command-contract.js';

/** Verify current release trust as well as the database's exact enabled closure. */
export async function requireDeploymentModules(
  client: PoolClient,
  participant: string,
  privacy: string,
  verify: ModuleReleaseVerifier | undefined,
) {
  if (!verify) throw new ConfigurationRepositoryError('PC-AUTH-0005');
  await client.query('select pg_advisory_xact_lock_shared(hashtextextended($1,0))', [
    `module-admission:${participant}:${privacy}`,
  ]);
  try {
    await readVerifiedModuleLifecycleSnapshot(client, participant, privacy, verify);
  } catch (error) {
    if (error instanceof ContractError) throw new ConfigurationRepositoryError('PC-AUTH-0005');
    throw error;
  }
  const selected = await client.query<{ digest: Buffer | null }>(
    'select openpc.deployment_module_generation($1,$2) digest',
    [participant, privacy],
  );
  const digest = selected.rows[0]?.digest;
  if (!Buffer.isBuffer(digest) || digest.length !== 32)
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  return digest;
}

export async function mutateModuleLifecycle(
  pool: Pool,
  context: MutationContext,
  input: { inputDigest: string; targetRef: string } | { replacementDigest: string },
  verify: ModuleReleaseVerifier,
  identity: IdentityRuntimeVerifier | undefined,
  evidence: ConfigurationBusinessEvidence | undefined,
) {
  if (
    !identity ||
    !evidence ||
    !['MOD-OP-INSTALL', 'MOD-OP-ENABLE', 'MOD-OP-DISABLE'].includes(context.catalogOperationId)
  )
    throw new ContractError('PC-MODULE-7008');
  const disable = context.catalogOperationId === 'MOD-OP-DISABLE';
  if (disable) {
    const operation = controlMutationForAction('ACT-MODULES_UPDATE_RESOURCE-V1', 'MOD-OP-DISABLE');
    if (
      !operation ||
      operation.catalogOperationId !== context.catalogOperationId ||
      operation.resourceType !== 'modules' ||
      operation.operationClass !== 'UPDATE' ||
      !operation.makerCheckerRequired ||
      !operation.stepUpRequired ||
      operation.aggregateType !== context.aggregateType ||
      context.resourceType !== operation.resourceType ||
      context.actionIntentId !== operation.actionIntentId ||
      context.operationClass !== operation.operationClass ||
      !('replacementDigest' in input)
    )
      throw new ContractError('PC-MODULE-7008');
  } else if (!('inputDigest' in input)) throw new ContractError('PC-MODULE-7000');
  let disableFence: ModuleDisableFence | undefined;
  return new AtomicConfigurationMutation(pool, identity, evidence).execute(
    context,
    async (client, id, operationId) => {
      const { participantId, privacyDomainId } = context.authorization;
      if (!disable)
        await client.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
          `module-admission:${participantId}:${privacyDomainId}`,
        ]);
      const before = await readModuleAdmissionState(client, context);
      if (
        !before ||
        before.revision !== context.expectedRevision ||
        (disable
          ? !disableFence ||
            !('replacementDigest' in input) ||
            input.replacementDigest !==
              moduleDisableReplacementDigest({
                operation: 'MOD-OP-DISABLE',
                targetRef: `urn:openpc:resource:${id}`,
                expectedRevision: before.revision,
                manifestDigest: hex(before.manifestDigest),
              })
          : !('inputDigest' in input) ||
            input.targetRef !== `urn:openpc:resource:${id}` ||
            input.inputDigest !==
              moduleLifecycleInputDigest(
                input.targetRef,
                before.revision,
                hex(before.manifestDigest),
              ))
      )
        throw new ContractError('PC-MODULE-7009');
      const rows = await readVerifiedModuleLifecycleSnapshot(
        client,
        participantId,
        privacyDomainId,
        verify,
      );
      const root = rows.find((row) => row.stored.moduleInstallationId === id);
      if (!root) throw new ContractError('PC-MODULE-7003');
      const closure = await dependencyClosure(
        client,
        { participantId, privacyDomainId },
        root.release,
        verify,
        Date.now(),
      );
      if (closure.closureDigest !== before.dependencyDigest.toString('hex'))
        throw new ContractError('PC-MODULE-7003');
      // Enumerate relevant current serving references, without embedding policy or credential payloads.
      const references = disable
        ? undefined
        : await client.query(
            `select
      (select coalesce(jsonb_agg(jsonb_build_array(policy_generation_id,state,active) order by policy_generation_id),'[]'::jsonb)
       from control.policy_generation where participant_id=$1 and privacy_domain_id=$2) policies,
      (select coalesce(jsonb_agg(jsonb_build_array(runtime_target_id,revision,state,active_generation_digest) order by runtime_target_id),'[]'::jsonb)
       from control.runtime_target where participant_id=$1 and privacy_domain_id=$2) targets`,
            [participantId, privacyDomainId],
          );
      const document = {
        operation: context.catalogOperationId,
        moduleId: before.moduleId,
        revision: before.revision,
        participantId,
        privacyDomainId,
        authorityDigest: hex(context.authorization.evidenceDigest),
        dependencyDigest: hex(before.dependencyDigest),
        referenceDigest: disableFence?.observation.observationDigest ?? sha256(references?.rows[0]),
        ...(disableFence ? { disableObservation: disableFence.observation } : {}),
        modules: rows.map(({ release, stored, configuration }) => ({
          moduleId: release.manifest.metadata.id,
          version: release.manifest.metadata.version,
          manifestDigest: hex(release.manifestDigest),
          configurationDigest: hex(release.configurationDigest),
          stackLockDigest: release.manifest.compatibility.stackLockDigest,
          state: stored.state,
          generation: configuration.generation,
          active: configuration.active,
          activeManifestDigest: configuration.activeManifest
            ? hex(configuration.activeManifest)
            : null,
          capabilities: release.manifest.capabilities.provided.map(
            (capability) => capability.capabilityId,
          ),
          dependencies: release.manifest.dependencies.map((dependency) => ({
            moduleId: dependency.providerModuleId,
            version: dependency.version,
            manifestDigest: dependency.manifestDigest,
            capabilityId: dependency.capabilityId,
          })),
          conflicts: release.manifest.conflicts.moduleIds,
        })),
      };
      const executable =
        process.env.OPENPC_POLICY_CORE_BIN ??
        fileURLToPath(new URL('../../../../target/debug/openpc-policy-evaluator', import.meta.url));
      const evaluated = JSON.parse(
        execFileSync(executable, [], {
          encoding: 'utf8',
          input: JSON.stringify({ command: 'MODULE_LIFECYCLE_SIMULATION', value: document }),
          timeout: 10000,
          maxBuffer: 1024 * 1024,
        }),
      );
      const enable = context.catalogOperationId === 'MOD-OP-ENABLE';
      if (
        evaluated.result?.identity !== 'PC-MODULE-LIFECYCLE-1/PC-CBOR-1' ||
        evaluated.result.authority !== 'SIMULATION_ONLY' ||
        !/^[0-9a-f]{64}$/u.test(evaluated.result.inputDigest) ||
        evaluated.result.runtimePermission !== 'NONE' ||
        evaluated.result.moduleId !== before.moduleId ||
        evaluated.result.manifestDigest !== hex(before.manifestDigest) ||
        evaluated.result.configurationDigest !== hex(before.configurationDigest) ||
        evaluated.result.dependencyDigest !== hex(before.dependencyDigest) ||
        evaluated.result.generation !== 1 ||
        evaluated.result.state !== (enable ? 'ENABLED' : 'INSTALLED_DISABLED') ||
        !/^[0-9a-f]{64}$/u.test(evaluated.resultDigest) ||
        !/^(?:[0-9a-f]{2})+$/u.test(evaluated.inputBytes) ||
        !/^(?:[0-9a-f]{2})+$/u.test(evaluated.resultBytes)
      )
        throw new ContractError('PC-MODULE-7003');
      const resultDigest = Buffer.from(evaluated.resultDigest, 'hex');
      const resultCbor = Buffer.from(evaluated.resultBytes, 'hex');
      if (
        !createHash('sha256').update(resultCbor).digest().equals(resultDigest) ||
        createHash('sha256').update(Buffer.from(evaluated.inputBytes, 'hex')).digest('hex') !==
          evaluated.result.inputDigest
      )
        throw new ContractError('PC-MODULE-7003');
      const revision = (BigInt(before.revision) + 1n).toString();
      await client.query(
        `insert into control.module_lifecycle_evaluation
      (operation_id,participant_id,privacy_domain_id,module_installation_id,revision,input_cbor,result_cbor,result_digest)
      values($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          operationId,
          participantId,
          privacyDomainId,
          id,
          revision,
          Buffer.from(evaluated.inputBytes, 'hex'),
          resultCbor,
          resultDigest,
        ],
      );
      await client.query(
        `update control.module_installation set state=$4,aggregate_version=$5,
      active_manifest_digest=$6,lifecycle_evaluation_digest=$7,lifecycle_operation_id=$8,
      authority_epoch=$9,delegation_epoch=$10,updated_at=clock_timestamp()
      where participant_id=$1 and privacy_domain_id=$2 and module_installation_id=$3`,
        [
          participantId,
          privacyDomainId,
          id,
          enable ? 'ENABLED' : 'INSTALLED_DISABLED',
          revision,
          enable ? before.manifestDigest : null,
          resultDigest,
          operationId,
          context.authorization.authorityEpoch,
          context.authorization.delegationEpoch,
        ],
      );
      if (enable || disable) {
        const changed = await client.query(
          `update control.module_configuration_generation set active=$4
      where participant_id=$1 and privacy_domain_id=$2 and module_installation_id=$3 and generation=1 and active=$5`,
          [participantId, privacyDomainId, id, enable, disable],
        );
        if (changed.rowCount !== 1) throw new ContractError('PC-MODULE-7009');
      }
      const after = await readModuleAdmissionState(client, context);
      if (!after) throw new ContractError('PC-MODULE-7003');
      return {
        businessState: bindModuleLifecycleTransition(context, before, after),
        result: undefined,
        revision,
        outboxEventType: 'io.openpc.control.command.committed.v1',
      };
    },
    undefined,
    disable
      ? async (client) => {
          if (!('replacementDigest' in input)) throw new ContractError('PC-MODULE-7000');
          disableFence = await acquireModuleDisableFence(
            pool,
            client,
            context,
            input.replacementDigest,
            verify,
          );
          return disableFence;
        }
      : undefined,
  );
}
