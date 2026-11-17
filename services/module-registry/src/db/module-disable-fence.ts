import { Client, type Pool, type PoolClient } from 'pg';
import type { MutationCommitFence } from '../../../control-api/src/configuration/persistence/atomic-mutation.js';
import type { MutationContext } from '../../../control-api/src/configuration/persistence/types.js';
import { uuidv7 } from '../../../control-api/src/configuration/governed-mutation-http.js';
import { ContractError } from '../domain/errors.js';
import { moduleDisableReplacementDigest } from '../module-command-contract.js';
import { readVerifiedModuleLifecycleSnapshot } from './module-lifecycle-snapshot.js';
import type { ModuleReleaseVerifier } from './module-release-store.js';
import {
  assertModuleLifecycleObservationUnchanged,
  freezeModuleLifecycleObservation,
  lockModuleLifecycleReferences,
  moduleLifecyclePreflightRequest,
  observeModuleLifecycleReferences,
  type ModuleLifecyclePreflightObservation,
} from './module-lifecycle-preflight.js';

export interface ModuleDisableFence extends MutationCommitFence {
  readonly observation: ModuleLifecyclePreflightObservation;
}

/** Admission is internal and operation-specific. A non-authorizing observation
 * cannot substitute for UPDATE, independent approval or fresh WebAuthn. */
export function requireModuleDisablePredicates(observation: ModuleLifecyclePreflightObservation) {
  const required = [
    'reverseDependencies',
    'policyReferences',
    'configurationReferences',
    'runtimeReferences',
    'factProjectionDrain',
    'uiInvalidation',
    'grantAndOwnedDataSafety',
    'custodyDisposition',
  ];
  if (
    Object.keys(observation.predicates).length !== required.length ||
    required.some((key) => !Object.hasOwn(observation.predicates, key)) ||
    !/^sha256:[0-9a-f]{64}$/u.test(observation.observationDigest) ||
    observation.operation !== 'MOD-OP-DISABLE' ||
    observation.target.state !== 'ENABLED' ||
    Object.entries(observation.predicates).some(
      ([name, predicate]) =>
        predicate.references.length !== 0 ||
        predicate.unresolved.length !== 0 ||
        (name === 'custodyDisposition'
          ? predicate.status !== 'NOT_APPLICABLE'
          : predicate.status !== 'CLEAR'),
    )
  )
    throw new ContractError('PC-MODULE-7009');
}

/** Reference locks belong to the actual writer transaction. The fresh observer
 * never locks Identity rows or borrows READ authority, and never owns/relinquishes
 * the writer's locks. Every atomic serialization retry calls this afresh. */
export async function acquireModuleDisableFence(
  pool: Pool,
  writer: PoolClient,
  context: MutationContext,
  replacementDigest: string,
  verify: ModuleReleaseVerifier,
): Promise<ModuleDisableFence> {
  if (context.catalogOperationId !== 'MOD-OP-DISABLE') throw new ContractError('PC-MODULE-7008');
  const scope = context.authorization;
  await lockModuleLifecycleReferences(writer, scope);
  const rows = await readVerifiedModuleLifecycleSnapshot(
    writer,
    scope.participantId,
    scope.privacyDomainId,
    verify,
  );
  const root = rows.find(({ stored }) => stored.moduleInstallationId === context.resourceId);
  if (!root) throw new ContractError('PC-MODULE-7009');
  const request = moduleLifecyclePreflightRequest.parse({
    operation: 'MOD-OP-DISABLE',
    moduleInstallationId: context.resourceId,
    expectedRevision: context.expectedRevision,
    generation: root.configuration.generation,
    manifestDigest: `sha256:${root.release.manifestDigest.toString('hex')}`,
    configurationDigest: `sha256:${root.release.configurationDigest.toString('hex')}`,
  });
  if (
    moduleDisableReplacementDigest({
      operation: request.operation,
      targetRef: `urn:openpc:resource:${context.resourceId}`,
      expectedRevision: request.expectedRevision,
      manifestDigest: request.manifestDigest,
    }) !== replacementDigest
  )
    throw new ContractError('PC-MODULE-7009');

  // Separate connection avoids pool-slot deadlock with an admitted writer in
  // every pool slot. Finite deadlines include native semantic decoding time.
  const reader = new Client({
    ...pool.options,
    password: pool.options.password,
    connectionTimeoutMillis: Math.min(pool.options.connectionTimeoutMillis || 5000, 5000),
    query_timeout: 5500,
  });
  const started = performance.now();
  let connected = false;
  let closed = false;
  let failed = false;
  const fail = () => {
    failed = true;
  };
  reader.on('error', fail);
  const healthy = () => {
    if (closed || failed || performance.now() - started >= 30000)
      throw new ContractError('PC-MODULE-7009');
  };
  const release = async () => {
    if (closed) return;
    closed = true;
    if (connected) await reader.query('rollback').catch(fail);
    await reader.end().catch(fail);
    reader.off('error', fail);
  };
  try {
    await reader.connect();
    connected = true;
    await reader.query('begin isolation level read committed read only');
    await reader.query("set local statement_timeout='5s'");
    await reader.query("set local lock_timeout='1500ms'");
    await reader.query("set local idle_in_transaction_session_timeout='35s'");
    await reader.query('set local row_security=on');
    await reader.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)",
      [scope.participantId, scope.privacyDomainId, uuidv7(), context.actionIntentId],
    );
    const observation = freezeModuleLifecycleObservation(
      await observeModuleLifecycleReferences(reader, scope, request, verify, healthy),
    );
    healthy();
    // The SERIALIZABLE writer may predate a committed source writer even though
    // its nonblocking locks now succeed. Compare every observed owner/predicate
    // before making any lifecycle writes, not just the requested target revision.
    assertModuleLifecycleObservationUnchanged(
      observation.observationDigest,
      await observeModuleLifecycleReferences(writer, scope, request, verify, healthy),
    );
    requireModuleDisablePredicates(observation);
    healthy();
    return {
      observation,
      revalidate: async () => {
        healthy();
        const current = await observeModuleLifecycleReferences(
          reader,
          scope,
          request,
          verify,
          healthy,
        );
        assertModuleLifecycleObservationUnchanged(observation.observationDigest, current);
        requireModuleDisablePredicates(current);
        healthy();
      },
      // No reread of the intentionally changed predecessor after COMMIT.
      release,
    };
  } catch (error) {
    await release();
    throw error;
  }
}
