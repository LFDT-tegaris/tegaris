import { readFileSync } from 'node:fs';
import type { Pool } from 'pg';
import { requireDeploymentModules } from '../../../../module-registry/src/db/module-lifecycle-store.js';
import type { ModuleReleaseVerifier } from '../../../../module-registry/src/db/module-release-store.js';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { ConfigurationRepositoryError, type MutationContext } from '../persistence/types.js';
import { deploymentReservationCore } from './intent-core.js';
import type { CreateDeploymentSubmission } from './submission-contract.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import { readDeploymentResult, managementDeploymentState } from './result-readback.js';

const predecessorSource = readFileSync(
  new URL('./predecessor-source.sql', import.meta.url),
  'utf8',
);

export class DeploymentSubmissionRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;

  constructor(
    pool: Pool,
    verifier?: IdentityRuntimeVerifier,
    private readonly moduleVerifier?: ModuleReleaseVerifier,
  ) {
    this.mutations = new AtomicConfigurationMutation(pool, verifier);
    this.reads = new ScopedConfigurationRead(pool);
  }

  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const found = await client.query<{ command: string; handoff: boolean }>(
        `select candidate.consumed_operation_id::text command,coalesce(reservation.state='HANDOFF',false) handoff
         from control.mutation_candidate candidate
         left join control.deployment_address_reservation reservation
          on reservation.command_id=candidate.consumed_operation_id
          and reservation.participant_id=candidate.participant_id and reservation.privacy_domain_id=candidate.privacy_domain_id
         where candidate.participant_id=$1 and candidate.privacy_domain_id=$2 and candidate.resource_id=$3 and candidate.maker_principal_id=$4
         and candidate.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT' and candidate.state='CONSUMED'`,
        [
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          context.resourceId,
          context.authorization.principalId,
        ],
      );
      if (found.rowCount !== 1 || !found.rows[0])
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
      const command = found.rows[0].command;
      const result = await readDeploymentResult(
        client,
        command,
        context.authorization.participantId,
        context.authorization.privacyDomainId,
        context.authorization.principalId,
      );
      return {
        deploymentSubmissionId: `urn:openpc:resource:${context.resourceId}`,
        operationId: `urn:openpc:operation:${command}`,
        ...(result
          ? managementDeploymentState(result.status)
          : found.rows[0].handoff
            ? { state: 'WRITE_AMBIGUITY', truthState: 'WRITE_AMBIGUITY' }
            : { state: 'ACCEPTED', truthState: 'UNKNOWN' }),
        revision: result?.sequence ?? '0',
        runtimePermission: 'NONE',
        attempt: result?.outcome.attempt ?? null,
        occurrence: result?.outcome.occurrence ?? null,
        invalidation: result?.outcome.invalidation ?? null,
        association: result?.association ?? null,
        associationCurrent: result?.associationCurrent ?? false,
      };
    });
  }

  create(context: MutationContext, input: CreateDeploymentSubmission) {
    return this.mutations.execute(context, async (client, attemptId, commandId) => {
      const authority = context.authorization;
      const moduleGenerationDigest = await requireDeploymentModules(
        client,
        authority.participantId,
        authority.privacyDomainId,
        this.moduleVerifier,
      );
      const selected = await client.query<{
        preparationBytes: Buffer;
        publicationBytes: Buffer;
        nowMs: string;
        moduleGenerationDigest: Buffer | null;
      }>(
        `select intent.preparation_bytes as "preparationBytes",intent.publication_bytes as "publicationBytes",
          intent.module_generation_digest as "moduleGenerationDigest",
          floor(extract(epoch from clock_timestamp())*1000)::text as "nowMs"
         from control.deployment_intent intent
         join control.wallet_binding wallet on wallet.wallet_binding_id=intent.wallet_binding_id
          and wallet.participant_id=intent.participant_id and wallet.privacy_domain_id=intent.privacy_domain_id
          and wallet.subject_id=intent.execution_principal_id and wallet.state='ACTIVE'
          and wallet.binding_epoch::text=convert_from(intent.preparation_bytes,'UTF8')::jsonb->'context'->>'walletBindingEpoch'
         join control.runtime_target target on target.runtime_target_id=intent.runtime_target_id
          and target.participant_id=intent.participant_id and target.privacy_domain_id=intent.privacy_domain_id
          and target.state='ACTIVE_MATCHED' and target.active_generation_digest=target.desired_generation_digest
          and target.policy_generation_digest='sha256:'||(convert_from(intent.preparation_bytes,'UTF8')::jsonb->'context'->>'policyGenerationDigest')
         join control.principal executor on executor.participant_id=intent.participant_id
          and executor.principal_id=intent.execution_principal_id and executor.kind='WORKLOAD' and executor.state='ACTIVE'
         where intent.participant_id=$1 and intent.privacy_domain_id=$2 and intent.actor_principal_id=$3
          and intent.deployment_intent_id=$4 and intent.execution_workload_id is not null
          and intent.expires_at>clock_timestamp()
          and exists(select 1 from control.credential credential where credential.participant_id=intent.participant_id
           and credential.principal_id=intent.execution_principal_id and credential.kind='WORKLOAD_MTLS'
           and credential.audience=intent.execution_workload_id and credential.state='ACTIVE'
           and credential.valid_from<=clock_timestamp() and credential.valid_until>clock_timestamp())
         for share of intent,wallet,target`,
        [
          authority.participantId,
          authority.privacyDomainId,
          authority.principalId,
          input.deploymentIntentId.slice('urn:openpc:resource:'.length),
        ],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005');
      const row = selected.rows[0]!;
      if (!row.moduleGenerationDigest?.equals(moduleGenerationDigest))
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
      let predecessorRecordBytes: string | undefined;
      if (input.predecessorOperationId !== undefined) {
        const predecessor = await client.query<{ preparationBytes: Buffer }>(predecessorSource, [
          authority.participantId,
          authority.privacyDomainId,
          authority.principalId,
          input.predecessorOperationId.slice('urn:openpc:operation:'.length),
        ]);
        if (predecessor.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005');
        predecessorRecordBytes = `0x${predecessor.rows[0]!.preparationBytes.toString('hex')}`;
      }
      // This checks the exact immutable signing preimage, signer and context.
      // It does not reserve an address or establish live workload authorization.
      deploymentReservationCore({
        publication: JSON.parse(row.publicationBytes.toString('utf8')),
        recordBytes: `0x${row.preparationBytes.toString('hex')}`,
        signedTransaction: input.signedTransaction,
        commandId,
        attemptId,
        nowMs: Number(row.nowMs),
        ...(predecessorRecordBytes === undefined ? {} : { predecessorRecordBytes }),
      });
      // The atomic owner retains the approved candidate, operation and outbox.
      // Only the worker can subsequently claim the global reservation and hand
      // these same IDs to the live target/PDS/Broker admission path.
      return {
        result: undefined,
        revision: '1',
        asynchronous: true,
        outboxEventType: 'openpc.deployment.submission.requested.v1',
      };
    });
  }
}
