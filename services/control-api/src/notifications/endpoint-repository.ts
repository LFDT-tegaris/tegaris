import {
  businessTransitionProfileForOperation,
  BusinessSigningTrustError,
  controlMutationForAction,
} from '@openpc/security-kernel';
import type { Pool, PoolClient } from 'pg';
import type { NotificationEndpoint } from '../../../../generated/typescript/openapi/types.gen.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import { sha256 } from '../configuration/digest.js';
import { selectPage, type ListRequest, type PageResult } from '../configuration/pagination.js';
import { AtomicConfigurationMutation } from '../configuration/persistence/atomic-mutation.js';
import type { ConfigurationBusinessEvidence } from '../configuration/persistence/business-receipt-writer.js';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../configuration/persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
  type OperationRecord,
} from '../configuration/persistence/types.js';
import {
  assertNotificationEndpointCreate,
  assertNotificationEndpointReplacement,
  assertNotificationEndpointVerification,
  bindNotificationEndpointBusinessState,
  endpointBinding,
  readNotificationEndpointBusinessState,
  type NotificationEndpointBusinessState,
} from './endpoint-business-state.js';
import { endpointStateAfterReplacement } from './endpoint-binding.js';
import {
  acquireNotificationInstallationFence,
  currentNotificationChannel,
  readNotificationReplacementChoices,
} from './endpoint-admission.js';
import {
  assertNotificationEndpointConstruction,
  assertNotificationEndpointVerificationObservation,
  requireNotificationEndpointOwners,
  type NotificationEndpointOwners,
} from './endpoint-owner-contract.js';
import {
  endpointRequest,
  NotificationEndpointResolution,
  type EndpointCommand,
  type EndpointCreateInput,
  type EndpointUpdateInput,
  type EndpointVerifyInput,
} from './endpoint-resolution.js';

const projection = `endpoint_id::text as "notificationEndpointId",participant_id::text as "participantId",
  channel,destination_ref as "destinationRef",state,arbitrary_egress as "arbitraryEgress",revision::text,
  to_char(created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "createdAt",
  to_char(updated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "updatedAt"`;

function record(row: NotificationEndpoint): NotificationEndpoint {
  // Explicit public projection: no credential/profile/candidate/verification material.
  return {
    notificationEndpointId: `urn:openpc:resource:${row.notificationEndpointId}`,
    participantId: `urn:openpc:participant:${row.participantId}`,
    channel: row.channel,
    destinationRef: row.destinationRef,
    state: row.state,
    arbitraryEgress: row.arbitraryEgress,
    revision: row.revision,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}
function integrationMissing(): never {
  throw new ConfigurationRepositoryError('PC-INTEGRATION-5001');
}
function conflict(): never {
  throw new ConfigurationRepositoryError('PC-DATA-6007');
}

/** Actual operation-specific SQL admission; missing migrations or role grants
 * remain integration failures. This runs inside the real mutation transaction. */
export async function requireCanonicalEndpointPersistence(
  client: PoolClient,
  context: MutationContext,
): Promise<void> {
  const profile = businessTransitionProfileForOperation(context.catalogOperationId);
  if (!profile || String(profile.aggregateType) !== 'notification-endpoint') integrationMissing();
  try {
    await client.query('select openpc.assert_notification_endpoint_persistence($1,$2)', [
      context.catalogOperationId,
      Buffer.from(profile.profileDigest.slice(7), 'hex'),
    ]);
  } catch (error) {
    if (
      error &&
      typeof error === 'object' &&
      'code' in error &&
      ['42883', '42P01', '42501', 'P0002', 'P0003', 'P0001'].includes(String(error.code))
    )
      integrationMissing();
    throw error;
  }
}

export class NotificationEndpointRepository {
  private readonly reads: ScopedConfigurationRead;
  private readonly resolution: NotificationEndpointResolution;

  constructor(
    private readonly pool: Pool,
    private readonly identityRuntimeVerifier?: IdentityRuntimeVerifier,
    private readonly businessEvidence?: ConfigurationBusinessEvidence,
    private readonly owners?: NotificationEndpointOwners,
  ) {
    this.reads = new ScopedConfigurationRead(pool);
    this.resolution = new NotificationEndpointResolution(owners);
  }

  private profile(context: MutationContext, command: EndpointCommand) {
    requireNotificationEndpointOwners(this.owners);
    if (
      typeof this.identityRuntimeVerifier?.verifyCanonicalAssertion !== 'function' ||
      typeof this.businessEvidence?.signer?.sign !== 'function' ||
      !this.businessEvidence.environmentId
    )
      integrationMissing();
    const operationId = `CFG-OP-${command}-NOTIFICATION-ENDPOINT`;
    const profile = businessTransitionProfileForOperation(operationId);
    if (!profile) integrationMissing();
    const operation = controlMutationForAction(context.actionIntentId, operationId);
    if (
      !operation ||
      context.catalogOperationId !== operationId ||
      context.aggregateType !== 'notification-endpoint' ||
      String(profile.aggregateType) !== context.aggregateType ||
      profile.actionIntentId !== context.actionIntentId ||
      profile.resourceType !== context.resourceType ||
      operation.resourceType !== context.resourceType ||
      operation.operationClass !== context.operationClass ||
      operation.makerCheckerRequired ||
      operation.stepUpRequired !== (command !== 'VERIFY')
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    return profile;
  }

  private async execute(
    context: MutationContext,
    command: EndpointCommand,
    apply: (
      client: PoolClient,
      before: Readonly<NotificationEndpointBusinessState> | undefined,
      operationId: string,
    ) => Promise<{
      result: NotificationEndpoint;
      assert: (after: Readonly<NotificationEndpointBusinessState> | undefined) => void;
      revalidate: () => void;
    }>,
  ): Promise<OperationRecord> {
    // Fail before opening a transaction while any canonical dependency is absent.
    // Once installed, AtomicConfigurationMutation owns signer discovery/fencing,
    // fresh WebAuthn, idempotency, signed state/outbox and ambiguous-COMMIT recovery.
    const profile = this.profile(context, command);
    const scope = {
      participantId: context.authorization.participantId,
      privacyDomainId: context.authorization.privacyDomainId,
      aggregateId: context.resourceId,
    };
    const binding = {
      ...scope,
      aggregateType: context.aggregateType,
      profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
    };
    let revalidate: (() => void) | undefined;
    const verifier = this.identityRuntimeVerifier;
    if (!verifier) integrationMissing();
    const sourceFence = await acquireNotificationInstallationFence(this.pool, context, verifier);
    let primaryFailure: unknown;
    let failed = false;
    let result: OperationRecord | undefined;
    try {
      result = await new AtomicConfigurationMutation(
        sourceFence.mutationPool,
        verifier,
        this.businessEvidence,
        requireCanonicalEndpointPersistence,
      )
        .execute(
          context,
          async (client, _resourceId, operationId) => {
            const before = await readNotificationEndpointBusinessState(client, scope);
            if (
              command === 'CREATE'
                ? before !== undefined
                : !before || before.revision !== context.expectedRevision
            )
              conflict();
            const written = await apply(client, before, operationId);
            const after = await readNotificationEndpointBusinessState(client, scope);
            written.assert(after);
            revalidate = written.revalidate;
            return {
              result: written.result,
              revision: written.result.revision,
              outboxEventType: 'io.openpc.control.command.committed.v1',
              businessState: {
                before: bindNotificationEndpointBusinessState(binding, before),
                after: bindNotificationEndpointBusinessState(binding, after),
              },
            };
          },
          undefined,
          async (client) => {
            // Each serialization attempt replaces its own expiry check. Provider and
            // installation/restriction fences remain held through the attempt.
            revalidate = undefined;
            return {
              revalidate: async () => {
                await sourceFence.revalidate();
                if (!revalidate) conflict();
                revalidate();
                const after = await readNotificationEndpointBusinessState(client, scope);
                if (!after) conflict();
                const current = await currentNotificationChannel(
                  client,
                  scope,
                  after.credentialRef,
                );
                if (current.channel.signedProfileDigest !== after.channelProfileDigest) conflict();
                // The same installation/Identity fences are retained through COMMIT. Time
                // bounds are re-evaluated after signing, not only at construction.
                revalidate();
              },
              release: async () => {},
            };
          },
        )
        .catch((error: unknown) => {
          // The shared mutation owner has already rolled back. Missing/stale signer
          // admission cannot fall back to an unsigned endpoint mutation.
          if (error instanceof BusinessSigningTrustError) integrationMissing();
          throw error;
        });
    } catch (error) {
      primaryFailure = error;
      failed = true;
    }
    try {
      await sourceFence.release();
    } catch (error) {
      // Never retry a business effect here. Cleanup uncertainty requires original-key
      // readback; retain the original failure as well when the mutation failed.
      if (failed)
        throw new AggregateError(
          [primaryFailure, error],
          'Notification mutation and source cleanup failed',
        );
      throw error;
    }
    if (failed) throw primaryFailure;
    if (!result) integrationMissing();
    return result;
  }

  async replacements(context: ReadContext) {
    if (
      context.actionIntentId !== 'ACT-NOTIFICATION_ENDPOINTS_READ_RESOURCE-V1' ||
      context.resourceType !== 'notification-endpoints'
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    return this.reads.execute(context, async (client) => {
      const before = await readNotificationEndpointBusinessState(
        client,
        {
          participantId: context.authorization.participantId,
          privacyDomainId: context.authorization.privacyDomainId,
          aggregateId: context.resourceId,
        },
        'NONE',
      );
      if (!before) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return {
        notificationEndpointId: `urn:openpc:resource:${context.resourceId}`,
        revision: before.revision,
        authority: 'NONE' as const,
        items: await readNotificationReplacementChoices(client, before),
      };
    });
  }

  async create(context: MutationContext, value: EndpointCreateInput): Promise<OperationRecord> {
    const input = endpointRequest(context, 'CREATE', value);
    const bound = { ...context, candidate: input };
    const candidateDigest = sha256(input);
    return this.execute(bound, 'CREATE', async (client, before) => {
      const construction = await this.resolution.create(client, bound, input);
      const b = construction.binding;
      const inserted = await client.query<NotificationEndpoint>(
        `insert into control.notification_endpoint
        (endpoint_id,participant_id,privacy_domain_id,channel,destination_ref,channel_profile_digest,
         credential_ref,state,arbitrary_egress,revision,candidate_digest,verification_id)
        values($1,$2,$3,$4,$5,$6,$7,'DISABLED',false,1,$8,null) returning ${projection}`,
        [
          b.endpointId,
          b.participantId,
          b.privacyDomainId,
          b.channel,
          b.destinationRef,
          b.channelProfileDigest,
          b.credentialRef,
          candidateDigest,
        ],
      );
      if (inserted.rowCount !== 1 || !inserted.rows[0]) conflict();
      const scope = {
        participantId: b.participantId,
        privacyDomainId: b.privacyDomainId,
        aggregateId: b.endpointId,
      };
      return {
        result: record(inserted.rows[0]),
        assert: (after) =>
          assertNotificationEndpointCreate(scope, before, after, { binding: b, candidateDigest }),
        revalidate: () => {
          assertNotificationEndpointConstruction(b, construction, Date.now());
        },
      };
    });
  }

  async update(context: MutationContext, value: EndpointUpdateInput): Promise<OperationRecord> {
    const input = endpointRequest(context, 'UPDATE', value);
    const bound = { ...context, candidate: input };
    return this.execute(bound, 'UPDATE', async (client, before) => {
      if (!before) conflict();
      const construction = await this.resolution.replacement(client, bound, before, input);
      const b = construction.binding;
      const state = endpointStateAfterReplacement(before.state, endpointBinding(before), b);
      const changed = await client.query<NotificationEndpoint>(
        `update control.notification_endpoint
        set channel=$4,destination_ref=$5,channel_profile_digest=$6,credential_ref=$7,state=$8,
          verification_id=null,revision=$9,candidate_digest=$10,updated_at=clock_timestamp()
        where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3 and revision=$11 and state<>'RETIRED'
        returning ${projection}`,
        [
          b.participantId,
          b.privacyDomainId,
          b.endpointId,
          b.channel,
          b.destinationRef,
          b.channelProfileDigest,
          b.credentialRef,
          state,
          b.revision,
          input.replacementDigest,
          input.expectedRevision,
        ],
      );
      if (changed.rowCount !== 1 || !changed.rows[0]) conflict();
      const scope = {
        participantId: b.participantId,
        privacyDomainId: b.privacyDomainId,
        aggregateId: b.endpointId,
      };
      return {
        result: record(changed.rows[0]),
        assert: (after) =>
          assertNotificationEndpointReplacement(scope, before, after, { ...input, binding: b }),
        revalidate: () => {
          assertNotificationEndpointConstruction(b, construction, Date.now());
        },
      };
    });
  }

  async verify(context: MutationContext, value: EndpointVerifyInput): Promise<OperationRecord> {
    const input = endpointRequest(context, 'VERIFY', value);
    const bound = { ...context, candidate: input };
    return this.execute(bound, 'VERIFY', async (client, before, operationId) => {
      if (!before) conflict();
      const observation = await this.resolution.verify(client, bound, operationId, before, input);
      const b = observation.result.binding;
      const verification = { ...b, verificationId: observation.verificationId };
      // The observation/source receipt remains with its canonical owner. Store
      // only its exact resulting binding and the original atomic operation here.
      const inserted = await client.query(
        `insert into control.notification_endpoint_verification
        (verification_id,participant_id,privacy_domain_id,endpoint_id,endpoint_revision,channel,
         destination_ref,channel_profile_digest,credential_ref,operation_id)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          observation.verificationId,
          b.participantId,
          b.privacyDomainId,
          b.endpointId,
          b.revision,
          b.channel,
          b.destinationRef,
          b.channelProfileDigest,
          b.credentialRef,
          operationId,
        ],
      );
      if (inserted.rowCount !== 1) conflict();
      const changed = await client.query<NotificationEndpoint>(
        `update control.notification_endpoint
        set state='ACTIVE',revision=$4,verification_id=$5,updated_at=clock_timestamp()
        where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3 and revision=$6
          and state in ('DISABLED','ACTIVE') returning ${projection}`,
        [
          b.participantId,
          b.privacyDomainId,
          b.endpointId,
          b.revision,
          observation.verificationId,
          input.expectedRevision,
        ],
      );
      if (changed.rowCount !== 1 || !changed.rows[0]) conflict();
      const scope = {
        participantId: b.participantId,
        privacyDomainId: b.privacyDomainId,
        aggregateId: b.endpointId,
      };
      return {
        result: record(changed.rows[0]),
        assert: (after) =>
          assertNotificationEndpointVerification(scope, before, after, {
            expectedRevision: input.expectedRevision,
            verification,
          }),
        revalidate: () => {
          assertNotificationEndpointVerificationObservation(
            before,
            { operationId, inputDigest: input.inputDigest },
            observation,
            Date.now(),
          );
        },
      };
    });
  }

  async get(context: ReadContext): Promise<NotificationEndpoint> {
    if (
      context.actionIntentId !== 'ACT-NOTIFICATION_ENDPOINTS_READ_RESOURCE-V1' ||
      context.resourceType !== 'notification-endpoints' ||
      context.resourceId === '*'
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    return this.reads.execute(context, async (client) => {
      const found = await client.query<NotificationEndpoint>(
        `select ${projection} from control.notification_endpoint
        where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3`,
        [
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          context.resourceId,
        ],
      );
      if (found.rowCount !== 1 || !found.rows[0])
        throw new ConfigurationRepositoryError('PC-FACT-4001');
      return record(found.rows[0]);
    });
  }

  async list(
    context: ReadContext,
    request: ListRequest,
  ): Promise<PageResult<NotificationEndpoint>> {
    if (
      context.actionIntentId !== 'ACT-NOTIFICATION_ENDPOINTS_READ_COLLECTION-V1' ||
      context.resourceType !== 'notification-endpoints' ||
      context.resourceId !== '*'
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    return this.reads.execute(context, (client) =>
      selectPage<NotificationEndpoint, NotificationEndpoint>(client, request, {
        table: 'control.notification_endpoint',
        idColumn: 'endpoint_id',
        projection,
        filterColumns: { state: 'state', channel: 'channel', destinationRef: 'destination_ref' },
        rowId: (row) => row.notificationEndpointId,
        rowUpdatedAt: (row) => row.updatedAt,
        map: record,
      }),
    );
  }
}
