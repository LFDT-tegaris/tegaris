import type { PoolClient } from 'pg';
import { controlMutationForAction } from '@openpc/security-kernel';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../configuration/persistence/types.js';
import {
  createNotificationEndpointSchema,
  updateNotificationEndpointSchema,
  verifyNotificationEndpointSchema,
} from './contracts.js';
import {
  endpointBinding,
  parseNotificationEndpointBusinessState,
  type NotificationEndpointBusinessState,
} from './endpoint-business-state.js';
import {
  notificationEndpointConstruction,
  assertNotificationEndpointConstruction,
  assertNotificationEndpointVerificationObservation,
  notificationEndpointReplacementDigest,
  requireNotificationEndpointOwners,
  type NotificationEndpointOwners,
} from './endpoint-owner-contract.js';

export type EndpointCreateInput = z.infer<typeof createNotificationEndpointSchema>;
export type EndpointUpdateInput = z.infer<typeof updateNotificationEndpointSchema>;
export type EndpointVerifyInput = z.infer<typeof verifyNotificationEndpointSchema>;
export type EndpointCommand = 'CREATE' | 'UPDATE' | 'VERIFY';

function rejected(): never {
  throw new ConfigurationRepositoryError('PC-DATA-6007');
}

/** Request consistency only. AtomicConfigurationMutation remains the actual
 * session, policy, fresh WebAuthn, replay and signed mutation authority. */
export function endpointRequest<
  T extends EndpointCreateInput | EndpointUpdateInput | EndpointVerifyInput,
>(context: MutationContext, command: EndpointCommand, value: T): Readonly<T> {
  const schema =
    command === 'CREATE'
      ? createNotificationEndpointSchema
      : command === 'UPDATE'
        ? updateNotificationEndpointSchema
        : verifyNotificationEndpointSchema;
  const operation = controlMutationForAction(
    context.actionIntentId,
    `CFG-OP-${command}-NOTIFICATION-ENDPOINT`,
  );
  if (
    !operation ||
    operation.resourceType !== context.resourceType ||
    operation.operationClass !== context.operationClass
  )
    rejected();
  const supplied = schema.safeParse(value);
  const candidate = schema.safeParse(context.candidate);
  if (
    !supplied.success ||
    !candidate.success ||
    sha256(supplied.data) !== sha256(candidate.data) ||
    supplied.data.actionIntentId !== context.actionIntentId ||
    supplied.data.actionIntentDigest !== context.actionIntentDigest ||
    context.catalogOperationId !== `CFG-OP-${command}-NOTIFICATION-ENDPOINT` ||
    context.aggregateType !== 'notification-endpoint'
  )
    rejected();
  if (command === 'CREATE') {
    const input = createNotificationEndpointSchema.parse(supplied.data);
    if (
      context.expectedRevision !== '0' ||
      input.participantId !== `urn:openpc:participant:${context.authorization.participantId}`
    )
      rejected();
  } else {
    const input =
      command === 'UPDATE'
        ? updateNotificationEndpointSchema.parse(supplied.data)
        : verifyNotificationEndpointSchema.parse(supplied.data);
    if (
      input.expectedRevision !== context.expectedRevision ||
      ('targetRef' in input && input.targetRef !== `urn:openpc:resource:${context.resourceId}`)
    )
      rejected();
  }
  return Object.freeze(supplied.data) as Readonly<T>;
}

function predecessor(context: MutationContext, value: Readonly<NotificationEndpointBusinessState>) {
  const before = parseNotificationEndpointBusinessState(
    {
      participantId: context.authorization.participantId,
      privacyDomainId: context.authorization.privacyDomainId,
      aggregateId: context.resourceId,
    },
    value,
  );
  if (!before || before.revision !== context.expectedRevision) rejected();
  return before;
}

/** A consumer of constructor-owned implementations, NOT an authoritative
 * resolver. There is no default, public injection point, secret access or I/O
 * outside the exact PoolClient supplied by the atomic mutation owner. */
export class NotificationEndpointResolution {
  constructor(private readonly owners?: NotificationEndpointOwners) {}

  async create(client: PoolClient, context: MutationContext, value: EndpointCreateInput) {
    const input = endpointRequest(context, 'CREATE', value);
    const owners = requireNotificationEndpointOwners(this.owners);
    const selected = notificationEndpointConstruction.safeParse(
      await owners.resolveCreate(client, context, input),
    );
    if (!selected.success) rejected();
    return assertNotificationEndpointConstruction(
      {
        ...selected.data.binding,
        participantId: context.authorization.participantId,
        privacyDomainId: context.authorization.privacyDomainId,
        endpointId: context.resourceId,
        revision: '1',
        channel: input.channel,
        destinationRef: input.destinationRef,
      },
      selected.data,
      Date.now(),
    );
  }

  async replacement(
    client: PoolClient,
    context: MutationContext,
    value: Readonly<NotificationEndpointBusinessState>,
    request: EndpointUpdateInput,
  ) {
    const input = endpointRequest(context, 'UPDATE', request);
    const before = predecessor(context, value);
    if (before.state === 'RETIRED') rejected();
    const owners = requireNotificationEndpointOwners(this.owners);
    const selected = notificationEndpointConstruction.safeParse(
      await owners.resolveReplacement(client, context, before, input),
    );
    if (!selected.success) rejected();
    const resolved = assertNotificationEndpointConstruction(
      {
        ...selected.data.binding,
        participantId: before.participantId,
        privacyDomainId: before.privacyDomainId,
        endpointId: before.endpointId,
        revision: String(BigInt(before.revision) + 1n),
      },
      selected.data,
      Date.now(),
    );
    if (
      notificationEndpointReplacementDigest(endpointBinding(before), resolved) !==
        input.replacementDigest ||
      input.replacementDigest === before.candidateDigest
    )
      rejected();
    return resolved;
  }

  async verify(
    client: PoolClient,
    context: MutationContext,
    operationId: string,
    value: Readonly<NotificationEndpointBusinessState>,
    request: EndpointVerifyInput,
  ) {
    const input = endpointRequest(context, 'VERIFY', request);
    const before = predecessor(context, value);
    if (!['DISABLED', 'ACTIVE'].includes(before.state)) rejected();
    const owners = requireNotificationEndpointOwners(this.owners);
    const observed = await owners.verify(client, context, operationId, before, input);
    return assertNotificationEndpointVerificationObservation(
      before,
      { operationId, inputDigest: input.inputDigest },
      observed,
      Date.now(),
    );
  }
}
