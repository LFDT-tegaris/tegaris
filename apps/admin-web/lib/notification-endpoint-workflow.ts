import { z } from 'zod';
import type { NotificationEndpoint } from '../../../generated/typescript/openapi/types.gen';
import { safeProblemSchema } from '@openpc/ui-shell';
import {
  actionEnvelopeSchema,
  collectionResponseSchema,
  digestSchema,
  notificationResponseSchema,
  openPcUrnSchema,
  operationResponseSchema,
  resourceUrnSchema,
} from '../../../services/control-api/src/configuration/resource-contracts';
import {
  notificationChannel,
  notificationEndpointState,
  notificationRevision,
} from '../../../services/control-api/src/notifications/endpoint-binding';
import { notificationBinding, notificationEtag, notificationId } from './notification-workflow';

export const notificationEndpointWorkbench = '/api/v1/ui/notification-endpoint-workbench';
export const endpointCreateAction = {
  id: 'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1',
  digest: 'sha256:5c86363197220c6ef9e4dfa653b551c758e2fd117276fa0fe8f2bdaa49a7ffc0',
} as const;
export const endpointUpdateAction = {
  id: 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
  digest: 'sha256:8d3db9f82f631334222a946973f6ea8de29484f231b566a6bef0d16792b2a5ec',
} as const;
export const endpointVerifyActionId = 'ACT-NOTIFICATION_UPDATE_VERIFY-V1';
export const endpointRequestKey = (value: string) => `workbench-notification-endpoint-${value}`;
export const endpointRef = resourceUrnSchema.refine(
  (value) => value === value.trim() && value.startsWith('urn:openpc:resource:'),
);
const revision = notificationRevision;
// Exact projection of NotificationEndpointV1. No private installation, credential,
// challenge, proof or transport bytes are part of the public model.
export const endpointRecord = notificationResponseSchema
  .pick({ participantId: true, revision: true, createdAt: true, updatedAt: true })
  .extend({
    notificationEndpointId: endpointRef,
    channel: notificationChannel,
    destinationRef: openPcUrnSchema,
    arbitraryEgress: z.literal(false),
    state: notificationEndpointState,
    revision,
  })
  .strict() satisfies z.ZodType<NotificationEndpoint>;
const request = { actorKey: notificationBinding.shape.actorKey, requestKey: z.uuid() };
const selected = { endpointRef, expectedRevision: revision, etag: notificationEtag };
const creation = {
  ...request,
  ...endpointRecord.pick({ channel: true, destinationRef: true, arbitraryEgress: true }).shape,
  reason: actionEnvelopeSchema.shape.reason,
};
const replacement = {
  ...request,
  ...selected,
  replacementDigest: digestSchema,
  reason: actionEnvelopeSchema.shape.reason,
};
// Public choice projection committed in fe1c4f9c. Informational only; PATCH
// admits the chosen immutable binding under its own authorization transaction.
export const endpointReplacementChoice = z.strictObject({
  channel: notificationChannel,
  destinationRef: openPcUrnSchema,
  replacementDigest: digestSchema,
});
export const endpointReplacements = z.strictObject({
  notificationEndpointId: endpointRef,
  revision,
  authority: z.literal('NONE'),
  items: z.array(endpointReplacementChoice).max(64),
});
export const endpointCommand = z.discriminatedUnion('command', [
  z.strictObject({
    ...request,
    command: z.literal('VERIFY'),
    ...selected,
    reason: actionEnvelopeSchema.shape.reason,
  }),
  z.strictObject({
    ...creation,
    command: z.literal('CREATE'),
    candidateDigest: digestSchema,
  }),
  z.strictObject({
    ...replacement,
    command: z.literal('UPDATE'),
    candidateDigest: digestSchema,
  }),
  z.strictObject({ ...creation, command: z.literal('REVIEW_CREATE') }),
  z.strictObject({ ...replacement, command: z.literal('REVIEW_UPDATE') }),
]);
export const endpointQuery = z.discriminatedUnion('view', [
  z.strictObject({
    view: z.literal('LIST'),
    limit: z.enum(['10', '25', '50']).default('25'),
    cursor: collectionResponseSchema(endpointRecord).shape.nextCursor.unwrap().optional(),
    filter: z
      .string()
      .max(512)
      .regex(/^(state|channel|destinationRef):(eq|ne|prefix):[^\r\n]+(?![\s\S])/u)
      .optional(),
    sort: z.enum(['updatedAt', '-updatedAt']).default('-updatedAt'),
  }),
  z.strictObject({ view: z.literal('DETAIL'), actorKey: request.actorKey, endpointRef }),
  z.strictObject({ view: z.literal('REPLACEMENTS'), actorKey: request.actorKey, endpointRef }),
  z.strictObject({
    view: z.literal('OPERATION'),
    actorKey: request.actorKey,
    operationId: notificationId,
  }),
]);
export const endpointOperation = operationResponseSchema.omit({ signingResult: true }).strict();
export const endpointCreationRequest = endpointCommand.options[1];
export const endpointUpdateRequest = endpointCommand.options[2];
export const endpointMutation = z.union([
  endpointCommand.options[0],
  endpointCreationRequest,
  endpointUpdateRequest,
]);
export const endpointView = z.discriminatedUnion('kind', [
  notificationBinding
    .extend({ kind: z.literal('REPLACEMENTS'), choices: endpointReplacements })
    .strict(),
  notificationBinding
    .extend({
      kind: z.literal('UPDATE_REVIEW'),
      request: endpointUpdateRequest,
      choice: endpointReplacementChoice,
      stepUp: z.strictObject({
        actionIntentId: z.literal(endpointUpdateAction.id),
        actionIntentDigest: z.literal(endpointUpdateAction.digest),
        resourceId: z.uuid(),
        resourceDigest: digestSchema,
      }),
    })
    .strict(),
  notificationBinding
    .extend({
      kind: z.literal('CREATE_REVIEW'),
      request: endpointCreationRequest,
      stepUp: z.strictObject({
        actionIntentId: z.literal(endpointCreateAction.id),
        actionIntentDigest: z.literal(endpointCreateAction.digest),
        resourceId: z.uuid(),
        resourceDigest: digestSchema,
      }),
    })
    .strict(),
  notificationBinding
    .extend({ kind: z.literal('LIST'), page: collectionResponseSchema(endpointRecord) })
    .strict(),
  notificationBinding
    .extend({ kind: z.literal('DETAIL'), endpoint: endpointRecord, etag: notificationEtag })
    .strict(),
  notificationBinding
    .extend({ kind: z.literal('OPERATION'), operation: endpointOperation })
    .strict(),
]);
export const endpointUnknownProblem = z.strictObject({
  type: z.literal('https://errors.openpc.local/conflict'),
  title: z.string().min(1).max(160),
  status: z.literal(409),
  code: z.literal('PC-FACT-4001'),
  truthState: z.literal('UNKNOWN'),
  retryable: z.literal(false),
  traceId: notificationId,
});
export const endpointProblem = z.union([endpointUnknownProblem, safeProblemSchema]);
export const endpointPending = z.strictObject({
  request: endpointMutation,
  operationId: notificationId.optional(),
  uncertain: z.boolean(),
});
export type EndpointCommand = z.infer<typeof endpointCommand>;
export type EndpointMutation = z.infer<typeof endpointMutation>;
export type EndpointUpdateCommand = z.infer<typeof endpointUpdateRequest>;
export type EndpointCreateCommand = z.infer<typeof endpointCreationRequest>;
export type EndpointVerifyCommand = Extract<EndpointCommand, { command: 'VERIFY' }>;
export type EndpointView = z.infer<typeof endpointView>;
export type EndpointPending = z.infer<typeof endpointPending>;
export type EndpointOperation = z.infer<typeof endpointOperation>;
export type EndpointBinding = z.infer<typeof notificationBinding>;

export function endpointOperationMatches(
  operation: EndpointOperation,
  request: EndpointMutation,
): boolean {
  return (
    operation.actionIntentId ===
      (request.command === 'CREATE'
        ? endpointCreateAction.id
        : request.command === 'UPDATE'
          ? endpointUpdateAction.id
          : endpointVerifyActionId) &&
    (request.command === 'CREATE'
      ? endpointRef.safeParse(operation.resourceRef).success
      : operation.resourceRef === request.endpointRef) &&
    operation.idempotencyKey === endpointRequestKey(request.requestKey)
  );
}
// Only explicit no-effect rejections may release a first request. UNKNOWN,
// malformed responses, transport loss and later denials retain uncertainty.
export function endpointDefiniteRejection(value: unknown, status: number): boolean {
  const result = endpointProblem.safeParse(value);
  if (!result.success || result.data.status !== status) return false;
  return (
    (result.data.code === 'PC-DATA-6004' && result.data.truthState === 'FAILED') ||
    (result.data.code === 'PC-DATA-6007' && result.data.truthState === 'STALE')
  );
}
