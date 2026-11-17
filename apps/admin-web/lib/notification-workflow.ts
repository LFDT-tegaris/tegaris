import { z } from 'zod';
import type {
  Notification,
  NotificationPage,
  Operation,
} from '../../../generated/typescript/openapi/types.gen';
import {
  actionEnvelopeSchema,
  collectionResponseSchema,
  digestSchema,
  notificationResponseSchema,
  openPcUrnSchema,
  operationResponseSchema,
  uuidSchema,
} from '../../../services/control-api/src/configuration/resource-contracts';

// Browser-safe projections of the existing owners, not a second business model.
export const notificationEndpoint = '/api/v1/ui/notification-workbench';
const exact = (value: string) => value === value.trim();
export const notificationId = uuidSchema.refine(exact);
export const notificationRef = openPcUrnSchema.refine(
  (value) => exact(value) && value.startsWith('urn:openpc:resource:'),
);
const revision = notificationResponseSchema.shape.revision.refine(
  (value) =>
    exact(value) && /^[1-9][0-9]{0,19}$/u.test(value) && BigInt(value) <= 18446744073709551615n,
);
export const notificationEtag = z
  .string()
  .regex(/^"sha256:[0-9a-f]{64}"$/u)
  .refine(exact);
export const notificationBinding = z.strictObject({
  actorKey: digestSchema.refine(exact),
  actor: z.strictObject({ participantId: notificationId, privacyDomainId: notificationId }),
});
export const notificationCreateFields = notificationResponseSchema
  .pick({
    severity: true,
    resourceRef: true,
    messageKey: true,
  })
  .extend({ reason: actionEnvelopeSchema.shape.reason })
  .strict();
const request = { actorKey: notificationBinding.shape.actorKey, requestKey: z.uuid() };
export const notificationCommand = z.discriminatedUnion('command', [
  z.strictObject({ ...request, command: z.literal('CREATE'), ...notificationCreateFields.shape }),
  z.strictObject({
    ...request,
    command: z.literal('ACKNOWLEDGE'),
    notificationRef,
    expectedRevision: revision,
    etag: notificationEtag,
    reason: actionEnvelopeSchema.shape.reason,
  }),
]);
export const notificationQuery = z.discriminatedUnion('view', [
  z.strictObject({
    view: z.literal('LIST'),
    cursor: collectionResponseSchema(notificationResponseSchema)
      .shape.nextCursor.unwrap()
      .optional(),
    limit: z.enum(['10', '25', '50']).default('25'),
    filter: z
      .string()
      .max(512)
      .regex(/^(state|severity|resourceRef|messageKey):(eq|ne|prefix):[^\r\n]+(?![\s\S])/u)
      .optional(),
    sort: z.enum(['updatedAt', '-updatedAt']).default('-updatedAt'),
  }),
  z.strictObject({ view: z.literal('DETAIL'), actorKey: request.actorKey, notificationRef }),
  z.strictObject({
    view: z.literal('OPERATION'),
    actorKey: request.actorKey,
    operationId: notificationId,
  }),
]);
export const notificationView = z.discriminatedUnion('kind', [
  notificationBinding
    .extend({ kind: z.literal('LIST'), page: collectionResponseSchema(notificationResponseSchema) })
    .strict(),
  notificationBinding
    .extend({
      kind: z.literal('DETAIL'),
      notification: notificationResponseSchema,
      etag: notificationEtag,
    })
    .strict(),
  notificationBinding
    .extend({
      kind: z.literal('OPERATION'),
      operation: operationResponseSchema.omit({ signingResult: true }).strict(),
    })
    .strict(),
]);
export type NotificationCommand = z.infer<typeof notificationCommand>;
export type NotificationView = z.infer<typeof notificationView>;
export type NotificationBinding = z.infer<typeof notificationBinding>;
export type { Notification, NotificationPage, Operation };

// Recovery hints confer no authority. The server authenticates and binds every
// use again. Persist only the original request/result identity, never credentials.
export const notificationPending = z.strictObject({
  request: notificationCommand,
  operationId: notificationId.optional(),
  uncertain: z.boolean(),
});
export type NotificationPending = z.infer<typeof notificationPending>;
