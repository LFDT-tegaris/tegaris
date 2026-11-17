import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { ConfigurationApiOptions } from '../configuration/http.js';
import { governedResourceMutation, resourceRead } from '../configuration/resource-http.js';
import {
  collectionResponseSchema,
  digestSchema,
  notificationResponseSchema,
  openPcUrnSchema,
  resourceUrnSchema,
} from '../configuration/resource-contracts.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import {
  createNotificationEndpointSchema,
  updateNotificationEndpointSchema,
  verifyNotificationEndpointSchema,
} from './contracts.js';
import { notificationChannel } from './endpoint-binding.js';
import { NotificationEndpointRepository } from './endpoint-repository.js';
import { NotificationEndpointVerificationWorkflow } from './endpoint-verification-workflow.js';

const response = notificationResponseSchema
  .pick({ participantId: true, revision: true, createdAt: true, updatedAt: true })
  .extend({
    notificationEndpointId: resourceUrnSchema,
    channel: notificationChannel,
    destinationRef: openPcUrnSchema,
    arbitraryEgress: z.literal(false),
    state: z.enum(['ACTIVE', 'DISABLED', 'QUARANTINED', 'RETIRED']),
  });

export const notificationReplacementChoices = z.strictObject({
  notificationEndpointId: resourceUrnSchema,
  revision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  authority: z.literal('NONE'),
  items: z
    .array(
      z.strictObject({
        channel: notificationChannel,
        destinationRef: resourceUrnSchema,
        replacementDigest: digestSchema,
      }),
    )
    .max(64),
});

/** Public endpoint operations retain the shared authentication/request boundary.
 * Only explicitly composed verification may prepare and dispatch its real source;
 * missing workload/provider composition does not change metadata capability. */
export function registerNotificationEndpointRoutes(
  app: FastifyInstance,
  options: ConfigurationApiOptions,
  verification?: NotificationEndpointVerificationWorkflow,
): void {
  const endpoints = new NotificationEndpointRepository(
    options.pool,
    options.identityRuntimeVerifier,
    options.businessEvidence,
    options.notificationEndpointOwners,
  );
  app.get(
    '/api/v1/notification-endpoints',
    resourceRead(
      options,
      'notification-endpoints',
      'ACT-NOTIFICATION_ENDPOINTS_READ_COLLECTION-V1',
      (context, request) => {
        if (!request) throw new ConfigurationRepositoryError('PC-DATA-6004');
        return endpoints.list(context, request);
      },
      collectionResponseSchema(response),
      new Set(['state', 'channel', 'destinationRef']),
    ),
  );
  app.get(
    '/api/v1/notification-endpoints/:id',
    resourceRead(
      options,
      'notification-endpoints',
      'ACT-NOTIFICATION_ENDPOINTS_READ_RESOURCE-V1',
      (context) => endpoints.get(context),
      response,
    ),
  );
  app.get(
    '/api/v1/notification-endpoints/:id/replacements',
    resourceRead(
      options,
      'notification-endpoints',
      'ACT-NOTIFICATION_ENDPOINTS_READ_RESOURCE-V1',
      (context) => endpoints.replacements(context),
      notificationReplacementChoices,
    ),
  );
  app.post(
    '/api/v1/notification-endpoints',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-NOTIFICATION-ENDPOINT',
      createNotificationEndpointSchema,
      (context, body) => endpoints.create(context, body),
    ),
  );
  app.patch(
    '/api/v1/notification-endpoints/:id',
    governedResourceMutation(
      options,
      'CFG-OP-UPDATE-NOTIFICATION-ENDPOINT',
      updateNotificationEndpointSchema,
      (context, body) => endpoints.update(context, body),
    ),
  );
  app.post(
    '/api/v1/notification-endpoints/:id/verify',
    governedResourceMutation(
      options,
      'CFG-OP-VERIFY-NOTIFICATION-ENDPOINT',
      verifyNotificationEndpointSchema,
      (context, body) => {
        if (!(verification instanceof NotificationEndpointVerificationWorkflow))
          throw new ConfigurationRepositoryError('PC-INTEGRATION-5001');
        return verification.verify(context, body);
      },
    ),
  );
}
