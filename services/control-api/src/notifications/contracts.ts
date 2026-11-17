import { z } from 'zod';
import {
  actionEnvelopeSchema,
  digestSchema,
  openPcUrnSchema,
} from '../configuration/resource-contracts.js';
import { sequence } from '../evidence/segment.js';
import { notificationChannel } from './endpoint-binding.js';

export const createNotificationEndpointSchema = actionEnvelopeSchema
  .extend({
    participantId: openPcUrnSchema,
    channel: notificationChannel,
    destinationRef: openPcUrnSchema,
    arbitraryEgress: z.literal(false),
  })
  .strict();
export const createNotificationSchema = actionEnvelopeSchema
  .extend({
    participantId: openPcUrnSchema,
    severity: z.enum(['INFO', 'WARNING', 'ERROR', 'CRITICAL']),
    resourceRef: openPcUrnSchema.nullable(),
    messageKey: z.string().regex(/^[a-z][a-z0-9.]{2,127}$/u),
  })
  .strict();
const replacement = actionEnvelopeSchema
  .extend({
    expectedRevision: sequence,
    replacementDigest: digestSchema,
  })
  .strict();
export const updateNotificationSchema = replacement;
export const updateNotificationEndpointSchema = replacement;
const command = actionEnvelopeSchema
  .extend({
    targetRef: openPcUrnSchema,
    expectedRevision: sequence,
    inputDigest: digestSchema,
  })
  .strict();
export const verifyNotificationEndpointSchema = command;
export const acknowledgeNotificationSchema = command;
