import { z } from 'zod';
import type { OpenPcEventEnvelopeV1 } from '../../../../generated/typescript/json-schema/event-envelope.js';
import { canonicalJson } from '../configuration/digest.js';
import type {
  EvidenceExportCompletedDataV1,
  NotificationDeliveryRequestedDataV1,
} from '../../../../generated/typescript/json-schema/event-payloads.js';
import { digestSchema, openPcUrnSchema, uuidSchema } from '../configuration/resource-contracts.js';
import { sequence } from '../evidence/segment.js';
import {
  notificationDeliveryIdentity,
  type NotificationDeliveryIdentity,
} from './delivery-policy.js';
import {
  notificationEndpointBinding,
  type NotificationEndpointBinding,
} from './endpoint-binding.js';

// Closed registered projections; structural parsing and retained-value comparison
// are never producer authentication, current authorization or durable admission.
const unpadded = (value: string) => value === value.trim();
const wireReference = openPcUrnSchema.refine(unpadded);
const wireDigest = digestSchema.refine(unpadded);
// Stop before the shared BigInt refinement on malformed strings. A schema
// rejection must remain a typed, secret-free input error rather than SyntaxError.
const wireCounter = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u, { abort: true })
  .refine(unpadded, { abort: true })
  .pipe(sequence);
const wireUuid = uuidSchema.refine(unpadded);
const evidenceExportCompleted = z.strictObject({
  evidenceExportId: wireReference,
  checkpoint: wireCounter,
  outputDigest: wireDigest,
  recordCount: wireCounter,
});
const notificationDeliveryRequested = z.strictObject({
  notificationOccurrenceId: wireReference,
  endpointId: wireReference,
  templateDigest: wireDigest,
  payloadDigest: wireDigest,
});
const contextScope = notificationDeliveryIdentity.pick({
  participantId: true,
  privacyDomainId: true,
});

export class NotificationEventInputError extends Error {
  constructor(
    readonly reason:
      | 'INVALID_DATA'
      | 'INVALID_ENVELOPE'
      | 'REPLAY_MISMATCH'
      | 'INVALID_BINDING'
      | 'SCOPE_MISMATCH'
      | 'BINDING_MISMATCH'
      | 'MISSING_OCCURRENCE_REFERENCE',
  ) {
    // Do not include event, destination, payload or caller-supplied values in diagnostics.
    super(`Notification event input ${reason}`);
  }
}

/** No recipient, delivery intent or success claim can be derived from export metadata. */
export function parseEvidenceExportCompletedData(value: unknown): EvidenceExportCompletedDataV1 {
  const parsed = evidenceExportCompleted.safeParse(value);
  if (!parsed.success) throw new NotificationEventInputError('INVALID_DATA');
  return parsed.data;
}

/** Preserve complete wire references, including their namespaces; do not normalize them to UUIDs. */
export function parseNotificationDeliveryRequestedData(
  value: unknown,
): NotificationDeliveryRequestedDataV1 {
  const parsed = notificationDeliveryRequested.safeParse(value);
  if (!parsed.success) throw new NotificationEventInputError('INVALID_DATA');
  return parsed.data;
}

/** Structural consistency only, not authority. P0 must authenticate the event and
 * trustedContext, load this occurrence's endpoint/template/payload bindings from
 * their authoritative stores, and recheck current restrictions under its fence.
 *
 * The committed event schema gives the occurrence reference only as OpenPcUrn;
 * no occurrence-specific namespace formatter is established. Therefore the exact
 * retained wire reference must come from its owning producer/admission. It cannot
 * be inferred from the incoming event, an endpoint, or the internal UUID. */
export function matchNotificationDeliveryRequestedData(
  value: unknown,
  bindings: {
    readonly trustedContext: Pick<
      NotificationDeliveryIdentity,
      'participantId' | 'privacyDomainId'
    >;
    readonly occurrence: NotificationDeliveryIdentity;
    readonly endpoint: NotificationEndpointBinding;
    readonly templateDigest: string;
    readonly notificationOccurrenceRef: string | undefined;
  },
): NotificationDeliveryRequestedDataV1 {
  const data = parseNotificationDeliveryRequestedData(value);
  const context = contextScope.safeParse(bindings.trustedContext);
  const occurrence = notificationDeliveryIdentity.safeParse(bindings.occurrence);
  const endpoint = notificationEndpointBinding.safeParse(bindings.endpoint);
  const template = wireDigest.safeParse(bindings.templateDigest);
  if (!context.success || !occurrence.success || !endpoint.success || !template.success)
    throw new NotificationEventInputError('INVALID_BINDING');
  if (
    ![
      ...Object.values(context.data),
      ...Object.values(occurrence.data),
      ...Object.values(endpoint.data),
    ].every(unpadded)
  )
    throw new NotificationEventInputError('INVALID_BINDING');

  // Scope equality is independent of resource-reference namespace validation.
  for (const scoped of [occurrence.data, endpoint.data]) {
    if (
      scoped.participantId !== context.data.participantId ||
      scoped.privacyDomainId !== context.data.privacyDomainId
    )
      throw new NotificationEventInputError('SCOPE_MISMATCH');
  }
  if (bindings.notificationOccurrenceRef === undefined)
    throw new NotificationEventInputError('MISSING_OCCURRENCE_REFERENCE');
  const retainedReference = wireReference.safeParse(bindings.notificationOccurrenceRef);
  if (!retainedReference.success) throw new NotificationEventInputError('INVALID_BINDING');

  // Endpoint public identity convention is already canonical. Comparing the full
  // URN rejects another namespace carrying the very same UUID.
  const endpointRef = `urn:openpc:resource:${endpoint.data.endpointId}`;
  if (
    data.endpointId !== endpointRef ||
    data.notificationOccurrenceId !== retainedReference.data ||
    data.payloadDigest !== occurrence.data.payloadDigest ||
    data.templateDigest !== template.data
  )
    throw new NotificationEventInputError('BINDING_MISMATCH');

  // Full reference equality above is mandatory. This extra check binds the
  // owner-supplied wire identity to the persisted UUID; it never selects a namespace.
  if (!retainedReference.data.endsWith(`:${occurrence.data.notificationOccurrenceId}`))
    throw new NotificationEventInputError('BINDING_MISMATCH');
  return data;
}

// schemas/asyncapi/openpc-events.asyncapi.yaml: LS-EVIDENCE-EXPORT produces
// EvidenceExportCompleted, ordered by evidenceExportId; LS-CONTROL-WORK produces
// NotificationDeliveryRequested, ordered by notificationOccurrenceId. Those
// logical owner names are NOT a published source-URN serialization convention.
const exportedType = 'io.openpc.evidence.export.completed.v1';
const requestedType = 'io.openpc.notification.delivery.requested.v1';
const exportedSchema =
  'https://schemas.openpc.local/event-payloads.schema.json#/$defs/EvidenceExportCompleted';
const requestedSchema =
  'https://schemas.openpc.local/event-payloads.schema.json#/$defs/NotificationDeliveryRequested';
const envelopeFields = {
  specversion: z.literal('1.0'),
  id: wireUuid,
  source: wireReference,
  subject: wireReference,
  time: z.iso.datetime({ precision: 6 }).refine(unpadded),
  datacontenttype: z.literal('application/json'),
  participantid: wireReference,
  privacydomainid: wireReference.optional(),
  correlationid: wireUuid,
  causationid: wireUuid.optional(),
  authoritygeneration: wireDigest.optional(),
  sequence: wireCounter,
  datadigest: wireDigest,
};
// JSON optional means absent, not an explicit undefined value. Preserve all
// registered members; stripping one would hide a changed replay envelope.
const jsonOptionals = (value: {
  privacydomainid?: string;
  causationid?: string;
  authoritygeneration?: string;
}) =>
  (['privacydomainid', 'causationid', 'authoritygeneration'] as const).every(
    (key) => !Object.hasOwn(value, key) || value[key] !== undefined,
  );
const exportedEnvelope = z
  .strictObject({
    ...envelopeFields,
    type: z.literal(exportedType),
    dataschema: z.literal(exportedSchema),
    data: evidenceExportCompleted,
  })
  .refine(jsonOptionals);
const requestedEnvelope = z
  .strictObject({
    ...envelopeFields,
    type: z.literal(requestedType),
    dataschema: z.literal(requestedSchema),
    data: notificationDeliveryRequested,
  })
  .refine(jsonOptionals);
export type EvidenceExportCompletedEnvelope = OpenPcEventEnvelopeV1 & {
  readonly type: typeof exportedType;
  readonly dataschema: typeof exportedSchema;
  readonly data: EvidenceExportCompletedDataV1;
};
export type NotificationDeliveryRequestedEnvelope = OpenPcEventEnvelopeV1 & {
  readonly type: typeof requestedType;
  readonly dataschema: typeof requestedSchema;
  readonly data: NotificationDeliveryRequestedDataV1;
};
export type NotificationSourceEnvelope =
  EvidenceExportCompletedEnvelope | NotificationDeliveryRequestedEnvelope;

/** Public syntax only. Optional privacy and authority-generation remain optional;
 * no occurrence/source namespace, partition field or positive sequence is invented. */
export function parseEvidenceExportCompletedEnvelope(
  value: unknown,
): EvidenceExportCompletedEnvelope {
  const parsed = exportedEnvelope.safeParse(value);
  if (!parsed.success) throw new NotificationEventInputError('INVALID_ENVELOPE');
  return parsed.data;
}
export function parseNotificationDeliveryRequestedEnvelope(
  value: unknown,
): NotificationDeliveryRequestedEnvelope {
  const parsed = requestedEnvelope.safeParse(value);
  if (!parsed.success) throw new NotificationEventInputError('INVALID_ENVELOPE');
  return parsed.data;
}
const sourceEnvelope = z.union([exportedEnvelope, requestedEnvelope]);
function parseNotificationSourceEnvelope(value: unknown): NotificationSourceEnvelope {
  const parsed = sourceEnvelope.safeParse(value);
  if (!parsed.success) throw new NotificationEventInputError('INVALID_ENVELOPE');
  return parsed.data;
}
const envelopeBinding = z.strictObject({
  participantId: wireUuid,
  privacyDomainId: wireUuid,
  source: wireReference,
  partition: wireReference,
  sequence: wireCounter,
  dataDigest: wireDigest,
});
export type NotificationEventEnvelopeBinding = z.infer<typeof envelopeBinding>;

/** Compare with the owning producer/consumer's retained inputs. These values
 * confer no authority: caller must authenticate their origin and current scope.
 * The partition is the registered DATA ordering key, not a global event cursor,
 * endpoint ID, guessed UUID or unregistered wire-envelope member. Sequence is an
 * exact retained position; durable gap detection/advancement remains with inbox.
 * Public schema establishes digest syntax, not these producers' hash preimage.
 * Therefore compare the producer-retained digest; never claim to authenticate
 * data by guessing JSON/CBOR encoding or accepting a caller's recalculated hash. */
export function matchNotificationEventEnvelope(
  value: unknown,
  bindingValue: NotificationEventEnvelopeBinding,
): NotificationSourceEnvelope {
  const event = parseNotificationSourceEnvelope(value);
  const parsed = envelopeBinding.safeParse(bindingValue);
  if (!parsed.success) throw new NotificationEventInputError('INVALID_BINDING');
  const binding = parsed.data;
  if (
    event.participantid !== `urn:openpc:participant:${binding.participantId}` ||
    event.privacydomainid !== `urn:openpc:privacy-domain:${binding.privacyDomainId}`
  )
    throw new NotificationEventInputError('SCOPE_MISMATCH');
  const partition =
    event.type === exportedType ? event.data.evidenceExportId : event.data.notificationOccurrenceId;
  if (
    event.source !== binding.source ||
    partition !== binding.partition ||
    event.sequence !== binding.sequence ||
    event.datadigest !== binding.dataDigest
  )
    throw new NotificationEventInputError('BINDING_MISMATCH');
  return event;
}

/** Retained-value replay comparison, never durable deduplication or admission.
 * Same ID alone (even with the same declared digest) cannot hide changed data,
 * scope, source, sequence, time, correlation, causation, generation or subject.
 * Object key order is immaterial. Exact serialized-byte preservation belongs to
 * the future authenticated inbox owner; this function accepts decoded JSON. */
export function matchRetainedNotificationEvent(
  value: unknown,
  retainedValue: unknown,
): NotificationSourceEnvelope {
  const event = parseNotificationSourceEnvelope(value);
  const retained = parseNotificationSourceEnvelope(retainedValue);
  if (event.id !== retained.id) throw new NotificationEventInputError('BINDING_MISMATCH');
  if (canonicalJson(event) !== canonicalJson(retained))
    throw new NotificationEventInputError('REPLAY_MISMATCH');
  return event;
}
