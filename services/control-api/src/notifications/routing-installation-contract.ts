import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { verifyInstalledNotificationRouting } from '../configuration/notification-routing-contract.js';
import { notificationChannel, notificationRevision } from './endpoint-binding.js';
import { openPcUrnSchema } from '../configuration/resource-contracts.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const hex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
const field = z.enum(['evidenceExportId', 'checkpoint', 'outputDigest', 'recordCount']);
const segment = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('TEXT'),
    value: z
      .string()
      .min(1)
      .max(1024)
      .refine((s) =>
        [...s].every((character) => {
          const code = character.charCodeAt(0);
          return code === 9 || code === 10 || code === 13 || (code >= 32 && code !== 127);
        }),
      ),
  }),
  z.strictObject({ kind: z.literal('FIELD'), field }),
]);
/** Initial authenticated configuration for a closed plain-text renderer. No HTML,
 * expressions, recipient lookup, secret reference or arbitrary event field. */
export const notificationRoutingInstallation = z.strictObject({
  trust: z.strictObject({
    environmentId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
    participantId: z.uuidv7(),
    privacyDomainId: z.uuidv7(),
    signedProfileDigest: digest,
    issuerSpkiHex: hex.length(182),
  }),
  signed: z.strictObject({ payloadHex: hex.max(131072), coseHex: hex.max(133120) }),
  template: z.strictObject({
    schema: z.literal('OPENPC_EVIDENCE_EXPORT_NOTIFICATION_TEMPLATE_V1'),
    templateId: z.uuidv7(),
    revision: notificationRevision,
    sourceEvent: z.literal('EvidenceExportCompleted'),
    format: z.literal('PLAIN_TEXT'),
    subject: z.array(segment).min(1).max(32),
    body: z.array(segment).min(1).max(64),
  }),
  recipientSet: z.strictObject({
    schema: z.literal('OPENPC_NOTIFICATION_ENDPOINT_RECIPIENT_V1'),
    endpointId: z.uuidv7(),
    channel: notificationChannel,
    destinationRef: openPcUrnSchema,
  }),
  redaction: z.strictObject({
    schema: z.literal('OPENPC_EVIDENCE_EXPORT_NOTIFICATION_FIELDS_V1'),
    allowedFields: z.array(field).min(1).max(4),
  }),
  producerTrustDigest: digest,
  installationReference: z
    .string()
    .min(1)
    .max(256)
    .refine((value) => value === value.trim()),
});
export type NotificationRoutingInstallation = z.infer<typeof notificationRoutingInstallation>;
export class NotificationRoutingInstallationError extends Error {
  constructor() {
    super('Notification routing installation unavailable');
  }
}
export function validateNotificationRoutingInstallation(value: unknown) {
  try {
    const input = notificationRoutingInstallation.parse(immutableJsonCopy(value));
    const route = verifyInstalledNotificationRouting(input.trust, input.signed);
    const claims = route.claims;
    const fields = input.redaction.allowedFields;
    if (input.template.subject.some((part) => part.kind === 'TEXT' && /[\r\n]/u.test(part.value)))
      throw new Error();
    if (
      claims.sourceEvent !== 'EvidenceExportCompleted' ||
      claims.templateDigest !== sha256(input.template) ||
      claims.recipientSetDigest !== sha256(input.recipientSet) ||
      claims.redactionProfileDigest !== sha256(input.redaction) ||
      claims.endpointId !== input.recipientSet.endpointId ||
      fields.some((value, index) => index > 0 && value <= fields[index - 1]!) ||
      [...input.template.subject, ...input.template.body].some(
        (part) => part.kind === 'FIELD' && !fields.includes(part.field),
      )
    )
      throw new Error();
    const bytes = Buffer.from(canonicalJson(input));
    if (bytes.length > 131072 || Buffer.byteLength(canonicalJson(input.template)) > 16384)
      throw new Error();
    return { input, route, bytes, installationDigest: sha256(bytes) };
  } catch {
    throw new NotificationRoutingInstallationError();
  }
}
