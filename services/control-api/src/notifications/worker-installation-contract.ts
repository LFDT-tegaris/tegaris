import { z } from 'zod';
import { verifyInstalledNotificationWorkerProfile } from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const hex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
const uuid = z.uuidv7();
const positive = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);
const text = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u);
export const notificationWorkerInstallation = z.strictObject({
  pins: z.strictObject({
    issuerSpkiHex: hex.length(182),
    signedProfileDigest: digest,
    environmentId: text,
    participantId: uuid,
    privacyDomainId: uuid,
    profileId: uuid,
    revision: positive,
    serviceId: z.enum(['LS-CONTROL-WORK', 'LS-NOTIFICATION']),
    processRole: z.enum(['ROLE-CONTROL-WORKER', 'ROLE-NOTIFICATION-WORKER']),
    subscriptionId: z.enum([
      'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1',
      'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1',
      'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1',
    ]),
    principalId: uuid,
    workloadCredentialId: uuid,
    workloadEpoch: positive,
    workloadId: text,
    workloadKeyDigest: digest,
  }),
  signed: z.strictObject({ payloadHex: hex.max(131072), coseHex: hex.max(262144) }),
  installationReference: z
    .string()
    .min(1)
    .max(256)
    .refine((v) => v.trim() === v),
});
export type NotificationWorkerInstallation = z.infer<typeof notificationWorkerInstallation>;
export class NotificationWorkerAdmissionError extends Error {
  constructor() {
    super('Notification worker admission unavailable');
  }
}
export function validateNotificationWorkerInstallation(value: unknown, nowMs: number) {
  try {
    const input = immutableJsonCopy(notificationWorkerInstallation.parse(immutableJsonCopy(value)));
    const { issuerSpkiHex, ...pins } = input.pins;
    const profile = verifyInstalledNotificationWorkerProfile(
      { ...pins, issuerSpki: Buffer.from(issuerSpkiHex, 'hex') },
      Buffer.from(input.signed.payloadHex, 'hex'),
      Buffer.from(input.signed.coseHex, 'hex'),
      nowMs,
    );
    const bytes = Buffer.from(canonicalJson(input));
    if (bytes.length > 262144) throw new Error();
    return Object.freeze({
      input,
      profile,
      get bytes() {
        return Buffer.from(bytes);
      },
      installationDigest: sha256(bytes),
    });
  } catch {
    throw new NotificationWorkerAdmissionError();
  }
}
