import { z } from 'zod';
import { protectedObjectBinding } from './protected-contracts.js';
import { digest } from './segment.js';

export const protectedCiphertext = z.strictObject({
  keyId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/u),
  nonceBase64: z.base64().length(16),
  ciphertextBase64: z.base64().min(24).max(87404),
});

export const protectedVaultObject = protectedObjectBinding.extend({
  dataClass: z.literal('RAW_SOURCE_BODY'),
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  sinkId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
  payloadDigest: digest,
  ciphertextBytes: z.number().int().min(17).max(65552),
  retainUntil: z.iso.datetime({ precision: 6 }),
});
export const protectedSinkReceipt = z.strictObject({
  object: protectedVaultObject,
  versionId: digest,
  assurance: z.literal('LOCAL_FSYNC_READBACK'),
  receiptDigest: digest,
});
export type ProtectedVaultObject = z.infer<typeof protectedVaultObject>;
export type ProtectedCiphertext = z.infer<typeof protectedCiphertext>;
