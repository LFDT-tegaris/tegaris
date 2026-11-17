import { createPublicKey } from 'node:crypto';
import { z } from 'zod';
import { isExactSigningSecretReference } from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { notificationPayloadBinding } from './notification-payload-crypto.js';
import {
  decodeEvidenceKmsResponse,
  encodeEvidenceKmsResponse,
  verifyEvidenceKmsClaim,
  evidenceKmsAbsentDigest,
  type EvidenceKmsOperation,
  type EvidenceKmsReceiptClaims,
  type EvidenceWrappedKeyClaims,
} from '../../../../packages/security-kernel/src/evidence-kms/codec.js';

export type EvidenceKmsFailure =
  'INVALID' | 'UNAVAILABLE' | 'REVOKED' | 'SCOPE' | 'STALE' | 'INTEGRITY' | 'CONFLICT' | 'UNKNOWN';

/** Safe at the service boundary. Never attach a provider response, key or cause. */
export class EvidenceKmsError extends Error {
  constructor(readonly code: EvidenceKmsFailure) {
    super(code === 'REVOKED' ? 'OPS_SECRET_REVOKED' : 'OPS_SECRET_UNRESOLVED');
    this.name = 'EvidenceKmsError';
  }
}
export function rejectEvidenceKms(code: EvidenceKmsFailure): never {
  throw new EvidenceKmsError(code);
}

export const kmsDigest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const kmsUuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
export const kmsOrdinal = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const name = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u);
const exactText = (maximum: number) =>
  z
    .string()
    .min(1)
    .max(maximum)
    .refine(
      (value) =>
        value === value.trim() &&
        value === value.normalize('NFC') &&
        Buffer.byteLength(value) <= maximum &&
        ![...value].some(
          (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
        ),
    );
const time = z
  .number()
  .int()
  .min(0)
  .max(Number.MAX_SAFE_INTEGER)
  .refine((value) => !Object.is(value, -0));
const spki = z
  .string()
  .regex(/^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$/u)
  .refine((value) => {
    try {
      const key = createPublicKey({ key: Buffer.from(value, 'hex'), type: 'spki', format: 'der' });
      return (
        key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1'
      );
    } catch {
      return false;
    }
  });

/** Public initial trust only. A parsed value is not an installed grant, a signed
 * provider status, or evidence that the external KEK is non-exportable. */
export const evidenceKmsInstallationInput = z
  .strictObject({
    owner: z.literal('LS-EVIDENCE-EXPORT'),
    secretClass: z.literal('SECRET-EVIDENCE-VAULT'),
    environmentId: name,
    participantId: kmsUuid,
    privacyDomainId: kmsUuid,
    installationId: kmsUuid,
    producerTrustDigest: kmsDigest,
    reference: exactText(331),
    version: exactText(96),
    keyEpoch: kmsOrdinal,
    providerId: name,
    providerOrigin: exactText(512),
    providerTlsSpkiDigest: kmsDigest,
    profileIssuerSpkiHex: spki,
    providerReceiptSpkiHex: spki,
    recoveryAuthoritySpkiHex: spki,
    providerKeyId: exactText(256),
    providerKeyVersion: exactText(96),
    wrapProfileDigest: kmsDigest,
    policyDigest: kmsDigest,
    recoveryProfileDigest: kmsDigest,
    profileDigest: kmsDigest,
    permissions: z
      .array(z.enum(['ENCRYPT', 'DECRYPT']))
      .min(1)
      .max(2)
      .refine((values) => values.join(',') === [...new Set(values)].sort().join(',')),
    validFromMs: time,
    validUntilMs: time,
  })
  .superRefine((value, context) => {
    let validOrigin = false;
    try {
      const url = new URL(value.providerOrigin);
      validOrigin =
        /^https:\/\/[a-z0-9.-]+(?::[1-9][0-9]{0,4})?$/u.test(value.providerOrigin) &&
        url.protocol === 'https:' &&
        url.origin === value.providerOrigin &&
        url.username === '' &&
        url.password === '' &&
        url.hostname !== '';
    } catch {
      /* The typed admission below fails closed. */
    }
    const exactReference = isExactSigningSecretReference(value.reference, value.version);
    const path = value.reference.slice(
      value.reference.indexOf('/', 9) + 1,
      value.reference.lastIndexOf('#'),
    );
    if (
      !validOrigin ||
      !exactReference ||
      path.split('/').some((part) => ['', '.', '..'].includes(part)) ||
      value.reference.split('/')[2] !== value.providerId ||
      /^(latest|current)$/iu.test(value.providerKeyVersion) ||
      value.validUntilMs <= value.validFromMs
    )
      context.addIssue({ code: 'custom', message: 'Invalid Evidence key installation' });
    if (
      new Set([
        value.profileIssuerSpkiHex,
        value.providerReceiptSpkiHex,
        value.recoveryAuthoritySpkiHex,
      ]).size !== 3
    )
      context.addIssue({ code: 'custom', message: 'Evidence key signing roles must be distinct' });
  });
export type EvidenceKmsInstallationInput = z.infer<typeof evidenceKmsInstallationInput>;

export const evidenceKmsRecipientRequest = z.strictObject({
  participantId: kmsUuid,
  privacyDomainId: kmsUuid,
  producerTrustDigest: kmsDigest,
  installationDigest: kmsDigest,
});
export type EvidenceKmsRecipientRequest = z.infer<typeof evidenceKmsRecipientRequest>;

/** The reviewed first consumer. Reuse the existing crypto owner's complete
 * binding; the wrapped-record digest is deliberately absent to avoid a cycle. */
export const evidenceKmsObjectIntent = notificationPayloadBinding.omit({ keyId: true });
export type EvidenceKmsObjectIntent = z.infer<typeof evidenceKmsObjectIntent>;
export const evidenceKmsPrepareInput = z.strictObject({
  recipient: evidenceKmsRecipientRequest,
  attemptId: kmsUuid,
  objectIntent: evidenceKmsObjectIntent,
});
export const evidenceKmsAttemptSelector = z.strictObject({
  recipient: evidenceKmsRecipientRequest,
  attemptId: kmsUuid,
});
export const evidenceKmsUnwrapInput = z.strictObject({
  recipient: evidenceKmsRecipientRequest,
  attemptId: kmsUuid,
  keyId: kmsDigest,
  use: z.enum(['ENCRYPT', 'DECRYPT']),
});
export type EvidenceKmsPrepareInput = z.infer<typeof evidenceKmsPrepareInput>;
export type EvidenceKmsAttemptSelector = z.infer<typeof evidenceKmsAttemptSelector>;
export type EvidenceKmsUnwrapInput = z.infer<typeof evidenceKmsUnwrapInput>;

/** Reject accessors and non-data objects before a validator can invoke them. */
function plain(value: unknown, depth = 0, remaining = { nodes: 0 }): void {
  if (++remaining.nodes > 256 || depth > 8) rejectEvidenceKms('INVALID');
  if (value === null || typeof value !== 'object') return;
  const array = Array.isArray(value);
  if (Object.getPrototypeOf(value) !== (array ? Array.prototype : Object.prototype))
    rejectEvidenceKms('INVALID');
  if (array && (value.length > 256 || Object.keys(value).length !== value.length))
    rejectEvidenceKms('INVALID');
  for (const key of Reflect.ownKeys(value)) {
    if (array && key === 'length') continue;
    const property = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== 'string' || !property || !('value' in property) || !property.enumerable)
      rejectEvidenceKms('INVALID');
    if (array && (!/^(0|[1-9][0-9]*)$/u.test(key) || Number(key) >= value.length))
      rejectEvidenceKms('INVALID');
    plain(property.value, depth + 1, remaining);
  }
}
export function parseEvidenceKms<T>(schema: z.ZodType<T>, value: unknown): T {
  try {
    plain(value);
    const parsed = schema.safeParse(value);
    if (!parsed.success) rejectEvidenceKms('INVALID');
    return parsed.data;
  } catch {
    throw new EvidenceKmsError('INVALID');
  }
}
export function validateEvidenceKmsInstallation(value: unknown) {
  const pins = parseEvidenceKms(evidenceKmsInstallationInput, value);
  const bytes = Buffer.from(canonicalJson(pins));
  return { pins, bytes, digest: sha256(bytes) };
}

export type EvidenceKmsAttemptState = 'PREPARED' | 'DISPATCHED' | 'UNKNOWN' | 'PROVED' | 'REJECTED';
export function assertEvidenceKmsTransition(
  before: EvidenceKmsAttemptState,
  after: EvidenceKmsAttemptState,
): void {
  if (
    (before === 'PREPARED' && after === 'DISPATCHED') ||
    ((before === 'DISPATCHED' || before === 'UNKNOWN') &&
      (after === 'UNKNOWN' || after === 'PROVED' || after === 'REJECTED'))
  )
    return;
  rejectEvidenceKms('CONFLICT');
}

export const evidenceKmsLimits = Object.freeze({
  requestBytes: 32768,
  responseBytes: 262144,
  wrappedRecordBytes: 65536,
  requestTimeoutMs: 5000,
  leaseMaximumMs: 1000,
  statusMaximumAgeMs: 5000,
});

export interface EvidenceKmsExpectedResponse {
  readonly operation: Exclude<EvidenceKmsOperation, 'RECOVERY_FLOOR'>;
  readonly attemptId: string;
  readonly exchangeId: string;
  readonly requestDigest: string;
  readonly originalRequestDigest: string;
  readonly objectIntentDigest: string;
  readonly challenge: string;
  readonly keyId: string;
  readonly keyUse: 'NONE' | 'ENCRYPT' | 'DECRYPT';
  readonly nowMs: number;
  readonly minimumSequence: string;
  readonly minimumRecoveryFloor: string;
}
/** Pure expectations from an independently loaded owner, not a destructive
 * attempt/admission model. attemptId and originalRequestDigest retain the key's
 * creation identity; exchangeId/requestDigest/challenge name this observation.
 * ENCRYPT/DECRYPT profile permissions confer no DESTROY authority. */
export type EvidenceKmsExpectedDestructionResponse = Omit<
  EvidenceKmsExpectedResponse,
  'operation' | 'keyUse'
> & { readonly operation: 'DESTROY'; readonly keyUse: 'NONE' };
const destructionExpectedResponse = z.strictObject({
  operation: z.literal('DESTROY'),
  attemptId: kmsUuid,
  exchangeId: kmsUuid,
  requestDigest: kmsDigest,
  originalRequestDigest: kmsDigest,
  objectIntentDigest: kmsDigest,
  challenge: z.string().regex(/^[0-9a-f]{64}$/u),
  keyId: kmsDigest.refine((value) => value !== evidenceKmsAbsentDigest),
  keyUse: z.literal('NONE'),
  nowMs: time,
  minimumSequence: kmsOrdinal,
  minimumRecoveryFloor: kmsOrdinal,
});
const providerFields = [
  'environmentId',
  'participantId',
  'privacyDomainId',
  'providerId',
  'reference',
  'version',
  'providerKeyId',
  'providerKeyVersion',
  'keyEpoch',
  'wrapProfileDigest',
  'policyDigest',
  'recoveryProfileDigest',
] as const;

/** Pure cryptographic verification, never caller admission. The database/runtime
 * owner supplies independently loaded pins and original committed expectations.
 * Every failing path erases any decoded provider material. */
export function verifyEvidenceKmsResponse(
  bytes: Buffer,
  pins: EvidenceKmsInstallationInput,
  expected: EvidenceKmsExpectedResponse,
) {
  let response: ReturnType<typeof decodeEvidenceKmsResponse> | undefined;
  try {
    plain(expected);
    if (expected.operation === 'DESTROY') {
      expected = parseEvidenceKms(destructionExpectedResponse, expected);
      pins = validateEvidenceKmsInstallation(pins).pins;
    }
    if (!Number.isSafeInteger(expected.nowMs) || expected.nowMs < 0) rejectEvidenceKms('INVALID');
    response = decodeEvidenceKmsResponse(bytes);
    if (sha256(response.profile.cose) !== pins.profileDigest) rejectEvidenceKms('INTEGRITY');
    const profile = verifyEvidenceKmsClaim(
      'EvidenceKmsProfileV1',
      Buffer.from(pins.profileIssuerSpkiHex, 'hex'),
      response.profile,
    );
    const permissions = pins.permissions.length === 2 ? 'ENCRYPT_AND_DECRYPT' : pins.permissions[0];
    if (
      providerFields.some((key) => profile[key] !== pins[key]) ||
      profile.profileId !== pins.installationId ||
      profile.producerTrustDigest !== pins.producerTrustDigest ||
      profile.providerOrigin !== pins.providerOrigin ||
      profile.providerTlsSpkiDigest !== pins.providerTlsSpkiDigest ||
      profile.receiptKeyId !== sha256(Buffer.from(pins.providerReceiptSpkiHex, 'hex')) ||
      profile.recoveryKeyId !== sha256(Buffer.from(pins.recoveryAuthoritySpkiHex, 'hex')) ||
      profile.validFromMs !== pins.validFromMs ||
      profile.validUntilMs !== pins.validUntilMs ||
      profile.permissions !== permissions
    )
      rejectEvidenceKms('INTEGRITY');
    if (
      expected.operation !== 'READ_ATTEMPT' &&
      (expected.nowMs < profile.validFromMs || expected.nowMs >= profile.validUntilMs)
    )
      rejectEvidenceKms('STALE');
    const receipt = verifyEvidenceKmsClaim(
      'EvidenceKmsReceiptV1',
      Buffer.from(pins.providerReceiptSpkiHex, 'hex'),
      response.receipt,
    );
    const recovery = verifyEvidenceKmsClaim(
      'EvidenceKmsReceiptV1',
      Buffer.from(pins.recoveryAuthoritySpkiHex, 'hex'),
      response.recovery,
    );
    const check = (r: EvidenceKmsReceiptClaims, recoveryRole: boolean) => {
      if (
        providerFields.some((key) => r[key] !== pins[key]) ||
        r.profileDigest !== pins.profileDigest ||
        r.operation !== (recoveryRole ? 'RECOVERY_FLOOR' : expected.operation) ||
        r.attemptId !== expected.attemptId ||
        r.exchangeId !== expected.exchangeId ||
        r.requestDigest !== expected.requestDigest ||
        r.objectIntentDigest !== expected.objectIntentDigest ||
        r.challenge !== expected.challenge ||
        r.keyUse !== (recoveryRole ? 'NONE' : expected.keyUse) ||
        r.observedAtMs > expected.nowMs ||
        r.observedAtMs < expected.nowMs - evidenceKmsLimits.statusMaximumAgeMs ||
        r.validUntilMs <= expected.nowMs ||
        r.validUntilMs - r.observedAtMs > evidenceKmsLimits.statusMaximumAgeMs ||
        BigInt(r.providerSequence) < BigInt(expected.minimumSequence) ||
        BigInt(r.recoveryFloor) < BigInt(expected.minimumRecoveryFloor)
      )
        rejectEvidenceKms('STALE');
    };
    check(receipt, false);
    check(recovery, true);
    if (
      recovery.outcome !== 'PROVED' ||
      recovery.keyState !== receipt.keyState ||
      recovery.keyId !== receipt.keyId ||
      recovery.providerSequence !== receipt.providerSequence ||
      recovery.recoveryFloor !== receipt.recoveryFloor
    )
      rejectEvidenceKms('INTEGRITY');
    let record: EvidenceWrappedKeyClaims | undefined;
    if (response.record.payload.length || response.record.cose.length) {
      record = verifyEvidenceKmsClaim(
        'EvidenceWrappedKeyRecordV1',
        Buffer.from(pins.providerReceiptSpkiHex, 'hex'),
        response.record,
      );
      if (
        providerFields.some((key) => record![key] !== pins[key]) ||
        record.profileDigest !== pins.profileDigest ||
        record.attemptId !== expected.attemptId ||
        record.originalRequestDigest !== expected.originalRequestDigest ||
        record.objectIntentDigest !== expected.objectIntentDigest ||
        sha256(response.record.payload) !== receipt.keyId ||
        record.createdAtMs < profile.validFromMs ||
        record.createdAtMs >= profile.validUntilMs ||
        record.createdAtMs > expected.nowMs
      )
        rejectEvidenceKms('INTEGRITY');
    }
    if (expected.keyId !== evidenceKmsAbsentDigest && receipt.keyId !== expected.keyId)
      rejectEvidenceKms('INTEGRITY');
    // Destruction always names the original retained key, including an UNKNOWN
    // or REJECTED observation. Missing custody cannot become an absent-key
    // success or a no-effect/cancellation claim. Do not alter the outcome.
    if (expected.operation === 'DESTROY' && !record) rejectEvidenceKms('INTEGRITY');
    if (
      receipt.outcome === 'PROVED' &&
      ['PREPARE', 'READ_ATTEMPT', 'UNWRAP'].includes(expected.operation) &&
      !record
    )
      rejectEvidenceKms('INTEGRITY');
    if (receipt.outcome !== 'PROVED' && receipt.keyId !== evidenceKmsAbsentDigest && !record)
      rejectEvidenceKms('INTEGRITY');
    if (expected.operation === 'UNWRAP' && receipt.outcome === 'PROVED') {
      if (
        response.material.length !== 32 ||
        sha256(response.material) !== receipt.materialDigest ||
        !pins.permissions.includes(expected.keyUse as 'ENCRYPT' | 'DECRYPT')
      )
        rejectEvidenceKms('INTEGRITY');
    } else if (response.material.length !== 0 || receipt.materialDigest !== evidenceKmsAbsentDigest)
      rejectEvidenceKms('INTEGRITY');
    return { response, profile, receipt, recovery, record };
  } catch (error) {
    response?.material.fill(0);
    if (error instanceof EvidenceKmsError) throw error;
    throw new EvidenceKmsError('INTEGRITY');
  }
}

/** Exact original signed bytes only. No raw DEK or untrusted provider diagnostics
 * enter the receipt store, including for an UNWRAP response. */
export function evidenceKmsReceiptBytes(
  verified: ReturnType<typeof verifyEvidenceKmsResponse>,
): Buffer {
  const pair = (value: { payload: Buffer; cose: Buffer }) => ({
    payloadHex: value.payload.toString('hex'),
    coseHex: value.cose.toString('hex'),
  });
  return Buffer.from(
    canonicalJson({
      profile: pair(verified.response.profile),
      receipt: pair(verified.response.receipt),
      record: pair(verified.response.record),
      recovery: pair(verified.response.recovery),
    }),
  );
}

/** Re-verify a retained STATUS observation using its original committed request.
 * Stored public signatures contain no material. This is a bounded observation,
 * never a lease or permission to call the provider on another worker's behalf. */
export function verifyStoredEvidenceKmsStatus(
  bytes: Buffer,
  pins: EvidenceKmsInstallationInput,
  expected: EvidenceKmsExpectedResponse,
) {
  try {
    if (
      !Buffer.isBuffer(bytes) ||
      !bytes.length ||
      bytes.length > evidenceKmsLimits.responseBytes ||
      expected.operation !== 'STATUS' ||
      expected.keyUse !== 'NONE'
    )
      rejectEvidenceKms('INVALID');
    const hex = z
      .string()
      .regex(/^(?:[0-9a-f]{2})*$/u)
      .max(262144);
    const pair = z.strictObject({ payloadHex: hex, coseHex: hex });
    const parsed = z
      .strictObject({ profile: pair, receipt: pair, record: pair, recovery: pair })
      .parse(JSON.parse(bytes.toString('utf8')));
    if (!bytes.equals(Buffer.from(canonicalJson(parsed)))) rejectEvidenceKms('INTEGRITY');
    const decode = (p: z.infer<typeof pair>) => ({
      payload: Buffer.from(p.payloadHex, 'hex'),
      cose: Buffer.from(p.coseHex, 'hex'),
    });
    const result = verifyEvidenceKmsResponse(
      encodeEvidenceKmsResponse({
        profile: decode(parsed.profile),
        receipt: decode(parsed.receipt),
        record: decode(parsed.record),
        recovery: decode(parsed.recovery),
        material: Buffer.alloc(0),
      }),
      pins,
      expected,
    );
    if (result.receipt.outcome !== 'PROVED' || result.receipt.keyState !== 'CURRENT')
      rejectEvidenceKms('UNAVAILABLE');
    return result.receipt;
  } catch (error) {
    if (error instanceof EvidenceKmsError) throw error;
    return rejectEvidenceKms('INTEGRITY');
  }
}

/** Historical wrapped-record integrity only; current eligibility is separate. */
export function verifyStoredEvidenceWrappedKey(
  payload: Buffer,
  cose: Buffer,
  pins: EvidenceKmsInstallationInput,
  expected: Pick<
    EvidenceKmsExpectedResponse,
    'attemptId' | 'originalRequestDigest' | 'objectIntentDigest' | 'keyId'
  >,
) {
  try {
    const record = verifyEvidenceKmsClaim(
      'EvidenceWrappedKeyRecordV1',
      Buffer.from(pins.providerReceiptSpkiHex, 'hex'),
      { payload, cose },
    );
    if (
      providerFields.some((key) => record[key] !== pins[key]) ||
      record.profileDigest !== pins.profileDigest ||
      record.attemptId !== expected.attemptId ||
      record.originalRequestDigest !== expected.originalRequestDigest ||
      record.objectIntentDigest !== expected.objectIntentDigest ||
      sha256(payload) !== expected.keyId ||
      record.createdAtMs < pins.validFromMs ||
      record.createdAtMs >= pins.validUntilMs
    )
      rejectEvidenceKms('INTEGRITY');
    return record;
  } catch {
    return rejectEvidenceKms('INTEGRITY');
  }
}
