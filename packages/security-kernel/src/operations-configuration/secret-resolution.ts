import { createHash, createPublicKey } from 'node:crypto';
import { z } from 'zod';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import {
  signConsumerCose,
  verifyConsumerCose,
  type ConsumerCoseContext,
} from '../fact-consumer/cose-framing.js';
import { operationsConfigurationCoseProfiles } from './generated.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const uint = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((v) => BigInt(v) <= MAX_UINT64);
const positive = uint.refine((v) => v !== '0');
const milliseconds = z
  .number()
  .int()
  .min(0)
  .max(Number.MAX_SAFE_INTEGER)
  .refine((v) => !Object.is(v, -0));
export const operationsSecretResolutionClaimsSchema = z
  .strictObject({
    environmentId: z.string().regex(/^[a-z][a-z0-9-]{2,31}$/u),
    participantId: uuid,
    privacyDomainId: uuid,
    associationId: uuid,
    operationsInstallationDigest: digest,
    candidateDigest: digest,
    generationId: uuid,
    recipientBindingDigest: digest,
    recipientInstallationDigest: digest,
    recipientGeneration: positive,
    field: z.literal('postgres.candidateIndexDsnSecretRef'),
    consumerId: z.literal('LS-FACT-BRIDGE'),
    storeId: z.literal('STORE-CANDIDATE-INDEX-PG'),
    referenceFingerprint: digest,
    version: z
      .string()
      .regex(/^[A-Za-z0-9._-]{1,96}$/u)
      .refine((v) => !['latest', 'current'].includes(v)),
    fingerprint: digest,
    principalId: uuid,
    workloadCredentialId: uuid,
    workloadCredentialEpoch: uint,
    consumerInstanceId: uuid,
    consumerStartedAtMs: milliseconds,
    observerInstanceId: uuid,
    observerStartedAtMs: milliseconds,
    challengeId: uuid,
    probeDigest: digest,
    observedAtMs: milliseconds,
    validUntilMs: milliseconds,
    issuerKeyId: digest,
    issuerEpoch: positive,
  })
  .superRefine((v, ctx) => {
    if (
      v.observedAtMs < Math.max(v.consumerStartedAtMs, v.observerStartedAtMs) ||
      v.validUntilMs <= v.observedAtMs ||
      v.validUntilMs - v.observedAtMs > 30000
    )
      ctx.addIssue({ code: 'custom', message: 'Observation interval rejected' });
  });
export type OperationsSecretResolutionClaims = z.infer<
  typeof operationsSecretResolutionClaimsSchema
>;
const rejected = (): never => {
  throw new Error('OPS_SECRET_OBSERVATION_REJECTED');
};

/** Pure closed input validation. Never consults getters/coercion or grants trust. */
export function parseOperationsSecretResolutionClaims(
  input: unknown,
): Readonly<OperationsSecretResolutionClaims> {
  if (!input || Object.getPrototypeOf(input) !== Object.prototype) return rejected();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (
    Reflect.ownKeys(descriptors).some(
      (name) =>
        typeof name !== 'string' ||
        !descriptors[name]!.enumerable ||
        !Object.hasOwn(descriptors[name]!, 'value'),
    )
  )
    return rejected();
  const parsed = operationsSecretResolutionClaimsSchema.safeParse(input);
  if (!parsed.success) return rejected();
  return Object.freeze(parsed.data);
}

interface RegisteredProfile extends ConsumerCoseContext {
  definitionDigest: string;
  fields: readonly { key: number; name: string; type: string }[];
}
function profile(): RegisteredProfile {
  // There is deliberately no numeric fallback while canonical registration is
  // pending. Importing/validating a contract never fabricates signing success.
  const value = (
    operationsConfigurationCoseProfiles as unknown as Record<string, RegisteredProfile>
  )['OperationsSecretResolutionV1'];
  if (
    !value ||
    !Number.isSafeInteger(value.schemaId) ||
    !Number.isSafeInteger(value.purposeCode) ||
    !digest.safeParse(value.definitionDigest).success
  )
    return rejected();
  return value;
}
function toWire(type: string, value: unknown): CborValue {
  if (type === 'H32') return Buffer.from(digest.parse(value).slice(7), 'hex');
  if (type === 'uuidv7') return Buffer.from(uuid.parse(value).replaceAll('-', ''), 'hex');
  if (type === 'u64' || type === 'u64p')
    return BigInt((type === 'u64' ? uint : positive).parse(value));
  if (type === 'safe_uint') return milliseconds.parse(value);
  if (typeof value !== 'string') return rejected();
  return value;
}
export function encodeOperationsSecretResolution(input: OperationsSecretResolutionClaims): Buffer {
  const claims = parseOperationsSecretResolutionClaims(input);
  const context = profile();
  return encodeCbor(
    new Map(
      context.fields.map((field) => [
        field.key,
        toWire(
          field.type,
          field.key === 0
            ? context.definitionDigest
            : claims[field.name as keyof OperationsSecretResolutionClaims],
        ),
      ]),
    ),
  );
}
export function decodeOperationsSecretResolution(
  payload: Buffer,
): Readonly<OperationsSecretResolutionClaims> {
  if (!Buffer.isBuffer(payload) || payload.length === 0 || payload.length > 65536)
    return rejected();
  const context = profile();
  const map = decodeCbor(payload);
  if (!(map instanceof Map) || map.size !== context.fields.length) return rejected();
  const values: Record<string, unknown> = {};
  for (const field of context.fields) {
    let value = map.get(field.key);
    if (field.type === 'H32') {
      if (!Buffer.isBuffer(value) || value.length !== 32) return rejected();
      value = `sha256:${value.toString('hex')}`;
    } else if (field.type === 'uuidv7') {
      if (!Buffer.isBuffer(value) || value.length !== 16) return rejected();
      const hex = value.toString('hex');
      value = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    } else if (field.type === 'u64' || field.type === 'u64p' || field.type === 'safe_uint') {
      if (typeof value !== 'bigint') return rejected();
      value = field.type === 'safe_uint' ? Number(value) : value.toString();
    }
    if (field.key === 0) {
      if (value !== context.definitionDigest) return rejected();
    } else values[field.name] = value;
  }
  const claims = parseOperationsSecretResolutionClaims(values);
  if (!encodeOperationsSecretResolution(claims).equals(payload)) return rejected();
  return claims;
}
function requireP256(spki: Buffer) {
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
    rejected();
}
export function signOperationsSecretResolution(
  privateKey: Buffer,
  spki: Buffer,
  payload: Buffer,
): Buffer {
  requireP256(spki);
  if (decodeOperationsSecretResolution(payload).issuerKeyId !== evidenceKeyId(spki))
    return rejected();
  return signConsumerCose(profile(), privateKey, spki, payload);
}
/** Framing only. Durable association and live producer/source checks are required
 * separately, even after a successful cryptographic verification. */
export function verifyOperationsSecretResolution(
  spki: Buffer,
  payload: Buffer,
  cose: Buffer,
): Readonly<OperationsSecretResolutionClaims> {
  try {
    requireP256(spki);
    const claims = decodeOperationsSecretResolution(payload);
    if (
      claims.issuerKeyId !== evidenceKeyId(spki) ||
      !verifyConsumerCose(profile(), spki, payload, cose)
    )
      return rejected();
    return claims;
  } catch {
    return rejected();
  }
}
export function operationsSecretObservationDigest(bytes: Buffer): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}
