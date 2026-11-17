import { createHash } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { signConsumerCose, verifyConsumerCose } from '../fact-consumer/cose-framing.js';
import { operationsConfigurationCoseProfiles } from './generated.js';

const profile = operationsConfigurationCoseProfiles.OperationsSiteDocumentV1;
const profiles = ['local', 'development', 'test', 'staging', 'production'] as const;
export interface OperationsSiteDocumentClaims {
  environmentId: string;
  profile: (typeof profiles)[number];
  generationId: string;
  baseGenerationId: string;
  siteDigest: string;
  configurationSchemaDigest: string;
  namedProfileDigest: string;
  declaredContentDigest: string;
  issuerKeyId: string;
  issuerEpoch: string;
  validFromMs: number;
  validUntilMs: number;
}
const rejected = (): never => {
  throw new Error('Operations site signature rejected');
};
const digest = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
function valueToWire(type: string, value: unknown): CborValue {
  if (type === 'H32') {
    if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value)) return rejected();
    return Buffer.from(value.slice(7), 'hex');
  }
  if (type === 'dns_label') {
    if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{2,31}$/u.test(value)) return rejected();
    return value;
  }
  if (type === 'generation_urn') {
    if (
      typeof value !== 'string' ||
      !/^urn:openpc:generation:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        value,
      )
    )
      return rejected();
    return value;
  }
  if (type === 'u64p') {
    if (
      typeof value !== 'string' ||
      !/^[1-9][0-9]{0,19}$/u.test(value) ||
      BigInt(value) > MAX_UINT64
    )
      return rejected();
    return BigInt(value);
  }
  if (type === 'safe_uint') {
    if (
      typeof value !== 'number' ||
      !Number.isSafeInteger(value) ||
      value < 0 ||
      Object.is(value, -0)
    )
      return rejected();
    return value;
  }
  if (type === 'enum local=1 development=2 test=3 staging=4 production=5') {
    const index = profiles.findIndex((name) => name === value);
    return index < 0 ? rejected() : index + 1;
  }
  return rejected();
}
function valueFromWire(type: string, value: CborValue | undefined): unknown {
  if (type === 'H32')
    return Buffer.isBuffer(value) && value.length === 32
      ? `sha256:${value.toString('hex')}`
      : rejected();
  if (type === 'u64p') return typeof value === 'bigint' ? value.toString() : rejected();
  if (type === 'safe_uint')
    return typeof value === 'bigint' && value <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(value)
      : rejected();
  if (type.startsWith('enum '))
    return typeof value === 'bigint' && value >= 1n && value <= 5n
      ? profiles[Number(value) - 1]
      : rejected();
  return value;
}
export function encodeOperationsSiteDocument(value: OperationsSiteDocumentClaims): Buffer {
  const names = profile.fields.slice(1).map((field) => field.name);
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== names.length ||
    names.some((name) => {
      const field = Object.getOwnPropertyDescriptor(value, name);
      return !field || !('value' in field) || !field.enumerable;
    })
  )
    return rejected();
  const claims = value as unknown as Record<string, unknown>;
  const fields = new Map<number, CborValue>();
  for (const field of profile.fields)
    fields.set(
      field.key,
      valueToWire(field.type, field.key === 0 ? profile.definitionDigest : claims[field.name]),
    );
  if (value.generationId === value.baseGenerationId || value.validFromMs >= value.validUntilMs)
    return rejected();
  return encodeCbor(fields);
}
export function decodeOperationsSiteDocument(
  payload: Buffer,
): Readonly<OperationsSiteDocumentClaims> {
  if (!Buffer.isBuffer(payload) || payload.length === 0 || payload.length > 65536)
    return rejected();
  const decoded = decodeCbor(payload);
  if (!(decoded instanceof Map) || decoded.size !== profile.fields.length) return rejected();
  const claims: Record<string, unknown> = {};
  for (const field of profile.fields) {
    const value = valueFromWire(field.type, decoded.get(field.key));
    if (field.key === 0) {
      if (value !== profile.definitionDigest) return rejected();
    } else claims[field.name] = value;
  }
  const result = claims as unknown as OperationsSiteDocumentClaims;
  if (!encodeOperationsSiteDocument(result).equals(payload)) return rejected();
  return Object.freeze(result);
}
/** Cryptographic framing only; signing is not generation admission or effectiveness. */
export function signOperationsSiteDocument(
  privateKey: Buffer,
  issuerSpki: Buffer,
  payload: Buffer,
): Buffer {
  const claims = decodeOperationsSiteDocument(payload);
  if (claims.issuerKeyId !== evidenceKeyId(issuerSpki)) return rejected();
  return signConsumerCose(profile, privateKey, issuerSpki, payload);
}
export function verifyOperationsSiteDocument(
  issuerSpki: Buffer,
  payload: Buffer,
  cose: Buffer,
): Readonly<OperationsSiteDocumentClaims> {
  try {
    const claims = decodeOperationsSiteDocument(payload);
    if (
      claims.issuerKeyId !== evidenceKeyId(issuerSpki) ||
      !verifyConsumerCose(profile, issuerSpki, payload, cose)
    )
      return rejected();
    return claims;
  } catch {
    return rejected();
  }
}

/** Independently installed trust. These pins must never be taken from the site
 * itself. Current issuer/revocation and generation fences belong to the durable
 * admission owner; the result below is authenticated input, not that authority. */
export interface InstalledOperationsSiteIssuer {
  readonly issuerSpki: Buffer;
  readonly issuerEpoch: string;
  readonly issuerValidFromMs: number;
  readonly issuerValidUntilMs: number;
  readonly environmentId: string;
  readonly profile: OperationsSiteDocumentClaims['profile'];
  readonly configurationSchemaDigest: string;
  readonly namedProfileDigest: string;
}
export function verifyInstalledOperationsSiteDocument(
  pins: InstalledOperationsSiteIssuer,
  expected: Pick<
    OperationsSiteDocumentClaims,
    'generationId' | 'baseGenerationId' | 'siteDigest' | 'declaredContentDigest'
  >,
  payload: Buffer,
  cose: Buffer,
  nowMs: number,
): Readonly<OperationsSiteDocumentClaims> & { readonly signedDocumentDigest: string } {
  try {
    valueToWire('safe_uint', nowMs);
    valueToWire('safe_uint', pins.issuerValidFromMs);
    valueToWire('safe_uint', pins.issuerValidUntilMs);
    const claims = verifyOperationsSiteDocument(pins.issuerSpki, payload, cose);
    for (const name of [
      'issuerEpoch',
      'environmentId',
      'profile',
      'configurationSchemaDigest',
      'namedProfileDigest',
    ] as const)
      if (claims[name] !== pins[name]) return rejected();
    for (const name of [
      'generationId',
      'baseGenerationId',
      'siteDigest',
      'declaredContentDigest',
    ] as const)
      if (claims[name] !== expected[name]) return rejected();
    if (
      claims.validFromMs < pins.issuerValidFromMs ||
      claims.validUntilMs > pins.issuerValidUntilMs ||
      nowMs < claims.validFromMs ||
      nowMs >= claims.validUntilMs
    )
      return rejected();
    return Object.freeze({ ...claims, signedDocumentDigest: digest(cose) });
  } catch {
    return rejected();
  }
}
