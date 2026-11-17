import { createHash } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { workloadRenewalRequestContext } from './generated-request.js';
import { workloadRenewalAuthorizationContext } from './generated-authorization.js';
import type { WorkloadRenewalRequest, WorkloadRenewalPolicyAuthorization } from './types.js';

const reject = (): never => {
  throw new Error('Invalid canonical workload renewal');
};
type Context = typeof workloadRenewalRequestContext | typeof workloadRenewalAuthorizationContext;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const enums: Readonly<Record<string, Readonly<Record<string, number>>>> = {
  requestProfile: { 'pc.identity.workload-renewal.request.v1': 1 },
  authorizationProfile: { 'pc.identity.workload-renewal.policy-authorization.v1': 1 },
  policyAuthorized: { POLICY_AUTHORIZED: 1 },
};
function hash(value: unknown): Buffer {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value)) return reject();
  return Buffer.from(value.slice(7), 'hex');
}
function uuid(value: unknown): Buffer {
  if (typeof value !== 'string' || !uuidPattern.test(value)) return reject();
  return Buffer.from(value.replaceAll('-', ''), 'hex');
}
function uint(value: unknown, positive = false): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/u.test(value)) return reject();
  const integer = BigInt(value);
  if (integer > MAX_UINT64 || (positive && integer === 0n)) return reject();
  return integer;
}
function fields(context: Context, type: string) {
  return (
    context.types as Readonly<
      Record<string, readonly { key: number; name: string; type: string }[]>
    >
  )[type];
}
function wire(context: Context, type: string, value: unknown): CborValue {
  const shape = fields(context, type);
  if (shape) {
    if (
      value === null ||
      typeof value !== 'object' ||
      Object.getPrototypeOf(value) !== Object.prototype
    )
      return reject();
    if (
      Reflect.ownKeys(value).length !==
      shape.filter((field) => field.type !== 'definitionDigest').length
    )
      return reject();
    const result = new Map<number, CborValue>();
    for (const field of shape) {
      if (field.type === 'definitionDigest') {
        result.set(field.key, hash(context.definitionDigest));
        continue;
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, field.name);
      if (!descriptor || !('value' in descriptor)) return reject();
      result.set(field.key, wire(context, field.type, descriptor.value));
    }
    return result;
  }
  const choices = enums[type];
  if (choices) {
    if (typeof value !== 'string' || !Object.hasOwn(choices, value)) return reject();
    return choices[value]!;
  }
  switch (type) {
    case 'H32':
      return hash(value);
    case 'uuid':
      return uuid(value);
    case 'u64':
      return uint(value);
    case 'u64p':
      return uint(value, true);
    case 'nanos': {
      const integer = uint(value);
      if (integer % 1000n !== 0n) return reject();
      return integer;
    }
    case 'version1':
      if (value !== '1') return reject();
      return 1n;
    case 'workload':
      if (
        typeof value !== 'string' ||
        !value.startsWith('urn:openpc:workload:') ||
        !uuidPattern.test(value.slice('urn:openpc:workload:'.length))
      )
        return reject();
      return value;
    case 'id':
      if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}$/u.test(value))
        return reject();
      return value;
    case 'requestBytes':
      if (!Buffer.isBuffer(value)) return reject();
      decodeWorkloadRenewalRequest(value);
      return value;
    default:
      return reject();
  }
}
function fromWire(context: Context, type: string, value: CborValue | undefined): unknown {
  const shape = fields(context, type);
  if (shape) {
    if (!(value instanceof Map) || value.size !== shape.length) return reject();
    const result: Record<string, unknown> = {};
    for (const field of shape) {
      if (!value.has(field.key)) return reject();
      const item = value.get(field.key);
      if (field.type === 'definitionDigest') {
        if (!Buffer.isBuffer(item) || !item.equals(hash(context.definitionDigest))) return reject();
      } else result[field.name] = fromWire(context, field.type, item);
    }
    return result;
  }
  const choices = enums[type];
  if (choices) {
    if (typeof value !== 'bigint') return reject();
    return Object.entries(choices).find(([, code]) => BigInt(code) === value)?.[0] ?? reject();
  }
  switch (type) {
    case 'H32':
      if (!Buffer.isBuffer(value) || value.length !== 32) return reject();
      return `sha256:${value.toString('hex')}`;
    case 'uuid': {
      if (!Buffer.isBuffer(value) || value.length !== 16) return reject();
      const h = value.toString('hex');
      return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    }
    case 'version1':
      if (value !== 1n) return reject();
      return '1';
    case 'u64':
    case 'u64p':
    case 'nanos':
      if (typeof value !== 'bigint') return reject();
      return value.toString();
    case 'workload':
    case 'id':
      if (typeof value !== 'string') return reject();
      return value;
    case 'requestBytes':
      if (!Buffer.isBuffer(value)) return reject();
      return value;
    default:
      return reject();
  }
}
export function workloadRenewalDigest(bytes: Buffer): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}
function validateRequest(value: WorkloadRenewalRequest) {
  const start = BigInt(value.requestValidFromNs),
    end = BigInt(value.requestValidUntilNs);
  const from = BigInt(value.requestedCertificateNotBeforeNs),
    until = BigInt(value.requestedCertificateNotAfterNs);
  if (
    !(
      end > start &&
      end - start <= 120000000000n &&
      from % 1000000000n === 0n &&
      until % 1000000000n === 0n &&
      until > from &&
      until - from <= 86400000000000n
    ) ||
    value.renewalId === value.predecessorCredentialId
  )
    return reject();
}
export function encodeWorkloadRenewalRequest(value: WorkloadRenewalRequest): Buffer {
  const encoded = wire(workloadRenewalRequestContext, 'Request', value);
  validateRequest(value);
  return encodeCbor(encoded);
}
export function decodeWorkloadRenewalRequest(bytes: Buffer): WorkloadRenewalRequest {
  const value = fromWire(
    workloadRenewalRequestContext,
    'Request',
    decodeCbor(bytes),
  ) as WorkloadRenewalRequest;
  if (!encodeWorkloadRenewalRequest(value).equals(bytes)) return reject();
  return value;
}
function validateAuthorization(value: WorkloadRenewalPolicyAuthorization) {
  const request = decodeWorkloadRenewalRequest(value.requestBytes);
  const issued = BigInt(value.issuedAtNs),
    until = BigInt(value.validUntilNs);
  if (
    value.requestDigest !== workloadRenewalDigest(value.requestBytes) ||
    value.signer.participantId !== request.participantId ||
    value.signer.privacyDomainId !== request.privacyDomainId ||
    value.signer.keyId === request.newKeyDigest ||
    new Set([
      request.renewalId,
      request.predecessorCredentialId,
      value.operationId,
      value.credentialId,
    ]).size !== 4 ||
    issued < BigInt(request.requestValidFromNs) ||
    !(until > issued && until - issued <= 30000000000n) ||
    until > BigInt(request.requestValidUntilNs) ||
    until > BigInt(value.attestationValidUntilNs)
  )
    return reject();
}
export function encodeWorkloadRenewalPolicyAuthorization(
  value: WorkloadRenewalPolicyAuthorization,
): Buffer {
  const encoded = wire(workloadRenewalAuthorizationContext, 'Authorization', value);
  validateAuthorization(value);
  return encodeCbor(encoded);
}
export function decodeWorkloadRenewalPolicyAuthorization(
  bytes: Buffer,
): WorkloadRenewalPolicyAuthorization {
  const value = fromWire(
    workloadRenewalAuthorizationContext,
    'Authorization',
    decodeCbor(bytes),
  ) as WorkloadRenewalPolicyAuthorization;
  if (!encodeWorkloadRenewalPolicyAuthorization(value).equals(bytes)) return reject();
  return value;
}
