import { createHash } from 'node:crypto';
import { types as utilityTypes } from 'node:util';

import { z } from 'zod';

import {
  actionIntentIdSchema,
  openPcUrnSchema,
  rfc3339MicrosUtcSchema,
  sha256DigestSchema,
  uint64StringSchema,
} from './primitives.js';

export const authorityDecisionValues = [
  'ALLOW',
  'DENY',
  'UNKNOWN',
  'UNAVAILABLE',
  'STALE',
  'CONFLICT',
  'TAMPERED',
  'INCOMPATIBLE',
] as const;

export const authorityContextSchema = z.strictObject({
  principalId: openPcUrnSchema,
  participantId: openPcUrnSchema,
  privacyDomainId: openPcUrnSchema,
  sessionId: openPcUrnSchema,
  authorityEnvelopeId: openPcUrnSchema,
  authorityEpoch: uint64StringSchema,
  delegationEpoch: uint64StringSchema,
  actionIntentId: actionIntentIdSchema,
  policyGenerationDigest: sha256DigestSchema,
  factGenerationDigest: sha256DigestSchema,
});

export const authorityEvaluationSchema = z
  .strictObject({
    decision: z.enum(authorityDecisionValues),
    authorized: z.boolean(),
    terminal: z.boolean(),
    existenceVisible: z.boolean(),
    payloadVisible: z.boolean(),
    authorityContext: authorityContextSchema,
    inputsDigest: sha256DigestSchema,
    evaluatedAt: rfc3339MicrosUtcSchema,
    explanationCodes: z
      .array(z.string().regex(/^[A-Z][A-Z0-9_]{2,127}$/u))
      .min(1)
      .refine(
        (values) => new Set(values).size === values.length,
        'explanation codes must be unique',
      ),
    traceSetId: z.literal('TS-ID-AUTHORIZATION'),
  })
  .superRefine((evaluation, context) => {
    const allow = evaluation.decision === 'ALLOW';
    if (evaluation.authorized !== allow) {
      context.addIssue({
        code: 'custom',
        path: ['authorized'],
        message: 'only ALLOW may authorize',
      });
    }
    if (
      (allow &&
        (evaluation.terminal || !evaluation.existenceVisible || !evaluation.payloadVisible)) ||
      (!allow && (!evaluation.terminal || evaluation.existenceVisible || evaluation.payloadVisible))
    ) {
      context.addIssue({
        code: 'custom',
        path: ['decision'],
        message: 'authority visibility and terminal state must match the decision',
      });
    }
  });

function ownDataDescriptor(object: object, key: PropertyKey): PropertyDescriptor {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (
    descriptor === undefined ||
    !('value' in descriptor) ||
    !descriptor.enumerable ||
    typeof key === 'symbol'
  ) {
    throw new TypeError('canonical input must contain only enumerable string data properties');
  }
  return descriptor;
}

function serializeCanonicalObject(value: object, ancestors: Set<object>): string {
  if (utilityTypes.isProxy(value)) throw new TypeError('canonical input cannot be a proxy');
  if (ancestors.has(value)) throw new TypeError('cyclic canonical input');
  ancestors.add(value);
  try {
    if (value instanceof Date) {
      if (Object.getPrototypeOf(value) !== Date.prototype || Reflect.ownKeys(value).length !== 0) {
        throw new TypeError('date input contains unsupported properties');
      }
      if (Number.isNaN(value.getTime())) throw new TypeError('invalid date');
      return JSON.stringify(value.toISOString());
    }
    if (Buffer.isBuffer(value)) {
      if (Object.getPrototypeOf(value) !== Buffer.prototype) {
        throw new TypeError('buffer input must use the canonical Buffer prototype');
      }
      const keys = Reflect.ownKeys(value);
      if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) {
        throw new TypeError('buffer input contains unsupported properties');
      }
      return `{${keys
        .sort((left, right) => String(left).localeCompare(String(right)))
        .map((key) => {
          const descriptor = ownDataDescriptor(value, key);
          return `${JSON.stringify(key)}:${serializeCanonicalJsonValue(descriptor.value, ancestors)}`;
        })
        .join(',')}}`;
    }
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        throw new TypeError('array input must use the canonical Array prototype');
      }
      const keys = Reflect.ownKeys(value);
      const expectedKeys = Array.from({ length: value.length }, (_, index) => String(index));
      if (
        keys.length !== expectedKeys.length + 1 ||
        keys.at(-1) !== 'length' ||
        keys.slice(0, -1).some((key, index) => key !== expectedKeys[index])
      ) {
        throw new TypeError('canonical arrays must be dense and contain no extra properties');
      }
      return `[${expectedKeys
        .map((key) => serializeCanonicalJsonValue(ownDataDescriptor(value, key).value, ancestors))
        .join(',')}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('canonical input must contain only supported objects');
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key === 'symbol')) {
      throw new TypeError('canonical input cannot contain symbol properties');
    }
    return `{${keys
      .map(String)
      .sort()
      .map((key) => {
        const descriptor = ownDataDescriptor(value, key);
        return `${JSON.stringify(key)}:${serializeCanonicalJsonValue(descriptor.value, ancestors)}`;
      })
      .join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

function serializeCanonicalJsonValue(value: unknown, ancestors: Set<object>): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError('canonical numbers must be finite and not negative zero');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'object') return serializeCanonicalObject(value, ancestors);
  throw new TypeError('canonical input contains an unsupported value');
}

export function canonicalAuthorizationJson(value: unknown): string {
  return serializeCanonicalJsonValue(value, new Set());
}

export function canonicalAuthorizationDigestBytes(value: unknown): Buffer {
  return createHash('sha256').update(canonicalAuthorizationJson(value)).digest();
}

export function canonicalAuthorizationDigest(value: unknown): `sha256:${string}` {
  return `sha256:${canonicalAuthorizationDigestBytes(value).toString('hex')}`;
}

export type AuthorityContext = z.infer<typeof authorityContextSchema>;
export type AuthorityEvaluation = z.infer<typeof authorityEvaluationSchema>;
