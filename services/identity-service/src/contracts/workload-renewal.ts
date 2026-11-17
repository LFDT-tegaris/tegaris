import { createHash, createPublicKey } from 'node:crypto';
import { z } from 'zod';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { sha256DigestSchema as digestPrimitive } from './primitives.js';
import {
  decodeWorkloadRenewalRequest,
  verifyWorkloadRenewalCose,
  workloadRenewalDigest,
} from '../../../../packages/security-kernel/src/index.js';

// Preserve the frozen worker's template-literal type after exact validation.
const sha256DigestSchema = digestPrimitive.pipe(z.templateLiteral(['sha256:', z.string()]));

const generation = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const base64 = (max: number) =>
  z
    .string()
    .min(4)
    .max(max)
    .refine((value) => Buffer.from(value, 'base64').toString('base64') === value);
const instant = z.iso.datetime({ precision: 3 });
const ids = {
  renewalId: z.uuidv7(),
  operationId: z.uuidv7(),
  credentialId: z.uuidv7(),
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  principalId: z.uuidv7(),
  workloadId: z
    .string()
    .regex(
      /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    ),
  familyId: z.uuidv7(),
  instanceId: z.uuidv7(),
  instanceGeneration: generation,
  predecessorCredentialId: z.uuidv7(),
  expectedFamilyGeneration: generation,
  policyId: z.uuidv7(),
  policyRevision: generation,
  policyDigest: sha256DigestSchema,
  attestationProfileDigest: sha256DigestSchema,
  attestationDigest: sha256DigestSchema,
  issuerProfileDigest: sha256DigestSchema,
  providerQualificationDigest: sha256DigestSchema,
  providerRequestId: z.uuidv7(),
};

/** Provider v2 is a distinct contract. No v1 request or immutable signature is
 * reinterpreted as v2; all fields below are committed before provider I/O. */
export const workloadRenewalProviderRequestSchema = z
  .strictObject({
    version: z.literal(2),
    ...ids,
    publicKeySpkiDerBase64: base64(2048),
    requestPayloadBase64: base64(8192),
    newKeyProofBase64: base64(8192),
    algorithm: z.literal('ECDSA_P256_SHA256'),
    uriSan: z.string().max(256),
    audience: z.string().min(1).max(256),
    validFrom: instant,
    validUntil: instant,
  })
  .superRefine((value, context) => {
    const fail = (message: string) => context.addIssue({ code: 'custom', message });
    if (
      value.providerRequestId !== value.renewalId ||
      new Set([
        value.renewalId,
        value.operationId,
        value.credentialId,
        value.predecessorCredentialId,
      ]).size !== 4
    )
      fail('distinct original identities required');
    if (
      value.uriSan !==
      `urn:openpc:participant:${value.participantId}:workload:${value.workloadId.split(':').at(-1)}`
    )
      fail('registered workload SAN required');
    const lifetime = Date.parse(value.validUntil) - Date.parse(value.validFrom);
    if (
      lifetime <= 0 ||
      lifetime > 86_400_000 ||
      Date.parse(value.validFrom) % 1000 !== 0 ||
      Date.parse(value.validUntil) % 1000 !== 0
    )
      fail('finite exact certificate interval required');
    try {
      const bytes = Buffer.from(value.publicKeySpkiDerBase64, 'base64');
      const key = createPublicKey({ key: bytes, format: 'der', type: 'spki' });
      if (
        key.asymmetricKeyType !== 'ec' ||
        key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
        !Buffer.from(key.export({ format: 'der', type: 'spki' })).equals(bytes)
      )
        fail('canonical P256 public key required');
      const payload = Buffer.from(value.requestPayloadBase64, 'base64');
      const proof = Buffer.from(value.newKeyProofBase64, 'base64');
      const signed = decodeWorkloadRenewalRequest(payload);
      if (
        !verifyWorkloadRenewalCose('REQUEST', bytes, payload, proof) ||
        signed.newKeyDigest !== workloadRenewalDigest(bytes)
      )
        fail('exact successor key proof required');
      for (const field of [
        'participantId',
        'privacyDomainId',
        'familyId',
        'instanceId',
        'instanceGeneration',
        'workloadId',
        'principalId',
        'renewalId',
        'predecessorCredentialId',
        'policyId',
        'policyRevision',
        'policyDigest',
        'attestationProfileDigest',
        'attestationDigest',
        'issuerProfileDigest',
        'providerQualificationDigest',
      ] as const)
        if (signed[field] !== value[field]) fail('signed renewal scope binding required');
      if (
        signed.predecessorGeneration !== value.expectedFamilyGeneration ||
        BigInt(signed.requestedCertificateNotBeforeNs) !==
          BigInt(Date.parse(value.validFrom)) * 1000000n ||
        BigInt(signed.requestedCertificateNotAfterNs) !==
          BigInt(Date.parse(value.validUntil)) * 1000000n
      )
        fail('signed renewal interval and generation binding required');
    } catch {
      fail('canonical P256 public key required');
    }
  });
export type WorkloadRenewalProviderRequest = z.infer<typeof workloadRenewalProviderRequestSchema>;

export const workloadRenewalOriginalSchema = z
  .strictObject({
    version: z.literal(2),
    ...ids,
    providerRequestBase64: base64(32768),
    providerRequestDigest: sha256DigestSchema,
  })
  .superRefine((original, context) => {
    try {
      const bytes = Buffer.from(original.providerRequestBase64, 'base64');
      const request = workloadRenewalProviderRequestSchema.parse(
        JSON.parse(bytes.toString('utf8')),
      );
      const canonical = Buffer.from(canonicalDefinitionJson(request));
      if (!canonical.equals(bytes) || renewalBytesDigest(bytes) !== original.providerRequestDigest)
        throw new Error();
      for (const field of Object.keys(ids) as (keyof typeof ids)[])
        if (request[field] !== original[field]) throw new Error();
    } catch {
      context.addIssue({ code: 'custom', message: 'exact canonical original request required' });
    }
  });

/** An externally qualified provider signs this statement in its own proof
 * domain. Qualification must guarantee linearizable read-original and exact
 * idempotency; authentication alone cannot establish those properties. */
export const workloadRenewalProviderProofSchema = z
  .strictObject({
    domain: z.literal('OPENPC_WORKLOAD_RENEWAL_PROVIDER_OBSERVATION'),
    version: z.literal(2),
    kind: z.enum(['NOT_ISSUED', 'CERTIFICATE']),
    providerRequestId: z.uuidv7(),
    providerRequestDigest: sha256DigestSchema,
    providerQualificationDigest: sha256DigestSchema,
    observationRevision: generation,
    observedAt: instant,
    validUntil: instant,
    certificateDigest: sha256DigestSchema.nullable(),
  })
  .superRefine((value, context) => {
    if (
      (value.kind === 'CERTIFICATE') !== (value.certificateDigest !== null) ||
      Date.parse(value.validUntil) <= Date.parse(value.observedAt)
    )
      context.addIssue({ code: 'custom', message: 'bounded observation kind required' });
  });
export const workloadRenewalProviderProofEnvelopeSchema = z.strictObject({
  statement: workloadRenewalProviderProofSchema,
  signatureBase64: base64(128),
});

export function renewalBytesDigest(bytes: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}
export function encodeWorkloadRenewalProviderRequest(input: WorkloadRenewalProviderRequest) {
  return Buffer.from(canonicalDefinitionJson(workloadRenewalProviderRequestSchema.parse(input)));
}
