import {
  signingSecretReferencePattern,
  isExactSigningSecretReference,
} from '../../../../packages/security-kernel/src/business-transition/secret-reference.js';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { z } from 'zod';
import {
  qualificationOnlinePurposes,
  qualificationCanonicalJson,
  qualificationDigest,
  qualificationSpki,
} from '../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uuid = z.uuidv7();
const epoch = z
  .string()
  .regex(/^[1-9][0-9]{0,15}$/u)
  .refine((v) => Number.isSafeInteger(Number(v)));
const time = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER)
  .refine((v) => !Object.is(v, -0));
const name = z.string().regex(/^[a-z][a-z0-9-]{2,31}$/u);
const text = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u);
const purpose = z.enum(qualificationOnlinePurposes);
const spki = z
  .string()
  .regex(/^[0-9a-f]{182}$/u)
  .refine((v) => {
    try {
      qualificationSpki(Buffer.from(v, 'hex'));
      return true;
    } catch {
      return false;
    }
  });
const reference = z.string().regex(new RegExp(signingSecretReferencePattern, 'u')).max(331);
const version = z
  .string()
  .regex(/^[a-zA-Z0-9._-]{1,96}$/u)
  .refine((v) => !['latest', 'current'].includes(v.toLowerCase()));

export const qualificationKeyPeerSchema = z.strictObject({
  principalId: uuid,
  credentialId: uuid,
  participantEpoch: epoch,
  principalEpoch: epoch,
  credentialEpoch: epoch,
  workloadId: text,
  keyDigest: digest,
  certificateDigest: digest,
});
export type QualificationKeyPeer = z.infer<typeof qualificationKeyPeerSchema>;
function separatedPeers(subject: QualificationKeyPeer, observer: QualificationKeyPeer) {
  return (
    subject.participantEpoch === observer.participantEpoch &&
    (
      ['principalId', 'credentialId', 'workloadId', 'keyDigest', 'certificateDigest'] as const
    ).every((field) => subject[field] !== observer[field])
  );
}
/** Privileged public installation pins. These never come from a provider response. */
const installation = {
  installationId: uuid,
  participantId: uuid,
  privacyDomainId: uuid,
  environmentId: name,
  authorityId: name,
  rootEpoch: epoch,
  keyId: digest,
  keyEpoch: epoch,
  purpose,
  publicKeySpkiHex: spki,
  reference,
  version,
  providerId: text,
  providerOrigin: z.url(),
  providerTlsSpkiDigest: digest,
  peer: qualificationKeyPeerSchema,
  validFromMs: time,
  validUntilMs: time,
};
export const qualificationKeyInstallationSchema = z
  .discriminatedUnion('schemaVersion', [
    z.strictObject({ ...installation, schemaVersion: z.literal(1) }),
    z.strictObject({
      ...installation,
      schemaVersion: z.literal(2),
      observer: qualificationKeyPeerSchema,
    }),
  ])
  .superRefine((v, c) => {
    const origin = new URL(v.providerOrigin);
    if (
      origin.protocol !== 'https:' ||
      origin.origin !== v.providerOrigin ||
      origin.username ||
      origin.password ||
      !isExactSigningSecretReference(v.reference, v.version) ||
      v.validUntilMs <= v.validFromMs ||
      qualificationDigest(Buffer.from(v.publicKeySpkiHex, 'hex')) !== v.keyId ||
      new Set([
        v.keyId,
        v.providerTlsSpkiDigest,
        v.peer.keyDigest,
        ...(v.schemaVersion === 2 ? [v.observer.keyDigest] : []),
      ]).size !== (v.schemaVersion === 2 ? 4 : 3) ||
      (v.schemaVersion === 2 && !separatedPeers(v.peer, v.observer))
    )
      c.addIssue({ code: 'custom', message: 'Invalid qualification key installation' });
  });
export type QualificationKeyInstallation = z.infer<typeof qualificationKeyInstallationSchema>;

export class QualificationKeyProviderUnknown extends Error {
  constructor() {
    super('Qualification key observation requires reconciliation');
  }
}
export function qualificationKeyCopy<T>(value: T): Readonly<T> {
  const json = qualificationCanonicalJson(value);
  if (Buffer.byteLength(json) > 131072) throw new QualificationKeyProviderUnknown();
  const copy: T = JSON.parse(json);
  const freeze = (v: unknown): void => {
    if (v !== null && typeof v === 'object') {
      for (const child of Object.values(v)) freeze(child);
      Object.freeze(v);
    }
  };
  freeze(copy);
  return copy;
}
export function qualificationKeyInstallation(value: unknown) {
  const pins = qualificationKeyCopy(
    qualificationKeyInstallationSchema.parse(qualificationKeyCopy(value)),
  );
  const bytes = Buffer.from(qualificationCanonicalJson(pins));
  return Object.freeze({
    pins,
    digest: qualificationDigest(bytes),
    get bytes() {
      return Buffer.from(bytes);
    },
  });
}
const binding = {
  installationDigest: digest,
  participantId: uuid,
  privacyDomainId: uuid,
  environmentId: name,
  authorityId: name,
  rootEpoch: epoch,
  keysetDigest: digest,
  revocationsDigest: digest,
  keyId: digest,
  keyEpoch: epoch,
  purpose,
  providerId: text,
  reference,
  version,
  peer: qualificationKeyPeerSchema,
  operationId: uuid,
  attemptId: uuid,
  issuedAtMs: time,
  deadlineAtMs: time,
};
const proofBinding = {
  method: z.literal('PROVE'),
  inspectionAttemptId: uuid,
  challengeHex: z.string().regex(/^[0-9a-f]{64}$/u),
  descriptorDigest: digest,
};
export const qualificationKeyRequestSchema = z
  .discriminatedUnion('schemaVersion', [
    z.discriminatedUnion('method', [
      z.strictObject({ ...binding, schemaVersion: z.literal(1), method: z.literal('INSPECT') }),
      z.strictObject({ ...binding, schemaVersion: z.literal(1), ...proofBinding }),
    ]),
    z.discriminatedUnion('method', [
      z.strictObject({
        ...binding,
        schemaVersion: z.literal(2),
        observer: qualificationKeyPeerSchema,
        method: z.literal('INSPECT'),
      }),
      z.strictObject({
        ...binding,
        schemaVersion: z.literal(2),
        observer: qualificationKeyPeerSchema,
        ...proofBinding,
      }),
    ]),
  ])
  .superRefine((v, c) => {
    if (
      v.deadlineAtMs <= v.issuedAtMs ||
      v.deadlineAtMs - v.issuedAtMs > 10000 ||
      !isExactSigningSecretReference(v.reference, v.version) ||
      (v.schemaVersion === 2 && !separatedPeers(v.peer, v.observer))
    )
      c.addIssue({ code: 'custom', message: 'Invalid qualification observation interval' });
  });
export type QualificationKeyRequest = z.infer<typeof qualificationKeyRequestSchema>;
const acl = z.strictObject({
  credentialId: uuid,
  credentialEpoch: epoch,
  certificateDigest: digest,
  methods: z
    .array(z.enum(['INSPECT', 'PROVE']))
    .min(1)
    .max(2)
    .refine((v) => new Set(v).size === v.length),
});
/** Authenticated external policy observation, not an OpenPC eligibility claim.
 * Software fixture assurance must never be promoted to hardware assurance. */
const descriptor = {
  providerId: text,
  participantId: uuid,
  privacyDomainId: uuid,
  environmentId: name,
  authorityId: name,
  rootEpoch: epoch,
  keyId: digest,
  keyEpoch: epoch,
  purpose,
  reference,
  version,
  publicKeySpkiHex: spki,
  algorithm: z.literal('ES256'),
  state: z.enum(['ACTIVE', 'REVOKED', 'RETIRED']),
  validFromMs: time,
  validUntilMs: time,
  policyRevision: epoch,
  custody: z.enum(['EXTERNAL_SOFTWARE_FIXTURE', 'EXTERNAL_PROVIDER']),
  clients: z.array(acl).min(1).max(64),
};
const observerPair = z
  .strictObject({
    observer: qualificationKeyPeerSchema,
    subject: qualificationKeyPeerSchema,
    methods: acl.shape.methods,
  })
  .refine((p) => separatedPeers(p.subject, p.observer));
export const qualificationKeyDescriptorSchema = z
  .discriminatedUnion('schemaVersion', [
    z.strictObject({ ...descriptor, schemaVersion: z.literal(1) }),
    z.strictObject({
      ...descriptor,
      schemaVersion: z.literal(2),
      observers: z.array(observerPair).min(1).max(64),
    }),
  ])
  .superRefine((v, c) => {
    if (
      v.validUntilMs <= v.validFromMs ||
      !isExactSigningSecretReference(v.reference, v.version) ||
      qualificationDigest(Buffer.from(v.publicKeySpkiHex, 'hex')) !== v.keyId ||
      new Set(v.clients.map((p) => p.certificateDigest)).size !== v.clients.length ||
      (v.schemaVersion === 2 &&
        (new Set(
          v.observers.map((p) => p.observer.certificateDigest + ':' + p.subject.certificateDigest),
        ).size !== v.observers.length ||
          v.observers.some(
            (p) =>
              !v.clients.some(
                (c) =>
                  c.credentialId === p.subject.credentialId &&
                  c.credentialEpoch === p.subject.credentialEpoch &&
                  c.certificateDigest === p.subject.certificateDigest &&
                  p.methods.every((m) => c.methods.includes(m)),
              ),
          )))
    )
      c.addIssue({ code: 'custom', message: 'Invalid external key descriptor' });
  });
export type QualificationKeyDescriptor = z.infer<typeof qualificationKeyDescriptorSchema>;
export const qualificationKeyObservationSchema = z
  .strictObject({
    schemaVersion: z.union([z.literal(1), z.literal(2)]),
    attemptId: uuid,
    requestDigest: digest,
    observedAtMs: time,
    outcome: z.enum(['OBSERVED', 'REJECTED']),
    reason: z
      .enum([
        'DENIED',
        'EXPIRED',
        'REVOKED',
        'KEY_UNAVAILABLE',
        'DESCRIPTOR_CHANGED',
        'ATTEMPT_CONFLICT',
      ])
      .nullable(),
    descriptor: qualificationKeyDescriptorSchema.nullable(),
    proofHex: z
      .string()
      .regex(/^[0-9a-f]{128}$/u)
      .nullable(),
  })
  .superRefine((v, c) => {
    if (
      v.outcome === 'OBSERVED'
        ? v.reason !== null ||
          v.descriptor === null ||
          v.descriptor.schemaVersion !== v.schemaVersion
        : v.reason === null || v.proofHex !== null || v.descriptor !== null
    )
      c.addIssue({ code: 'custom', message: 'Invalid qualification key outcome' });
  });
export type QualificationKeyObservation = z.infer<typeof qualificationKeyObservationSchema>;
export function qualificationKeyRequestDigest(value: QualificationKeyRequest) {
  return (
    'sha256:' +
    createHash('sha256')
      .update(
        `pc.qualification-key-observation-request.v${qualificationKeyRequestSchema.parse(value).schemaVersion}\0`,
      )
      .update(qualificationCanonicalJson(qualificationKeyRequestSchema.parse(value)))
      .digest('hex')
  );
}
export function qualificationKeyDescriptorDigest(value: QualificationKeyDescriptor) {
  return qualificationDigest(
    Buffer.from(qualificationCanonicalJson(qualificationKeyDescriptorSchema.parse(value))),
  );
}
/** Not COSE and not arbitrary caller payload: this exact non-receipt domain is fixed. */
export function qualificationKeyPossessionPreimage(
  original: QualificationKeyRequest,
  descriptor: QualificationKeyDescriptor,
) {
  const request = qualificationKeyRequestSchema.parse(original);
  if (
    request.method !== 'PROVE' ||
    request.schemaVersion !== descriptor.schemaVersion ||
    request.descriptorDigest !== qualificationKeyDescriptorDigest(descriptor)
  )
    throw new QualificationKeyProviderUnknown();
  return Buffer.from(
    `pc.qualification-key-possession.v${request.schemaVersion}\0` +
      qualificationCanonicalJson({ request, descriptor }),
  );
}
export function validateQualificationKeyRequest(
  value: unknown,
  trust: QualificationKeyInstallation,
): QualificationKeyRequest {
  const request = qualificationKeyCopy(
    qualificationKeyRequestSchema.parse(qualificationKeyCopy(value)),
  );
  const installed = qualificationKeyInstallation(trust),
    p = installed.pins;
  if (
    request.schemaVersion !== p.schemaVersion ||
    request.installationDigest !== installed.digest ||
    (request.schemaVersion === 2 &&
      (p.schemaVersion !== 2 ||
        qualificationCanonicalJson(request.observer) !== qualificationCanonicalJson(p.observer))) ||
    [
      'participantId',
      'privacyDomainId',
      'environmentId',
      'authorityId',
      'rootEpoch',
      'keyId',
      'keyEpoch',
      'purpose',
      'providerId',
      'reference',
      'version',
    ].some((k) => request[k as keyof typeof request] !== p[k as keyof typeof p]) ||
    qualificationCanonicalJson(request.peer) !== qualificationCanonicalJson(p.peer) ||
    request.issuedAtMs < p.validFromMs ||
    request.deadlineAtMs > p.validUntilMs
  )
    throw new QualificationKeyProviderUnknown();
  return request;
}
/** Provider-authorized inspection pair only. This reports the subject's ACL;
 * observer key possession never proves subject key possession or SIGN authority. */
export function qualificationKeyDescriptorAdmits(
  descriptor: QualificationKeyDescriptor,
  request: QualificationKeyRequest,
): boolean {
  if (
    descriptor.schemaVersion !== request.schemaVersion ||
    !descriptor.clients.some(
      (c) =>
        c.credentialId === request.peer.credentialId &&
        c.credentialEpoch === request.peer.credentialEpoch &&
        c.certificateDigest === request.peer.certificateDigest &&
        c.methods.includes(request.method),
    )
  )
    return false;
  return (
    request.schemaVersion === 1 ||
    (descriptor.schemaVersion === 2 &&
      descriptor.observers.some(
        (pair) =>
          qualificationCanonicalJson(pair.observer) ===
            qualificationCanonicalJson(request.observer) &&
          qualificationCanonicalJson(pair.subject) === qualificationCanonicalJson(request.peer) &&
          pair.methods.includes(request.method),
      ))
  );
}
export function validateQualificationKeyObservation(
  original: QualificationKeyRequest,
  value: unknown,
  trust: QualificationKeyInstallation,
  first?: QualificationKeyObservation,
): QualificationKeyObservation {
  const request = validateQualificationKeyRequest(original, trust);
  const o = qualificationKeyCopy(
    qualificationKeyObservationSchema.parse(qualificationKeyCopy(value)),
  );
  if (
    o.schemaVersion !== request.schemaVersion ||
    o.attemptId !== request.attemptId ||
    o.requestDigest !== qualificationKeyRequestDigest(request) ||
    o.observedAtMs < request.issuedAtMs ||
    (o.outcome === 'OBSERVED' && o.observedAtMs >= request.deadlineAtMs) ||
    (first && qualificationCanonicalJson(first) !== qualificationCanonicalJson(o))
  )
    throw new QualificationKeyProviderUnknown();
  if (o.outcome === 'REJECTED') return o;
  const d = o.descriptor!;
  if (
    [
      'participantId',
      'privacyDomainId',
      'environmentId',
      'authorityId',
      'rootEpoch',
      'keyId',
      'keyEpoch',
      'purpose',
      'providerId',
      'reference',
      'version',
    ].some((k) => d[k as keyof typeof d] !== request[k as keyof typeof request]) ||
    d.publicKeySpkiHex !== trust.publicKeySpkiHex ||
    d.state !== 'ACTIVE' ||
    o.observedAtMs < d.validFromMs ||
    o.observedAtMs >= d.validUntilMs ||
    !qualificationKeyDescriptorAdmits(d, request)
  )
    throw new QualificationKeyProviderUnknown();
  if (
    request.method === 'INSPECT'
      ? o.proofHex !== null
      : o.proofHex === null ||
        !verify(
          'sha256',
          qualificationKeyPossessionPreimage(request, d),
          {
            key: createPublicKey({
              key: Buffer.from(d.publicKeySpkiHex, 'hex'),
              format: 'der',
              type: 'spki',
            }),
            dsaEncoding: 'ieee-p1363',
          },
          Buffer.from(o.proofHex, 'hex'),
        )
  )
    throw new QualificationKeyProviderUnknown();
  return o;
}
export interface QualificationKeyProvider {
  /** Only a committed exclusive native DISPATCHED claim permits this exchange. */
  perform(original: QualificationKeyRequest): Promise<QualificationKeyObservation>;
  /** Exact original lookup only. ABSENT is uncertainty, never permission to perform again. */
  lookup(
    original: QualificationKeyRequest,
    first?: QualificationKeyObservation,
  ): Promise<QualificationKeyObservation | undefined>;
  close(): void;
}
