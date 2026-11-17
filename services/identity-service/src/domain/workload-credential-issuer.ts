import { createHash, timingSafeEqual, X509Certificate } from 'node:crypto';

import { z } from 'zod';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';

const responseSchema = z.strictObject({
  certificateDer: z.string().min(1).max(32_768),
});

const localCertificate = z.strictObject({
  credentialId: z.uuid(),
  participantId: z.uuid(),
  principalId: z.uuid(),
  workloadId: z.string().regex(/^urn:openpc:workload:[0-9a-f-]{36}$/u),
  publicKeySpkiDer: z.string().min(1),
  certificateDer: z.string().min(1),
});
export const localWorkloadIssuerProfileSchema = z.strictObject({
  profileId: z.uuid(),
  endpoint: z.url(),
  trustedCaPem: z.string().min(1).max(16_384),
  certificates: z.array(localCertificate).min(1).max(10_000),
});

export interface ImmutableLocalWorkloadIssuerManifest {
  readonly localQaEnabled: boolean;
  readonly manifestDigest: Buffer;
  readonly certificates: readonly {
    readonly requestDigest: Buffer;
    readonly certificateFingerprint: Buffer;
    readonly validity: { readonly validFromMs: number; readonly validUntilMs: number };
  }[];
}

type LocalIssuerProfileInput = {
  readonly bytes: Buffer;
  readonly expectedDigest: string;
  readonly endpoint: string;
  readonly trustedCaPem: Buffer;
  readonly localQaEnabled: boolean;
  readonly now?: Date;
};
/** Current-use qualification retains its original expiry semantics. */
export function readImmutableLocalWorkloadIssuerProfile(
  input: LocalIssuerProfileInput,
): ImmutableLocalWorkloadIssuerManifest {
  return authenticateLocalIssuerProfile(input, true);
}
/** Authenticate retained installed bytes so the control plane can recover an
 * expired provider configuration. This does not attest certificate currentness.
 * The returned DER-derived bounds fence provider dispatch and live verification.
 */
export function authenticateHistoricalLocalWorkloadIssuerProfile(
  input: Omit<LocalIssuerProfileInput, 'now'>,
): ImmutableLocalWorkloadIssuerManifest {
  return authenticateLocalIssuerProfile(input, false);
}
function authenticateLocalIssuerProfile(
  input: LocalIssuerProfileInput,
  requireCurrent: boolean,
): ImmutableLocalWorkloadIssuerManifest {
  if (
    !input.localQaEnabled ||
    !/^[0-9a-f]{64}$/u.test(input.expectedDigest) ||
    createHash('sha256').update(input.bytes).digest('hex') !== input.expectedDigest
  )
    throw new Error('Installed local issuer profile is not qualified');
  const profile = localWorkloadIssuerProfileSchema.parse(JSON.parse(input.bytes.toString('utf8')));
  const endpoint = new URL(profile.endpoint);
  if (
    endpoint.href !== new URL(input.endpoint).href ||
    endpoint.pathname !== `/v1/certificates/${profile.profileId}` ||
    endpoint.search !== '' ||
    endpoint.hash !== '' ||
    !new X509Certificate(Buffer.from(profile.trustedCaPem)).raw.equals(
      new X509Certificate(input.trustedCaPem).raw,
    )
  )
    throw new Error('Installed local issuer endpoint or CA mismatch');
  if (new Set(profile.certificates.map((v) => v.credentialId)).size !== profile.certificates.length)
    throw new Error('Duplicate local issuer credential');
  const certificates = profile.certificates.map((certificate) => {
    const der = Buffer.from(certificate.certificateDer, 'base64'),
      spki = Buffer.from(certificate.publicKeySpkiDer, 'base64');
    if (
      der.toString('base64') !== certificate.certificateDer ||
      spki.toString('base64') !== certificate.publicKeySpkiDer
    )
      throw new Error('Noncanonical local issuer certificate encoding');
    const request = { ...certificate, publicKeySpkiDer: spki };
    const authenticated = authenticateWorkloadCertificate(der, input.trustedCaPem, request);
    const observed = requireCurrent
      ? verifyIssuedWorkloadCertificate(der, input.trustedCaPem, request, input.now)
      : authenticated?.certificate;
    if (!observed || !authenticated) throw new Error('Untrusted local issuer profile certificate');
    return {
      requestDigest: workloadCertificateRequestDigest(request),
      certificateFingerprint: observed.certificateFingerprint,
      validity: authenticated.validity,
    };
  });
  return {
    localQaEnabled: true,
    manifestDigest: Buffer.from(input.expectedDigest, 'hex'),
    certificates,
  };
}

/** Security ceiling, distinct from the issuer's configured certificate lifetime. */
export const WORKLOAD_CERTIFICATE_MAX_LIFETIME_MS = 24 * 60 * 60 * 1000;

export interface WorkloadCertificateRequest {
  readonly credentialId: string;
  readonly participantId: string;
  readonly principalId: string;
  readonly workloadId: string;
  readonly publicKeySpkiDer: Buffer;
}

export interface IssuedWorkloadCertificate extends WorkloadCertificateRequest {
  readonly certificateDer: Buffer;
  readonly issuer: string;
  readonly uriSan: string;
  readonly keyId: string;
  readonly certificateFingerprint: Buffer;
  readonly notBefore: Date;
  readonly notAfter: Date;
}

/** Reconciliation profile supplied by the actual transport adapter. A profile
 * never grants credential or recovery authority. Missing qualification denies
 * recovery issuance; normal issuance remains compatible. */
export interface WorkloadIssuerRecovery {
  readonly profileDigest: Buffer;
  readonly replayProfile: 'IMMUTABLE_REQUEST_RESPONSE' | 'READBACK_REQUIRED';
  verifyObservation(
    input: WorkloadCertificateRequest,
    certificateDer: Buffer,
    now: Date,
  ): IssuedWorkloadCertificate | undefined;
}
export interface WorkloadCredentialIssuer {
  readonly recovery?: WorkloadIssuerRecovery;
  issue(
    input: WorkloadCertificateRequest,
    signal?: AbortSignal,
  ): Promise<IssuedWorkloadCertificate>;
}

export const rejectingWorkloadCredentialIssuer: WorkloadCredentialIssuer = {
  async issue() {
    throw new Error('Workload certificate issuer is not configured');
  },
};

/** The same canonical request digest is retained by the durable issuance owner. */
export function workloadCertificateRequestDigest(input: WorkloadCertificateRequest): Buffer {
  return canonicalAuthorizationDigestBytes({
    credentialId: input.credentialId,
    participantId: input.participantId,
    principalId: input.principalId,
    workloadId: input.workloadId,
    publicKeySpkiDer: input.publicKeySpkiDer.toString('base64'),
  });
}

function exactUriSan(certificate: X509Certificate): string | undefined {
  const entries = (certificate.subjectAltName ?? '').split(', ').filter(Boolean);
  return entries.length === 1 && entries[0]?.startsWith('URI:') ? entries[0].slice(4) : undefined;
}

export function verifyIssuedWorkloadCertificate(
  certificateDer: Buffer,
  trustedCaPem: Buffer,
  input: WorkloadCertificateRequest,
  now = new Date(),
): IssuedWorkloadCertificate | undefined {
  try {
    const authenticated = authenticateWorkloadCertificate(certificateDer, trustedCaPem, input);
    const nowMs = now.getTime();
    if (
      !authenticated ||
      !Number.isFinite(nowMs) ||
      authenticated.validity.validFromMs > nowMs + 5_000 ||
      authenticated.validity.validUntilMs <= nowMs
    )
      return undefined;
    return authenticated.certificate;
  } catch {
    return undefined;
  }
}
function authenticateWorkloadCertificate(
  certificateDer: Buffer,
  trustedCaPem: Buffer,
  input: WorkloadCertificateRequest,
):
  | {
      certificate: IssuedWorkloadCertificate;
      validity: { validFromMs: number; validUntilMs: number };
    }
  | undefined {
  try {
    const certificate = new X509Certificate(certificateDer);
    const trustedCa = new X509Certificate(trustedCaPem);
    const publicKeySpkiDer = Buffer.from(
      certificate.publicKey.export({ format: 'der', type: 'spki' }),
    );
    const requestedKey = Buffer.from(input.publicKeySpkiDer);
    const workloadUuid = input.workloadId.split(':').at(-1) ?? '';
    const expectedSan = `urn:openpc:participant:${input.participantId}:workload:${workloadUuid}`;
    const uriSan = exactUriSan(certificate);
    const notBefore = new Date(certificate.validFrom);
    const notAfter = new Date(certificate.validTo);
    const caNotBefore = new Date(trustedCa.validFrom);
    const caNotAfter = new Date(trustedCa.validTo);
    const lifetime = notAfter.getTime() - notBefore.getTime();
    const clientAuthOid = '1.3.6.1.5.5.7.3.2';
    if (
      !trustedCa.ca ||
      !Number.isFinite(caNotBefore.getTime()) ||
      !Number.isFinite(caNotAfter.getTime()) ||
      caNotAfter <= caNotBefore ||
      !certificate.checkIssued(trustedCa) ||
      !certificate.verify(trustedCa.publicKey) ||
      uriSan !== expectedSan ||
      requestedKey.length !== publicKeySpkiDer.length ||
      !timingSafeEqual(requestedKey, publicKeySpkiDer) ||
      !certificate.keyUsage?.includes(clientAuthOid) ||
      !Number.isFinite(notBefore.getTime()) ||
      !Number.isFinite(notAfter.getTime()) ||
      notAfter > caNotAfter ||
      notAfter <= caNotBefore ||
      lifetime <= 0 ||
      lifetime > WORKLOAD_CERTIFICATE_MAX_LIFETIME_MS
    ) {
      return undefined;
    }
    return {
      certificate: {
        ...input,
        certificateDer: Buffer.from(certificate.raw),
        issuer: trustedCa.fingerprint256,
        uriSan,
        keyId: `sha256:${createHash('sha256').update(publicKeySpkiDer).digest('hex')}`,
        certificateFingerprint: createHash('sha256').update(certificate.raw).digest(),
        notBefore,
        notAfter,
      },
      validity: {
        validFromMs: Math.max(notBefore.getTime(), caNotBefore.getTime()),
        validUntilMs: notAfter.getTime(),
      },
    };
  } catch {
    return undefined;
  }
}

export function createHttpWorkloadCredentialIssuer(input: {
  readonly endpoint: string;
  readonly authorizationToken: string;
  readonly trustedCaPem: Buffer;
  readonly allowInsecureHttp?: boolean;
  readonly fetch?: typeof fetch;
  /** Only the independently inspected local adapter's immutable manifest may
   * qualify replay. Production recovery retains readback-required uncertainty. */
  readonly immutableLocalManifest?: ImmutableLocalWorkloadIssuerManifest;
}): WorkloadCredentialIssuer {
  const endpoint = new URL(input.endpoint);
  if (
    endpoint.protocol !== 'https:' &&
    !(input.allowInsecureHttp && endpoint.protocol === 'http:')
  ) {
    throw new Error('Workload certificate issuer requires HTTPS');
  }
  const immutable = input.immutableLocalManifest;
  if (
    immutable &&
    (!immutable.localQaEnabled ||
      immutable.manifestDigest.length !== 32 ||
      immutable.certificates.length === 0 ||
      immutable.certificates.length > 10000 ||
      immutable.certificates.some(
        (v) =>
          v.requestDigest.length !== 32 ||
          v.certificateFingerprint.length !== 32 ||
          !v.validity ||
          !Number.isSafeInteger(v.validity.validFromMs) ||
          !Number.isSafeInteger(v.validity.validUntilMs) ||
          v.validity.validFromMs < 0 ||
          v.validity.validUntilMs <= v.validity.validFromMs ||
          v.validity.validUntilMs - v.validity.validFromMs > WORKLOAD_CERTIFICATE_MAX_LIFETIME_MS,
      ) ||
      new Set(immutable.certificates.map((v) => v.requestDigest.toString('hex'))).size !==
        immutable.certificates.length)
  )
    throw new Error('Immutable issuer replay requires a qualified local QA manifest');
  const pinnedResponses = new Map(
    immutable?.certificates.map((v) => [
      v.requestDigest.toString('hex'),
      v.certificateFingerprint.toString('hex'),
    ]) ?? [],
  );
  const pinnedValidity = new Map(
    immutable?.certificates.map((v) => [v.requestDigest.toString('hex'), { ...v.validity }]) ?? [],
  );
  const replayProfile = immutable
    ? ('IMMUTABLE_REQUEST_RESPONSE' as const)
    : ('READBACK_REQUIRED' as const);
  const profileDigest = canonicalAuthorizationDigestBytes({
    domain: 'pc.identity.workload-issuer-recovery-profile.v1',
    replayProfile,
    endpoint: endpoint.href,
    trustedCaDigest: `sha256:${createHash('sha256').update(new X509Certificate(input.trustedCaPem).raw).digest('hex')}`,
    ...(immutable
      ? {
          manifestDigest: `sha256:${immutable.manifestDigest.toString('hex')}`,
          certificates: [...pinnedResponses]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([requestDigest, certificateFingerprint]) => ({
              requestDigest,
              certificateFingerprint,
            })),
        }
      : {}),
  });
  const verifyObservation = (
    candidate: WorkloadCertificateRequest,
    certificateDer: Buffer,
    now: Date,
  ) => {
    const observed = verifyIssuedWorkloadCertificate(
      certificateDer,
      input.trustedCaPem,
      candidate,
      now,
    );
    if (
      observed &&
      (!immutable ||
        pinnedResponses.get(workloadCertificateRequestDigest(candidate).toString('hex')) ===
          observed.certificateFingerprint.toString('hex'))
    )
      return observed;
    return undefined;
  };
  const request = input.fetch ?? fetch;
  return {
    recovery: {
      profileDigest,
      replayProfile,
      verifyObservation,
    },
    async issue(candidate, signal) {
      if (
        immutable &&
        !pinnedResponses.has(workloadCertificateRequestDigest(candidate).toString('hex'))
      )
        throw new Error('Workload request is outside the qualified immutable manifest');
      if (immutable) {
        const validity = pinnedValidity.get(
          workloadCertificateRequestDigest(candidate).toString('hex'),
        );
        const nowMs = Date.now();
        if (!validity || validity.validFromMs > nowMs + 5_000 || validity.validUntilMs <= nowMs)
          throw new Error('Installed issuer certificate is not current');
      }
      const response = await request(endpoint, {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${input.authorizationToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          credentialId: candidate.credentialId,
          participantId: candidate.participantId,
          principalId: candidate.principalId,
          workloadId: candidate.workloadId,
          publicKeySpkiDer: candidate.publicKeySpkiDer.toString('base64'),
        }),
        redirect: 'error',
        ...(signal === undefined ? {} : { signal }),
      });
      if (!response.ok) throw new Error('Workload certificate issuance failed');
      const parsed = responseSchema.safeParse(await response.json());
      if (!parsed.success) throw new Error('Invalid workload issuer response');
      const certificateDer = Buffer.from(parsed.data.certificateDer, 'base64');
      if (certificateDer.toString('base64') !== parsed.data.certificateDer) {
        throw new Error('Invalid workload certificate encoding');
      }
      const verified = verifyObservation(candidate, certificateDer, new Date());
      if (verified === undefined) throw new Error('Untrusted workload certificate');
      return verified;
    },
  };
}
