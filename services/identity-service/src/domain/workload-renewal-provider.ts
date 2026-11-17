import { createPublicKey, verify } from 'node:crypto';
import { z } from 'zod';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import {
  renewalBytesDigest,
  workloadRenewalOriginalSchema,
  workloadRenewalProviderProofEnvelopeSchema,
  workloadRenewalProviderRequestSchema,
} from '../contracts/workload-renewal.js';
import {
  verifyIssuedWorkloadCertificate,
  type IssuedWorkloadCertificate,
} from './workload-credential-issuer.js';
import type {
  WorkloadRenewalDigest,
  WorkloadRenewalOriginal,
  WorkloadRenewalReadback,
  WorkloadRenewalProvider,
  WorkloadRenewalIssuePermit,
} from './workload-renewal-worker-contract.js';

/** Configuration read from the installed provider qualification owner. This
 * verifier authenticates observations; it cannot install/approve this profile
 * or grant issuance. Absent installed qualification remains fail closed. */
export interface WorkloadRenewalProviderProfile {
  readonly endpoint: string;
  readonly audience: string;
  readonly maximumLeafLifetimeMs: number;
  readonly qualificationDigest: WorkloadRenewalDigest;
  readonly issuerProfileDigest: WorkloadRenewalDigest;
  readonly observationSignerSpkiDer: Buffer;
  readonly trustedCaPem: Buffer;
}
export interface VerifiedWorkloadRenewalObservation {
  readonly kind: 'NOT_ISSUED' | 'CERTIFICATE';
  readonly proofRevision: string;
  readonly proofDigest: WorkloadRenewalDigest;
  readonly fresh: boolean;
  /** Missing/invalid/expired certificate cannot become usable. A signed issued
   * outcome still requires cleanup even when its DER fails verification. */
  readonly certificate: IssuedWorkloadCertificate | undefined;
}

export function verifyWorkloadRenewalObservation(
  input: WorkloadRenewalOriginal,
  observation: WorkloadRenewalReadback,
  profile: WorkloadRenewalProviderProfile,
  now: Date,
): VerifiedWorkloadRenewalObservation | undefined {
  try {
    if (
      observation.kind === 'UNKNOWN' ||
      !Number.isFinite(now.getTime()) ||
      !workloadRenewalProviderResponseSchema.safeParse(observation).success
    )
      return undefined;
    const original = workloadRenewalOriginalSchema.parse(input);
    const request = workloadRenewalProviderRequestSchema.parse(
      JSON.parse(Buffer.from(original.providerRequestBase64, 'base64').toString('utf8')),
    );
    if (
      request.audience !== profile.audience ||
      !Number.isSafeInteger(profile.maximumLeafLifetimeMs) ||
      profile.maximumLeafLifetimeMs <= 0 ||
      profile.maximumLeafLifetimeMs > 86400000 ||
      Date.parse(request.validUntil) - Date.parse(request.validFrom) > profile.maximumLeafLifetimeMs
    )
      return undefined;
    if (
      profile.qualificationDigest !== original.providerQualificationDigest ||
      profile.issuerProfileDigest !== original.issuerProfileDigest ||
      observation.providerRequestId !== original.providerRequestId ||
      observation.providerRequestDigest !== original.providerRequestDigest ||
      observation.providerQualificationDigest !== original.providerQualificationDigest ||
      observation.proofBase64.length > 8192
    )
      return undefined;
    const bytes = Buffer.from(observation.proofBase64, 'base64');
    if (bytes.toString('base64') !== observation.proofBase64) return undefined;
    const envelope = workloadRenewalProviderProofEnvelopeSchema.parse(
      JSON.parse(bytes.toString('utf8')),
    );
    if (!Buffer.from(canonicalDefinitionJson(envelope)).equals(bytes)) return undefined;
    const key = createPublicKey({
      key: profile.observationSignerSpkiDer,
      format: 'der',
      type: 'spki',
    });
    const signature = Buffer.from(envelope.signatureBase64, 'base64');
    if (
      key.asymmetricKeyType !== 'ed25519' ||
      signature.length !== 64 ||
      !Buffer.from(key.export({ format: 'der', type: 'spki' })).equals(
        profile.observationSignerSpkiDer,
      ) ||
      !verify(null, Buffer.from(canonicalDefinitionJson(envelope.statement)), key, signature)
    )
      return undefined;
    const proof = envelope.statement;
    if (
      proof.kind !== observation.kind ||
      proof.providerRequestId !== original.providerRequestId ||
      proof.providerRequestDigest !== original.providerRequestDigest ||
      proof.providerQualificationDigest !== original.providerQualificationDigest ||
      Date.parse(proof.observedAt) > now.getTime() + 5000 ||
      Date.parse(proof.validUntil) - Date.parse(proof.observedAt) > 60_000
    )
      return undefined;
    let certificate: IssuedWorkloadCertificate | undefined;
    if (observation.kind === 'CERTIFICATE') {
      if (observation.certificateDerBase64.length > 32768) return undefined;
      const der = Buffer.from(observation.certificateDerBase64, 'base64');
      if (
        der.toString('base64') !== observation.certificateDerBase64 ||
        renewalBytesDigest(der) !== proof.certificateDigest
      )
        return undefined;
      certificate = verifyIssuedWorkloadCertificate(
        der,
        profile.trustedCaPem,
        {
          credentialId: original.credentialId,
          participantId: original.participantId,
          principalId: original.principalId,
          workloadId: original.workloadId,
          publicKeySpkiDer: Buffer.from(request.publicKeySpkiDerBase64, 'base64'),
        },
        now,
      );
      if (
        certificate &&
        (certificate.notBefore.toISOString() !== request.validFrom ||
          certificate.notAfter.toISOString() !== request.validUntil)
      )
        certificate = undefined;
    }
    return {
      kind: proof.kind,
      proofRevision: proof.observationRevision,
      proofDigest: renewalBytesDigest(bytes),
      fresh: Date.parse(proof.validUntil) > now.getTime(),
      certificate,
    };
  } catch {
    return undefined;
  }
}

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const workloadRenewalProviderResponseSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('NOT_ISSUED'),
    providerRequestId: z.uuidv7(),
    providerRequestDigest: digest,
    providerQualificationDigest: digest,
    proofBase64: z.string().min(1).max(8192),
  }),
  z.strictObject({
    kind: z.literal('CERTIFICATE'),
    providerRequestId: z.uuidv7(),
    providerRequestDigest: digest,
    providerQualificationDigest: digest,
    proofBase64: z.string().min(1).max(8192),
    certificateDerBase64: z.string().min(1).max(32768),
  }),
]);
const unknown = (reason: 'TRANSPORT_UNAVAILABLE' | 'UNQUALIFIED_RESPONSE') =>
  ({ kind: 'UNKNOWN', reason }) as const;

/** The permit checker must read the original committed authorization through
 * its scoped store. No caller-provided authorization ID or port object suffices.
 * Calls are outside a database transaction; revocation can race provider I/O,
 * so every response is recorded/reconciled and never implies current usability. */
export function createHttpWorkloadRenewalProvider(input: {
  readonly endpoint: string;
  readonly authorizationToken: string;
  readonly qualificationDigest: WorkloadRenewalDigest;
  readonly checkCommittedPermit: (
    permit: WorkloadRenewalIssuePermit,
    binding: WorkloadRenewalTransportBinding,
  ) => Promise<void>;
  readonly fetch?: typeof fetch;
}): WorkloadRenewalProvider {
  // This adapter belongs to one installed transport binding. The current
  // durable owner is still consulted on every write; caller object mutation
  // cannot replace that checker, its qualification or its bearer token.
  const { authorizationToken, qualificationDigest, checkCommittedPermit } = input;
  const endpoint = new URL(input.endpoint);
  if (
    endpoint.protocol !== 'https:' ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    !/^sha256:[0-9a-f]{64}$/u.test(qualificationDigest) ||
    authorizationToken.length === 0 ||
    /[\r\n]/u.test(authorizationToken)
  )
    throw new Error('Workload renewal provider configuration rejected');
  const fetcher = input.fetch ?? fetch;
  const request = async (
    original: WorkloadRenewalOriginal,
    write: boolean,
    signal: AbortSignal,
  ) => {
    try {
      if (signal.aborted) return unknown('TRANSPORT_UNAVAILABLE');
      const parsed = workloadRenewalOriginalSchema.parse(original);
      if (parsed.providerQualificationDigest !== qualificationDigest)
        return unknown('UNQUALIFIED_RESPONSE');
      const url = new URL(endpoint);
      url.pathname = `${url.pathname.replace(/\/$/u, '')}/v2/certificates/${parsed.providerRequestId}`;
      const reply = await fetcher(url, {
        method: write ? 'PUT' : 'GET',
        signal,
        redirect: 'error',
        headers: {
          'authorization': `Bearer ${authorizationToken}`,
          'content-type': 'application/json',
          'x-openpc-request-digest': parsed.providerRequestDigest,
        },
        ...(write
          ? { body: Buffer.from(parsed.providerRequestBase64, 'base64').toString('utf8') }
          : {}),
      });
      // A late response cannot reverse cancellation or prove non-issuance.
      // The original attempt still requires durable recording/reconciliation.
      if (signal.aborted) {
        await reply.body?.cancel();
        return unknown('TRANSPORT_UNAVAILABLE');
      }
      // No HTTP status, including404, is a non-issuance statement.
      if (!reply.ok) return unknown('UNQUALIFIED_RESPONSE');
      const reader = reply.body?.getReader();
      if (!reader) return unknown('UNQUALIFIED_RESPONSE');
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        for (;;) {
          const next = await reader.read();
          if (signal.aborted) {
            await reader.cancel();
            return unknown('TRANSPORT_UNAVAILABLE');
          }
          if (next.done) break;
          size += next.value.length;
          if (size > 49152) {
            await reader.cancel();
            return unknown('UNQUALIFIED_RESPONSE');
          }
          chunks.push(next.value);
        }
      } finally {
        reader.releaseLock();
      }
      const observation = workloadRenewalProviderResponseSchema.parse(
        JSON.parse(Buffer.concat(chunks).toString('utf8')),
      );
      if (
        observation.providerRequestId !== parsed.providerRequestId ||
        observation.providerRequestDigest !== parsed.providerRequestDigest ||
        observation.providerQualificationDigest !== parsed.providerQualificationDigest
      )
        return unknown('UNQUALIFIED_RESPONSE');
      return signal.aborted
        ? unknown('TRANSPORT_UNAVAILABLE')
        : (observation as WorkloadRenewalReadback);
    } catch {
      return unknown('TRANSPORT_UNAVAILABLE');
    }
  };
  return {
    qualificationDigest: qualificationDigest,
    readOriginal: (original, signal) => request(original, false, signal),
    async issueExact(permit, signal) {
      if (signal.aborted) return unknown('TRANSPORT_UNAVAILABLE');
      try {
        // The checked object and exact original bytes remain the same through
        // asynchronous durable authorization and transport. This seals port
        // inputs, never substitutes for the store's committed permit check.
        Object.freeze(permit.claim.original);
        Object.freeze(permit.claim);
        Object.freeze(permit);
        await checkCommittedPermit(permit, {
          endpoint: endpoint.href,
          qualificationDigest: qualificationDigest,
        });
      } catch {
        return unknown('UNQUALIFIED_RESPONSE');
      }
      const result = await request(permit.claim.original, true, signal);
      return result.kind === 'NOT_ISSUED' ? unknown('UNQUALIFIED_RESPONSE') : result;
    },
  };
}

export interface WorkloadRenewalTransportBinding {
  readonly endpoint: string;
  readonly qualificationDigest: WorkloadRenewalDigest;
}
