import { createHash, createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { access, mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  decodeIdentityAuthorityEnvelope,
  evidenceKeyId,
  signIdentityAuthorityEnvelopeCose,
} from '../../../packages/security-kernel/src/index.js';
import { canonicalDefinitionJson } from '../../../packages/security-kernel/src/business-transition/definition.js';
import {
  identityEnvelopeProviderDescriptorSchema,
  identityEnvelopeProviderRequestSchema,
  identityEnvelopeProviderRequestDigest,
  validateIdentityEnvelopeProviderObservation,
  type IdentityEnvelopeProviderDescriptor,
  type IdentityEnvelopeProviderObservation,
  type IdentityEnvelopeProviderLookup,
  type IdentityEnvelopeProviderRequest,
} from '../../../services/identity-service/src/domain/identity-envelope-signing-provider.js';
import {
  durableWrite,
  optionalJson,
  FixtureProviderDenied,
} from './signing-provider-fixture-store.js';

export interface FixtureEnvelopeSigningClient {
  certificate: Buffer;
  credentialId: string;
  workloadId: string;
  participantId: string;
  privacyDomainId: string;
  environmentId: string;
  keyOwnerCredentialId: string;
  methods: readonly ('SIGN_AUTHORITY_ENVELOPE' | 'ORIGINAL_LOOKUP')[];
}
export interface FixtureEnvelopeSigningConfiguration {
  clients: readonly FixtureEnvelopeSigningClient[];
  initialKeys: readonly {
    descriptor: IdentityEnvelopeProviderDescriptor;
    privateKeyPkcs8Der: Buffer;
  }[];
}
interface Attempt {
  request: IdentityEnvelopeProviderRequest;
  requestDigest: string;
  certificateDigest: string;
  preparedAtNs: string;
  dispatchedAtNs: string | null;
  observation: IdentityEnvelopeProviderObservation | null;
}
const now = () => (BigInt(Date.now()) * 1000000n).toString();
const hash = (value: string | Buffer) =>
  'sha256:' + createHash('sha256').update(value).digest('hex');

/** External provider fixture only. No control DB, approval, issuer authority or
 * retry is synthesized; an unknown DISPATCHED attempt stays unresolved. */
export async function createEnvelopeFixtureStore(
  root: string,
  config: FixtureEnvelopeSigningConfiguration,
) {
  const clients = new Map(
    config.clients.map((client) => {
      const certificate = new X509Certificate(client.certificate);
      if (
        certificate.subjectAltName !==
          `URI:urn:openpc:participant:${client.participantId}:workload:${client.workloadId}` ||
        client.methods.length === 0 ||
        new Set(client.methods).size !== client.methods.length ||
        !client.methods.every(
          (method) => method === 'SIGN_AUTHORITY_ENVELOPE' || method === 'ORIGINAL_LOOKUP',
        )
      )
        throw new FixtureProviderDenied();
      return [hash(certificate.raw), client] as const;
    }),
  );
  if (clients.size !== config.clients.length) throw new FixtureProviderDenied();
  const keys = config.initialKeys.map((value) => {
    const descriptor = identityEnvelopeProviderDescriptorSchema.parse(value.descriptor);
    const spki = createPublicKey(
      createPrivateKey({ key: value.privateKeyPkcs8Der, type: 'pkcs8', format: 'der' }),
    ).export({ type: 'spki', format: 'der' });
    if (evidenceKeyId(spki) !== descriptor.fingerprint) throw new FixtureProviderDenied();
    return { ...value, descriptor };
  });
  const base = join(root, 'identity-envelope');
  for (const directory of ['keys', 'public', 'attempts', 'faults'])
    await mkdir(join(base, directory), { recursive: true, mode: 0o700 });
  const publicPath = (reference: string) =>
    join(base, 'public', hash(reference).slice(7) + '.json');
  const privatePath = (reference: string) => join(base, 'keys', hash(reference).slice(7) + '.der');
  const attemptPath = (id: string) => join(base, 'attempts', id + '.json');
  for (const key of keys) {
    const prior = await optionalJson<IdentityEnvelopeProviderDescriptor>(
      publicPath(key.descriptor.reference),
    );
    if (prior !== undefined) {
      // Restart validates all immutable installation pins, never restores a key.
      identityEnvelopeProviderDescriptorSchema.parse(prior);
      if (
        canonicalDefinitionJson({ ...prior, state: key.descriptor.state }) !==
        canonicalDefinitionJson(key.descriptor)
      )
        throw new FixtureProviderDenied();
      continue;
    }
    await durableWrite(privatePath(key.descriptor.reference), key.privateKeyPkcs8Der);
    await durableWrite(
      publicPath(key.descriptor.reference),
      canonicalDefinitionJson(key.descriptor),
    );
  }
  function authorize(
    input: unknown,
    peer: string,
    method: FixtureEnvelopeSigningClient['methods'][number],
  ) {
    const request = identityEnvelopeProviderRequestSchema.parse(input),
      client = clients.get(peer);
    if (
      client === undefined ||
      !client.methods.includes(method) ||
      client.credentialId !== request.callerWorkloadCredentialId ||
      client.participantId !== request.participantId ||
      client.privacyDomainId !== request.privacyDomainId ||
      client.environmentId !== request.environmentId ||
      client.keyOwnerCredentialId !== request.workloadCredentialId
    )
      throw new FixtureProviderDenied();
    return request;
  }
  async function original(request: IdentityEnvelopeProviderRequest, peer: string) {
    const found = await optionalJson<Attempt>(attemptPath(request.attemptId));
    if (
      found !== undefined &&
      (found.requestDigest !== identityEnvelopeProviderRequestDigest(request) ||
        found.certificateDigest !== peer ||
        canonicalDefinitionJson(found.request) !== canonicalDefinitionJson(request))
    )
      throw new FixtureProviderDenied();
    if (found?.observation) validateIdentityEnvelopeProviderObservation(request, found.observation);
    return found;
  }
  async function fault(id: string, name: string) {
    try {
      await access(join(base, 'faults', id + '.' + name));
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      return false;
    }
  }
  return {
    hasClient: (peer: string) => clients.has(peer),
    async execute(input: unknown, peer: string) {
      const request = authorize(input, peer, 'SIGN_AUTHORITY_ENVELOPE');
      const prior = await original(request, peer);
      if (prior !== undefined) {
        if (prior.observation === null) throw new Error('Original provider effect unresolved');
        return { observation: prior.observation, drop: false };
      }
      const descriptor = identityEnvelopeProviderDescriptorSchema.parse(
        await optionalJson(publicPath(request.reference)),
      );
      for (const field of Object.keys(descriptor) as (keyof IdentityEnvelopeProviderDescriptor)[]) {
        if (
          field in request &&
          descriptor[field] !== request[field as keyof IdentityEnvelopeProviderRequest]
        )
          throw new FixtureProviderDenied();
      }
      const payload = Buffer.from(request.payloadHex, 'hex');
      const issued = BigInt(decodeIdentityAuthorityEnvelope(payload).issuedAtNs),
        timestamp = BigInt(now());
      if (
        descriptor.fingerprint !== request.expectedFingerprint ||
        descriptor.state !== 'ACTIVE' ||
        issued < BigInt(descriptor.validFromNs) ||
        issued > timestamp ||
        timestamp >= BigInt(descriptor.validUntilNs)
      )
        throw new FixtureProviderDenied();
      // Every peer, scope, method, profile, key and payload check precedes journal mutation.
      const attempt: Attempt = {
        request,
        requestDigest: identityEnvelopeProviderRequestDigest(request),
        certificateDigest: peer,
        preparedAtNs: now(),
        dispatchedAtNs: null,
        observation: null,
      };
      await durableWrite(attemptPath(request.attemptId), canonicalDefinitionJson(attempt));
      attempt.dispatchedAtNs = now();
      await durableWrite(attemptPath(request.attemptId), canonicalDefinitionJson(attempt));
      if (await fault(request.attemptId, 'unknown')) return { observation: undefined, drop: true };
      const privateKey = await readFile(privatePath(request.reference));
      try {
        const observation = validateIdentityEnvelopeProviderObservation(request, {
          schemaVersion: 1,
          method: request.method,
          attemptId: request.attemptId,
          operationId: request.operationId,
          requestDigest: attempt.requestDigest,
          recordedAtNs: now(),
          descriptor,
          coseHex: signIdentityAuthorityEnvelopeCose(
            privateKey,
            Buffer.from(descriptor.publicKeySpkiHex, 'hex'),
            payload,
          ).toString('hex'),
        });
        attempt.observation = observation;
        await durableWrite(attemptPath(request.attemptId), canonicalDefinitionJson(attempt));
        return { observation, drop: await fault(request.attemptId, 'drop') };
      } finally {
        privateKey.fill(0);
      }
    },
    async lookup(input: unknown, peer: string): Promise<IdentityEnvelopeProviderLookup> {
      const request = authorize(input, peer, 'ORIGINAL_LOOKUP');
      const found = await original(request, peer);
      if (found?.observation) return { state: 'OBSERVED', observation: found.observation };
      return {
        state: found === undefined ? 'NOT_FOUND' : 'UNKNOWN',
        attemptId: request.attemptId,
        operationId: request.operationId,
        requestDigest: identityEnvelopeProviderRequestDigest(request),
      };
    },
  };
}
