import { createPrivateKey, createPublicKey, sign, X509Certificate } from 'node:crypto';
import { mkdir, open, readFile, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { signConsumerCose } from '../../../packages/security-kernel/src/fact-consumer/cose-framing.js';
import { notificationAsyncProfiles } from '../../../packages/security-kernel/src/operations-configuration/notification-async.js';
import {
  qualificationSigningInstallation,
  qualificationSigningRequestSchema,
  qualificationSigningRequestDigest,
  qualificationSigningPurposes,
  validateQualificationSigningRequest,
  type QualificationSigningFamily,
  type QualificationSigningRequest,
  type QualificationSigningObservation,
} from '../../../services/identity-service/src/domain/qualification-signing-provider.js';
import {
  qualificationCanonicalJson,
  qualificationDigest,
} from '../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import {
  qualificationKeyCopy,
  qualificationKeyDescriptorSchema,
  qualificationKeyDescriptorDigest,
  qualificationKeyDescriptorAdmits,
  qualificationKeyRequestSchema,
  qualificationKeyRequestDigest,
  qualificationKeyPossessionPreimage,
  qualificationKeyObservationSchema,
  qualificationKeyPeerSchema,
  type QualificationKeyDescriptor,
  type QualificationKeyPeer,
  type QualificationKeyRequest,
  type QualificationKeyObservation,
  type QualificationKeyInstallation,
} from '../../../services/identity-service/src/domain/qualification-key-provider.js';

export interface QualificationFixtureClient {
  readonly certificate: Buffer;
  readonly peer: QualificationKeyPeer;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly environmentId: string;
}
export interface QualificationFixtureConfiguration {
  readonly clients: readonly QualificationFixtureClient[];
  /** Separate finite SIGN grants. INSPECT/PROVE permissions confer no signing authority. */
  readonly signingGrants?: readonly {
    readonly installation: QualificationKeyInstallation;
    readonly qualificationInstallationId: string;
    readonly family: QualificationSigningFamily;
  }[];
  readonly initialKeys: readonly {
    descriptor: QualificationKeyDescriptor;
    privateKeyPkcs8Der: Buffer;
  }[];
}
export class QualificationFixtureDenied extends Error {}
function fail(): never {
  throw new QualificationFixtureDenied('Qualification external provider denied');
}
const canonical = (v: unknown) => Buffer.from(qualificationCanonicalJson(v));
async function readOptional(path: string): Promise<unknown | undefined> {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw e;
  }
}
async function durable(path: string, value: Buffer) {
  const next = path + '.next',
    f = await open(next, 'w', 0o600);
  try {
    await f.writeFile(value);
    await f.sync();
  } finally {
    await f.close();
  }
  await rename(next, path);
  const d = await open(join(path, '..'), 'r');
  try {
    await d.sync();
  } finally {
    await d.close();
  }
}
const recordSchema = z.strictObject({
  request: qualificationKeyRequestSchema,
  observation: qualificationKeyObservationSchema.nullable(),
});

/** External substitute only; one key/client store, independent of Control.
 * The signing journal owns durable dispatch and original-result retention. */
export async function createQualificationFixtureStore(
  root: string,
  config: QualificationFixtureConfiguration,
) {
  const home = join(root, 'qualification');
  for (const directory of ['keys', 'attempts', 'faults'])
    await mkdir(join(home, directory), { recursive: true, mode: 0o700 });
  const clients = new Map<string, QualificationFixtureClient>();
  for (const raw of config.clients) {
    const certificate = new X509Certificate(raw.certificate),
      peer = qualificationKeyPeerSchema.parse(raw.peer);
    const fingerprint = qualificationDigest(certificate.raw),
      spki = qualificationDigest(certificate.publicKey.export({ type: 'spki', format: 'der' }));
    if (
      fingerprint !== peer.certificateDigest ||
      spki !== peer.keyDigest ||
      clients.has(fingerprint) ||
      certificate.subjectAltName !==
        `URI:urn:openpc:participant:${raw.participantId}:workload:${peer.workloadId.split(':').at(-1)}`
    )
      fail();
    clients.set(fingerprint, {
      ...raw,
      peer: qualificationKeyCopy(peer),
      certificate: Buffer.from(raw.certificate),
    });
  }
  const path = (keyId: string) =>
    join(
      home,
      'keys',
      z
        .string()
        .regex(/^sha256:[0-9a-f]{64}$/u)
        .parse(keyId)
        .slice(7),
    );
  for (const key of config.initialKeys) {
    const descriptor = qualificationKeyDescriptorSchema.parse(key.descriptor);
    if (
      descriptor.custody !== 'EXTERNAL_SOFTWARE_FIXTURE' ||
      descriptor.clients.some((c) => {
        const p = clients.get(c.certificateDigest)?.peer;
        return !p || p.credentialId !== c.credentialId || p.credentialEpoch !== c.credentialEpoch;
      })
    )
      fail();
    if (
      descriptor.schemaVersion === 2 &&
      descriptor.observers.some((pair) =>
        [pair.subject, pair.observer].some(
          (p) =>
            qualificationCanonicalJson(clients.get(p.certificateDigest)?.peer) !==
            qualificationCanonicalJson(p),
        ),
      )
    )
      fail();
    const actual = createPublicKey(
      createPrivateKey({ key: key.privateKeyPkcs8Der, format: 'der', type: 'pkcs8' }),
    ).export({ type: 'spki', format: 'der' });
    if (actual.toString('hex') !== descriptor.publicKeySpkiHex) fail();
    const old = await readOptional(path(descriptor.keyId) + '.json');
    if (old !== undefined) {
      const prior = qualificationKeyDescriptorSchema.parse(old);
      if (
        prior.keyId !== descriptor.keyId ||
        prior.publicKeySpkiHex !== descriptor.publicKeySpkiHex ||
        prior.reference !== descriptor.reference ||
        prior.purpose !== descriptor.purpose
      )
        fail();
      continue;
    }
    await durable(path(descriptor.keyId) + '.der', Buffer.from(key.privateKeyPkcs8Der));
    await durable(path(descriptor.keyId) + '.json', canonical(descriptor));
  }
  if ((config.signingGrants?.length ?? 0) > 64) fail();
  const signingGrants = (config.signingGrants ?? []).map((grant) => {
    const installation = qualificationSigningInstallation(grant.installation),
      qualificationInstallationId = z.uuidv7().parse(grant.qualificationInstallationId),
      family = z.enum(['input', 'capacity']).parse(grant.family),
      pins = installation.pins;
    if (
      pins.purpose !== qualificationSigningPurposes[family] ||
      [pins.peer, pins.observer].some((peer) => {
        const client = clients.get(peer.certificateDigest);
        return (
          !client ||
          client.participantId !== pins.participantId ||
          client.privacyDomainId !== pins.privacyDomainId ||
          client.environmentId !== pins.environmentId ||
          qualificationCanonicalJson(client.peer) !== qualificationCanonicalJson(peer)
        );
      })
    )
      fail();
    return { installation, qualificationInstallationId, family };
  });
  const attemptPath = (id: string) => join(home, 'attempts', z.uuidv7().parse(id) + '.json');
  const authenticate = (request: QualificationKeyRequest, certificateDigest: string) => {
    const client = clients.get(certificateDigest);
    if (
      !client ||
      request.participantId !== client.participantId ||
      request.privacyDomainId !== client.privacyDomainId ||
      request.environmentId !== client.environmentId ||
      qualificationCanonicalJson(request.schemaVersion === 2 ? request.observer : request.peer) !==
        qualificationCanonicalJson(client.peer)
    )
      fail();
    return client;
  };
  const observation = (
    request: QualificationKeyRequest,
    reason: QualificationKeyObservation['reason'],
    descriptor: QualificationKeyDescriptor | null = null,
    proofHex: string | null = null,
  ): QualificationKeyObservation =>
    qualificationKeyObservationSchema.parse({
      schemaVersion: request.schemaVersion,
      attemptId: request.attemptId,
      requestDigest: qualificationKeyRequestDigest(request),
      observedAtMs: Date.now(),
      outcome: reason ? 'REJECTED' : 'OBSERVED',
      reason,
      descriptor,
      proofHex,
    });
  const finish = async (request: QualificationKeyRequest): Promise<QualificationKeyObservation> => {
    const raw = await readOptional(path(request.keyId) + '.json');
    let result: QualificationKeyObservation;
    if (raw === undefined) result = observation(request, 'KEY_UNAVAILABLE');
    else {
      const d = qualificationKeyDescriptorSchema.parse(raw),
        now = Date.now();
      const exact = [
        'participantId',
        'privacyDomainId',
        'environmentId',
        'authorityId',
        'rootEpoch',
        'keyId',
        'keyEpoch',
        'purpose',
        'reference',
        'version',
        'providerId',
      ].every((k) => d[k as keyof typeof d] === request[k as keyof typeof request]);
      if (!exact || !qualificationKeyDescriptorAdmits(d, request))
        result = observation(request, 'DENIED');
      else if (d.state !== 'ACTIVE') result = observation(request, 'REVOKED');
      else if (
        now < request.issuedAtMs ||
        now >= request.deadlineAtMs ||
        now < d.validFromMs ||
        now >= d.validUntilMs
      )
        result = observation(request, 'EXPIRED');
      else if (
        request.method === 'PROVE' &&
        request.descriptorDigest !== qualificationKeyDescriptorDigest(d)
      )
        result = observation(request, 'DESCRIPTOR_CHANGED');
      else {
        const proof =
          request.method === 'PROVE'
            ? sign('sha256', qualificationKeyPossessionPreimage(request, d), {
                key: createPrivateKey({
                  key: await readFile(path(d.keyId) + '.der'),
                  format: 'der',
                  type: 'pkcs8',
                }),
                dsaEncoding: 'ieee-p1363',
              }).toString('hex')
            : null;
        result = observation(request, null, d, proof);
      }
    }
    await durable(attemptPath(request.attemptId), canonical({ request, observation: result }));
    return result;
  };
  /** Immutable client authentication only: safe before journal writes and for
   * historical lookup. No key/grant/clock read or signing side effect. */
  const authenticateSigningPeer = (
    value: QualificationSigningRequest,
    certificateDigest: string,
  ) => {
    const request = qualificationSigningRequestSchema.parse(qualificationKeyCopy(value)),
      client = clients.get(certificateDigest);
    if (
      !client ||
      request.participantId !== client.participantId ||
      request.privacyDomainId !== client.privacyDomainId ||
      request.environmentId !== client.environmentId ||
      qualificationCanonicalJson(request.observer) !== qualificationCanonicalJson(client.peer)
    )
      fail();
    return request;
  };
  const operations = {
    hasClient(certificateDigest: string) {
      return clients.has(certificateDigest);
    },
    /** Called only by the external journal after its durable exclusive claim.
     * certificateDigest must come from the actual authorized TLS socket. */
    async signQualification(
      value: QualificationSigningRequest,
      certificateDigest: string,
    ): Promise<QualificationSigningObservation> {
      const request = authenticateSigningPeer(value, certificateDigest);
      const rejected = (
        reason: Extract<QualificationSigningObservation, { outcome: 'REJECTED' }>['reason'],
      ): QualificationSigningObservation => ({
        schemaVersion: 1,
        attemptId: request.attemptId,
        requestDigest: qualificationSigningRequestDigest(request),
        observedAtMs: Date.now(),
        outcome: 'REJECTED',
        reason,
      });
      const grants = signingGrants.filter(
        (grant) =>
          grant.family === request.family &&
          grant.qualificationInstallationId === request.qualificationInstallationId &&
          grant.installation.digest === request.installationDigest,
      );
      if (grants.length !== 1) return rejected('DENIED');
      const grant = grants[0]!;
      try {
        validateQualificationSigningRequest(request, grant.installation.pins);
      } catch {
        return rejected('DENIED');
      }
      const raw = await readOptional(path(request.keyId) + '.json');
      if (raw === undefined) return rejected('KEY_UNAVAILABLE');
      const descriptor = qualificationKeyDescriptorSchema.parse(raw);
      if (
        descriptor.schemaVersion !== 2 ||
        descriptor.publicKeySpkiHex !== grant.installation.pins.publicKeySpkiHex ||
        (
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
          ] as const
        ).some((key) => descriptor[key] !== request[key])
      )
        return rejected('DENIED');
      if (descriptor.state !== 'ACTIVE') return rejected('REVOKED');
      const key = await readFile(path(request.keyId) + '.der'),
        now = Date.now();
      if (
        now < request.issuedAtMs ||
        now >= request.deadlineAtMs ||
        now < descriptor.validFromMs ||
        now >= descriptor.validUntilMs ||
        now < grant.installation.pins.validFromMs ||
        now >= grant.installation.pins.validUntilMs
      )
        return rejected('EXPIRED');
      const cose = signConsumerCose(
        notificationAsyncProfiles[request.family],
        key,
        Buffer.from(descriptor.publicKeySpkiHex, 'hex'),
        Buffer.from(request.payloadHex, 'hex'),
      );
      const finishedAt = Date.now();
      if (
        finishedAt >= request.deadlineAtMs ||
        finishedAt >= descriptor.validUntilMs ||
        finishedAt >= grant.installation.pins.validUntilMs
      )
        return rejected('EXPIRED');
      return {
        schemaVersion: 1,
        attemptId: request.attemptId,
        requestDigest: qualificationSigningRequestDigest(request),
        observedAtMs: now,
        outcome: 'SIGNED',
        coseHex: cose.toString('hex'),
      };
    },
    async execute(value: unknown, certificateDigest: string) {
      const request = qualificationKeyCopy(qualificationKeyRequestSchema.parse(value));
      authenticate(request, certificateDigest);
      const existing = await readOptional(attemptPath(request.attemptId));
      if (existing !== undefined) {
        const old = recordSchema.parse(existing);
        if (qualificationKeyRequestDigest(old.request) !== qualificationKeyRequestDigest(request))
          return {
            observation: observation(request, 'ATTEMPT_CONFLICT'),
            drop: false,
            hold: false,
          };
        // Incomplete original never generates a new proof on replay/restart.
        if (!old.observation) fail();
        return { observation: old.observation, drop: false, hold: false };
      }
      await durable(attemptPath(request.attemptId), canonical({ request, observation: null }));
      const fault = await readOptional(join(home, 'faults', request.attemptId + '.json'));
      if (
        fault !== undefined &&
        !z
          .strictObject({
            mode: z.enum(['DROP_AFTER_PERSIST', 'STOP_BEFORE_RESULT', 'HOLD_AFTER_PERSIST']),
          })
          .safeParse(fault).success
      )
        fail();
      if ((fault as { mode?: string } | undefined)?.mode === 'STOP_BEFORE_RESULT') fail();
      const result = await finish(request);
      return {
        observation: result,
        drop: (fault as { mode?: string } | undefined)?.mode === 'DROP_AFTER_PERSIST',
        hold: (fault as { mode?: string } | undefined)?.mode === 'HOLD_AFTER_PERSIST',
      };
    },
    async lookup(value: unknown, certificateDigest: string) {
      const input = z
          .strictObject({
            schemaVersion: z.union([z.literal(1), z.literal(2)]),
            original: qualificationKeyRequestSchema,
          })
          .parse(value),
        request = input.original;
      if (input.schemaVersion !== request.schemaVersion) fail();
      authenticate(request, certificateDigest);
      const raw = await readOptional(attemptPath(request.attemptId));
      if (raw === undefined)
        return {
          state: 'ABSENT' as const,
          attemptId: request.attemptId,
          requestDigest: qualificationKeyRequestDigest(request),
        };
      const old = recordSchema.parse(raw);
      if (
        qualificationKeyRequestDigest(old.request) !== qualificationKeyRequestDigest(request) ||
        !old.observation
      )
        fail();
      return { state: 'OBSERVED' as const, observation: old.observation };
    },
    /** External policy-owner control for real revocation/replacement tests. No HTTP route. */
    async replacePolicy(
      keyId: string,
      policy: Pick<QualificationKeyDescriptor, 'clients' | 'state'>,
    ) {
      const previous = qualificationKeyDescriptorSchema.parse(
        await readOptional(path(keyId) + '.json'),
      );
      if (
        (previous.state === 'REVOKED' && policy.state === 'ACTIVE') ||
        (previous.state === 'RETIRED' && policy.state !== 'RETIRED')
      )
        fail();
      const next = qualificationKeyDescriptorSchema.parse({
        ...previous,
        ...qualificationKeyCopy(policy),
        policyRevision: String(BigInt(previous.policyRevision) + 1n),
      });
      if (next.clients.some((c) => !clients.has(c.certificateDigest))) fail();
      await durable(path(keyId) + '.json', canonical(next));
    },
  };
  // The external key and policy owner serializes changes with actual key use.
  // Response delivery barriers belong outside this critical section.
  let tail: Promise<unknown> = Promise.resolve();
  const serialized = <T>(work: () => Promise<T>): Promise<T> => {
    const result = tail.then(work);
    tail = result.catch(() => undefined);
    return result;
  };
  return {
    hasClient: operations.hasClient,
    authenticateQualificationSigningPeer: (
      request: QualificationSigningRequest,
      certificateDigest: string,
    ): void => {
      authenticateSigningPeer(request, certificateDigest);
    },
    signQualification: (request: QualificationSigningRequest, certificateDigest: string) =>
      serialized(() => operations.signQualification(request, certificateDigest)),
    execute: (value: unknown, certificateDigest: string) =>
      serialized(() => operations.execute(value, certificateDigest)),
    lookup: (value: unknown, certificateDigest: string) =>
      serialized(() => operations.lookup(value, certificateDigest)),
    replacePolicy: (keyId: string, policy: Pick<QualificationKeyDescriptor, 'clients' | 'state'>) =>
      serialized(() => operations.replacePolicy(keyId, policy)),
  };
}
