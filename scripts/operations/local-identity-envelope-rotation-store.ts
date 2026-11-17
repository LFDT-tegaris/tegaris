import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  X509Certificate,
} from 'node:crypto';
import { access, mkdir, open, readFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { evidenceKeyId } from '../../packages/security-kernel/src/index.js';
import { canonicalDefinitionJson } from '../../packages/security-kernel/src/business-transition/definition.js';
import {
  identityEnvelopeRotationDescriptorSchema,
  identityEnvelopeRotationRequestSchema,
  identityEnvelopeRotationRequestDigest,
  identityEnvelopeRotationPossessionPreimage,
  validateIdentityEnvelopeRotationObservation,
  isIdentityEnvelopePredecessorEffect,
  type IdentityEnvelopeRotationDescriptor,
  type IdentityEnvelopeRotationObservation,
  type IdentityEnvelopeRotationRequest,
  type IdentityEnvelopeRotationLookup,
} from '../../services/identity-service/src/domain/identity-envelope-rotation-provider.js';
import {
  identityEnvelopeProviderDescriptorSchema,
  type IdentityEnvelopeProviderDescriptor,
} from '../../services/identity-service/src/domain/identity-envelope-signing-provider.js';
import {
  createEnvelopeFixtureStore,
  type FixtureEnvelopeSigningConfiguration,
} from '../../tests/integration/local-runtime/signing-provider-envelope-store.js';
import {
  durableWrite,
  optionalJson,
  FixtureProviderDenied,
} from '../../tests/integration/local-runtime/signing-provider-fixture-store.js';

interface KeyRecord {
  descriptor: IdentityEnvelopeRotationDescriptor;
  normal: IdentityEnvelopeProviderDescriptor | null;
  rotationId: string;
  governanceDigest: string;
  lastAttemptId: string;
  lastObservation: IdentityEnvelopeRotationObservation;
}
interface Attempt {
  request: IdentityEnvelopeRotationRequest;
  requestDigest: string;
  certificateDigest: string;
  startedAtNs: string;
  plannedDescriptor: IdentityEnvelopeRotationDescriptor | null;
  observation: IdentityEnvelopeRotationObservation | null;
}
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const now = () => (BigInt(Date.now()) * 1000000n).toString();
const equal = (a: unknown, b: unknown) => canonicalDefinitionJson(a) === canonicalDefinitionJson(b);

/** Local external provider, with no control-database or business authority.
 * Normal371 and rotation share one serial owner and the original key custody.
 * A key manifest fences normal signing before any destructive private effect.
 * Lookup can record an already observed original effect; it never generates,
 * signs, revokes or deletes private material a second time. */
export async function createLocalIdentityEnvelopeRotationStore(input: {
  root: string;
  clients: FixtureEnvelopeSigningConfiguration['clients'];
  predecessorReference: string;
  predecessorFingerprint: string;
  keyValiditySeconds: number;
}) {
  if (
    !Number.isSafeInteger(input.keyValiditySeconds) ||
    input.keyValiditySeconds < 900 ||
    input.keyValiditySeconds > 86400
  )
    throw new FixtureProviderDenied();
  const normal = await createEnvelopeFixtureStore(input.root, {
    clients: input.clients,
    initialKeys: [],
  });
  const base = join(input.root, 'identity-envelope');
  const journalRoot = join(base, 'rotation-attempts');
  const manifestRoot = join(base, 'rotation-keys');
  await mkdir(journalRoot, { recursive: true, mode: 0o700 });
  await mkdir(manifestRoot, { recursive: true, mode: 0o700 });
  const keyPath = (reference: string) => join(base, 'keys', hash(reference) + '.der');
  const publicPath = (reference: string) => join(base, 'public', hash(reference) + '.json');
  const manifestPath = (reference: string) => join(manifestRoot, hash(reference) + '.json');
  const attemptPath = (id: string) => join(journalRoot, id + '.json');
  const peers = new Map(
    input.clients.map((client) => [
      'sha256:' +
        createHash('sha256').update(new X509Certificate(client.certificate).raw).digest('hex'),
      client,
    ]),
  );
  if (peers.size !== input.clients.length) throw new FixtureProviderDenied();
  let serial: Promise<unknown> = Promise.resolve();
  let stopping = false;
  const use = <T>(work: () => Promise<T>) => {
    if (stopping) return Promise.reject(new FixtureProviderDenied());
    const invocation = serial.then(work);
    serial = invocation.then(
      () => undefined,
      () => undefined,
    );
    return invocation;
  };
  async function record(reference: string) {
    const value = await optionalJson<KeyRecord>(manifestPath(reference));
    if (value !== undefined) {
      identityEnvelopeRotationDescriptorSchema.parse(value.descriptor);
      if (value.normal !== null) identityEnvelopeProviderDescriptorSchema.parse(value.normal);
      const attempt = await optionalJson<Attempt>(attemptPath(value.lastAttemptId));
      const owner = identityEnvelopeRotationRequestSchema.parse(attempt?.request);
      validateIdentityEnvelopeRotationObservation(owner, value.lastObservation);
      if (
        value.descriptor.reference !== reference ||
        value.lastAttemptId !== value.lastObservation.attemptId ||
        value.rotationId !== owner.rotationId ||
        value.governanceDigest !== owner.governanceDigest ||
        !equal(value.descriptor, value.lastObservation.descriptor)
      )
        throw new FixtureProviderDenied();
    }
    return value;
  }
  async function descriptor(reference: string) {
    const found = await record(reference);
    if (found) return { descriptor: found.descriptor, record: found };
    const legacy = await optionalJson<IdentityEnvelopeProviderDescriptor>(publicPath(reference));
    if (legacy === undefined) return undefined;
    const validated = identityEnvelopeProviderDescriptorSchema.parse(legacy);
    if (
      reference !== input.predecessorReference ||
      validated.fingerprint !== input.predecessorFingerprint ||
      validated.state !== 'ACTIVE'
    )
      throw new FixtureProviderDenied();
    const publicMetadata = Object.fromEntries(
      Object.entries(validated).filter(([name]) => name !== 'trustContextDigest'),
    );
    return {
      descriptor: identityEnvelopeRotationDescriptorSchema.parse({
        ...publicMetadata,
        revokedAtNs: null,
        retiredAtNs: null,
      }),
      normal: validated,
    };
  }
  function authorize(raw: unknown, peer: string) {
    const request = identityEnvelopeRotationRequestSchema.parse(raw),
      client = peers.get(peer);
    if (
      !client ||
      client.credentialId !== request.callerWorkloadCredentialId ||
      client.keyOwnerCredentialId !== request.workloadCredentialId ||
      client.participantId !== request.participantId ||
      client.privacyDomainId !== request.privacyDomainId ||
      client.environmentId !== request.environmentId ||
      (request.method === 'PROVE' &&
        request.recoveryPredecessor !== undefined &&
        (request.reference !== input.predecessorReference ||
          request.expectedFingerprint !== input.predecessorFingerprint)) ||
      ((request.method === 'REVOKE' || request.method === 'RETIRE') &&
        (request.reference !== input.predecessorReference ||
          request.expectedFingerprint !== input.predecessorFingerprint)) ||
      (request.method === 'PREPARE' && request.reference === input.predecessorReference)
    )
      throw new FixtureProviderDenied();
    return request;
  }
  async function original(request: IdentityEnvelopeRotationRequest, peer: string) {
    const found = await optionalJson<Attempt>(attemptPath(request.attemptId));
    if (
      found &&
      (!equal(found.request, request) ||
        found.requestDigest !== identityEnvelopeRotationRequestDigest(request) ||
        found.certificateDigest !== peer)
    )
      throw new FixtureProviderDenied();
    if (found?.observation) validateIdentityEnvelopeRotationObservation(request, found.observation);
    return found;
  }
  function observed(
    attempt: Attempt,
    key: IdentityEnvelopeRotationDescriptor | null,
    reason: IdentityEnvelopeRotationObservation['reason'] = null,
    resultHex: string | null = null,
  ) {
    return validateIdentityEnvelopeRotationObservation(attempt.request, {
      schemaVersion: 1,
      providerId: 'openpc-local-envelope-provider',
      attemptId: attempt.request.attemptId,
      operationId: attempt.request.operationId,
      requestDigest: attempt.requestDigest,
      method: attempt.request.method,
      recordedAtNs: now(),
      outcome: reason === null ? 'SUCCEEDED' : 'REJECTED',
      reason,
      descriptor: key,
      resultHex,
    });
  }
  async function finish(attempt: Attempt, observation: IdentityEnvelopeRotationObservation) {
    if (attempt.observation !== null && !equal(attempt.observation, observation))
      throw new FixtureProviderDenied();
    attempt.observation = observation;
    await durableWrite(attemptPath(attempt.request.attemptId), canonicalDefinitionJson(attempt));
    return observation;
  }
  async function publish(
    attempt: Attempt,
    key: IdentityEnvelopeRotationDescriptor,
    projection: IdentityEnvelopeProviderDescriptor | null,
  ) {
    const observation = observed(attempt, key);
    const value: KeyRecord = {
      descriptor: key,
      normal: projection,
      rotationId: attempt.request.rotationId,
      governanceDigest: attempt.request.governanceDigest,
      lastAttemptId: attempt.request.attemptId,
      lastObservation: observation,
    };
    // This is the authoritative normal-signing fence and original effect record.
    await durableWrite(manifestPath(key.reference), canonicalDefinitionJson(value));
    if (projection !== null)
      await durableWrite(publicPath(key.reference), canonicalDefinitionJson(projection));
    return finish(attempt, observation);
  }
  async function privateMatches(key: IdentityEnvelopeRotationDescriptor) {
    let bytes: Buffer;
    try {
      bytes = await readFile(keyPath(key.reference));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
      throw error;
    }
    try {
      const spki = createPublicKey(
        createPrivateKey({ key: bytes, type: 'pkcs8', format: 'der' }),
      ).export({ type: 'spki', format: 'der' });
      if (spki.toString('hex') !== key.publicKeySpkiHex) throw new FixtureProviderDenied();
      return true;
    } finally {
      bytes.fill(0);
    }
  }
  async function reconcile(attempt: Attempt) {
    const found = await record(attempt.request.reference);
    if (found?.lastAttemptId === attempt.request.attemptId) {
      if (found.governanceDigest !== attempt.request.governanceDigest)
        throw new FixtureProviderDenied();
      validateIdentityEnvelopeRotationObservation(attempt.request, found.lastObservation);
      if (found.normal !== null)
        await durableWrite(
          publicPath(attempt.request.reference),
          canonicalDefinitionJson(found.normal),
        );
      return finish(attempt, found.lastObservation);
    }
    // Readback of the exact immutable PREPARE or RETIRE effect. No entropy,
    // signature, revocation or unlink is repeated by this reconciliation.
    if (
      attempt.request.method === 'PREPARE' &&
      attempt.plannedDescriptor !== null &&
      found === undefined &&
      (await privateMatches(attempt.plannedDescriptor))
    )
      return publish(attempt, attempt.plannedDescriptor, null);
    if (
      attempt.request.method === 'RETIRE' &&
      found?.descriptor.state === 'REVOKED' &&
      attempt.plannedDescriptor !== null &&
      equal(attempt.plannedDescriptor, found.descriptor) &&
      found.rotationId === attempt.request.rotationId &&
      found.governanceDigest === attempt.request.governanceDigest
    ) {
      try {
        await access(keyPath(attempt.request.reference));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        const retired = {
          ...found.descriptor,
          state: 'RETIRED' as const,
          retiredAtNs: attempt.startedAtNs,
        };
        return publish(
          attempt,
          retired,
          found.normal === null ? null : { ...found.normal, state: 'RETIRED' },
        );
      }
    }
    return undefined;
  }
  async function perform(raw: unknown, peer: string) {
    const request = authorize(raw, peer),
      previous = await original(request, peer);
    if (previous) {
      const prior = previous.observation ?? (await reconcile(previous));
      if (prior === undefined) throw new FixtureProviderDenied();
      return prior;
    }
    const existing = await descriptor(request.reference);
    let preparedBytes: Buffer | undefined;
    let plannedDescriptor: IdentityEnvelopeRotationDescriptor | null = null;
    if (request.method === 'PREPARE' && existing === undefined) {
      // Refuse an unowned orphan key rather than regenerate or overwrite it.
      try {
        await access(keyPath(request.reference));
        throw new FixtureProviderDenied();
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      const generated = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const spki = generated.publicKey.export({ type: 'spki', format: 'der' });
      preparedBytes = generated.privateKey.export({ type: 'pkcs8', format: 'der' });
      const commandFields = [
        'method',
        'callerWorkloadCredentialId',
        'rotationId',
        'operationId',
        'attemptId',
        'issuerParticipantEpoch',
        'issuerPrincipalEpoch',
        'governanceDigest',
        'expectedFingerprint',
      ];
      const binding = Object.fromEntries(
        Object.entries(request).filter(([name]) => !commandFields.includes(name)),
      );
      const start = BigInt(now());
      plannedDescriptor = identityEnvelopeRotationDescriptorSchema.parse({
        ...binding,
        algorithm: 'ES256',
        publicKeySpkiHex: spki.toString('hex'),
        fingerprint: evidenceKeyId(spki),
        validFromNs: start.toString(),
        validUntilNs: (start + BigInt(input.keyValiditySeconds) * 1000000000n).toString(),
        state: 'ACTIVE',
        revokedAtNs: null,
        retiredAtNs: null,
      });
    }
    if (
      request.method === 'RETIRE' &&
      existing?.descriptor.state === 'REVOKED' &&
      existing.record &&
      existing.record.rotationId === request.rotationId &&
      existing.record.governanceDigest === request.governanceDigest &&
      (await privateMatches(existing.descriptor))
    )
      plannedDescriptor = existing.descriptor;
    const attempt: Attempt = {
      request,
      requestDigest: identityEnvelopeRotationRequestDigest(request),
      certificateDigest: peer,
      startedAtNs: now(),
      plannedDescriptor,
      observation: null,
    };
    try {
      await durableWrite(attemptPath(request.attemptId), canonicalDefinitionJson(attempt));
      if (request.method === 'PREPARE') {
        if (existing !== undefined || plannedDescriptor === null || preparedBytes === undefined)
          return finish(attempt, observed(attempt, null, 'NOT_APPLIED'));
        if (
          request.expectedFingerprint !== undefined &&
          request.expectedFingerprint !== plannedDescriptor.fingerprint
        )
          return finish(attempt, observed(attempt, null, 'FINGERPRINT_MISMATCH'));
        await durableWrite(keyPath(request.reference), preparedBytes);
        return publish(attempt, plannedDescriptor, null);
      }
      if (!existing) return finish(attempt, observed(attempt, null, 'KEY_NOT_FOUND'));
      const key = existing.descriptor;
      const fields = [
        'participantId',
        'privacyDomainId',
        'environmentId',
        'workloadCredentialId',
        'workloadCredentialEpoch',
        'reference',
        'version',
      ] as const;
      const pinnedPredecessor =
        isIdentityEnvelopePredecessorEffect(request) &&
        request.reference === input.predecessorReference &&
        request.expectedFingerprint === input.predecessorFingerprint;
      if (
        fields.some(
          (field) =>
            key[field] !== request[field] &&
            !(
              pinnedPredecessor &&
              (field === 'workloadCredentialId' || field === 'workloadCredentialEpoch')
            ),
        )
      )
        return finish(attempt, observed(attempt, null, 'WRONG_SCOPE'));
      if (key.fingerprint !== request.expectedFingerprint)
        return finish(attempt, observed(attempt, null, 'FINGERPRINT_MISMATCH'));
      if (
        existing.record &&
        (existing.record.rotationId !== request.rotationId ||
          existing.record.governanceDigest !== request.governanceDigest)
      )
        return finish(attempt, observed(attempt, null, 'ATTEMPT_CONFLICT'));
      if (request.method === 'RETIRE') {
        if (key.state !== 'REVOKED' || !existing.record || plannedDescriptor === null)
          return finish(attempt, observed(attempt, null, 'NOT_APPLIED'));
        if (!(await privateMatches(key)))
          return finish(attempt, observed(attempt, null, 'NOT_APPLIED'));
        await unlink(keyPath(request.reference));
        const directory = await open(join(base, 'keys'), 'r');
        try {
          await directory.sync();
        } finally {
          await directory.close();
        }
        return publish(
          attempt,
          { ...key, state: 'RETIRED', retiredAtNs: attempt.startedAtNs },
          existing.record.normal === null ? null : { ...existing.record.normal, state: 'RETIRED' },
        );
      }
      if (key.state !== 'ACTIVE') return finish(attempt, observed(attempt, null, 'REVOKED'));
      if (request.method === 'REVOKE') {
        const projection =
          existing.record?.normal ?? ('normal' in existing ? (existing.normal ?? null) : null);
        return publish(
          attempt,
          { ...key, state: 'REVOKED', revokedAtNs: now() },
          projection === null ? null : { ...projection, state: 'REVOKED' },
        );
      }
      if (
        BigInt(now()) < BigInt(key.validFromNs) ||
        (BigInt(now()) >= BigInt(key.validUntilNs) &&
          !(request.method === 'PROVE' && request.recoveryPredecessor !== undefined))
      )
        return finish(attempt, observed(attempt, null, 'EXPIRED'));
      if (request.method === 'DISTRIBUTE') {
        if (!existing.record || existing.record.normal !== null)
          return finish(attempt, observed(attempt, null, 'NOT_APPLIED'));
        const metadata = Object.fromEntries(
          Object.entries(key).filter(([name]) => name !== 'revokedAtNs' && name !== 'retiredAtNs'),
        );
        const projection = identityEnvelopeProviderDescriptorSchema.parse({
          ...metadata,
          trustContextDigest: request.trustContextDigest,
        });
        return publish(attempt, key, projection);
      }
      if (
        BigInt(now()) < BigInt(request.challengeIssuedAtNs) ||
        BigInt(now()) >= BigInt(request.challengeExpiresAtNs)
      )
        return finish(attempt, observed(attempt, null, 'EXPIRED'));
      if (!(await privateMatches(key)))
        return finish(attempt, observed(attempt, null, 'KEY_NOT_FOUND'));
      const privateBytes = await readFile(keyPath(request.reference));
      try {
        const proof = sign('sha256', identityEnvelopeRotationPossessionPreimage(request), {
          key: createPrivateKey({ key: privateBytes, type: 'pkcs8', format: 'der' }),
          dsaEncoding: 'ieee-p1363',
        }).toString('hex');
        return finish(attempt, observed(attempt, key, null, proof));
      } finally {
        privateBytes.fill(0);
      }
    } finally {
      preparedBytes?.fill(0);
    }
  }
  return {
    hasClient: (peer: string) => peers.has(peer),
    perform: (raw: unknown, peer: string) => use(() => perform(raw, peer)),
    lookup: (raw: unknown, peer: string): Promise<IdentityEnvelopeRotationLookup> =>
      use(async () => {
        const request = authorize(raw, peer),
          found = await original(request, peer);
        const observation = found?.observation ?? (found ? await reconcile(found) : undefined);
        return observation
          ? { state: 'OBSERVED', observation }
          : {
              state: found ? 'UNKNOWN' : 'NOT_FOUND',
              attemptId: request.attemptId,
              operationId: request.operationId,
              requestDigest: identityEnvelopeRotationRequestDigest(request),
            };
      }),
    normalPerform: (raw: unknown, peer: string) =>
      use(async () => {
        const reference =
          typeof raw === 'object' && raw !== null && 'reference' in raw ? raw.reference : undefined;
        if (typeof reference !== 'string') throw new FixtureProviderDenied();
        const found = await record(reference);
        if (found === undefined && reference !== input.predecessorReference)
          throw new FixtureProviderDenied();
        if (found === undefined) await descriptor(reference);
        if (
          found &&
          (found.descriptor.state !== 'ACTIVE' ||
            found.normal === null ||
            !equal(await optionalJson(publicPath(reference)), found.normal))
        )
          throw new FixtureProviderDenied();
        return normal.execute(raw, peer);
      }),
    normalLookup: (raw: unknown, peer: string) => use(() => normal.lookup(raw, peer)),
    async close() {
      stopping = true;
      await serial;
    },
  };
}
