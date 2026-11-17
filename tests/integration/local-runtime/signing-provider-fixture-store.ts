import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import { mkdir, open, readFile, readdir, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import {
  evidenceKeyId,
  signReceiptCose,
  signReceiptCoseV2,
} from '../../../packages/security-kernel/src/business-transition/cose.js';
import {
  decodeAdmittedReceipt,
  admittedReceiptSchemaVersion,
} from '../../../packages/security-kernel/src/business-transition/admitted-receipt.js';
import {
  businessProviderDescriptorSchema,
  businessProviderObservationSchema,
  businessProviderPossessionPreimage,
  businessProviderRequestDigest,
  type BusinessProviderDescriptor,
  type BusinessProviderObservation,
  type BusinessProviderRequest,
} from '../../../services/identity-service/src/domain/business-signing-provider.js';

/** Genuinely external local provider substitute. Its durable truth is independent of the control database. */
export interface FixtureSigningClient {
  readonly credentialId: string;
  readonly workloadId: string;
  readonly certificate: Buffer;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly additionalPrivacyDomainIds?: readonly string[];
  readonly environmentId: string;
  readonly methods: readonly BusinessProviderRequest['method'][];
  readonly managedKeyOwners: readonly string[];
  readonly signingProfiles: readonly {
    profileId: string;
    profileVersion: number;
    profileDigest: string;
  }[];
}
function permitsPrivacyDomain(client: FixtureSigningClient, privacyDomainId: string): boolean {
  return (
    privacyDomainId === client.privacyDomainId ||
    client.additionalPrivacyDomainIds?.includes(privacyDomainId) === true
  );
}
interface StoredKey {
  descriptor: BusinessProviderDescriptor;
  distributed: boolean;
  creatorAttempt: string;
}
interface StoredAttempt {
  request: BusinessProviderRequest;
  startedAtNs: string;
  observation: BusinessProviderObservation | null;
}
const nowNs = () => (BigInt(Date.now()) * 1000000n).toString();
const fileId = (reference: string) => createHash('sha256').update(reference).digest('hex');
export async function optionalJson<T>(path: string): Promise<T | undefined> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as T;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
}
export async function durableWrite(path: string, value: string | Buffer): Promise<void> {
  const temporary = path + '.next';
  const file = await open(temporary, 'w', 0o600);
  try {
    await file.writeFile(value);
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temporary, path);
  const directory = await open(join(path, '..'), 'r');
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}
async function durableUnlink(path: string): Promise<void> {
  await unlink(path).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
  });
  const directory = await open(join(path, '..'), 'r');
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

export async function createFixtureSigningStore(config: {
  readonly root: string;
  readonly initialKeys: readonly {
    descriptor: BusinessProviderDescriptor;
    privateKeyPkcs8Der: Buffer;
  }[];
}) {
  for (const folder of ['keys', 'public', 'attempts', 'faults'])
    await mkdir(join(config.root, folder), { recursive: true, mode: 0o700 });
  const publicPath = (reference: string) =>
    join(config.root, 'public', fileId(reference) + '.json');
  const privatePath = (reference: string) => join(config.root, 'keys', fileId(reference) + '.der');
  const attemptPath = (attemptId: string) => join(config.root, 'attempts', attemptId + '.json');
  for (const initial of config.initialKeys) {
    const descriptor = businessProviderDescriptorSchema.parse(initial.descriptor);
    const actual = createPublicKey(
      createPrivateKey({ key: initial.privateKeyPkcs8Der, format: 'der', type: 'pkcs8' }),
    ).export({ format: 'der', type: 'spki' });
    if (evidenceKeyId(actual) !== descriptor.fingerprint)
      throw new Error('Invalid initial provider key');
    const prior = await optionalJson<StoredKey>(publicPath(descriptor.reference));
    if (prior !== undefined) {
      if (prior.descriptor.fingerprint !== descriptor.fingerprint)
        throw new Error('Provider bootstrap drift');
      continue; // Never restore a revoked or retired key during process restart.
    }
    await durableWrite(privatePath(descriptor.reference), initial.privateKeyPkcs8Der);
    await durableWrite(
      publicPath(descriptor.reference),
      JSON.stringify({ descriptor, distributed: true, creatorAttempt: 'BOOTSTRAP' }),
    );
  }
  const observed = (
    record: StoredAttempt,
    descriptor: BusinessProviderDescriptor | null,
    reason: BusinessProviderObservation['reason'] = null,
    resultHex: string | null = null,
  ): BusinessProviderObservation =>
    businessProviderObservationSchema.parse({
      schemaVersion: 1,
      providerId: 'local-ephemeral-signing-provider-v1',
      attemptId: record.request.attemptId,
      operationId: record.request.operationId,
      requestDigest: businessProviderRequestDigest(record.request),
      method: record.request.method,
      recordedAtNs: nowNs(),
      outcome: reason === null ? 'SUCCEEDED' : 'REJECTED',
      reason,
      descriptor,
      resultHex,
    });
  async function finish(record: StoredAttempt, observation: BusinessProviderObservation) {
    await durableWrite(
      attemptPath(record.request.attemptId),
      JSON.stringify({ ...record, observation }),
    );
    return observation;
  }
  function preparedDescriptor(
    record: StoredAttempt,
    publicKey: Buffer,
  ): BusinessProviderDescriptor {
    const request = record.request;
    return businessProviderDescriptorSchema.parse({
      participantId: request.participantId,
      privacyDomainId: request.privacyDomainId,
      workloadCredentialId: request.workloadCredentialId,
      environmentId: request.environmentId,
      secretClass: request.secretClass,
      purpose: request.purpose,
      reference: request.reference,
      version: request.version,
      algorithm: 'ES256',
      publicKeySpkiHex: publicKey.toString('hex'),
      fingerprint: evidenceKeyId(publicKey),
      validFromNs: record.startedAtNs,
      validUntilNs: (BigInt(record.startedAtNs) + 86400000000000n).toString(),
      state: 'ACTIVE',
      revokedAtNs: null,
      retiredAtNs: null,
    });
  }
  async function recover(record: StoredAttempt): Promise<BusinessProviderObservation> {
    const request = record.request;
    let stored = await optionalJson<StoredKey>(publicPath(request.reference));
    if (stored !== undefined) {
      for (const key of [
        'participantId',
        'privacyDomainId',
        'workloadCredentialId',
        'environmentId',
        'secretClass',
        'purpose',
        'reference',
        'version',
      ] as const)
        if (stored.descriptor[key] !== request[key])
          return finish(record, observed(record, null, 'WRONG_SCOPE'));
      if (
        'expectedFingerprint' in request &&
        stored.descriptor.fingerprint !== request.expectedFingerprint
      )
        return finish(record, observed(record, null, 'FINGERPRINT_MISMATCH'));
    }
    if (request.method === 'PREPARE' && stored === undefined) {
      let privateBytes: Buffer | undefined;
      try {
        privateBytes = await readFile(privatePath(request.reference));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
      if (privateBytes !== undefined) {
        try {
          const publicKey = createPublicKey(
            createPrivateKey({ key: privateBytes, format: 'der', type: 'pkcs8' }),
          ).export({ format: 'der', type: 'spki' });
          stored = {
            descriptor: preparedDescriptor(record, publicKey),
            distributed: false,
            creatorAttempt: request.attemptId,
          };
          await durableWrite(publicPath(request.reference), JSON.stringify(stored));
        } finally {
          privateBytes.fill(0);
        }
      }
    }
    if (
      stored !== undefined &&
      request.method === 'PREPARE' &&
      stored.creatorAttempt === request.attemptId
    )
      return finish(record, observed(record, stored.descriptor));
    if (
      stored !== undefined &&
      request.method === 'REVOKE' &&
      stored.descriptor.state === 'REVOKED'
    )
      return finish(record, observed(record, stored.descriptor));
    if (
      stored !== undefined &&
      request.method === 'RETIRE' &&
      stored.descriptor.state === 'RETIRED'
    )
      return finish(record, observed(record, stored.descriptor));
    if (
      stored !== undefined &&
      request.method === 'RETIRE' &&
      stored.descriptor.state === 'REVOKED'
    ) {
      let absent = false;
      try {
        const file = await open(privatePath(request.reference), 'r');
        await file.close();
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        absent = true;
      }
      if (absent) {
        stored.descriptor.state = 'RETIRED';
        stored.descriptor.retiredAtNs = nowNs();
        await durableWrite(publicPath(request.reference), JSON.stringify(stored));
        return finish(record, observed(record, stored.descriptor));
      }
    }
    return finish(record, observed(record, null, 'NOT_APPLIED'));
  }
  // A response is sent only after the observation is durable. A crash never upgrades a STARTED record by guessing.
  for (const name of await readdir(join(config.root, 'attempts'))) {
    if (!/^[0-9a-f-]{36}\.json$/u.test(name)) continue;
    const record = await optionalJson<StoredAttempt>(join(config.root, 'attempts', name));
    if (record?.observation === null) await recover(record);
  }
  async function perform(
    record: StoredAttempt,
    client: FixtureSigningClient,
    faultMode?: string,
  ): Promise<BusinessProviderObservation> {
    const request = record.request;
    let stored = await optionalJson<StoredKey>(publicPath(request.reference));
    if (request.method === 'PREPARE' && stored === undefined) {
      const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' });
      const descriptor = preparedDescriptor(record, publicKey);
      stored = { descriptor, distributed: false, creatorAttempt: request.attemptId };
      await durableWrite(
        privatePath(request.reference),
        pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
      );
      if (faultMode === 'DROP_AFTER_PRIVATE_MATERIAL') throw new FixtureProviderInterrupted();
      await durableWrite(publicPath(request.reference), JSON.stringify(stored));
    }
    if (stored === undefined) return observed(record, null, 'KEY_NOT_FOUND');
    const descriptor = stored.descriptor;
    for (const key of [
      'participantId',
      'privacyDomainId',
      'workloadCredentialId',
      'environmentId',
      'secretClass',
      'purpose',
      'reference',
      'version',
    ] as const)
      if (descriptor[key] !== request[key]) return observed(record, null, 'WRONG_SCOPE');
    if ('expectedFingerprint' in request && descriptor.fingerprint !== request.expectedFingerprint)
      return observed(record, null, 'FINGERPRINT_MISMATCH');
    if (request.method === 'INSPECT') return observed(record, descriptor);
    if (request.method === 'REVOKE') {
      if (descriptor.state === 'RETIRED') return observed(record, descriptor, 'REVOKED');
      if (descriptor.state !== 'REVOKED') {
        descriptor.state = 'REVOKED';
        descriptor.revokedAtNs = nowNs();
        await durableWrite(publicPath(request.reference), JSON.stringify(stored));
      }
      return observed(record, descriptor);
    }
    if (request.method === 'RETIRE') {
      if (descriptor.state === 'ACTIVE') return observed(record, descriptor, 'INVALID_REQUEST');
      if (descriptor.state !== 'RETIRED') {
        await durableUnlink(privatePath(request.reference));
        if (faultMode === 'DROP_AFTER_PRIVATE_RETIREMENT') throw new FixtureProviderInterrupted();
        descriptor.state = 'RETIRED';
        descriptor.retiredAtNs = nowNs();
        await durableWrite(publicPath(request.reference), JSON.stringify(stored));
      }
      return observed(record, descriptor);
    }
    if (descriptor.state !== 'ACTIVE') return observed(record, descriptor, 'REVOKED');
    if (
      BigInt(nowNs()) < BigInt(descriptor.validFromNs) ||
      BigInt(nowNs()) >= BigInt(descriptor.validUntilNs)
    )
      return observed(record, descriptor, 'EXPIRED');
    if (request.method === 'DISTRIBUTE') {
      stored.distributed = true;
      await durableWrite(publicPath(request.reference), JSON.stringify(stored));
    }
    if (request.method === 'PROVE' || request.method === 'SIGN_RECEIPT') {
      if (!stored.distributed || request.workloadCredentialId !== client.credentialId)
        return observed(record, descriptor, 'WRONG_SCOPE');
      const privateBytes = await readFile(privatePath(request.reference));
      try {
        if (request.method === 'PROVE')
          return observed(
            record,
            descriptor,
            null,
            sign('sha256', businessProviderPossessionPreimage(request), {
              key: createPrivateKey({ key: privateBytes, format: 'der', type: 'pkcs8' }),
              dsaEncoding: 'ieee-p1363',
            }).toString('hex'),
          );
        const payload = Buffer.from(request.payloadHex, 'hex');
        const receipt = decodeAdmittedReceipt(payload);
        if (
          !client.signingProfiles.some(
            (profile) =>
              profile.profileId === receipt.transitionProfileId &&
              profile.profileVersion === receipt.transitionProfileVersion &&
              profile.profileDigest === 'sha256:' + receipt.transitionProfileDigest.toString('hex'),
          ) ||
          receipt.participantId !== request.participantId ||
          receipt.privacyDomainId !== request.privacyDomainId ||
          receipt.environmentId !== request.environmentId ||
          receipt.receiptId !== request.attemptId ||
          receipt.operationId !== request.operationId ||
          receipt.signerId !== descriptor.fingerprint ||
          receipt.recordedAtNs < BigInt(descriptor.validFromNs) ||
          receipt.recordedAtNs >= BigInt(descriptor.validUntilNs) ||
          receipt.recordedAtNs > BigInt(nowNs())
        )
          return observed(record, descriptor, 'WRONG_SCOPE');
        return observed(
          record,
          descriptor,
          null,
          (admittedReceiptSchemaVersion(receipt) === 1 ? signReceiptCose : signReceiptCoseV2)(
            privateBytes,
            Buffer.from(descriptor.publicKeySpkiHex, 'hex'),
            payload,
          ).toString('hex'),
        );
      } finally {
        privateBytes.fill(0);
      }
    }
    return observed(record, descriptor);
  }
  return {
    async lookup(id: string, client: FixtureSigningClient) {
      const countPath = join(config.root, 'attempts', id + '.lookup-count');
      const priorCount = (await optionalJson<number>(countPath)) ?? 0;
      await durableWrite(countPath, JSON.stringify(priorCount + 1));
      if (await optionalJson<boolean>(join(config.root, 'attempts', id + '.lookup-blocked')))
        throw new FixtureProviderInterrupted();
      const record = await optionalJson<StoredAttempt>(attemptPath(id));
      if (record === undefined) return { state: 'ABSENT', attemptId: id };
      if (
        record.request.participantId !== client.participantId ||
        !permitsPrivacyDomain(client, record.request.privacyDomainId) ||
        record.request.environmentId !== client.environmentId
      )
        throw new FixtureProviderDenied();
      return { state: 'OBSERVED', observation: record.observation ?? (await recover(record)) };
    },
    async execute(
      input: BusinessProviderRequest,
      client: FixtureSigningClient,
    ): Promise<FixtureProviderExecution> {
      if (
        input.callerWorkloadCredentialId !== client.credentialId ||
        input.participantId !== client.participantId ||
        !permitsPrivacyDomain(client, input.privacyDomainId) ||
        input.environmentId !== client.environmentId ||
        !client.methods.includes(input.method) ||
        !client.managedKeyOwners.includes(input.workloadCredentialId) ||
        !input.reference.startsWith('secret://local/')
      )
        throw new FixtureProviderDenied();
      const prior = await optionalJson<StoredAttempt>(attemptPath(input.attemptId));
      if (prior !== undefined) {
        const observation =
          businessProviderRequestDigest(prior.request) !== businessProviderRequestDigest(input)
            ? observed(
                { request: input, startedAtNs: nowNs(), observation: null },
                null,
                'ATTEMPT_CONFLICT',
              )
            : (prior.observation ?? (await recover(prior)));
        return { observation, drop: false, delayMs: 0 };
      }
      const record: StoredAttempt = { request: input, startedAtNs: nowNs(), observation: null };
      await durableWrite(attemptPath(input.attemptId), JSON.stringify(record));
      const faultPath = join(config.root, 'faults', input.attemptId + '.json');
      let fault = await optionalJson<{ mode: string; delayMs?: number }>(faultPath);
      if (fault !== undefined) await unlink(faultPath);
      // Public ordinary signing derives its attempt inside an uncommitted transaction.
      // Claim a one-shot external transport fault without requiring the test to fabricate that attempt.
      if (fault === undefined) {
        const claimed = join(config.root, 'faults', input.attemptId + '.claimed');
        try {
          await rename(join(config.root, 'faults', `next-${input.method}.json`), claimed);
          fault = await optionalJson<{ mode: string; delayMs?: number }>(claimed);
          await unlink(claimed);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        }
      }
      if (fault?.mode === 'DROP_BEFORE_EFFECT')
        return { observation: null, drop: true, delayMs: 0 };
      if (fault?.mode === 'REJECT_NOT_APPLIED' || fault?.mode === 'REJECT_INVALID_REQUEST') {
        const observation = await finish(
          record,
          observed(
            record,
            null,
            fault.mode === 'REJECT_NOT_APPLIED' ? 'NOT_APPLIED' : 'INVALID_REQUEST',
          ),
        );
        return { observation, drop: false, delayMs: 0 };
      }
      let observation: BusinessProviderObservation;
      try {
        observation = await finish(record, await perform(record, client, fault?.mode));
      } catch (error) {
        if (error instanceof FixtureProviderInterrupted)
          return { observation: null, drop: true, delayMs: 0 };
        throw error;
      }
      // Corrupt only the wire response; durable provider truth remains available by lookup.
      if (fault?.mode === 'MISMATCH_AFTER_EFFECT')
        observation = { ...observation, operationId: input.attemptId };
      if (fault?.mode === 'DROP_AFTER_EFFECT_PAUSE_LOOKUP')
        await durableWrite(
          join(config.root, 'attempts', input.attemptId + '.lookup-blocked'),
          'true',
        );
      const delayMs = fault?.mode === 'TIMEOUT_AFTER_EFFECT' ? (fault.delayMs ?? 1500) : 0;
      if (!Number.isSafeInteger(delayMs) || delayMs < 0 || delayMs > 5000)
        throw new Error('Invalid fixture timeout');
      return {
        observation,
        drop:
          fault?.mode === 'DROP_AFTER_EFFECT' || fault?.mode === 'DROP_AFTER_EFFECT_PAUSE_LOOKUP',
        delayMs,
      };
    },
  };
}
export class FixtureProviderDenied extends Error {}
class FixtureProviderInterrupted extends Error {}
interface FixtureProviderExecution {
  observation: BusinessProviderObservation | null;
  drop: boolean;
  delayMs: number;
}
