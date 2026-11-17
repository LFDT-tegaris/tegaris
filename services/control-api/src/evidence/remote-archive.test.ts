import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import { sealSegment } from './segment.js';
import { sinkDurabilityReceipt, vaultObject } from './local-vault.js';
import { protectedVaultObject } from './protected-custody-contracts.js';
import { RemoteEvidenceArchive } from './remote-archive.js';
import {
  RemoteArchiveError,
  archiveProtection,
  remoteArchiveProfile,
  retentionMicros,
  type ArchiveAttemptBinding,
  type RemoteArchiveAttemptOwner,
  type RemoteArchiveIntent,
  type RemoteArchiveProfile,
} from './remote-archive-contracts.js';
import {
  signS3Request,
  S3ArchiveTransport,
  type S3ArchiveCredentials,
} from './remote-archive-s3.js';

interface FixtureObject {
  key: string;
  versionId: string;
  bytes: string;
  retention: string;
  initialHold: string;
  metadata: Record<string, string>;
}
interface ExternalFixture {
  endpoint: string;
  faults: {
    dropPutResponse: boolean;
    dropHoldResponse: boolean;
    denyRead: boolean;
    corruptRead: boolean;
    wrongVersion: boolean;
    shortRetention: boolean;
    forceHold: 'ON' | 'OFF' | null;
    malformedListing: boolean;
    repeatPage: boolean;
    pageSize: number;
    redirectRead: boolean;
  };
  counts: { puts: number; gets: number; lists: number; holds: number; denied: number };
  objects(): Promise<FixtureObject[]>;
  addVersion(original: FixtureObject, deleteMarker?: boolean): Promise<void>;
  rewriteVersion(original: FixtureObject, patch: Partial<FixtureObject>): Promise<void>;
  close(): Promise<void>;
}
type FixtureOptions = {
  root: string;
  bucket: string;
  expectedOwner: string;
  region: string;
  credentials: S3ArchiveCredentials;
  port?: number;
};
const fixtureUrl = new URL(
  '../../../../tests/integration/local-runtime/evidence-remote-archive-fixture.mjs',
  import.meta.url,
);
const { startRemoteArchiveFixture } = (await import(fixtureUrl.href)) as {
  startRemoteArchiveFixture(options: FixtureOptions): Promise<ExternalFixture>;
};

const roots: string[] = [],
  servers: ExternalFixture[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) await server.close();
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

/** TRANSPORT-ONLY test seam, deliberately without a SQL owner implementation.
 * These tests supply a dispatch decision to exercise external I/O. They do not
 * establish durable admission, approval, fencing, checkpoint or journey success.
 * Real owner/role/SQL/restart tests must replace this seam during integration.
 */
function dispatch(
  mode: 'INITIAL_SEND' | 'RECONCILE',
  inspect?: (binding: ArchiveAttemptBinding) => void,
): RemoteArchiveAttemptOwner {
  return {
    async run(binding, perform) {
      inspect?.(binding);
      return perform(mode);
    },
  };
}
async function setup() {
  const root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT!, 'remote-archive-'));
  roots.push(root);
  const credentials = {
    accessKeyId: `TEST${randomBytes(12).toString('hex')}`,
    secretAccessKey: randomBytes(32).toString('base64'),
  };
  const options = {
    root,
    credentials,
    bucket: 'archive-test',
    expectedOwner: '123456789012',
    region: 'us-east-1',
  };
  const external = await startRemoteArchiveFixture(options);
  servers.push(external);
  const profile: RemoteArchiveProfile = {
    profileId: 'local-s3-interface',
    sinkId: 'remote-test',
    endpoint: external.endpoint,
    transport: 'LOOPBACK_TEST',
    region: options.region,
    bucket: options.bucket,
    expectedBucketOwner: options.expectedOwner,
    prefix: 'evidence',
    lockMode: 'COMPLIANCE',
    requestTimeoutMs: 3000,
    maxVersionPages: 4,
  };
  const archive = new RemoteEvidenceArchive(
    profile,
    async () => credentials,
    dispatch('INITIAL_SEND'),
  );
  const receipt = Buffer.from(
    'synthetic external-interface source; not authenticated business evidence',
  );
  const sealed = sealSegment(
    {
      version: 'OPENPC_EVIDENCE_SEGMENT_V1',
      participantId: randomUUID(),
      privacyDomainId: randomUUID(),
      streamId: 'original-stream',
      segmentId: randomUUID(),
      firstSequence: '1',
      throughSequence: '1',
      previousSegmentDigest: null,
      keyId: 'original-key',
      retentionUntil: '2027-01-01T00:00:00.000001Z',
    },
    [
      {
        recordId: randomUUID(),
        evidenceClass: 'BUSINESS_TRANSITION',
        sourceFormat: 'TEST_RECEIPT',
        receiptDigest: sha256(receipt),
        receiptBase64: receipt.toString('base64'),
        occurredAt: '2026-09-23T00:00:00.000000Z',
      },
    ],
    randomBytes(32),
  );
  const intent: RemoteArchiveIntent = {
    intentId: uuidv7(),
    profileDigest: archive.profileDigest,
    source: {
      kind: 'SEGMENT',
      object: vaultObject(profile.sinkId, sealed.header, sealed.objectDigest),
    },
    payloadDigest: sealed.objectDigest,
    payloadBytes: sealed.bytes.length,
    initialProtection: { revision: '1', rules: [] },
  };
  const makeArchive = (mode: 'INITIAL_SEND' | 'RECONCILE', owner = dispatch(mode)) =>
    new RemoteEvidenceArchive(profile, async () => credentials, owner);
  return {
    root,
    options,
    external,
    profile,
    credentials,
    archive,
    intent,
    bytes: sealed.bytes,
    makeArchive,
  };
}
function hold(state: 'ACTIVE' | 'RELEASED' = 'ACTIVE') {
  return {
    holdId: uuidv7(),
    selectorDigest: sha256('hold'),
    creationOperationId: uuidv7(),
    releaseOperationId: state === 'ACTIVE' ? null : uuidv7(),
    state,
    revision: state === 'ACTIVE' ? ('1' as const) : ('2' as const),
  };
}

it('bounds credential acquisition and prevents new requests after caller cancellation', async () => {
  const f = await setup();
  const controller = new AbortController();
  controller.abort();
  await expect(
    f.archive.withinDeadline(() => f.archive.put(f.intent, f.bytes, uuidv7()), controller.signal),
  ).rejects.toMatchObject({ code: 'UNAVAILABLE' });
  expect(f.external.counts.puts).toBe(0);
  expect(f.external.counts.lists).toBe(0);
  let release: ((value: S3ArchiveCredentials) => void) | undefined;
  const credentials = new Promise<S3ArchiveCredentials>((resolve) => {
    release = resolve;
  });
  const transport = new S3ArchiveTransport(
    { ...f.profile, requestTimeoutMs: 100 },
    () => credentials,
  );
  await expect(
    transport.withinDeadline(() => transport.discoverVersions('pending')),
  ).rejects.toMatchObject({ code: 'UNAVAILABLE' });
  release!(f.credentials);
  await new Promise((resolve) => setImmediate(resolve));
  expect(f.external.counts.lists).toBe(0);
});

it('checks elapsed admission synchronously when credential work delays the abort timer', async () => {
  const f = await setup();
  const transport = new S3ArchiveTransport(f.profile, async () => {
    const until = performance.now() + 25;
    while (performance.now() < until) {
      /* intentional external credential CPU stall */
    }
    return f.credentials;
  });
  await expect(
    transport.withinDeadline(
      () => transport.discoverVersions('expired'),
      undefined,
      performance.now() + 5,
    ),
  ).rejects.toMatchObject({ code: 'UNAVAILABLE' });
  expect(f.external.counts.lists).toBe(0);
});

it('shares one deadline across nested requests instead of renewing it for readback', async () => {
  const f = await setup();
  const clock = vi.spyOn(performance, 'now').mockReturnValue(10_000);
  let calls = 0;
  const transport = new S3ArchiveTransport({ ...f.profile, requestTimeoutMs: 5000 }, async () => {
    calls++;
    if (calls === 2) clock.mockReturnValue(15_500);
    return f.credentials;
  });
  try {
    await expect(
      transport.withinDeadline(async () => {
        await transport.discoverVersions('first');
        clock.mockReturnValue(14_500);
        await transport.withinDeadline(() => transport.discoverVersions('second'));
      }),
    ).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(calls).toBe(2);
    expect(f.external.counts.lists).toBe(1);
    expect(f.external.counts.puts).toBe(0);
  } finally {
    clock.mockRestore();
  }
});

describe('SEM-055–059 remote external-interface proof; SQL custody and WORM qualification remain open', () => {
  it('matches the independently published AWS SigV4 GET signing vector', () => {
    // Public AWS example values, never credentials for any account.
    const signed = signS3Request(
      'GET',
      new URL('https://examplebucket.s3.amazonaws.com/test.txt'),
      { range: 'bytes=0-9' },
      Buffer.alloc(0),
      'us-east-1',
      {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      },
      new Date('2013-05-24T00:00:00Z'),
    );
    expect(signed.authorization).toContain(
      'Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41',
    );
  });

  it('retains original ciphertext and opaque version through independent fixture and adapter restart', async () => {
    const f = await setup();
    const result = await f.archive.put(f.intent, f.bytes, uuidv7());
    expect(result.assurance).toBe('REMOTE_INTERFACE_VERIFIED');
    expect(result.providerQualification).toBe('NOT_ESTABLISHED');
    expect(result.locator.versionId).not.toBe(f.intent.payloadDigest);
    expect(result.locator.versionId).toContain('/+=');
    expect(sinkDurabilityReceipt.safeParse(result).success).toBe(false);
    expect(await f.archive.readExact(f.intent, result.locator)).toEqual(f.bytes);
    await f.external.close();
    const restarted = await startRemoteArchiveFixture({
      ...f.options,
      port: Number(new URL(f.external.endpoint).port),
    });
    servers.push(restarted);
    expect(await f.makeArchive('RECONCILE').reconcilePut(f.intent)).toEqual(result);
    expect(await restarted.objects()).toHaveLength(1);
    expect(restarted.counts.puts).toBe(0);
  });

  it('reconciles persisted-but-response-lost PUT without a second upload or new identity', async () => {
    const f = await setup(),
      attemptId = uuidv7();
    f.external.faults.dropPutResponse = true;
    await expect(f.archive.put(f.intent, f.bytes, attemptId)).rejects.toMatchObject({
      code: 'AMBIGUOUS',
    });
    expect(await f.external.objects()).toHaveLength(1);
    const recovered = await f.makeArchive('RECONCILE').put(f.intent, f.bytes, attemptId);
    expect(recovered.intent).toEqual(f.intent);
    expect(f.external.counts.puts).toBe(1);
    expect(Buffer.from((await f.external.objects())[0]!.bytes, 'base64')).toEqual(f.bytes);
  });

  it('does not turn an empty complete listing into permission to repeat an ambiguous PUT', async () => {
    const f = await setup();
    await expect(f.makeArchive('RECONCILE').put(f.intent, f.bytes, uuidv7())).rejects.toMatchObject(
      { code: 'AMBIGUOUS' },
    );
    expect(f.external.counts.puts).toBe(0);
    expect(await f.external.objects()).toHaveLength(0);
  });

  it('preserves one exact external version under concurrent conditional uploads', async () => {
    const f = await setup();
    const [first, second] = await Promise.all([
      f.archive.put(f.intent, f.bytes, uuidv7()),
      f.makeArchive('INITIAL_SEND').put(f.intent, f.bytes, uuidv7()),
    ]);
    expect(first).toEqual(second);
    expect(await f.external.objects()).toHaveLength(1);
    expect(f.external.counts.puts).toBeLessThanOrEqual(2);
  });

  it('requires the attempt owner and binds its original intent, action and hold snapshot', async () => {
    const f = await setup(),
      attemptId = uuidv7();
    const owner: RemoteArchiveAttemptOwner = {
      async run(binding) {
        expect(binding).toMatchObject({
          attemptId,
          intent: f.intent,
          intentDigest: sha256(f.intent),
          action: 'PUT',
          locator: null,
          protectionDigest: sha256(f.intent.initialProtection),
        });
        throw new RemoteArchiveError('UNAVAILABLE');
      },
    };
    await expect(
      f.makeArchive('INITIAL_SEND', owner).put(f.intent, f.bytes, attemptId),
    ).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(f.external.counts.lists + f.external.counts.puts).toBe(0);
    expect(
      () => new RemoteEvidenceArchive(f.profile, async () => f.credentials, null as never),
    ).toThrow();
  });

  it('rejects an owner-returned receipt that differs from the actual observation', async () => {
    const f = await setup();
    const owner: RemoteArchiveAttemptOwner = {
      async run(_binding, perform) {
        return { ...(await perform('INITIAL_SEND')), receiptDigest: sha256('forged') };
      },
    };
    await expect(
      f.makeArchive('INITIAL_SEND', owner).put(f.intent, f.bytes, uuidv7()),
    ).rejects.toMatchObject({ code: 'INTEGRITY' });
  });

  it('preserves overlapping aggregate holds when one supplied rule is released', async () => {
    const f = await setup();
    const rules = [hold(), hold()].sort((a, b) => (a.holdId < b.holdId ? -1 : 1));
    f.intent.initialProtection = { revision: '1', rules };
    const original = await f.archive.put(f.intent, f.bytes, uuidv7());
    const remaining = archiveProtection.parse({
      revision: '2',
      rules: [
        { ...rules[0], state: 'RELEASED', revision: '2', releaseOperationId: uuidv7() },
        rules[1],
      ],
    });
    const covered = await f.archive.reconcileProtection(
      f.intent,
      original.locator,
      remaining,
      uuidv7(),
    );
    expect(covered.observedLegalHold).toBe('ON');
    expect(covered.protectionDigest).toBe(sha256(remaining));
    expect(f.external.counts.holds).toBe(0);
    const released = archiveProtection.parse({
      revision: '3',
      rules: remaining.rules.map((rule) =>
        rule.state === 'RELEASED'
          ? rule
          : { ...rule, state: 'RELEASED', revision: '2', releaseOperationId: uuidv7() },
      ),
    });
    const result = await f.archive.reconcileProtection(
      f.intent,
      original.locator,
      released,
      uuidv7(),
    );
    expect(result.observedLegalHold).toBe('OFF');
    expect(result.locator).toEqual(original.locator);
    expect(await f.external.objects()).toHaveLength(1);
  });

  it('reconciles a durable hold change with lost response without reapplying the toggle', async () => {
    const f = await setup(),
      original = await f.archive.put(f.intent, f.bytes, uuidv7());
    const protection = { revision: '2', rules: [hold()] },
      attemptId = uuidv7();
    f.external.faults.dropHoldResponse = true;
    await expect(
      f.archive.reconcileProtection(f.intent, original.locator, protection, attemptId),
    ).rejects.toMatchObject({ code: 'AMBIGUOUS' });
    expect(
      (
        await f
          .makeArchive('RECONCILE')
          .reconcileProtection(f.intent, original.locator, protection, attemptId)
      ).observedLegalHold,
    ).toBe('ON');
    expect(f.external.counts.holds).toBe(1);
  });

  it('does not retry a protection mutation whose previous effect remains uncertain', async () => {
    const f = await setup(),
      original = await f.archive.put(f.intent, f.bytes, uuidv7());
    await expect(
      f
        .makeArchive('RECONCILE')
        .reconcileProtection(
          f.intent,
          original.locator,
          { revision: '2', rules: [hold()] },
          uuidv7(),
        ),
    ).rejects.toMatchObject({ code: 'AMBIGUOUS' });
    expect(f.external.counts.holds).toBe(0);
  });

  it.each(['corruptRead', 'wrongVersion', 'shortRetention', 'denyRead', 'redirectRead'] as const)(
    'withholds verification on external %s and never repairs by replacing the object',
    async (fault) => {
      const f = await setup(),
        original = await f.archive.put(f.intent, f.bytes, uuidv7());
      f.external.faults[fault] = true;
      await expect(f.archive.verifyExact(f.intent, original.locator)).rejects.toThrow();
      expect(f.external.counts.puts).toBe(1);
      expect(await f.external.objects()).toHaveLength(1);
    },
  );

  it('rejects hold coverage on the wrong version and a mismatching observed protection bit', async () => {
    const f = await setup(),
      original = await f.archive.put(f.intent, f.bytes, uuidv7());
    f.external.faults.forceHold = 'ON';
    await expect(f.archive.verifyExact(f.intent, original.locator)).rejects.toMatchObject({
      code: 'PROTECTION_MISMATCH',
    });
    await expect(
      f.archive.reconcileProtection(
        f.intent,
        { ...original.locator, versionId: 'other' },
        { revision: '2', rules: [hold()] },
        uuidv7(),
      ),
    ).rejects.toThrow();
    expect(f.external.counts.holds).toBe(0);
  });

  it('rejects a changed scope, sink, digest, length, profile or original intent', async () => {
    const f = await setup(),
      original = await f.archive.put(f.intent, f.bytes, uuidv7());
    for (const changed of [
      { ...f.intent, profileDigest: sha256('different-profile') },
      { ...f.intent, payloadDigest: sha256('other') },
      { ...f.intent, payloadBytes: f.bytes.length + 1 },
      { ...f.intent, intentId: uuidv7() },
      {
        ...f.intent,
        source: {
          ...f.intent.source,
          object: { ...f.intent.source.object, participantId: randomUUID() },
        },
      },
      {
        ...f.intent,
        source: { ...f.intent.source, object: { ...f.intent.source.object, sinkId: 'other' } },
      },
    ]) {
      await expect(
        f.archive.readExact(changed as RemoteArchiveIntent, original.locator),
      ).rejects.toThrow();
    }
    await expect(
      f.archive.put({ ...f.intent, intentId: uuidv7() }, f.bytes, uuidv7()),
    ).rejects.toMatchObject({ code: 'INTEGRITY' });
    expect(f.external.counts.puts).toBe(1);
  });

  it('rejects provider metadata substitution even when the ciphertext still matches', async () => {
    const f = await setup(),
      original = await f.archive.put(f.intent, f.bytes, uuidv7());
    const stored = (await f.external.objects())[0]!;
    await f.external.rewriteVersion(stored, {
      metadata: { ...stored.metadata, 'x-amz-meta-openpc-source': sha256('different-scope') },
    });
    await expect(f.archive.readExact(f.intent, original.locator)).rejects.toMatchObject({
      code: 'INTEGRITY',
    });
    expect(f.external.counts.puts).toBe(1);
  });

  it.each([false, true])(
    'refuses competing versions or delete markers (marker=%s)',
    async (marker) => {
      const f = await setup();
      const original = await f.archive.put(f.intent, f.bytes, uuidv7());
      await f.external.addVersion((await f.external.objects())[0]!, marker);
      f.external.faults.pageSize = 1;
      await expect(f.archive.reconcilePut(f.intent)).rejects.toMatchObject({ code: 'CONFLICT' });
      // A latest alias/delete marker cannot substitute for the known immutable version.
      expect(await f.archive.readExact(f.intent, original.locator)).toEqual(f.bytes);
      expect(f.external.counts.puts).toBe(1);
    },
  );

  it.each(['repeatPage', 'malformedListing'] as const)(
    'fails closed on incomplete or malformed version discovery: %s',
    async (fault) => {
      const f = await setup();
      await f.archive.put(f.intent, f.bytes, uuidv7());
      f.external.faults[fault] = true;
      await expect(f.archive.reconcilePut(f.intent)).rejects.toThrow();
      expect(f.external.counts.puts).toBe(1);
    },
  );

  it('rejects invalid transport profiles and unauthenticated external requests', async () => {
    const f = await setup();
    for (const endpoint of [
      'http://example.com',
      'http://localhost',
      'http://127.0.0.1/path',
      'http://user:pass@127.0.0.1',
      'http://127.0.0.1?redirect=1',
    ])
      expect(remoteArchiveProfile.safeParse({ ...f.profile, endpoint }).success).toBe(false);
    const bad = new RemoteEvidenceArchive(
      f.profile,
      async () => ({ ...f.credentials, secretAccessKey: randomBytes(32).toString('hex') }),
      dispatch('INITIAL_SEND'),
    );
    await expect(bad.put(f.intent, f.bytes, uuidv7())).rejects.toMatchObject({
      code: 'UNAVAILABLE',
    });
    expect(await f.external.objects()).toHaveLength(0);
    expect(f.external.counts.denied).toBe(1);
  });

  it('keeps protected-proof source, ciphertext/key and retention distinct from ordinary evidence', async () => {
    const f = await setup(),
      sourceDigest = sha256('synthetic-proof');
    const payload = {
      keyId: 'protected-original-key',
      nonceBase64: randomBytes(12).toString('base64'),
      ciphertextBase64: randomBytes(64).toString('base64'),
    };
    const object = protectedVaultObject.parse({
      dataClass: 'RAW_SOURCE_BODY',
      participantId: f.intent.source.object.participantId,
      privacyDomainId: f.intent.source.object.privacyDomainId,
      sinkId: f.profile.sinkId,
      objectRef: `urn:openpc:resource:${uuidv7()}`,
      objectVersion: '1',
      objectDigest: sourceDigest,
      payloadDigest: sha256(payload),
      ciphertextBytes: 64,
      retainUntil: '2028-01-01T00:00:00.000000Z',
      source: {
        evidenceId: `urn:openpc:resource:${uuidv7()}`,
        occurrenceId: uuidv7(),
        operationId: uuidv7(),
        sourceReceiptDigest: sourceDigest,
        proofDigest: sourceDigest,
        assertionDigest: sourceDigest,
        signatureDigest: sourceDigest,
        signerKeyDigest: sourceDigest,
        occurredAt: '2026-09-23T00:00:00.000000Z',
        materialType: 'IDENTITY_SIGNED_AUTHORIZATION_ASSERTION',
        evidenceClass: 'AUTHENTICATION',
        sourceFormat: 'IDENTITY_RUNTIME_ASSERTION_3002_2_13',
        occurrenceIntegrity: 'CONTROL_DATABASE_IMMUTABLE',
        proofIntegrity: 'IDENTITY_COSE_ED25519',
        finality: 'NOT_APPLICABLE',
        authorityEffect: 'NONE',
      },
    });
    const bytes = Buffer.from(canonicalJson(payload));
    const proof: RemoteArchiveIntent = {
      ...f.intent,
      intentId: uuidv7(),
      source: { kind: 'PROTECTED_PROOF', object },
      payloadDigest: sha256(bytes),
      payloadBytes: bytes.length,
    };
    const ordinary = await f.archive.put(f.intent, f.bytes, uuidv7());
    const protectedResult = await f.archive.put(proof, bytes, uuidv7());
    expect(protectedResult.locator.key).not.toBe(ordinary.locator.key);
    expect(protectedResult.observedRetention.retainUntil).toBe(object.retainUntil);
    expect(protectedResult.intent.source).toEqual(proof.source);
    expect(await f.archive.readExact(proof, protectedResult.locator)).toEqual(bytes);
    expect(await f.external.objects()).toHaveLength(2);
    const stored = (await f.external.objects()).find(
      (value) => value.versionId === protectedResult.locator.versionId,
    )!;
    await f.external.rewriteVersion(stored, { retention: '2028-01-01T00:00:00.000001Z' });
    await expect(f.archive.verifyExact(proof, protectedResult.locator)).rejects.toMatchObject({
      code: 'PROTECTION_MISMATCH',
    });
  });

  it('compares retention without discarding sub-millisecond precision', () => {
    expect(
      retentionMicros('2027-01-01T00:00:00.000001Z') - retentionMicros('2027-01-01T00:00:00Z'),
    ).toBe(1n);
    expect(() => retentionMicros('2027-02-31T00:00:00Z')).toThrow();
  });
});
