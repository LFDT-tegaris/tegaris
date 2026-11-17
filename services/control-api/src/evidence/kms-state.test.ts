import { expect, it, vi } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  assertEvidenceKmsTransition,
  type EvidenceKmsAttemptState,
  type EvidenceKmsPrepareInput,
} from './kms-contracts.js';
import {
  EvidenceKmsState,
  assertEvidenceKmsOriginal,
  assertEvidenceKmsReplay,
  inspectEvidenceKmsPrepareRequest,
  completeEvidenceKmsMaterial,
  type EvidenceKmsAttempt,
} from './kms-state.js';
import { sealNotificationPayload, openNotificationPayload } from './notification-payload-crypto.js';
import { openVaultDirectory, putVaultFile, readVaultFile } from './immutable-vault.js';
import { EvidenceKmsRuntime, type EvidenceKmsTlsMaterial } from './kms-runtime.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (n: string) => `sha256:${n.repeat(64)}`;
const input: EvidenceKmsPrepareInput = {
  recipient: {
    participantId: id(1),
    privacyDomainId: id(2),
    producerTrustDigest: digest('1'),
    installationDigest: digest('2'),
  },
  attemptId: id(3),
  objectIntent: {
    environmentId: 'local-kms',
    participantId: id(1),
    privacyDomainId: id(2),
    payloadObjectId: id(4),
    objectVersion: '1',
    notificationOccurrenceRef: `urn:openpc:notification-occurrence:${id(5)}`,
    routingProfileDigest: digest('3'),
    templateDigest: digest('4'),
    recipientSetDigest: digest('5'),
    redactionProfileDigest: digest('6'),
    preferenceGeneration: '1',
    payloadDigest: digest('7'),
  },
};
function original(): EvidenceKmsAttempt {
  const requestBytes = Buffer.from(
    canonicalJson({ ...input, operation: 'PREPARE', challenge: 'a'.repeat(64) }),
  );
  return {
    attemptId: input.attemptId,
    installationDigest: input.recipient.installationDigest,
    objectIntentDigest: sha256(input.objectIntent),
    authorityDigest: digest('8'),
    requestBytes,
    requestDigest: sha256(requestBytes),
    state: 'UNKNOWN',
    resultReceiptBytes: null,
  };
}

it('an ambiguous original can resolve but cannot return to preparation or dispatch', () => {
  const states: EvidenceKmsAttemptState[] = [
    'PREPARED',
    'DISPATCHED',
    'UNKNOWN',
    'PROVED',
    'REJECTED',
  ];
  const allowed = new Set([
    'PREPARED:DISPATCHED',
    'DISPATCHED:UNKNOWN',
    'DISPATCHED:PROVED',
    'DISPATCHED:REJECTED',
    'UNKNOWN:UNKNOWN',
    'UNKNOWN:PROVED',
    'UNKNOWN:REJECTED',
  ]);
  for (const before of states)
    for (const after of states) {
      const check = () => assertEvidenceKmsTransition(before, after);
      if (allowed.has(`${before}:${after}`)) expect(check).not.toThrow();
      else expect(check).toThrow('OPS_SECRET_UNRESOLVED');
    }
});

it('readback preserves the original challenge, intent and installation across restart', () => {
  const before = original();
  const restarted = { ...before, requestBytes: Buffer.from(before.requestBytes) };
  expect(() => assertEvidenceKmsOriginal(restarted, input)).not.toThrow();
  expect(() => assertEvidenceKmsReplay(restarted, input)).not.toThrow();
  expect(inspectEvidenceKmsPrepareRequest(restarted.requestBytes).challenge).toBe('a'.repeat(64));
  expect(restarted.requestBytes.equals(before.requestBytes)).toBe(true);
  for (const change of [
    { attemptId: id(9) },
    { installationDigest: digest('9') },
    { objectIntentDigest: digest('9') },
    { requestDigest: digest('9') },
  ])
    expect(() => assertEvidenceKmsOriginal({ ...before, ...change }, input)).toThrow(
      'OPS_SECRET_UNRESOLVED',
    );
});

it('another key epoch, tenant or business input is not a retry of the same object', () => {
  const before = original();
  for (const changed of [
    { ...input, attemptId: id(9) },
    { ...input, recipient: { ...input.recipient, installationDigest: digest('9') } },
    { ...input, recipient: { ...input.recipient, participantId: id(9) } },
    { ...input, objectIntent: { ...input.objectIntent, payloadDigest: digest('9') } },
    { ...input, objectIntent: { ...input.objectIntent, templateDigest: digest('9') } },
  ])
    expect(() => assertEvidenceKmsReplay(before, changed)).toThrow('OPS_SECRET_UNRESOLVED');
});

it('fails closed on noncanonical bytes, duplicate JSON keys, unknown fields and oversized requests', () => {
  const request = { ...input, operation: 'PREPARE', challenge: 'a'.repeat(64) };
  const canonical = canonicalJson(request);
  for (const bytes of [
    Buffer.alloc(0),
    Buffer.alloc(32769),
    Buffer.from(JSON.stringify(request)),
    Buffer.from(`${canonical}\n`),
    Buffer.from(canonical.replace('{', '{"challenge":"b",')),
    Buffer.from(canonicalJson({ ...request, admitted: true })),
    Buffer.from(canonicalJson({ ...request, challenge: 'a'.repeat(63) })),
    Buffer.from(
      canonicalJson({ ...request, objectIntent: { ...input.objectIntent, keyId: digest('9') } }),
    ),
  ])
    expect(() => inspectEvidenceKmsPrepareRequest(bytes)).toThrow('OPS_SECRET_UNRESOLVED');
});

it('foreign object scope is denied before any database or provider effect', async () => {
  const connect = vi.fn();
  const state = new EvidenceKmsState({ connect } as unknown as Pool, {} as IdentityKernel);
  await expect(
    state.prepare({} as TLSSocket, {
      ...input,
      objectIntent: { ...input.objectIntent, privacyDomainId: id(9) },
    }),
  ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
  expect(connect).not.toHaveBeenCalled();
});

it('requires an exact unwrap key and use before entering Identity or reserving an exchange', async () => {
  const connect = vi.fn();
  const state = new EvidenceKmsState({ connect } as unknown as Pool, {} as IdentityKernel);
  const selector = { recipient: input.recipient, attemptId: input.attemptId };
  for (const request of [
    selector,
    { ...selector, keyId: 'latest', use: 'ENCRYPT' },
    { ...selector, keyId: digest('9'), use: 'DECRYPT' },
  ]) {
    await expect(
      state.createExchange({} as TLSSocket, request, 'UNWRAP', 'ENCRYPT'),
    ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
  }
  expect(connect).not.toHaveBeenCalled();
});

it('denies missing ciphertext persistence and already cancelled work before database effects', async () => {
  const connect = vi.fn();
  const runtime = new EvidenceKmsRuntime(
    { connect } as unknown as Pool,
    {} as IdentityKernel,
    {} as EvidenceKmsTlsMaterial,
  );
  const request = {
    recipient: input.recipient,
    attemptId: input.attemptId,
    keyId: digest('6'),
    use: 'ENCRYPT',
  };
  const crypto = vi.fn();
  const persist = vi.fn();
  await expect(
    runtime.withObjectKey({} as TLSSocket, request, new AbortController().signal, crypto),
  ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
  const aborted = AbortSignal.abort();
  await expect(
    runtime.withObjectKey({} as TLSSocket, request, aborted, crypto, persist),
  ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
  await expect(runtime.prepareObjectKey({} as TLSSocket, input, aborted)).rejects.toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
  expect(connect).not.toHaveBeenCalled();
  expect(crypto).not.toHaveBeenCalled();
  expect(persist).not.toHaveBeenCalled();
});

function cryptoCase() {
  const plaintext = Buffer.from('minimized-payload');
  const objectIntent = { ...input.objectIntent, payloadDigest: sha256(plaintext) };
  const requestBytes = Buffer.from(
    canonicalJson({ ...input, objectIntent, operation: 'PREPARE', challenge: 'a'.repeat(64) }),
  );
  const attempt = {
    ...original(),
    requestBytes,
    requestDigest: sha256(requestBytes),
    objectIntentDigest: sha256(objectIntent),
  };
  const context = {
    client: {} as PoolClient,
    original: attempt,
    selector: { recipient: input.recipient, attemptId: input.attemptId },
    exchangeId: id(6),
    keyId: digest('6'),
    material: Buffer.alloc(32, 0x42),
    wire: Buffer.alloc(100, 0x42),
    leaseUntilMs: Date.now() + 1000,
    receiptUntilMs: Date.now() + 5000,
  };
  const seal = (material: { keyId: string; bytes: Buffer }) =>
    sealNotificationPayload({ ...objectIntent, keyId: material.keyId }, plaintext, material);
  return { context, seal, plaintext, objectIntent };
}

it('erases owned material and its wire frame before asynchronous immutable ciphertext write/readback', async () => {
  const root = process.env.OPENPC_PNC_TMP_ROOT;
  if (!root) throw new Error('OPENPC_PNC_TMP_ROOT is required');
  const directory = await openVaultDirectory(await mkdtemp(join(root, 'kms-ciphertext-')));
  const sample = cryptoCase();
  let signal: AbortSignal | undefined;
  try {
    const sealed = await completeEvidenceKmsMaterial(
      sample.context,
      (material) => {
        signal = material.signal;
        return sample.seal(material);
      },
      async (_client, ciphertext) => {
        expect(sample.context.material.every((byte) => byte === 0)).toBe(true);
        expect(sample.context.wire.every((byte) => byte === 0)).toBe(true);
        expect(signal?.aborted).toBe(true);
        expect(ciphertext).toMatchObject({
          attemptId: input.attemptId,
          exchangeId: id(6),
          payloadObjectId: input.objectIntent.payloadObjectId,
          objectIntentDigest: sample.context.original.objectIntentDigest,
          originalRequestDigest: sample.context.original.requestDigest,
          keyId: sample.context.keyId,
        });
        expect(ciphertext).not.toHaveProperty('material');
        await putVaultFile(directory, 'original.raw', ciphertext.bytes);
        return readVaultFile(directory, 'original.raw', 131072);
      },
    );
    expect(await readVaultFile(directory, 'original.raw', 131072)).toEqual(sealed.bytes);
  } finally {
    await rm(directory, { recursive: true });
  }
});

it('preserves ciphertext written before a later failure for original authenticated readback', async () => {
  const root = process.env.OPENPC_PNC_TMP_ROOT;
  if (!root) throw new Error('OPENPC_PNC_TMP_ROOT is required');
  const directory = await openVaultDirectory(await mkdtemp(join(root, 'kms-ciphertext-')));
  const sample = cryptoCase();
  let sealed: ReturnType<typeof sealNotificationPayload> | undefined;
  try {
    await expect(
      completeEvidenceKmsMaterial(
        sample.context,
        (material) => {
          sealed = sample.seal(material);
          return sealed;
        },
        async (_client, ciphertext) => {
          await putVaultFile(directory, 'original.raw', ciphertext.bytes);
          throw new Error('persistence acknowledgement lost');
        },
      ),
    ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
    expect(sample.context.material.every((byte) => byte === 0)).toBe(true);
    const readback = await readVaultFile(directory, 'original.raw', 131072);
    expect(readback).toEqual(sealed!.bytes);
    const restoredMaterial = Buffer.alloc(32, 0x42);
    try {
      const opened = openNotificationPayload(
        readback,
        sealed!.encryptedObjectDigest,
        sealed!.binding,
        { keyId: sample.context.keyId, bytes: restoredMaterial },
      );
      expect(opened).toEqual(sample.plaintext);
      opened.fill(0);
    } finally {
      restoredMaterial.fill(0);
    }
  } finally {
    await rm(directory, { recursive: true });
  }
});

it('rejects failed persistence, mismatched readback and a foreign ciphertext before result publication', async () => {
  for (const fault of [
    'WRITE_FAILURE',
    'READBACK_MISMATCH',
    'FOREIGN_BINDING',
    'FALSE_DIGEST',
    'RESULT_MUTATION',
  ] as const) {
    const sample = cryptoCase();
    let persists = 0;
    let sealed: ReturnType<typeof sealNotificationPayload>;
    await expect(
      completeEvidenceKmsMaterial(
        sample.context,
        (material) => {
          if (fault === 'FOREIGN_BINDING')
            return sealNotificationPayload(
              { ...sample.objectIntent, payloadObjectId: id(99), keyId: material.keyId },
              sample.plaintext,
              material,
            );
          sealed = sample.seal(material);
          if (fault === 'FALSE_DIGEST') sealed.encryptedObjectDigest = sha256('wrong-ciphertext');
          return sealed;
        },
        async (_client, ciphertext) => {
          persists++;
          expect(sample.context.material.every((byte) => byte === 0)).toBe(true);
          if (fault === 'WRITE_FAILURE') throw new Error('PRIVATE_CANARY');
          if (fault === 'RESULT_MUTATION') {
            sealed.bytes = Buffer.from('PRIVATE_CANARY');
            return Buffer.from(ciphertext.bytes);
          }
          return Buffer.from(ciphertext.bytes.subarray(1));
        },
      ),
    ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
    expect(persists).toBe(['FOREIGN_BINDING', 'FALSE_DIGEST'].includes(fault) ? 0 : 1);
    expect(sample.context.material.every((byte) => byte === 0)).toBe(true);
  }
});

it('rejects asynchronous or expired crypto and erases material on callback failure', async () => {
  for (const kind of ['ASYNC', 'THROW', 'EXPIRED', 'PROMISE'] as const) {
    const sample = cryptoCase();
    const persist = vi.fn();
    if (kind === 'EXPIRED') sample.context.leaseUntilMs = Date.now() - 1;
    const use =
      kind === 'ASYNC'
        ? async () => {
            throw new Error('PRIVATE_CANARY');
          }
        : () => {
            if (kind === 'PROMISE') return Promise.reject(new Error('PRIVATE_CANARY'));
            throw new Error('PRIVATE_CANARY');
          };
    await expect(completeEvidenceKmsMaterial(sample.context, use, persist)).rejects.toThrow(
      'OPS_SECRET_UNRESOLVED',
    );
    expect(persist).not.toHaveBeenCalled();
    expect(sample.context.material.every((byte) => byte === 0)).toBe(true);
    expect(sample.context.wire.every((byte) => byte === 0)).toBe(true);
  }
});
