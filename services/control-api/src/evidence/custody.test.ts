import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { LocalEvidenceVault, vaultObject } from './local-vault.js';
import {
  openSegment,
  sealSegment,
  sequence,
  type SegmentHeader,
  type SourceReceipt,
} from './segment.js';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import { encodeEvidenceHoldSelector } from './hold-contracts.js';

const temporaryRoot = process.env.OPENPC_PNC_TMP_ROOT!;
const directories: string[] = [];
afterEach(async () => {
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});
const metadata = (): SegmentHeader => ({
  version: 'OPENPC_EVIDENCE_SEGMENT_V1',
  participantId: randomUUID(),
  privacyDomainId: randomUUID(),
  streamId: 'control-test',
  segmentId: randomUUID(),
  firstSequence: '1',
  throughSequence: '3',
  previousSegmentDigest: null,
  keyId: 'test-key-1',
  retentionUntil: '2027-01-01T00:00:00.000000Z',
});
function records(): SourceReceipt[] {
  return (['AUTHENTICATION', 'BUSINESS_TRANSITION', 'EFFECT'] as const).map((evidenceClass) => {
    const bytes = Buffer.from(`retained ${evidenceClass} receipt`);
    return {
      recordId: randomUUID(),
      evidenceClass,
      sourceFormat: 'TEST_RECEIPT',
      occurredAt: '2026-09-21T00:00:00.000000Z',
      receiptDigest: sha256(bytes),
      receiptBase64: bytes.toString('base64'),
    };
  });
}
async function root() {
  const directory = await mkdtemp(join(temporaryRoot, 'evidence-custody-'));
  directories.push(directory);
  return directory;
}

describe('encrypted evidence segment and sink custody', () => {
  it('rejects padded sequence text without normalizing its durable identity', () => {
    for (const value of ['0', '9007199254740993', '18446744073709551615']) {
      expect(sequence.parse(value)).toBe(value);
      for (const padding of [' ', '\t', '\n', '\r', '\r\n', '\u2028', '\u2029']) {
        expect(sequence.safeParse(value + padding).success).toBe(false);
        expect(sequence.safeParse(padding + value).success).toBe(false);
      }
    }
  });
  it('preserves distinct receipt bytes and classes in a scope-bound encrypted contiguous chain', () => {
    const key = randomBytes(32);
    const original = records();
    const sealed = sealSegment(metadata(), original, key);
    expect(sealed.bytes.toString()).not.toContain('retained AUTHENTICATION');
    const result = openSegment(sealed.bytes, sealed.objectDigest, sealed.header, key);
    expect(result.records.map((record) => record.evidenceClass)).toEqual(
      original.map((record) => record.evidenceClass),
    );
    expect(result.records.map((record) => record.receiptBase64)).toEqual(
      original.map((record) => record.receiptBase64),
    );
    expect(result.records.map((record) => record.sequence)).toEqual(['1', '2', '3']);
    const successor = sealSegment(
      {
        ...sealed.header,
        segmentId: randomUUID(),
        firstSequence: '4',
        throughSequence: '6',
        previousSegmentDigest: sealed.objectDigest,
      },
      records(),
      key,
    );
    expect(
      openSegment(successor.bytes, successor.objectDigest, successor.header, key).records[0]
        ?.previousRecordDigest,
    ).toBe(sealed.objectDigest);
    expect(() =>
      openSegment(
        sealed.bytes,
        sealed.objectDigest,
        { ...sealed.header, participantId: randomUUID() },
        key,
      ),
    ).toThrow('integrity');
    expect(() =>
      openSegment(
        sealed.bytes,
        sealed.objectDigest,
        { ...sealed.header, privacyDomainId: randomUUID() },
        key,
      ),
    ).toThrow('integrity');
    expect(() =>
      openSegment(sealed.bytes, sealed.objectDigest, sealed.header, randomBytes(32)),
    ).toThrow('integrity');
  });

  it('rejects altered ciphertext/retention, invalid source digests, duplicate IDs and sequence gaps', () => {
    const key = randomBytes(32);
    const header = metadata();
    const original = records();
    expect(() => sealSegment(header, [...original.slice(0, 2), original[0]!], key)).toThrow(
      'conflict',
    );
    expect(() =>
      sealSegment(
        header,
        [{ ...original[0]!, receiptDigest: sha256('wrong') }, ...original.slice(1)],
        key,
      ),
    ).toThrow('integrity');
    expect(() => sealSegment({ ...header, firstSequence: '2' }, original, key)).toThrow('invalid');
    const sealed = sealSegment(header, original, key);
    for (const mutation of [
      (value: { header: SegmentHeader; ciphertext: string }) => {
        value.header.retentionUntil = '2020-01-01T00:00:00.000000Z';
      },
      (value: { header: SegmentHeader; ciphertext: string }) => {
        value.ciphertext = Buffer.from('altered ciphertext').toString('base64');
      },
    ]) {
      const changed = JSON.parse(sealed.bytes.toString());
      mutation(changed);
      const bytes = Buffer.from(canonicalJson(changed));
      expect(() => openSegment(bytes, sha256(bytes), changed.header, key)).toThrow('integrity');
    }
  });

  it('recovers exact durable acceptance after lost acknowledgement and concurrent retries', async () => {
    const directory = await root();
    const key = randomBytes(32);
    const sealed = sealSegment(metadata(), records(), key);
    const identity = vaultObject('local-test', sealed.header, sealed.objectDigest);
    const vault = await LocalEvidenceVault.open(directory, 'local-test');
    // Discard the first acknowledgement, as on a transport loss.
    await vault.put(identity, sealed.bytes);
    const reopened = await LocalEvidenceVault.open(directory, 'local-test');
    const receipts = await Promise.all(
      Array.from({ length: 4 }, () => reopened.put(identity, sealed.bytes)),
    );
    expect(new Set(receipts.map((receipt) => receipt.receiptDigest)).size).toBe(1);
    expect(receipts[0]?.assurance).toBe('LOCAL_FSYNC_READBACK');
    expect(await reopened.read(identity)).toEqual(sealed.bytes);
    expect((await readdir(directory)).filter((name) => name.endsWith('.segment'))).toHaveLength(1);
    expect((await readdir(directory)).filter((name) => name.startsWith('.pending'))).toHaveLength(
      0,
    );
    const conflict = sealSegment(sealed.header, records(), key);
    await expect(
      reopened.put(
        vaultObject('local-test', conflict.header, conflict.objectDigest),
        conflict.bytes,
      ),
    ).rejects.toThrow('integrity');
    expect(await reopened.read(identity)).toEqual(sealed.bytes);
  });

  it('never acknowledges a missing, corrupt, redirected, wrong-sink or wrong-scope object', async () => {
    const directory = await root();
    const sealed = sealSegment(metadata(), records(), randomBytes(32));
    const identity = vaultObject('local-test', sealed.header, sealed.objectDigest);
    const vault = await LocalEvidenceVault.open(directory, 'local-test');
    await expect(vault.verify(identity)).rejects.toThrow('unavailable');
    await expect(
      vault.put({ ...identity, privacyDomainId: randomUUID() }, sealed.bytes),
    ).rejects.toThrow('integrity');
    await expect(vault.put({ ...identity, sinkId: 'another-sink' }, sealed.bytes)).rejects.toThrow(
      'invalid',
    );
    await vault.put(identity, sealed.bytes);
    const path = join(directory, (await readdir(directory))[0]!);
    const saved = await readFile(path);
    await writeFile(path, '{}');
    await expect(vault.verify(identity)).rejects.toThrow('integrity');
    await rm(path);
    const redirected = join(directory, 'redirected');
    await writeFile(redirected, saved, { mode: 0o600 });
    await symlink(redirected, path);
    await expect(vault.verify(identity)).rejects.toThrow('integrity');
  });

  it('retains hold history, recovers lost acknowledgements and rejects changed or corrupt custody', async () => {
    const directory = await root();
    const sealed = sealSegment(metadata(), records(), randomBytes(32));
    const object = vaultObject('local-hold-test', sealed.header, sealed.objectDigest);
    const hold = {
      holdId: uuidv7(),
      selectorDigest: encodeEvidenceHoldSelector(object, { type: 'PRIVACY_DOMAIN' }).digest,
      creationOperationId: uuidv7(),
      releaseOperationId: null,
      state: 'ACTIVE' as const,
      revision: '1' as const,
    };
    const vault = await LocalEvidenceVault.open(directory, object.sinkId);
    await expect(vault.acknowledgeHold(object, hold)).rejects.toThrow('unavailable');
    await vault.put(object, sealed.bytes);
    const first = await vault.acknowledgeHold(object, hold);
    const reopened = await LocalEvidenceVault.open(directory, object.sinkId);
    const repeated = await Promise.all([
      reopened.acknowledgeHold(object, hold),
      reopened.acknowledgeHold(object, hold),
    ]);
    expect(repeated).toEqual([first, first]);
    await expect(
      reopened.acknowledgeHold(object, { ...hold, selectorDigest: sha256('different') }),
    ).rejects.toThrow('integrity');
    const release = {
      ...hold,
      revision: '2' as const,
      state: 'RELEASED' as const,
      releaseOperationId: uuidv7(),
    };
    const released = await reopened.acknowledgeHold(object, release);
    expect(released.state).toBe('RELEASED');
    expect(released.receiptDigest).not.toBe(first.receiptDigest);
    expect(await reopened.acknowledgeHold(object, release)).toEqual(released);
    const names = await readdir(directory);
    const active = names.find((name) => name.endsWith('.hold-1'))!;
    expect(JSON.parse(await readFile(join(directory, active), 'utf8')).state).toBe('ACTIVE');
    expect(names.filter((name) => name.endsWith('.hold-2'))).toHaveLength(1);
    expect(names.some((name) => name.startsWith('.pending'))).toBe(false);
    expect(await reopened.read(object)).toEqual(sealed.bytes);
    await writeFile(join(directory, active), '{}');
    await expect(reopened.acknowledgeHold(object, release)).rejects.toThrow('integrity');
  });
});
