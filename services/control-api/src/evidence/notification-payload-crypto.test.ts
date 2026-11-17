import { randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  inspectNotificationPayload,
  notificationPayloadEncryptionProfileDigest,
  openNotificationPayload,
  sealNotificationPayload,
  type NotificationPayloadBinding,
} from './notification-payload-crypto.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = (n: number) => sha256(Buffer.from(String(n)));
function fixture() {
  const plaintext = Buffer.from('authorized minimized synthetic notification');
  const material = { keyId: hash(80), bytes: randomBytes(32) };
  const binding: NotificationPayloadBinding = {
    environmentId: 'local',
    participantId: id(1),
    privacyDomainId: id(2),
    payloadObjectId: id(3),
    objectVersion: '1',
    notificationOccurrenceRef: `urn:openpc:resource:${id(4)}`,
    routingProfileDigest: hash(5),
    templateDigest: hash(6),
    recipientSetDigest: hash(7),
    redactionProfileDigest: hash(8),
    preferenceGeneration: '1',
    payloadDigest: sha256(plaintext),
    keyId: material.keyId,
  };
  const sealed = sealNotificationPayload(binding, plaintext, material);
  return { plaintext, material, binding, sealed };
}
it('binds an original encrypted notification to its complete durable identity', () => {
  const f = fixture();
  const opened = openNotificationPayload(
    f.sealed.bytes,
    f.sealed.encryptedObjectDigest,
    f.binding,
    f.material,
  );
  try {
    expect(opened).toEqual(f.plaintext);
    expect(f.sealed.bytes.includes(f.plaintext)).toBe(false);
    expect(f.sealed.bytes.includes(f.material.bytes)).toBe(false);
    const inspected = inspectNotificationPayload(f.sealed.bytes);
    expect(inspected.header.binding).toEqual(f.binding);
    expect(inspected.header.encryptionProfileDigest).toBe(
      notificationPayloadEncryptionProfileDigest,
    );
    expect(inspected.encryptionContextDigest).toBe(f.sealed.encryptionContextDigest);
    expect(inspected.encryptedObjectDigest).toBe(f.sealed.encryptedObjectDigest);
  } finally {
    opened.fill(0);
    f.material.bytes.fill(0);
  }
});
it.each([
  ['environmentId', 'foreign'],
  ['participantId', id(11)],
  ['privacyDomainId', id(12)],
  ['payloadObjectId', id(13)],
  ['notificationOccurrenceRef', `urn:openpc:resource:${id(14)}`],
  ['routingProfileDigest', hash(15)],
  ['templateDigest', hash(16)],
  ['recipientSetDigest', hash(17)],
  ['redactionProfileDigest', hash(18)],
  ['preferenceGeneration', '2'],
  ['payloadDigest', hash(19)],
  ['keyId', hash(81)],
] as const)('rejects substitution of %s even with the original key material', (field, value) => {
  const f = fixture();
  const changed = { ...f.binding, [field]: value };
  expect(() =>
    openNotificationPayload(f.sealed.bytes, f.sealed.encryptedObjectDigest, changed, {
      ...f.material,
      keyId: changed.keyId,
    }),
  ).toThrow('Evidence custody integrity');
  // A caller recomputing the outer digest still cannot change authenticated AAD.
  const envelope = JSON.parse(f.sealed.bytes.toString());
  envelope.header.binding = changed;
  const altered = Buffer.from(canonicalJson(envelope));
  expect(() =>
    openNotificationPayload(altered, sha256(altered), changed, {
      ...f.material,
      keyId: changed.keyId,
    }),
  ).toThrow('Evidence custody integrity');
});
it.each(['nonce', 'ciphertext', 'tag'])(
  'rejects altered %s with a recomputed object digest',
  (field) => {
    const f = fixture(),
      value = JSON.parse(f.sealed.bytes.toString());
    const encoding = field === 'ciphertext' ? 'base64' : 'hex';
    const bytes = Buffer.from(value[field], encoding);
    bytes[0] = bytes[0]! ^ 1;
    value[field] = bytes.toString(encoding);
    const changed = Buffer.from(canonicalJson(value));
    expect(() => openNotificationPayload(changed, sha256(changed), f.binding, f.material)).toThrow(
      'Evidence custody integrity',
    );
  },
);
it('rejects unavailable, relabeled and wrong keys without returning plaintext or input diagnostics', () => {
  const f = fixture();
  for (const material of [
    { ...f.material, bytes: Buffer.alloc(0) },
    { ...f.material, keyId: hash(82) },
  ])
    expect(() =>
      openNotificationPayload(f.sealed.bytes, f.sealed.encryptedObjectDigest, f.binding, material),
    ).toThrow('Evidence custody unavailable');
  expect(() =>
    openNotificationPayload(f.sealed.bytes, f.sealed.encryptedObjectDigest, f.binding, {
      ...f.material,
      bytes: randomBytes(32),
    }),
  ).toThrow(/^Evidence custody integrity$/u);
  expect(() => openNotificationPayload(f.sealed.bytes, hash(90), f.binding, f.material)).toThrow(
    /^Evidence custody integrity$/u,
  );
});
it('rejects another encryption domain, unknown fields, duplicate members and noncanonical encodings', () => {
  const f = fixture(),
    original = JSON.parse(f.sealed.bytes.toString());
  const invalid = [
    { ...original, header: { ...original.header, version: 'OPENPC_EVIDENCE_SEGMENT_V1' } },
    { ...original, header: { ...original.header, encryptionProfileDigest: hash(90) } },
    { ...original, authority: true },
    { ...original, ciphertext: original.ciphertext + '\n' },
    { ...original, nonce: `AA${original.nonce.slice(2)}` },
    { ...original, tag: '' },
  ].map((value) => Buffer.from(canonicalJson(value)));
  invalid.push(Buffer.from(JSON.stringify(original, null, 2)));
  invalid.push(
    Buffer.from(f.sealed.bytes.toString().replace('{', '{"nonce":"000000000000000000000000",')),
  );
  for (const bytes of invalid)
    expect(() => inspectNotificationPayload(bytes)).toThrow('Evidence custody integrity');
});
it('enforces payload and identity bounds, original digest, and independently generated nonces', () => {
  const f = fixture();
  for (const payload of [Buffer.alloc(0), Buffer.alloc(65537)])
    expect(() =>
      sealNotificationPayload(
        { ...f.binding, payloadDigest: sha256(payload) },
        payload,
        f.material,
      ),
    ).toThrow('Evidence custody capacity');
  expect(() =>
    sealNotificationPayload({ ...f.binding, payloadDigest: hash(1) }, f.plaintext, f.material),
  ).toThrow('Evidence custody integrity');
  for (const changed of [
    { ...f.binding, objectVersion: '2' },
    { ...f.binding, preferenceGeneration: '0' },
    { ...f.binding, preferenceGeneration: '18446744073709551616' },
    { ...f.binding, extra: 'secret' },
    { ...f.binding, keyId: 'latest' },
    { ...f.binding, keyId: 'secret://vault/payload#current' },
  ])
    expect(() =>
      sealNotificationPayload(changed as NotificationPayloadBinding, f.plaintext, f.material),
    ).toThrow(/^Evidence custody invalid$/u);
  const second = sealNotificationPayload(f.binding, f.plaintext, f.material);
  expect(inspectNotificationPayload(second.bytes).nonce).not.toEqual(
    inspectNotificationPayload(f.sealed.bytes).nonce,
  );
  const maximum = Buffer.alloc(65536, 42),
    binding = { ...f.binding, payloadDigest: sha256(maximum) };
  const sealed = sealNotificationPayload(binding, maximum, f.material);
  const opened = openNotificationPayload(
    sealed.bytes,
    sealed.encryptedObjectDigest,
    binding,
    f.material,
  );
  expect(opened).toEqual(maximum);
  opened.fill(0);
});
