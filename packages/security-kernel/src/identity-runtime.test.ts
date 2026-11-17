import { createHash, generateKeyPairSync, sign } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  decodeIdentityRuntimeActorProjection,
  encodeIdentityRuntimeActorProjection,
  signIdentityRuntimeActorProjectionCoseSign1Ed25519,
  verifyIdentityRuntimeActorProjectionCoseSign1Ed25519,
  decodeIdentityAuthContextAssertionPayload,
  encodeIdentityAuthContextAssertionPayload,
  identityAuthContextAssertionCoseContext,
  signIdentityAuthContextAssertionCoseSign1Ed25519,
  verifyIdentityAuthContextAssertionCoseSign1Ed25519,
  type IdentityAuthContextAssertionPayload,
} from './identity-runtime.js';

const activeKeyPair = generateKeyPairSync('ed25519');
const activePrivateKey = activeKeyPair.privateKey.export({ format: 'der', type: 'pkcs8' });
const activePublicKey = activeKeyPair.publicKey.export({ format: 'der', type: 'spki' });
const foreignPublicKey = generateKeyPairSync('ed25519').publicKey.export({
  format: 'der',
  type: 'spki',
});

const digest = (value: string) => createHash('sha256').update(value).digest();
const assertion: IdentityAuthContextAssertionPayload = {
  assertionId: 'auth-context-assertion-1',
  actorKeyDigest: digest('actor-key'),
  actorKind: 0,
  participantContextDigest: digest('participant-context'),
  audienceDigest: digest('identity-api'),
  senderBindingKind: 1,
  assuranceProfileDigest: digest('oidc-pkce-s256'),
  authorityVectorDigest: digest('authority-vector'),
  issuedAtNs: 1_787_510_400_000_000_000n,
  expiresAtNs: 1_787_510_430_000_000_000n,
  authenticationEvidenceDigest: digest('oidc-evidence'),
  senderCredentialBindingDigest: digest('opaque-session-and-csrf'),
};

it('rejects alternate DER identities for the same Ed25519 key', () => {
  const payload = encodeIdentityAuthContextAssertionPayload(assertion);
  const extended = Buffer.concat([activePublicKey, Buffer.from([0])]);
  expect(() =>
    signIdentityAuthContextAssertionCoseSign1Ed25519(activePrivateKey, extended, payload),
  ).toThrow('canonical Ed25519 SPKI');
  const cose = signIdentityAuthContextAssertionCoseSign1Ed25519(
    activePrivateKey,
    activePublicKey,
    payload,
  );
  expect(verifyIdentityAuthContextAssertionCoseSign1Ed25519(extended, payload, cose)).toBe(false);
});

describe('identity runtime actor projection 3003@2', () => {
  const projection = {
    actorKeyDigest: Buffer.alloc(32, 1),
    actorKind: 1 as const,
    participantContextDigest: Buffer.alloc(32, 2),
    roleAssignmentSetDigest: Buffer.alloc(32, 3),
    participantEnvelopeDigest: Buffer.alloc(32, 4),
    authorityVectorDigest: Buffer.alloc(32, 5),
  };
  it('encodes the exact six integer fields and excludes request authentication', () => {
    const payload = encodeIdentityRuntimeActorProjection(projection);
    expect(payload.toString('hex')).toBe(
      `a6005820${'01'.repeat(32)}0101025820${'02'.repeat(32)}035820${'03'.repeat(32)}045820${'04'.repeat(32)}055820${'05'.repeat(32)}`,
    );
    expect(decodeIdentityRuntimeActorProjection(payload)).toEqual(projection);
    const cose = signIdentityRuntimeActorProjectionCoseSign1Ed25519(
      activePrivateKey,
      activePublicKey,
      payload,
    );
    expect(
      verifyIdentityRuntimeActorProjectionCoseSign1Ed25519(activePublicKey, payload, cose),
    ).toBe(true);
    expect(
      verifyIdentityRuntimeActorProjectionCoseSign1Ed25519(foreignPublicKey, payload, cose),
    ).toBe(false);
    expect(verifyIdentityAuthContextAssertionCoseSign1Ed25519(activePublicKey, payload, cose)).toBe(
      false,
    );
    const assertionPayload = encodeIdentityAuthContextAssertionPayload(assertion);
    const assertionCose = signIdentityAuthContextAssertionCoseSign1Ed25519(
      activePrivateKey,
      activePublicKey,
      assertionPayload,
    );
    expect(
      verifyIdentityRuntimeActorProjectionCoseSign1Ed25519(
        activePublicKey,
        assertionPayload,
        assertionCose,
      ),
    ).toBe(false);
    const tampered = Buffer.from(payload);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
    expect(
      verifyIdentityRuntimeActorProjectionCoseSign1Ed25519(activePublicKey, tampered, cose),
    ).toBe(false);
    expect(
      verifyIdentityRuntimeActorProjectionCoseSign1Ed25519(
        activePublicKey,
        payload,
        resignWith(cose, payload, (header) =>
          Buffer.from(header.toString('hex').replace('190bbb', '190bba'), 'hex'),
        ),
      ),
    ).toBe(false);
  });
  it('rejects duplicate, missing, unknown, noncanonical, and trailing fields', () => {
    const payload = encodeIdentityRuntimeActorProjection(projection);
    for (const invalid of [
      Buffer.concat([payload, Buffer.from([0])]),
      Buffer.from(payload.subarray(1)),
      Buffer.concat([Buffer.from([0xa6, 0x18, 0]), payload.subarray(2)]),
      Buffer.concat([Buffer.from([0xa6, 1]), payload.subarray(2)]),
    ]) {
      expect(() => decodeIdentityRuntimeActorProjection(invalid)).toThrow();
    }
  });
});

function cborBytes(value: Buffer): Buffer {
  if (value.length < 24) return Buffer.concat([Buffer.from([0x40 | value.length]), value]);
  if (value.length <= 0xff) return Buffer.concat([Buffer.from([0x58, value.length]), value]);
  const length = Buffer.alloc(3);
  length[0] = 0x59;
  length.writeUInt16BE(value.length, 1);
  return Buffer.concat([length, value]);
}

function cborText(value: string): Buffer {
  const encoded = Buffer.from(value);
  if (encoded.length < 24) return Buffer.concat([Buffer.from([0x60 | encoded.length]), encoded]);
  return Buffer.concat([Buffer.from([0x78, encoded.length]), encoded]);
}

function resignWith(
  coseSign1: Buffer,
  payload: Buffer,
  mutateHeader: (header: Buffer) => Buffer,
  externalAad = Buffer.from(identityAuthContextAssertionCoseContext.externalAadHex, 'hex'),
): Buffer {
  expect(coseSign1.subarray(0, 3)).toEqual(Buffer.from([0xd2, 0x84, 0x58]));
  const headerLength = coseSign1[3]!;
  const headerStart = 4;
  const headerEnd = headerStart + headerLength;
  const header = mutateHeader(Buffer.from(coseSign1.subarray(headerStart, headerEnd)));
  expect(coseSign1[headerEnd]).toBe(0xa0);
  const payloadStart = headerEnd + 1;
  const width = coseSign1[payloadStart] === 0x59 ? 3 : 2;
  const length =
    width === 3 ? coseSign1.readUInt16BE(payloadStart + 1) : coseSign1[payloadStart + 1]!;
  // Callers supply the decoded semantic value; the signature covers its envelope.
  expect(payload.length).toBeLessThan(length);
  payload = coseSign1.subarray(payloadStart + width, payloadStart + width + length);
  const structure = Buffer.concat([
    Buffer.from([0x84]),
    cborText('Signature1'),
    cborBytes(header),
    cborBytes(externalAad),
    cborBytes(payload),
  ]);
  const signature = sign(null, structure, activeKeyPair.privateKey);
  return Buffer.concat([
    Buffer.from([0xd2, 0x84]),
    cborBytes(header),
    Buffer.from([0xa0]),
    cborBytes(payload),
    cborBytes(signature),
  ]);
}

describe('identity-runtime v2 auth-context assertion', () => {
  it('preserves a leading U+FEFF in the exact assertion bytes and signature', () => {
    const plain = encodeIdentityAuthContextAssertionPayload({ ...assertion, assertionId: 'a' });
    expect(plain.subarray(0, 4)).toEqual(Buffer.from('ac006161', 'hex'));
    // Map key 0 contains the four UTF-8 bytes EF BB BF 61, not a transport BOM.
    const payload = Buffer.concat([Buffer.from('ac0064efbbbf61', 'hex'), plain.subarray(4)]);
    const value = { ...assertion, assertionId: '\uFEFFa' };
    expect(encodeIdentityAuthContextAssertionPayload(value)).toEqual(payload);
    expect(decodeIdentityAuthContextAssertionPayload(payload)).toEqual(value);
    expect(
      encodeIdentityAuthContextAssertionPayload(decodeIdentityAuthContextAssertionPayload(payload)),
    ).toEqual(payload);
    const cose = signIdentityAuthContextAssertionCoseSign1Ed25519(
      activePrivateKey,
      activePublicKey,
      payload,
    );
    expect(verifyIdentityAuthContextAssertionCoseSign1Ed25519(activePublicKey, payload, cose)).toBe(
      true,
    );
    expect(verifyIdentityAuthContextAssertionCoseSign1Ed25519(activePublicKey, plain, cose)).toBe(
      false,
    );
  });

  it('preserves literal U+FEFF while retaining UTF-8, NFC, and byte-length validation', () => {
    for (const assertionId of ['\uFEFF', 'a\uFEFF', '\uFEFF\uFEFFa', '\uFEFF' + 'a'.repeat(157)]) {
      const value = { ...assertion, assertionId };
      expect(
        decodeIdentityAuthContextAssertionPayload(encodeIdentityAuthContextAssertionPayload(value)),
      ).toEqual(value);
    }
    for (const assertionId of ['\uFEFFe\u0301', '\uFEFF' + 'a'.repeat(158)]) {
      expect(() =>
        encodeIdentityAuthContextAssertionPayload({ ...assertion, assertionId }),
      ).toThrow('assertionId');
    }
    const plain = encodeIdentityAuthContextAssertionPayload({ ...assertion, assertionId: 'a' });
    const invalid = Buffer.concat([Buffer.from('ac0064efbbbfff', 'hex'), plain.subarray(4)]);
    expect(() => decodeIdentityAuthContextAssertionPayload(invalid)).toThrow();
  });

  it.each([
    ['content type', identityAuthContextAssertionCoseContext.contentType],
    ['purpose', identityAuthContextAssertionCoseContext.purpose],
  ])('rejects an independently signed leading U+FEFF in protected %s', (_name, value) => {
    const payload = encodeIdentityAuthContextAssertionPayload(assertion);
    const valid = signIdentityAuthContextAssertionCoseSign1Ed25519(
      activePrivateKey,
      activePublicKey,
      payload,
    );
    const control = resignWith(valid, payload, (header) => header);
    expect(
      verifyIdentityAuthContextAssertionCoseSign1Ed25519(activePublicKey, payload, control),
    ).toBe(true);
    const substituted = resignWith(valid, payload, (header) => {
      const encoded = cborText(value);
      const offset = header.indexOf(encoded);
      expect(offset).toBeGreaterThanOrEqual(0);
      expect(header.lastIndexOf(encoded)).toBe(offset);
      return Buffer.concat([
        header.subarray(0, offset),
        cborText('\uFEFF' + value),
        header.subarray(offset + encoded.length),
      ]);
    });
    expect(
      verifyIdentityAuthContextAssertionCoseSign1Ed25519(activePublicKey, payload, substituted),
    ).toBe(false);
  });

  it('round-trips the exact schema 3002 field model including uint64 nanoseconds', () => {
    const encoded = encodeIdentityAuthContextAssertionPayload(assertion);
    const decoded = decodeIdentityAuthContextAssertionPayload(encoded);
    expect(decoded).toEqual(assertion);
    expect(encoded[0]).toBe(0xac);
    expect(identityAuthContextAssertionCoseContext).toMatchObject({
      contentType: 'application/pc+cbor',
      externalAadHex:
        '7063706c616e653a636f73652d7369676e313a76320070632e636f73652e6964656e746974792d72756e74696d652e7632',
      purpose: 'pc.cose.identity-runtime.v2',
      purposeId: 13,
      schemaId: 3002,
      schemaVersion: 2,
      signatureProfileVersion: 2,
    });
  });

  it('signs with the accepted protected context, nonempty AAD, and SPKI key identity', () => {
    const payload = encodeIdentityAuthContextAssertionPayload(assertion);
    const coseSign1 = signIdentityAuthContextAssertionCoseSign1Ed25519(
      activePrivateKey,
      activePublicKey,
      payload,
    );
    expect(
      verifyIdentityAuthContextAssertionCoseSign1Ed25519(activePublicKey, payload, coseSign1),
    ).toBe(true);
    expect(
      verifyIdentityAuthContextAssertionCoseSign1Ed25519(foreignPublicKey, payload, coseSign1),
    ).toBe(false);
    const altered = Buffer.from(coseSign1);
    altered[altered.length - 1] = altered[altered.length - 1]! ^ 1;
    expect(
      verifyIdentityAuthContextAssertionCoseSign1Ed25519(activePublicKey, payload, altered),
    ).toBe(false);
  });

  it('rejects independently signed purpose and external-AAD substitutions', () => {
    const payload = encodeIdentityAuthContextAssertionPayload(assertion);
    const valid = signIdentityAuthContextAssertionCoseSign1Ed25519(
      activePrivateKey,
      activePublicKey,
      payload,
    );
    const wrongPurpose = resignWith(valid, payload, (header) => {
      const marker = Buffer.from('pc.cose.identity-runtime.v2');
      const offset = header.indexOf(marker);
      expect(offset).toBeGreaterThanOrEqual(0);
      header[offset] = 'q'.charCodeAt(0);
      return header;
    });
    const emptyAad = resignWith(valid, payload, (header) => header, Buffer.alloc(0));
    expect(
      verifyIdentityAuthContextAssertionCoseSign1Ed25519(activePublicKey, payload, wrongPurpose),
    ).toBe(false);
    expect(
      verifyIdentityAuthContextAssertionCoseSign1Ed25519(activePublicKey, payload, emptyAad),
    ).toBe(false);
  });

  it('rejects invalid schema fields, noncanonical maps, and empty validity', () => {
    expect(() =>
      encodeIdentityAuthContextAssertionPayload({ ...assertion, actorKeyDigest: Buffer.alloc(31) }),
    ).toThrow('bytes32');
    expect(() =>
      encodeIdentityAuthContextAssertionPayload({
        ...assertion,
        assertionId: 'e\u0301',
      }),
    ).toThrow('assertionId');
    expect(() =>
      encodeIdentityAuthContextAssertionPayload({
        ...assertion,
        expiresAtNs: assertion.issuedAtNs,
      }),
    ).toThrow('validity');

    const payload = encodeIdentityAuthContextAssertionPayload({
      ...assertion,
      senderCredentialBindingDigest: undefined,
    });
    const noncanonical = Buffer.from(payload);
    noncanonical[1] = 1;
    expect(() => decodeIdentityAuthContextAssertionPayload(noncanonical)).toThrow();
    expect(
      verifyIdentityAuthContextAssertionCoseSign1Ed25519(
        activePublicKey,
        noncanonical,
        signIdentityAuthContextAssertionCoseSign1Ed25519(
          activePrivateKey,
          activePublicKey,
          payload,
        ),
      ),
    ).toBe(false);
  });

  it('rejects keys outside the accepted Ed25519 profile', () => {
    const payload = encodeIdentityAuthContextAssertionPayload(assertion);
    const p384 = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const privateKey = p384.privateKey.export({ format: 'der', type: 'pkcs8' });
    const publicKey = p384.publicKey.export({ format: 'der', type: 'spki' });
    expect(() =>
      signIdentityAuthContextAssertionCoseSign1Ed25519(privateKey, publicKey, payload),
    ).toThrow('Ed25519');
    expect(
      verifyIdentityAuthContextAssertionCoseSign1Ed25519(publicKey, payload, Buffer.alloc(0)),
    ).toBe(false);
  });
});
