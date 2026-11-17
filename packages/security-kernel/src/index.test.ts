import { createPrivateKey, sign } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  encodeIdentityCredentialPayload,
  identityCredentialCoseContext,
  signIdentityCredentialCoseSign1Es256,
  verifyBoundCoseSign1Es256,
  verifyCoseSign1Es256,
  verifyEs256P1363,
} from './index.js';

const spki = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
  'hex',
);
const payload = Buffer.from(
  'a901781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631021957e50365312e302e300458202bcee470e17149e2d5cc67bbc2e5f14b368723181b47d7ebd3f4535e294b111105783b75726e3a6f70656e70633a7061727469636970616e743a30313866316532642d336334622d376136392d386162632d30313233343536373839616206783975726e3a6f70656e70633a7072696e636970616c3a30313866316532642d336334622d376136392d386162632d31313233343536373839616207613708781b323032362d30382d32345430303a30303a30302e3030303030305a09781b323032362d30382d32345430303a30353a30302e3030303030305a',
  'hex',
);
const sigStructure = Buffer.from(
  '846a5369676e6174757265315867a5012603776170706c69636174696f6e2f6f70656e70632b63626f720458205cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd31903e91957e51903ea781d6f70656e70633a6964656e746974792d63726564656e7469616c3a763140590108a901781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631021957e50365312e302e300458202bcee470e17149e2d5cc67bbc2e5f14b368723181b47d7ebd3f4535e294b111105783b75726e3a6f70656e70633a7061727469636970616e743a30313866316532642d336334622d376136392d386162632d30313233343536373839616206783975726e3a6f70656e70633a7072696e636970616c3a30313866316532642d336334622d376136392d386162632d31313233343536373839616207613708781b323032362d30382d32345430303a30303a30302e3030303030305a09781b323032362d30382d32345430303a30353a30302e3030303030305a',
  'hex',
);
const signature = Buffer.from(
  'c0283047c7739a45f0600ea88a379d7d0f20b76da383eb11173620b6c9befe4e3969529b1dba1b493fc93bf204a437a92f71e8b17447d7631a4663290eef19bf',
  'hex',
);
const cose = Buffer.from(
  'd2845867a5012603776170706c69636174696f6e2f6f70656e70632b63626f720458205cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd31903e91957e51903ea781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631a0590108a901781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631021957e50365312e302e300458202bcee470e17149e2d5cc67bbc2e5f14b368723181b47d7ebd3f4535e294b111105783b75726e3a6f70656e70633a7061727469636970616e743a30313866316532642d336334622d376136392d386162632d30313233343536373839616206783975726e3a6f70656e70633a7072696e636970616c3a30313866316532642d336334622d376136392d386162632d31313233343536373839616207613708781b323032362d30382d32345430303a30303a30302e3030303030305a09781b323032362d30382d32345430303a30353a30302e3030303030305a5840c0283047c7739a45f0600ea88a379d7d0f20b76da383eb11173620b6c9befe4e3969529b1dba1b493fc93bf204a437a92f71e8b17447d7631a4663290eef19bf',
  'hex',
);

function cborByteString(value: Buffer): Buffer {
  if (value.length < 24) return Buffer.concat([Buffer.from([0x40 | value.length]), value]);
  return Buffer.concat([Buffer.from([0x58, value.length]), value]);
}

function cborText(value: string): Buffer {
  const encoded = Buffer.from(value);
  if (encoded.length < 24) return Buffer.concat([Buffer.from([0x60 | encoded.length]), encoded]);
  return Buffer.concat([Buffer.from([0x78, encoded.length]), encoded]);
}

function cborUnsigned(value: number): Buffer {
  if (value < 24) return Buffer.from([value]);
  if (value <= 0xff) return Buffer.from([0x18, value]);
  const encoded = Buffer.alloc(3);
  encoded[0] = 0x19;
  encoded.writeUInt16BE(value, 1);
  return encoded;
}

function signedEnvelope(schemaId: number, purpose: string, payloadBytes = payload): Buffer {
  const keyId = Buffer.from(
    '5cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd3',
    'hex',
  );
  const protectedHeader = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x26, 0x03]),
    cborText('application/openpc+cbor'),
    Buffer.from([0x04]),
    cborByteString(keyId),
    Buffer.from([0x19, 0x03, 0xe9]),
    cborUnsigned(schemaId),
    Buffer.from([0x19, 0x03, 0xea]),
    cborText(purpose),
  ]);
  const structure = Buffer.concat([
    Buffer.from([0x84, 0x6a]),
    Buffer.from('Signature1'),
    cborByteString(protectedHeader),
    Buffer.from([0x40]),
    cborByteString(payloadBytes),
  ]);
  const privateKey = createPrivateKey({
    format: 'jwk',
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: Buffer.from(
        '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
        'hex',
      ).toString('base64url'),
      y: Buffer.from(
        '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
        'hex',
      ).toString('base64url'),
      d: Buffer.from(
        '0000000000000000000000000000000000000000000000000000000000000001',
        'hex',
      ).toString('base64url'),
    },
  });
  const signed = sign('sha256', structure, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return Buffer.concat([
    Buffer.from([0xd2, 0x84]),
    cborByteString(protectedHeader),
    Buffer.from([0xa0]),
    cborByteString(payloadBytes),
    cborByteString(signed),
  ]);
}

describe('ES256/COSE verification', () => {
  it('accepts the authoritative IEEE-P1363 vector and rejects mutation', () => {
    expect(
      encodeIdentityCredentialPayload({
        participantId: 'urn:openpc:participant:018f1e2d-3c4b-7a69-8abc-0123456789ab',
        principalId: 'urn:openpc:principal:018f1e2d-3c4b-7a69-8abc-1123456789ab',
        authorityEpoch: '7',
        issuedAt: '2026-08-24T00:00:00.000000Z',
        expiresAt: '2026-08-24T00:05:00.000000Z',
      }),
    ).toEqual(payload);
    expect(verifyEs256P1363(spki, sigStructure, signature)).toBe(true);
    const altered = Buffer.from(cose);
    altered[altered.length - 1] = altered[altered.length - 1]! ^ 1;
    expect(verifyCoseSign1Es256(spki, payload, cose, identityCredentialCoseContext)).toBe(true);
    expect(verifyCoseSign1Es256(spki, payload, altered, identityCredentialCoseContext)).toBe(false);
  });

  it('signs a canonical identity credential and preserves exact payload and key binding', () => {
    const privateKey = createPrivateKey({
      format: 'jwk',
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: Buffer.from(
          '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
          'hex',
        ).toString('base64url'),
        y: Buffer.from(
          '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
          'hex',
        ).toString('base64url'),
        d: Buffer.from(
          '0000000000000000000000000000000000000000000000000000000000000001',
          'hex',
        ).toString('base64url'),
      },
    });
    const generated = signIdentityCredentialCoseSign1Es256(
      privateKey.export({ format: 'der', type: 'pkcs8' }),
      spki,
      payload,
    );
    expect(verifyCoseSign1Es256(spki, payload, generated, identityCredentialCoseContext)).toBe(
      true,
    );
    const alteredPayload = Buffer.from(payload);
    alteredPayload[alteredPayload.length - 1] = alteredPayload[alteredPayload.length - 1]! ^ 1;
    expect(
      verifyCoseSign1Es256(spki, alteredPayload, generated, identityCredentialCoseContext),
    ).toBe(false);
  });

  it('rejects independently signed wrong-purpose and wrong-schema contexts', () => {
    const wrongPurpose = signedEnvelope(22501, 'openpc:module-ui-manifest:v1');
    const wrongSchema = signedEnvelope(22502, 'openpc:identity-credential:v1');
    expect(verifyCoseSign1Es256(spki, payload, wrongPurpose, identityCredentialCoseContext)).toBe(
      false,
    );
    expect(verifyCoseSign1Es256(spki, payload, wrongSchema, identityCredentialCoseContext)).toBe(
      false,
    );
  });

  it('verifies an opaque payload only when its protected context and trusted key match', () => {
    const opaquePayload = Buffer.from([0xa1, 0x01, 0x61, 0x78]);
    const context = { purpose: 'openpc:policy-artifact:v1', schemaId: 22503 };
    const signed = signedEnvelope(context.schemaId, context.purpose, opaquePayload);
    expect(verifyBoundCoseSign1Es256(spki, opaquePayload, signed, context)).toBe(true);
    expect(
      verifyBoundCoseSign1Es256(spki, opaquePayload, signed, {
        purpose: 'openpc:policy-activation:v1',
        schemaId: 22502,
      }),
    ).toBe(false);
    expect(verifyCoseSign1Es256(spki, opaquePayload, signed, context)).toBe(false);
  });

  it('rejects a freshly signed payload whose map keys are not in PC-CBOR-1 order', () => {
    const keyThree = payload.indexOf(Buffer.from([0x03, 0x65, 0x31, 0x2e, 0x30, 0x2e, 0x30]));
    expect(keyThree).toBeGreaterThan(0);
    const nonCanonical = Buffer.concat([
      Buffer.from([0xa9, 0x02]),
      cborUnsigned(22501),
      Buffer.from([0x01]),
      cborText('openpc:identity-credential:v1'),
      payload.subarray(keyThree),
    ]);
    expect(nonCanonical).not.toEqual(payload);
    expect(
      verifyCoseSign1Es256(
        spki,
        nonCanonical,
        signedEnvelope(22501, 'openpc:identity-credential:v1', nonCanonical),
        identityCredentialCoseContext,
      ),
    ).toBe(false);
  });
});
