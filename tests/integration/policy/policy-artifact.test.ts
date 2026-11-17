import { createHash, generateKeyPairSync, sign } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  decodePolicyArtifactPayload,
  encodePolicyArtifactPayload,
  policyArtifactCoseContext,
  verifyPolicyArtifactCose,
} from '../../../services/module-registry/src/domain/policy-artifact.js';

function encodedLength(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length <= 0xff) return Buffer.from([(major << 5) | 24, length]);
  const value = Buffer.alloc(3);
  value[0] = (major << 5) | 25;
  value.writeUInt16BE(length, 1);
  return value;
}

function bytes(value: Buffer): Buffer {
  return Buffer.concat([encodedLength(2, value.length), value]);
}

function text(value: string): Buffer {
  const encoded = Buffer.from(value);
  return Buffer.concat([encodedLength(3, encoded.length), encoded]);
}

function signedCose(
  privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'],
  publicKey: Buffer,
  payload: Buffer,
  context = policyArtifactCoseContext,
): Buffer {
  const protectedHeader = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x26, 0x03]),
    text('application/openpc+cbor'),
    Buffer.from([0x04]),
    bytes(createHash('sha256').update(publicKey).digest()),
    Buffer.from([0x19, 0x03, 0xe9]),
    encodedLength(0, context.schemaId),
    Buffer.from([0x19, 0x03, 0xea]),
    text(context.purpose),
  ]);
  const signatureInput = Buffer.concat([
    Buffer.from([0x84, 0x6a]),
    Buffer.from('Signature1'),
    bytes(protectedHeader),
    Buffer.from([0x40]),
    bytes(payload),
  ]);
  const signature = sign('sha256', signatureInput, {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return Buffer.concat([
    Buffer.from([0xd2, 0x84]),
    bytes(protectedHeader),
    Buffer.from([0xa0]),
    bytes(payload),
    bytes(signature),
  ]);
}

const participantId = 'urn:openpc:participant:018f1e2d-3c4b-7a69-8abc-0123456789ab';
const privacyDomainId = 'urn:openpc:privacy-domain:018f1e2d-3c4b-7a69-8abc-2123456789ab';
const policySetId = 'urn:openpc:policy-set:018f1e2d-3c4b-7a69-8abc-3123456789ab';

describe('PolicyArtifactV1', () => {
  it('round-trips the exact schema and verifies only a configured signer and context', () => {
    const signer = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const untrusted = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const publicKey = signer.publicKey.export({ format: 'der', type: 'spki' });
    const untrustedPublicKey = untrusted.publicKey.export({ format: 'der', type: 'spki' });
    const digest = Buffer.alloc(32, 0x11);
    const payload = encodePolicyArtifactPayload({
      participantId,
      privacyDomainId,
      policySetId,
      semanticVersion: '1.2.3',
      policySchemaDigest: Buffer.alloc(32, 0x22),
      semanticDigest: digest,
      dependencyClosureDigest: Buffer.alloc(32, 0x33),
      semanticBytesDigest: digest,
    });
    expect(decodePolicyArtifactPayload(payload)).toEqual({
      participantId,
      privacyDomainId,
      policySetId,
      semanticVersion: '1.2.3',
      policySchemaDigest: Buffer.alloc(32, 0x22),
      semanticDigest: digest,
      dependencyClosureDigest: Buffer.alloc(32, 0x33),
      semanticBytesDigest: digest,
    });
    const cose = signedCose(signer.privateKey, publicKey, payload);
    expect(verifyPolicyArtifactCose([{ publicKeySpkiDer: publicKey }], payload, cose)).toEqual(
      createHash('sha256').update(publicKey).digest(),
    );
    expect(
      verifyPolicyArtifactCose([{ publicKeySpkiDer: untrustedPublicKey }], payload, cose),
    ).toBeUndefined();
    expect(
      verifyPolicyArtifactCose(
        [{ publicKeySpkiDer: publicKey }],
        payload,
        signedCose(signer.privateKey, publicKey, payload, {
          purpose: 'openpc:policy-activation-authorization:v1',
          schemaId: 22502,
        }),
      ),
    ).toBeUndefined();
  });

  it('rejects digest mismatch, unknown or duplicate members, and noncanonical encodings', () => {
    const digest = Buffer.alloc(32, 0x11);
    expect(() =>
      encodePolicyArtifactPayload({
        participantId,
        privacyDomainId,
        policySetId,
        semanticVersion: '1.2.3',
        policySchemaDigest: Buffer.alloc(32, 0x22),
        semanticDigest: digest,
        dependencyClosureDigest: Buffer.alloc(32, 0x33),
        semanticBytesDigest: Buffer.alloc(32, 0x12),
      }),
    ).toThrow('semantic validation');

    const canonical = encodePolicyArtifactPayload({
      participantId,
      privacyDomainId,
      policySetId,
      semanticVersion: '1.2.3',
      policySchemaDigest: Buffer.alloc(32, 0x22),
      semanticDigest: digest,
      dependencyClosureDigest: Buffer.alloc(32, 0x33),
      semanticBytesDigest: digest,
    });
    const keyThree = canonical.indexOf(Buffer.from([0x03, 0x65, 0x31, 0x2e, 0x30, 0x2e, 0x30]));
    expect(keyThree).toBeGreaterThan(0);
    const nonCanonical = Buffer.concat([
      Buffer.from([0xac, 0x02]),
      encodedLength(0, policyArtifactCoseContext.schemaId),
      Buffer.from([0x01]),
      text(policyArtifactCoseContext.purpose),
      canonical.subarray(keyThree),
    ]);
    expect(() => decodePolicyArtifactPayload(nonCanonical)).toThrow('map order');

    const unknownMember = Buffer.from(canonical);
    const lastKey = unknownMember.lastIndexOf(Buffer.from([0x0c, 0x58, 0x20]));
    expect(lastKey).toBeGreaterThan(0);
    unknownMember[lastKey] = 0x0d;
    expect(() => decodePolicyArtifactPayload(unknownMember)).toThrow('unknown');

    const duplicateMember = Buffer.from(canonical);
    duplicateMember[lastKey] = 0x0b;
    expect(() => decodePolicyArtifactPayload(duplicateMember)).toThrow('map order');

    const nonCanonicalLength = Buffer.concat([Buffer.from([0xb8, 0x0c]), canonical.subarray(1)]);
    expect(() => decodePolicyArtifactPayload(nonCanonicalLength)).toThrow(
      'non-canonical CBOR length',
    );

    const invalidUtf8 = Buffer.from(canonical);
    const participant = invalidUtf8.indexOf(Buffer.from(participantId));
    expect(participant).toBeGreaterThan(0);
    invalidUtf8[participant] = 0xff;
    expect(() => decodePolicyArtifactPayload(invalidUtf8)).toThrow();
  });

  it('rejects an exact-payload or signature binding mutation', () => {
    const signer = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const publicKey = signer.publicKey.export({ format: 'der', type: 'spki' });
    const digest = Buffer.alloc(32, 0x11);
    const payload = encodePolicyArtifactPayload({
      participantId,
      privacyDomainId,
      policySetId,
      semanticVersion: '1.2.3',
      policySchemaDigest: Buffer.alloc(32, 0x22),
      semanticDigest: digest,
      dependencyClosureDigest: Buffer.alloc(32, 0x33),
      semanticBytesDigest: digest,
    });
    const cose = signedCose(signer.privateKey, publicKey, payload);
    const mutatedPayload = Buffer.from(payload);
    mutatedPayload[mutatedPayload.length - 1] ^= 1;
    expect(() =>
      verifyPolicyArtifactCose([{ publicKeySpkiDer: publicKey }], mutatedPayload, cose),
    ).toThrow();
    const mutatedSignature = Buffer.from(cose);
    mutatedSignature[mutatedSignature.length - 1] ^= 1;
    expect(
      verifyPolicyArtifactCose([{ publicKeySpkiDer: publicKey }], payload, mutatedSignature),
    ).toBeUndefined();
  });
});
