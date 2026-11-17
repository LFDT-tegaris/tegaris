import { randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { protectedProofSource } from './protected-contracts.js';
import { decryptProtectedProof, encryptProtectedProof } from './protected-crypto.js';

const id = (suffix: string) => `00000000-0000-7000-8000-${suffix.padStart(12, '0')}`;
const digest = `sha256:${'1'.repeat(64)}`;
const source = protectedProofSource.parse({
  evidenceId: `urn:openpc:resource:${id('1')}`,
  occurrenceId: id('2'),
  operationId: id('3'),
  sourceReceiptDigest: digest,
  proofDigest: digest,
  assertionDigest: digest,
  signatureDigest: digest,
  signerKeyDigest: digest,
  occurredAt: '2026-09-22T00:00:00.000000Z',
  materialType: 'IDENTITY_SIGNED_AUTHORIZATION_ASSERTION',
  evidenceClass: 'AUTHENTICATION',
  sourceFormat: 'IDENTITY_RUNTIME_ASSERTION_3002_2_13',
  occurrenceIntegrity: 'CONTROL_DATABASE_IMMUTABLE',
  proofIntegrity: 'IDENTITY_COSE_ED25519',
  finality: 'NOT_APPLICABLE',
  authorityEffect: 'NONE',
});
const payload = {
  version: 'OPENPC_PROTECTED_IDENTITY_PROOF_V1',
  participantId: id('4'),
  privacyDomainId: id('5'),
  source,
  assertionBase64: Buffer.from('private assertion').toString('base64'),
  coseSign1Base64: Buffer.from('original signature').toString('base64'),
};
const plaintext = Buffer.from(canonicalJson(payload));
const binding = {
  participantId: payload.participantId,
  privacyDomainId: payload.privacyDomainId,
  objectRef: `urn:openpc:resource:${id('6')}`,
  objectVersion: '1' as const,
  objectDigest: sha256(plaintext),
  source,
};

it('keeps exact protected bytes encrypted and permits retained key rotation without changing the object', () => {
  const oldKey = randomBytes(32),
    keys = { activeKeyId: 'first', keys: new Map([['first', oldKey]]) };
  const encrypted = encryptProtectedProof(keys, binding, plaintext);
  expect(encrypted.ciphertext.includes(Buffer.from('private assertion'))).toBe(false);
  expect(encrypted.ciphertext.includes(Buffer.from(payload.assertionBase64))).toBe(false);
  expect(
    decryptProtectedProof(
      {
        activeKeyId: 'second',
        keys: new Map([
          ['first', oldKey],
          ['second', randomBytes(32)],
        ]),
      },
      binding,
      encrypted,
    ),
  ).toEqual(payload);
  expect(encryptProtectedProof(keys, binding, plaintext).nonce).not.toEqual(encrypted.nonce);
});

it('rejects wrong scope, object, version, source, digest, key, ciphertext and authentication tag', () => {
  const keys = { activeKeyId: 'first', keys: new Map([['first', randomBytes(32)]]) };
  const encrypted = encryptProtectedProof(keys, binding, plaintext);
  for (const changed of [
    { ...binding, participantId: id('9') },
    { ...binding, privacyDomainId: id('9') },
    { ...binding, objectRef: `urn:openpc:resource:${id('9')}` },
    { ...binding, objectDigest: digest },
    { ...binding, source: { ...source, operationId: id('9') } },
  ])
    expect(() => decryptProtectedProof(keys, changed, encrypted)).toThrow('PC-DATA-6007');
  expect(() =>
    decryptProtectedProof(
      keys,
      { ...binding, objectVersion: '2' } as unknown as typeof binding,
      encrypted,
    ),
  ).toThrow('PC-DATA-6007');
  for (const index of [0, encrypted.ciphertext.length - 1]) {
    const ciphertext = Buffer.from(encrypted.ciphertext);
    ciphertext[index] = ciphertext[index]! ^ 1;
    expect(() => decryptProtectedProof(keys, binding, { ...encrypted, ciphertext })).toThrow(
      'PC-DATA-6007',
    );
  }
  expect(() =>
    decryptProtectedProof(
      { activeKeyId: 'first', keys: new Map([['first', randomBytes(32)]]) },
      binding,
      encrypted,
    ),
  ).toThrow('PC-DATA-6007');
  expect(() =>
    decryptProtectedProof({ activeKeyId: 'missing', keys: new Map() }, binding, encrypted),
  ).toThrow('PC-OPS-9002');
  expect(() =>
    encryptProtectedProof(keys, { ...binding, objectDigest: digest }, plaintext),
  ).toThrow('PC-DATA-6007');
});

it('does not admit caller-invented finality, business integrity, material or extra raw source fields', () => {
  for (const changed of [
    { finality: 'FINALIZED' },
    { evidenceClass: 'BUSINESS_TRANSITION' },
    { authorityEffect: 'AUTHORIZED' },
    { sourceFormat: 'RAW_WEBAUTHN_ASSERTION' },
    { raw: 'private' },
  ])
    expect(protectedProofSource.safeParse({ ...source, ...changed }).success).toBe(false);
});
