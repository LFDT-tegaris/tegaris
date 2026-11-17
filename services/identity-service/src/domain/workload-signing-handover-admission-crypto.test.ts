import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  encodeHandoverAdmissionAuthorization,
  signHandoverAdmissionAuthorization,
} from '@openpc/security-kernel';
import { handoverAdmissionAuthorizationFixture } from '../../../../packages/security-kernel/src/workload-signing-handover/authorization.fixture.js';
import {
  createHandoverAdmissionVerifier,
  createLocalHandoverAdmissionSigner,
  type HandoverAdmissionTrustPolicy,
} from './workload-signing-handover-admission-crypto.js';

const pair = () => {
  const key = generateKeyPairSync('ed25519');
  return {
    privateKey: key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    publicKey: key.publicKey.export({ format: 'der', type: 'spki' }),
  };
};
function policy(publicKey: Buffer): HandoverAdmissionTrustPolicy {
  const statement = handoverAdmissionAuthorizationFixture();
  return {
    participantId: statement.participantId,
    privacyDomainId: statement.privacyDomainId,
    environmentId: statement.environmentId,
    workloadPrincipalId: statement.workloadPrincipalId,
    workloadId: statement.workloadId,
    signers: [
      {
        publicKeySpkiDer: publicKey,
        validFromNs: '1793768400000000000',
        validUntilNs: '1793775600000000000',
      },
    ],
  };
}
function setup() {
  const key = pair(),
    trust = policy(key.publicKey),
    bytes = encodeHandoverAdmissionAuthorization(handoverAdmissionAuthorizationFixture());
  const signer = createLocalHandoverAdmissionSigner({
    policy: trust,
    activePrivateKeyPkcs8Der: key.privateKey,
    activePublicKeySpkiDer: key.publicKey,
  });
  return { key, trust, bytes, signer, signed: signer.signAuthorization(bytes) };
}

it('signs synchronously only under explicit purpose-specific scoped trust and verifies with public keys only', () => {
  const { trust, bytes, signer, signed } = setup();
  expect(signer.mode).toBe('LOCAL_BOUNDED_PURE');
  expect(signed).not.toBeInstanceOf(Promise);
  expect(signed.authorizationCbor).toEqual(bytes);
  const verifier = createHandoverAdmissionVerifier(trust);
  expect(Object.keys(verifier)).toEqual(['verifyAuthorization']);
  const verified = verifier.verifyAuthorization(bytes, signed.coseSign1);
  expect(verified?.statement).toEqual(handoverAdmissionAuthorizationFixture());
  expect(verified?.signerKeyDigest).toEqual(signed.signerKeyDigest);
  expect(verified?.authorizationDigest).toEqual(signed.authorizationDigest);
});

it.each([
  'participantId',
  'privacyDomainId',
  'environmentId',
  'workloadPrincipalId',
  'workloadId',
] as const)('denies a valid signature under foreign %s policy', (field) => {
  const { key, bytes, trust, signed } = setup();
  const foreign = {
    ...trust,
    [field]:
      field.endsWith('Id') && !['environmentId', 'workloadId'].includes(field)
        ? '01a10000-0000-7000-8000-000000000099'
        : 'foreign',
  };
  expect(
    createHandoverAdmissionVerifier(foreign).verifyAuthorization(bytes, signed.coseSign1),
  ).toBeUndefined();
  const other = createLocalHandoverAdmissionSigner({
    policy: foreign,
    activePrivateKeyPkcs8Der: key.privateKey,
    activePublicKeySpkiDer: key.publicKey,
  });
  expect(() => other.signAuthorization(bytes)).toThrow();
});

it('rejects unknown roots, mismatched key pairs and implicit ordinary Identity trust', () => {
  const { key, bytes, trust, signed } = setup(),
    stranger = pair();
  expect(
    createHandoverAdmissionVerifier(policy(stranger.publicKey)).verifyAuthorization(
      bytes,
      signed.coseSign1,
    ),
  ).toBeUndefined();
  const strangerSignature = signHandoverAdmissionAuthorization(
    stranger.privateKey,
    stranger.publicKey,
    bytes,
  );
  expect(
    createHandoverAdmissionVerifier(trust).verifyAuthorization(bytes, strangerSignature),
  ).toBeUndefined();
  expect(() =>
    createLocalHandoverAdmissionSigner({
      policy: trust,
      activePrivateKeyPkcs8Der: stranger.privateKey,
      activePublicKeySpkiDer: key.publicKey,
    }),
  ).toThrow();
  expect(() =>
    createLocalHandoverAdmissionSigner({
      policy: trust,
      activePrivateKeyPkcs8Der: stranger.privateKey,
      activePublicKeySpkiDer: stranger.publicKey,
    }),
  ).toThrow();
  expect(() =>
    createHandoverAdmissionVerifier(undefined as unknown as HandoverAdmissionTrustPolicy),
  ).toThrow();
  expect(() =>
    createHandoverAdmissionVerifier({
      trustedPublicKeysSpkiDer: [key.publicKey],
    } as unknown as HandoverAdmissionTrustPolicy),
  ).toThrow();
});

it.each([
  { validFromNs: '1793772000000001000', validUntilNs: '1793775600000000000' },
  { validFromNs: '1793768400000000000', validUntilNs: '1793772059999999000' },
])('requires the entire authorization window inside root trust %#', (interval) => {
  const { key, bytes, trust, signed } = setup();
  const bounded = { ...trust, signers: [{ publicKeySpkiDer: key.publicKey, ...interval }] };
  expect(
    createHandoverAdmissionVerifier(bounded).verifyAuthorization(bytes, signed.coseSign1),
  ).toBeUndefined();
  const signer = createLocalHandoverAdmissionSigner({
    policy: bounded,
    activePrivateKeyPkcs8Der: key.privateKey,
    activePublicKeySpkiDer: key.publicKey,
  });
  expect(() => signer.signAuthorization(bytes)).toThrow();
});

it('retains historical signature verification without asserting current authority or commitment', () => {
  const { bytes, signed, trust } = setup();
  const verified = createHandoverAdmissionVerifier(trust).verifyAuthorization(
    bytes,
    signed.coseSign1,
  );
  expect(verified?.statement.statementType).toBe('ADMISSION_AUTHORIZATION');
  expect(verified && Object.keys(verified).sort()).toEqual([
    'authorizationDigest',
    'signerKeyDigest',
    'statement',
  ]);
  const changed = encodeHandoverAdmissionAuthorization({
    ...handoverAdmissionAuthorizationFixture(),
    approvalDecisionDigest: 'sha256:' + 'ff'.repeat(32),
  });
  expect(
    createHandoverAdmissionVerifier(trust).verifyAuthorization(changed, signed.coseSign1),
  ).toBeUndefined();
});

it('captures immutable trust and key bytes rather than retaining mutable caller references', () => {
  const { trust, bytes, signed } = setup();
  const verifier = createHandoverAdmissionVerifier(trust);
  trust.signers[0]!.publicKeySpkiDer.fill(0);
  (trust as { environmentId: string }).environmentId = 'changed';
  (trust.signers as unknown[]).length = 0;
  expect(verifier.verifyAuthorization(bytes, signed.coseSign1)?.statement.environmentId).toBe(
    'synthetic-admission',
  );
});

it('rejects incomplete, wildcard, malformed, duplicate, accessor and sparse policies without invoking getters', () => {
  const key = pair(),
    trust = policy(key.publicKey);
  const malformed = [
    { ...trust, signers: [] },
    { ...trust, signers: [trust.signers[0], trust.signers[0]] },
    { ...trust, signers: new Array(1) },
    { ...trust, environmentId: '*' },
    { ...trust, participantId: 'all' },
    { ...trust, extra: true },
    {
      ...trust,
      signers: [
        { ...trust.signers[0], publicKeySpkiDer: Buffer.concat([key.publicKey, Buffer.from([0])]) },
      ],
    },
    { ...trust, signers: [{ ...trust.signers[0], validUntilNs: trust.signers[0]!.validFromNs }] },
    { ...trust, signers: [{ ...trust.signers[0], validFromNs: '01' }] },
  ];
  for (const entry of malformed)
    expect(() => createHandoverAdmissionVerifier(entry as HandoverAdmissionTrustPolicy)).toThrow();
  let calls = 0;
  const getter = () => {
    calls++;
    return trust.signers;
  };
  expect(() =>
    createHandoverAdmissionVerifier(
      Object.defineProperty({ ...trust }, 'signers', { get: getter }),
    ),
  ).toThrow();
  expect(() =>
    createHandoverAdmissionVerifier(
      Object.defineProperty({ ...trust }, 'participantId', { get: getter }),
    ),
  ).toThrow();
  const accessorSigner = Object.defineProperty({ ...trust.signers[0] }, 'validFromNs', {
    get: getter,
  });
  expect(() =>
    createHandoverAdmissionVerifier({
      ...trust,
      signers: [accessorSigner as HandoverAdmissionTrustPolicy['signers'][number]],
    }),
  ).toThrow();
  const sparse = [trust.signers[0]!];
  Object.defineProperty(sparse, 0, { get: getter });
  expect(() => createHandoverAdmissionVerifier({ ...trust, signers: sparse })).toThrow();
  expect(calls).toBe(0);
});

it('accepts exact root interval endpoints and rejects seventeen roots or duplicate Buffer copies', () => {
  const { key, bytes, signed, trust } = setup(),
    statement = handoverAdmissionAuthorizationFixture();
  const exact = {
    ...trust,
    signers: [
      {
        publicKeySpkiDer: key.publicKey,
        validFromNs: statement.admittedAtNs,
        validUntilNs: statement.authorizationExpiresAtNs,
      },
    ],
  };
  expect(
    createHandoverAdmissionVerifier(exact).verifyAuthorization(bytes, signed.coseSign1)?.statement,
  ).toEqual(statement);
  const roots = Array.from({ length: 17 }, () => ({
    ...trust.signers[0]!,
    publicKeySpkiDer: pair().publicKey,
  }));
  expect(() => createHandoverAdmissionVerifier({ ...trust, signers: roots })).toThrow();
  expect(() =>
    createHandoverAdmissionVerifier({
      ...trust,
      signers: [
        { ...trust.signers[0]!, publicKeySpkiDer: Buffer.from(key.publicKey) },
        { ...trust.signers[0]!, publicKeySpkiDer: Buffer.from(key.publicKey) },
      ],
    }),
  ).toThrow();
});

it('rejects a different key algorithm and retains copied signer inputs', () => {
  const { key, bytes, signer, trust } = setup();
  const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
    format: 'der',
    type: 'spki',
  });
  expect(() =>
    createHandoverAdmissionVerifier({
      ...trust,
      signers: [{ ...trust.signers[0]!, publicKeySpkiDer: ec }],
    }),
  ).toThrow();
  key.privateKey.fill(0);
  key.publicKey.fill(0);
  const signed = signer.signAuthorization(bytes);
  expect(signer.verifyAuthorization(bytes, signed.coseSign1)?.statement).toEqual(
    handoverAdmissionAuthorizationFixture(),
  );
});
