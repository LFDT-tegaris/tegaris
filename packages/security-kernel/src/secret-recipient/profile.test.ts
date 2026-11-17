import { createHash, generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { decodeCbor, encodeCbor } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import {
  decodeSecretRecipientProfile,
  encodeSecretRecipientProfile,
  signSecretRecipientProfile,
  verifyInstalledSecretRecipient,
  type SecretRecipientProfile,
} from './profile.js';
const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const spki = key.publicKey.export({ format: 'der', type: 'spki' });
const privateKey = key.privateKey.export({ format: 'der', type: 'pkcs8' });
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const profile: SecretRecipientProfile = {
  environmentId: 'test-environment',
  participantId: id(1),
  privacyDomainId: id(2),
  installationDigest: `sha256:${'a'.repeat(64)}`,
  generation: '1',
  consumerId: 'LS-FACT-BRIDGE',
  secretClass: 'SECRET-DB-CREDENTIAL',
  purpose: 'POSTGRES_CONNECT',
  store: 'STORE-CANDIDATE-INDEX-PG',
  reference: 'secret://test-memory-resolver/candidate-db#v1',
  version: 'v1',
  principalId: id(3),
  workloadCredentialId: id(4),
  workloadCredentialEpoch: '2',
  validFromMs: 1000,
  validUntilMs: 2000,
  issuerKeyId: evidenceKeyId(spki),
};
const { payload, cose } = signSecretRecipientProfile(privateKey, spki, profile);
const installed = {
  ...profile,
  issuerSpkiDer: spki,
  signedBindingDigest: `sha256:${createHash('sha256').update(cose).digest('hex')}`,
};
it('binds canonical signed recipient bytes to separate installation, scope and workload pins', () => {
  expect(decodeSecretRecipientProfile(payload)).toEqual(profile);
  expect(verifyInstalledSecretRecipient(installed, payload, cose, 1000)).toEqual(profile);
  expect(verifyInstalledSecretRecipient(installed, payload, cose, 1999)).toEqual(profile);
  for (const change of [
    { installationDigest: `sha256:${'b'.repeat(64)}` },
    { generation: '2' },
    { environmentId: 'other-environment' },
    { participantId: id(5) },
    { privacyDomainId: id(5) },
    { principalId: id(5) },
    { workloadCredentialId: id(5) },
    { workloadCredentialEpoch: '3' },
    { signedBindingDigest: `sha256:${'b'.repeat(64)}` },
  ])
    expect(() =>
      verifyInstalledSecretRecipient({ ...installed, ...change }, payload, cose, 1500),
    ).toThrow('Installed secret recipient rejected');
});
it('rejects expiry, wrong issuer, malformed signature and cross-purpose bytes', () => {
  for (const now of [999, 2000, NaN, Infinity, -1])
    expect(() => verifyInstalledSecretRecipient(installed, payload, cose, now)).toThrow();
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
    format: 'der',
    type: 'spki',
  });
  expect(() =>
    verifyInstalledSecretRecipient({ ...installed, issuerSpkiDer: other }, payload, cose, 1500),
  ).toThrow();
  const changed = Buffer.from(cose);
  changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
  expect(() =>
    verifyInstalledSecretRecipient(
      {
        ...installed,
        signedBindingDigest: `sha256:${createHash('sha256').update(changed).digest('hex')}`,
      },
      payload,
      changed,
      1500,
    ),
  ).toThrow();
  const container = decodeCbor(cose.subarray(1)) as unknown[];
  const header = decodeCbor(container[0] as Buffer) as Map<number, bigint>;
  header.set(102, 343n);
  const forged = Buffer.concat([
    Buffer.from([0xd2]),
    encodeCbor([encodeCbor(header), new Map(), payload, container[3] as Buffer]),
  ]);
  expect(() =>
    verifyInstalledSecretRecipient(
      {
        ...installed,
        signedBindingDigest: `sha256:${createHash('sha256').update(forged).digest('hex')}`,
      },
      payload,
      forged,
      1500,
    ),
  ).toThrow();
});
it('rejects unknown fields, widened consumers, floating references and noncanonical values', () => {
  for (const change of [
    { extra: 'unexpected' },
    { consumerId: 'LS-FLEET-CONTROL' },
    { secretClass: 'SECRET-SIGNING-KEY' },
    { purpose: 'ADMIN' },
    { store: 'STORE-CONTROL-PG' },
    { reference: 'secret://test-memory-resolver/candidate-db#latest', version: 'latest' },
    { reference: 'secret://test-memory-resolver/../candidate-db#v1' },
    { reference: 'secret://other-provider/candidate-db#v1' },
    { version: 'v2' },
    { generation: '01' },
    { generation: '0' },
    { workloadCredentialEpoch: '-1' },
    { participantId: 'bad' },
    { validFromMs: -0 },
    { validUntilMs: 1000 },
  ])
    expect(() =>
      encodeSecretRecipientProfile({ ...profile, ...change } as SecretRecipientProfile),
    ).toThrow();
  expect(() => decodeSecretRecipientProfile(Buffer.concat([payload, Buffer.from([0])]))).toThrow();
  const m = decodeCbor(payload) as Map<number, unknown>;
  m.set(99, 'extra');
  expect(() => decodeSecretRecipientProfile(encodeCbor(m as Map<number, string>))).toThrow();
});
it('rejects a non-P256 signing key even when it supplies its own issuer digest', () => {
  const other = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const publicKey = other.publicKey.export({ format: 'der', type: 'spki' });
  expect(() =>
    signSecretRecipientProfile(
      other.privateKey.export({ format: 'der', type: 'pkcs8' }),
      publicKey,
      { ...profile, issuerKeyId: evidenceKeyId(publicKey) },
    ),
  ).toThrow();
});
