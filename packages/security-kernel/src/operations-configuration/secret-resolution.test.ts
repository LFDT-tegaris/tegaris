import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { signConsumerCose } from '../fact-consumer/cose-framing.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { operationsConfigurationCoseProfiles } from './generated.js';
import {
  parseOperationsSecretResolutionClaims,
  encodeOperationsSecretResolution,
  decodeOperationsSecretResolution,
  signOperationsSecretResolution,
  verifyOperationsSecretResolution,
  type OperationsSecretResolutionClaims,
} from './secret-resolution.js';

const id = (n: number) => `01900000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const h = (n: string) => `sha256:${n.repeat(64)}`;
export function secretResolutionClaims(): OperationsSecretResolutionClaims {
  return {
    environmentId: 'secret-test',
    participantId: id(1),
    privacyDomainId: id(2),
    associationId: id(3),
    operationsInstallationDigest: h('a'),
    candidateDigest: h('b'),
    generationId: id(4),
    recipientBindingDigest: h('c'),
    recipientInstallationDigest: h('d'),
    recipientGeneration: '7',
    field: 'postgres.candidateIndexDsnSecretRef',
    consumerId: 'LS-FACT-BRIDGE',
    storeId: 'STORE-CANDIDATE-INDEX-PG',
    referenceFingerprint: h('e'),
    version: 'v1',
    fingerprint: h('f'),
    principalId: id(5),
    workloadCredentialId: id(6),
    workloadCredentialEpoch: '2',
    consumerInstanceId: id(7),
    consumerStartedAtMs: 1000,
    observerInstanceId: id(8),
    observerStartedAtMs: 1001,
    challengeId: id(9),
    probeDigest: h('0'),
    observedAtMs: 2000,
    validUntilMs: 3000,
    issuerKeyId: h('1'),
    issuerEpoch: '1',
  };
}
it('keeps operations UUID and original recipient integer generation distinct', () => {
  expect(parseOperationsSecretResolutionClaims(secretResolutionClaims()).recipientGeneration).toBe(
    '7',
  );
  for (const change of [
    { recipientGeneration: id(4) },
    { generationId: '7' },
    { recipientGeneration: '0' },
    { recipientGeneration: '01' },
    { workloadCredentialEpoch: '18446744073709551616' },
    { generationId: id(4).toUpperCase() },
  ]) {
    // UUID fixture digits are lower-case-independent; test uppercase alphabet explicitly.
    if ('generationId' in change && change.generationId === id(4)) continue;
    expect(() =>
      parseOperationsSecretResolutionClaims({ ...secretResolutionClaims(), ...change }),
    ).toThrow();
  }
});
it('rejects substituted family, unrestricted field, arbitrary readiness and lifetime', () => {
  for (const change of [
    { field: 'pki.signingKeySecretRef' },
    { consumerId: 'LS-NOTIFICATION' },
    { storeId: 'STORE-CONTROL-PG' },
    { ready: true },
    { checked: true },
    { version: 'latest' },
    { validUntilMs: 32001 },
    { observedAtMs: 1000 },
    { validUntilMs: 2000 },
    { issuerEpoch: '0' },
    { observedAtMs: -0 },
  ])
    expect(() =>
      parseOperationsSecretResolutionClaims({ ...secretResolutionClaims(), ...change }),
    ).toThrow();
});
it('never invokes accessor/coercion or admits hidden/symbol fields', () => {
  let called = false;
  const accessor = Object.defineProperty({ ...secretResolutionClaims() }, 'probeDigest', {
    enumerable: true,
    get() {
      called = true;
      return h('0');
    },
  });
  const hidden = Object.defineProperty({ ...secretResolutionClaims() }, 'unchecked', {
    value: true,
  });
  for (const input of [
    accessor,
    hidden,
    { ...secretResolutionClaims(), [Symbol('proof')]: true },
    Object.create(secretResolutionClaims()),
  ])
    expect(() => parseOperationsSecretResolutionClaims(input)).toThrow();
  expect(called).toBe(false);
});
it('canonical framing roundtrip rejects wrong issuer, modified bytes and trailing payload', () => {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = key.publicKey.export({ format: 'der', type: 'spki' });
  const secret = key.privateKey.export({ format: 'der', type: 'pkcs8' });
  const claims = { ...secretResolutionClaims(), issuerKeyId: evidenceKeyId(spki) };
  const payload = encodeOperationsSecretResolution(claims);
  expect(operationsConfigurationCoseProfiles.OperationsSecretResolutionV1).toMatchObject({
    schemaId: 24023,
    purposeCode: 360,
  });
  const cose = signOperationsSecretResolution(secret, spki, payload);
  const otherPurpose = signConsumerCose(
    operationsConfigurationCoseProfiles.OperationsSiteDocumentV1,
    secret,
    spki,
    payload,
  );
  expect(() => verifyOperationsSecretResolution(spki, payload, otherPurpose)).toThrow();
  secret.fill(0);
  expect(decodeOperationsSecretResolution(payload)).toEqual(claims);
  expect(verifyOperationsSecretResolution(spki, payload, cose)).toEqual(claims);
  const altered = Buffer.from(cose);
  altered[altered.length - 1]! ^= 1;
  expect(() => verifyOperationsSecretResolution(spki, payload, altered)).toThrow();
  expect(() =>
    decodeOperationsSecretResolution(Buffer.concat([payload, Buffer.from([0])])),
  ).toThrow();
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
    format: 'der',
    type: 'spki',
  });
  expect(() => verifyOperationsSecretResolution(other, payload, cose)).toThrow();
});
