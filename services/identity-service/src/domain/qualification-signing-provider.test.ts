import { expect, it } from 'vitest';
import { encodeNotificationAsync } from '../../../../packages/security-kernel/src/operations-configuration/notification-async.js';
import { qualificationDigest as hash } from '../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import {
  encodeCbor,
  decodeCbor,
  type CborValue,
} from '../../../../packages/security-kernel/src/canonical-cbor.js';
import {
  qualificationSigningRequestDigest,
  qualificationSigningIntentDigest,
  validateQualificationSigningRequest,
  validateQualificationSigningObservation,
  validateQualificationSigningLookup,
  type QualificationSigningRequest,
} from './qualification-signing-provider.js';
import {
  qualificationSigningWireFixture as fixture,
  qualificationSigningTestId as id,
} from '../../../../tests/integration/local-runtime/qualification-signing-cases.js';
const digest = (s: string) => hash(Buffer.from(s));
for (const family of ['input', 'capacity'] as const) {
  it(`validates exact ${family} canonical receipt bytes without granting native readiness`, () => {
    const f = fixture(family);
    const request = validateQualificationSigningRequest(f.request, f.trust);
    expect(Object.isFrozen(request.peer)).toBe(true);
    expect(validateQualificationSigningObservation(request, f.observation, f.trust)).toEqual(
      f.observation,
    );
    expect(
      validateQualificationSigningLookup(
        request,
        { schemaVersion: 1, state: 'RECORDED', observation: f.observation },
        f.trust,
        f.observation,
      ),
    ).toEqual(f.observation);
    expect(request).not.toHaveProperty('ready');
    expect(request).not.toHaveProperty('current');
  });
  it(`rejects ${family} substitutions at wire, installation and signed-byte boundaries`, () => {
    const f = fixture(family);
    for (const patch of [
      { method: 'PROVE' },
      { schemaVersion: 2 },
      { family: 'other' },
      { ready: true },
      { purpose: 'pc.cose.operations-qualification-input.v1' },
      { participantId: id(90) },
      { privacyDomainId: id(90) },
      { environmentId: 'other-environment' },
      { authorityId: 'other-authority' },
      { keyId: digest('other') },
      { keyEpoch: '2' },
      { rootEpoch: '2' },
      { version: 'latest' },
      { keyInstallationId: id(91) },
      { installationDigest: digest('other') },
      { reference: 'secret://test-provider/other#v1' },
      { peer: f.request.observer },
      { observer: f.request.peer },
      { observer: { ...f.request.observer, certificateDigest: digest('other') } },
      { issuedAtMs: -0 },
      { deadlineAtMs: 3000 },
      { deadlineAtMs: 13001 },
      { payloadHex: f.request.payloadHex + '00' },
      { payloadDigest: digest('other') },
    ])
      expect(() =>
        validateQualificationSigningRequest({ ...f.request, ...patch }, f.trust),
      ).toThrow();
    for (const patch of [
      { coseHex: f.observation.coseHex + '00' },
      {
        coseHex:
          f.observation.coseHex.slice(0, -2) +
          (Number.parseInt(f.observation.coseHex.slice(-2), 16) ^ 1).toString(16).padStart(2, '0'),
      },
      { coseHex: f.sign(f.payload, family === 'input' ? 'capacity' : 'input').toString('hex') },
      { attemptId: id(90) },
      { requestDigest: digest('other') },
      { observedAtMs: 10000 },
      { observedAtMs: 2999 },
      { ready: true },
    ])
      expect(() =>
        validateQualificationSigningObservation(f.request, { ...f.observation, ...patch }, f.trust),
      ).toThrow();
  });
}
it('binds capacity review/run, signer, issuance roots and reserved time without trusting their existence', () => {
  const f = fixture('capacity');
  for (const patch of [
    { sourceDigest: digest('other') },
    { runId: id(90) },
    { keysetDigest: digest('other') },
    { revocationsDigest: digest('other') },
    { issuedAtMs: 3001 },
  ])
    expect(() =>
      validateQualificationSigningRequest({ ...f.request, ...patch }, f.trust),
    ).toThrow();
  const payload = encodeNotificationAsync('capacity', {
    ...f.capacity,
    signerPrincipalId: f.request.observer.principalId,
  });
  expect(() =>
    validateQualificationSigningRequest(
      { ...f.request, payloadHex: payload.toString('hex'), payloadDigest: hash(payload) },
      f.trust,
    ),
  ).toThrow();
});
it('new UUIDs or key-installation identifiers cannot change business intent identity', () => {
  const f = fixture();
  const next = {
    ...f.request,
    operationId: id(70),
    attemptId: id(71),
    keyInstallationId: id(72),
    qualificationInstallationId: id(73),
  };
  expect(qualificationSigningIntentDigest(next)).toBe(qualificationSigningIntentDigest(f.request));
  expect(qualificationSigningRequestDigest(next)).not.toBe(
    qualificationSigningRequestDigest(f.request),
  );
  expect(qualificationSigningIntentDigest({ ...f.request, runId: id(74) })).not.toBe(
    qualificationSigningIntentDigest(f.request),
  );
});
it('preserves historical truth and original absence without permitting a changed or missing known result', () => {
  const f = fixture(); // Deliberately long expired; original verification is independent of current adoption.
  const absent = {
    schemaVersion: 1,
    state: 'ABSENT',
    attemptId: f.request.attemptId,
    requestDigest: qualificationSigningRequestDigest(f.request),
  };
  expect(validateQualificationSigningLookup(f.request, absent, f.trust)).toBeUndefined();
  expect(() =>
    validateQualificationSigningLookup(f.request, absent, f.trust, f.observation),
  ).toThrow();
  expect(() =>
    validateQualificationSigningLookup(f.request, { ...absent, attemptId: id(90) }, f.trust),
  ).toThrow();
  const changed = { ...f.observation, coseHex: f.sign().toString('hex') };
  expect(() =>
    validateQualificationSigningObservation(f.request, changed, f.trust, f.observation),
  ).toThrow();
  const rejection = {
    schemaVersion: 1,
    attemptId: f.request.attemptId,
    requestDigest: absent.requestDigest,
    observedAtMs: 200000,
    outcome: 'REJECTED',
    reason: 'REVOKED',
  };
  expect(validateQualificationSigningObservation(f.request, rejection, f.trust)).toEqual(rejection);
  expect(() =>
    validateQualificationSigningObservation(
      f.request,
      { ...rejection, coseHex: f.observation.coseHex },
      f.trust,
    ),
  ).toThrow();
});
it('rejects malformed CBOR and accessors without executing untrusted getters', () => {
  const f = fixture();
  let reads = 0;
  const input = { ...f.request };
  Object.defineProperty(input, 'payloadHex', {
    enumerable: true,
    get() {
      reads++;
      return f.request.payloadHex;
    },
  });
  expect(() => validateQualificationSigningRequest(input, f.trust)).toThrow();
  expect(reads).toBe(0);
  const map = decodeCbor(f.payload) as Map<number, CborValue>;
  map.set(0, Buffer.alloc(32));
  const bad = encodeCbor(map);
  expect(() =>
    validateQualificationSigningRequest(
      { ...f.request, payloadHex: bad.toString('hex'), payloadDigest: hash(bad) },
      f.trust,
    ),
  ).toThrow();
  expect(() =>
    qualificationSigningRequestDigest({
      ...f.request,
      family: 'arbitrary',
    } as unknown as QualificationSigningRequest),
  ).toThrow();
});
