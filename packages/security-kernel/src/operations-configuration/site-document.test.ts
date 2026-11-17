import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { evidenceKeyId } from '../business-transition/cose.js';
import { signConsumerCose } from '../fact-consumer/cose-framing.js';
import { operationsConfigurationCoseProfiles } from './generated.js';
import {
  decodeOperationsSiteDocument,
  encodeOperationsSiteDocument,
  signOperationsSiteDocument,
  verifyOperationsSiteDocument,
  verifyInstalledOperationsSiteDocument,
  type OperationsSiteDocumentClaims,
  type InstalledOperationsSiteIssuer,
} from './site-document.js';

function keys() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: pair.publicKey.export({ format: 'der', type: 'spki' }),
  };
}
const issuer = keys();
const h = (digit: string) => `sha256:${digit.repeat(64)}`;
const claims: OperationsSiteDocumentClaims = {
  environmentId: 'local-test',
  profile: 'local',
  generationId: 'urn:openpc:generation:018f0000-0000-7000-8000-000000000002',
  baseGenerationId: 'urn:openpc:generation:018f0000-0000-7000-8000-000000000001',
  siteDigest: h('a'),
  configurationSchemaDigest: h('b'),
  namedProfileDigest: h('c'),
  declaredContentDigest: h('d'),
  issuerKeyId: evidenceKeyId(issuer.spki),
  issuerEpoch: '2',
  validFromMs: 1000,
  validUntilMs: 2000,
};
const pins: InstalledOperationsSiteIssuer = {
  issuerSpki: issuer.spki,
  issuerEpoch: '2',
  issuerValidFromMs: 500,
  issuerValidUntilMs: 2500,
  environmentId: claims.environmentId,
  profile: 'local',
  configurationSchemaDigest: claims.configurationSchemaDigest,
  namedProfileDigest: claims.namedProfileDigest,
};
const original = {
  generationId: claims.generationId,
  baseGenerationId: claims.baseGenerationId,
  siteDigest: claims.siteDigest,
  declaredContentDigest: claims.declaredContentDigest,
};
function signed(value = claims) {
  const payload = encodeOperationsSiteDocument(value);
  return { payload, cose: signOperationsSiteDocument(issuer.privateKey, issuer.spki, payload) };
}
describe('AF-25 signed site input integrity, not generation authority', () => {
  it('verifies exact independent installation pins for every named profile', () => {
    for (const profile of ['local', 'development', 'test', 'staging', 'production'] as const) {
      const { payload, cose } = signed({ ...claims, profile });
      expect(decodeOperationsSiteDocument(payload)).toEqual({ ...claims, profile });
      const result = verifyInstalledOperationsSiteDocument(
        { ...pins, profile },
        original,
        payload,
        cose,
        1000,
      );
      expect(result.profile).toBe(profile);
      expect(result.signedDocumentDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(Object.isFrozen(result)).toBe(true);
      expect(result).not.toHaveProperty('startupAllowed');
      expect(result).not.toHaveProperty('effectiveDigest');
    }
  });
  it('rejects every foreign independent pin and every substituted document binding', () => {
    const { payload, cose } = signed();
    for (const patch of [
      { issuerSpki: keys().spki },
      { issuerEpoch: '1' },
      { environmentId: 'foreign-test' },
      { profile: 'production' as const },
      { configurationSchemaDigest: h('e') },
      { namedProfileDigest: h('e') },
      { issuerValidFromMs: 1001 },
      { issuerValidUntilMs: 1999 },
      { issuerValidFromMs: NaN },
    ])
      expect(() =>
        verifyInstalledOperationsSiteDocument({ ...pins, ...patch }, original, payload, cose, 1500),
      ).toThrow();
    for (const patch of [
      { generationId: claims.baseGenerationId },
      { baseGenerationId: claims.generationId },
      { siteDigest: h('e') },
      { declaredContentDigest: h('e') },
    ])
      expect(() =>
        verifyInstalledOperationsSiteDocument(pins, { ...original, ...patch }, payload, cose, 1500),
      ).toThrow();
    for (const now of [-1, -0, NaN, Infinity, 999, 2000, 2001])
      expect(() =>
        verifyInstalledOperationsSiteDocument(pins, original, payload, cose, now),
      ).toThrow();
    expect(
      verifyInstalledOperationsSiteDocument(pins, original, payload, cose, 1999).issuerEpoch,
    ).toBe('2');
  });
  it('rejects wrong purpose/schema, altered payload/signature and foreign issuer', () => {
    const { payload, cose } = signed();
    const context = operationsConfigurationCoseProfiles.OperationsSiteDocumentV1;
    for (const patch of [{ purposeCode: 358 }, { schemaId: 24021 }, { schemaVersion: 2 }]) {
      const other = signConsumerCose(
        { ...context, ...patch },
        issuer.privateKey,
        issuer.spki,
        payload,
      );
      expect(() => verifyOperationsSiteDocument(issuer.spki, payload, other)).toThrow();
    }
    const altered = Buffer.from(cose);
    altered[altered.length - 1] = altered[altered.length - 1]! ^ 1;
    expect(() => verifyOperationsSiteDocument(issuer.spki, payload, altered)).toThrow();
    expect(() => verifyOperationsSiteDocument(keys().spki, payload, cose)).toThrow();
    expect(() =>
      verifyOperationsSiteDocument(
        issuer.spki,
        encodeOperationsSiteDocument({ ...claims, siteDigest: h('e') }),
        cose,
      ),
    ).toThrow();
  });
  it('rejects aliases, invalid time/generation/epoch and hidden or extra properties', () => {
    for (const patch of [
      { profile: 'LOCAL' },
      { environmentId: 'ab' },
      { environmentId: 'a_b' },
      { generationId: claims.baseGenerationId },
      { baseGenerationId: claims.generationId.replace('generation:', 'resource:') },
      { issuerEpoch: '0' },
      { issuerEpoch: '02' },
      { issuerEpoch: '18446744073709551616' },
      { validFromMs: -0 },
      { validUntilMs: 1000 },
      { validUntilMs: Number.MAX_SAFE_INTEGER + 1 },
      { siteDigest: h('A') },
      { ready: true },
    ])
      expect(() =>
        encodeOperationsSiteDocument({ ...claims, ...patch } as OperationsSiteDocumentClaims),
      ).toThrow();
    const getter = { ...claims };
    Object.defineProperty(getter, 'siteDigest', { get: () => claims.siteDigest, enumerable: true });
    expect(() => encodeOperationsSiteDocument(getter)).toThrow();
    const hidden = { ...claims, [Symbol('extra')]: true };
    expect(() => encodeOperationsSiteDocument(hidden)).toThrow();
  });
  it('rejects duplicate, unknown, noncanonical, truncated and oversized wire bytes', () => {
    const { payload } = signed();
    for (const malformed of [
      Buffer.concat([Buffer.from([0xb8, 13]), payload.subarray(1)]),
      Buffer.concat([Buffer.from([0xae]), payload.subarray(1), Buffer.from([12, 0])]),
      Buffer.concat([Buffer.from([0xae]), payload.subarray(1), Buffer.from([13, 0])]),
      Buffer.concat([payload, Buffer.from([0])]),
      payload.subarray(1),
      payload.subarray(0, -1),
      Buffer.alloc(65537),
    ])
      expect(() => decodeOperationsSiteDocument(malformed)).toThrow();
  });
});
