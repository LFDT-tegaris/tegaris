import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import type { OpenPcEventEnvelopeV1 } from '../../../../generated/typescript/json-schema/event-envelope.js';
import type { EvidenceExportCompletedDataV1 } from '../../../../generated/typescript/json-schema/event-payloads.js';
import { decodeCbor, encodeCbor, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { signConsumerCose } from '../fact-consumer/cose-framing.js';
import { evidenceExportCoseContext } from './generated.js';
import {
  decodeEvidenceExportCompletion,
  encodeEvidenceExportCompletedData,
  encodeEvidenceExportCompletion,
  evidenceExportCompletionEnvelope,
  signEvidenceExportCompletion,
  verifyEvidenceExportCompletion,
  type EvidenceExportCompletionClaims,
} from './codec.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (n: number) => `sha256:${n.toString(16).padStart(2, '0').repeat(32)}`;
const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const privateKey = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
const data = {
  evidenceExportId: id(5),
  checkpoint: '9007199254740993',
  outputDigest: digest(1),
  recordCount: '3',
};
const claims: EvidenceExportCompletionClaims = {
  environmentId: 'local-evidence-export',
  participantId: id(1),
  privacyDomainId: id(2),
  eventId: id(3),
  sourceId: id(4),
  ...data,
  startOperationId: id(6),
  causationId: id(7),
  sequence: '18446744073709551615',
  recordedAtNs: '1800000000000001000',
  requestDigest: digest(2),
  dataDigest: `sha256:${createHash('sha256').update(encodeEvidenceExportCompletedData(data)).digest('hex')}`,
  authoritySnapshotDigest: digest(3),
  signerTrustSnapshotDigest: digest(4),
  signerKeyId: evidenceKeyId(spki),
};

it('binds the registered DATA preimage and exact public envelope without exposing protected evidence', () => {
  const payload = encodeEvidenceExportCompletedData(data);
  expect(decodeCbor(payload)).toEqual(
    new Map<number, CborValue>([
      [0, `urn:openpc:resource:${id(5)}`],
      [1, 9007199254740993n],
      [2, Buffer.from('01'.repeat(32), 'hex')],
      [3, 3n],
    ]),
  );
  const concrete = evidenceExportCompletionEnvelope(claims);
  const envelope: OpenPcEventEnvelopeV1 = concrete;
  const projected: EvidenceExportCompletedDataV1 = concrete.data;
  expect(projected).toEqual({ ...data, evidenceExportId: `urn:openpc:resource:${id(5)}` });
  expect(envelope).toMatchObject({
    source: `urn:openpc:service:${id(4)}`,
    subject: `urn:openpc:resource:${id(5)}`,
    correlationid: id(6),
    causationid: id(7),
    time: '2027-01-15T08:00:00.000001Z',
    sequence: '18446744073709551615',
    datadigest: claims.dataDigest,
  });
  const schema = JSON.parse(
    readFileSync(
      new URL('../../../../schemas/json/event-envelope.schema.json', import.meta.url),
      'utf8',
    ),
  );
  expect(Object.keys(envelope).every((key) => Object.hasOwn(schema.properties, key))).toBe(true);
  expect(schema.required.every((key: string) => Object.hasOwn(envelope, key))).toBe(true);
  expect(envelope).not.toHaveProperty('authoritygeneration');
  for (const privateField of [
    'requestDigest',
    'authoritySnapshotDigest',
    'signerTrustSnapshotDigest',
    'artifact',
    'recipient',
  ])
    expect(JSON.stringify(envelope)).not.toContain(privateField);
});

it('roundtrips canonical metadata and verifies its distinct signed purpose', () => {
  const payload = encodeEvidenceExportCompletion(claims);
  expect(decodeEvidenceExportCompletion(payload)).toEqual(claims);
  const signed = signEvidenceExportCompletion(claims, privateKey, spki);
  expect(verifyEvidenceExportCompletion(claims, spki, signed)).toBe(true);
  for (const context of [
    { ...evidenceExportCoseContext, schemaId: 24012 },
    { ...evidenceExportCoseContext, purposeCode: 349 },
    { ...evidenceExportCoseContext, schemaVersion: 2 },
    { ...evidenceExportCoseContext, externalAadHex: '00' },
  ])
    expect(
      verifyEvidenceExportCompletion(
        claims,
        spki,
        signConsumerCose(context, privateKey, spki, payload),
      ),
    ).toBe(false);
  const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
    format: 'der',
    type: 'spki',
  });
  expect(verifyEvidenceExportCompletion(claims, other, signed)).toBe(false);
  const changed = Buffer.from(signed);
  changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
  expect(verifyEvidenceExportCompletion(claims, spki, changed)).toBe(false);
});

it('rejects substitutions of every signed field and preserves original byte identity', () => {
  const signed = signEvidenceExportCompletion(claims, privateKey, spki);
  for (const key of Object.keys(claims) as (keyof EvidenceExportCompletionClaims)[]) {
    const value = claims[key];
    const replacement =
      key === 'environmentId'
        ? 'other-environment'
        : key === 'recordedAtNs'
          ? '1800000000000002000'
          : value.startsWith('sha256:')
            ? digest(9)
            : value.includes('-')
              ? id(99)
              : '2';
    expect(
      verifyEvidenceExportCompletion({ ...claims, [key]: replacement }, spki, signed),
      key,
    ).toBe(false);
  }
  expect(decodeEvidenceExportCompletion(encodeEvidenceExportCompletion(claims))).toEqual(claims);
});

it('rejects malformed, lossy, unregistered and mismatched metadata before signing', () => {
  for (const patch of [
    { sequence: '0' },
    { sequence: '18446744073709551616' },
    { sequence: '01' },
    { checkpoint: '1e3' },
    { recordCount: '0' },
    { recordCount: '129' },
    { checkpoint: '1' },
    { recordedAtNs: '1800000000000001001' },
    { sourceId: `urn:openpc:service:${id(4)}` },
    { eventId: id(3) + '\n' },
    { outputDigest: digest(1) + '\n' },
    { signerKeyId: 'private-canary' },
    { environmentId: 'private-canary\n' },
    { dataDigest: digest(9) },
    { artifact: 'private-canary' },
    { authorized: true },
    { checkpoint: Number('9007199254740993') },
  ])
    expect(() =>
      encodeEvidenceExportCompletion({ ...claims, ...patch } as EvidenceExportCompletionClaims),
    ).toThrow();
  for (const key of Object.keys(claims)) {
    const missing = { ...claims } as Record<string, unknown>;
    delete missing[key];
    expect(() =>
      encodeEvidenceExportCompletion(missing as unknown as EvidenceExportCompletionClaims),
    ).toThrow();
  }
  expect(() =>
    encodeEvidenceExportCompletedData({ ...data, recipient: 'private-canary' } as typeof data),
  ).toThrow();
  const bytes = encodeEvidenceExportCompletion(claims);
  const wire = decodeCbor(bytes) as Map<number, CborValue>;
  for (const mutation of [
    new Map([...wire, [99, 'private-canary']] as [number, CborValue][]),
    new Map([...wire].filter(([key]) => key !== 1)),
    new Map([...wire].map(([key, value]) => [key, key === 0 ? Buffer.alloc(32) : value])),
  ])
    expect(() => decodeEvidenceExportCompletion(encodeCbor(mutation))).toThrow();
  expect(() => decodeEvidenceExportCompletion(Buffer.concat([bytes, Buffer.from([0])]))).toThrow();
});
