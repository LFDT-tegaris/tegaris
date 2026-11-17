import { generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import {
  encodeEvidenceExportCompletedData,
  encodeEvidenceExportCompletion,
  evidenceExportCompletionEnvelope,
  evidenceExportCoseContext,
  evidenceKeyId,
  signEvidenceExportCompletion,
  type EvidenceExportCompletionClaims,
} from '@openpc/security-kernel';
import { signConsumerCose } from '../../../../packages/security-kernel/src/fact-consumer/cose-framing.js';
import { sha256 } from '../configuration/digest.js';
import type { EvidenceExportCompletionSource } from '../evidence/export-completion-source.js';
import { parseEvidenceExportCompletedEnvelope } from './event-input.js';
import {
  readNotificationEvidenceExportSource,
  NotificationSourceReadError,
  type NotificationEvidenceExportSourceInput,
} from './source-reader.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (n: number) => `sha256:${n.toString(16).padStart(2, '0').repeat(32)}`;
const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const privateKey = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
const otherSpki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
  format: 'der',
  type: 'spki',
});
const source: EvidenceExportCompletionSource = {
  participantId: id(1),
  privacyDomainId: id(2),
  streamId: 'CONTROL-BUSINESS',
  evidenceExportId: id(3),
  startOperationId: id(4),
  causationId: id(5),
  requestDigest: digest(1),
  checkpoint: '9007199254740993',
  outputDigest: digest(2),
  recordCount: '3',
};
function dataDigest(
  claims: Pick<
    EvidenceExportCompletionClaims,
    'evidenceExportId' | 'checkpoint' | 'outputDigest' | 'recordCount'
  >,
) {
  const { evidenceExportId, checkpoint, outputDigest, recordCount } = claims;
  return sha256(
    encodeEvidenceExportCompletedData({
      evidenceExportId,
      checkpoint,
      outputDigest,
      recordCount,
    }),
  );
}
const claims: EvidenceExportCompletionClaims = {
  environmentId: 'local-evidence-export',
  participantId: source.participantId,
  privacyDomainId: source.privacyDomainId,
  evidenceExportId: source.evidenceExportId,
  startOperationId: source.startOperationId,
  causationId: source.causationId,
  requestDigest: source.requestDigest,
  checkpoint: source.checkpoint,
  outputDigest: source.outputDigest,
  recordCount: source.recordCount,
  dataDigest: dataDigest(source),
  eventId: id(6),
  sourceId: id(7),
  sequence: '18446744073709551615',
  recordedAtNs: '1800000000000001000',
  authoritySnapshotDigest: digest(3),
  signerTrustSnapshotDigest: digest(4),
  signerKeyId: evidenceKeyId(spki),
};
function completion(value = claims) {
  return {
    payload: encodeEvidenceExportCompletion(value),
    cose: signEvidenceExportCompletion(value, privateKey, spki),
    envelope: evidenceExportCompletionEnvelope(value),
  };
}
function input(): NotificationEvidenceExportSourceInput {
  return {
    scope: {
      participantId: source.participantId,
      privacyDomainId: source.privacyDomainId,
      streamId: source.streamId,
    },
    evidenceExportId: source.evidenceExportId,
    completion: completion(),
    trust: {
      spki: Buffer.from(spki),
      environmentId: claims.environmentId,
      sourceId: claims.sourceId,
      signerKeyId: claims.signerKeyId,
      authoritySnapshotDigest: claims.authoritySnapshotDigest,
      signerTrustSnapshotDigest: claims.signerTrustSnapshotDigest,
    },
    reservation: {
      eventId: claims.eventId,
      sequence: claims.sequence,
      recordedAtNs: claims.recordedAtNs,
    },
  };
}

// Unit projection fixtures only: the adapter and canonical source reader are real,
// as are codecs and cryptography. The query double cannot establish SQL provenance,
// tenant isolation, transaction fences or end-to-end acceptance; those remain in
// postgres-evidence-export and the owning completion/notification journeys.
function database(projected: unknown = { ...source }, rowCount = 1) {
  const query = vi.fn(async () => ({ rowCount, rows: [{ source: projected }] }));
  return { query, client: { query } as unknown as Pick<PoolClient, 'query'> };
}
async function rejected(value: unknown, reason: NotificationSourceReadError['reason']) {
  const db = database();
  await expect(
    readNotificationEvidenceExportSource(db.client, value as NotificationEvidenceExportSourceInput),
  ).rejects.toEqual(new NotificationSourceReadError(reason));
  expect(db.query).not.toHaveBeenCalled();
}

describe('evidence export notification source binding', () => {
  it('joins the governed source, exact registered envelope and real COSE, preserving bytes', async () => {
    const original = input();
    const db = database();
    const result = await readNotificationEvidenceExportSource(db.client, original);
    expect(db.query).toHaveBeenCalledExactlyOnceWith(
      'select openpc.evidence_export_completion_source($1::uuid) source',
      [source.evidenceExportId],
    );
    expect(result).toEqual({ source, claims, ...original.completion });
    expect(result.payload).not.toBe(original.completion.payload);
    expect(result.cose).not.toBe(original.completion.cose);
    expect(result.envelope).toMatchObject({
      time: '2027-01-15T08:00:00.000001Z',
      sequence: '18446744073709551615',
      correlationid: source.startOperationId,
      causationid: source.causationId,
      source: `urn:openpc:service:${claims.sourceId}`,
      data: { checkpoint: '9007199254740993' },
    });
    expect(Object.keys(result).sort()).toEqual(['claims', 'cose', 'envelope', 'payload', 'source']);
    expect(JSON.stringify(result.envelope)).not.toContain('SnapshotDigest');
    expect(result).not.toHaveProperty('spki');
    result.payload.fill(0);
    result.cose.fill(0);
    expect(original.completion.payload).toEqual(encodeEvidenceExportCompletion(claims));
    const replay = await readNotificationEvidenceExportSource(db.client, original);
    expect(replay.cose).toEqual(original.completion.cose);
  });

  it.each([
    ['environmentId', 'other-environment'],
    ['sourceId', id(90)],
    ['signerKeyId', digest(90)],
    ['authoritySnapshotDigest', digest(90)],
    ['signerTrustSnapshotDigest', digest(90)],
  ] as const)('requires independently supplied trust binding %s', async (key, value) => {
    const valueInput = input();
    valueInput.trust[key] = value;
    await rejected(valueInput, 'BINDING_MISMATCH');
  });

  it.each([
    ['eventId', id(90)],
    ['sequence', '1'],
    ['recordedAtNs', '1800000000000002000'],
  ] as const)('requires the original reservation %s', async (key, value) => {
    const valueInput = input();
    valueInput.reservation[key] = value;
    await rejected(valueInput, 'BINDING_MISMATCH');
  });

  it('rejects foreign participant, privacy domain and export before SQL', async () => {
    for (const key of ['participantId', 'privacyDomainId'] as const) {
      const value = input();
      value.scope[key] = id(90);
      await rejected(value, 'BINDING_MISMATCH');
    }
    await rejected({ ...input(), evidenceExportId: id(90) }, 'BINDING_MISMATCH');
  });

  it('rejects wrong keys, altered signatures, framing and copied proofs', async () => {
    const wrongKey = input();
    wrongKey.trust.spki = otherSpki;
    await rejected(wrongKey, 'INVALID_SIGNATURE');
    const altered = input();
    const proof = altered.completion.cose;
    proof[proof.length - 1] = proof[proof.length - 1]! ^ 1;
    await rejected(altered, 'INVALID_SIGNATURE');
    for (const cose of [Buffer.alloc(0), Buffer.from([0xd2]), Buffer.alloc(70_000)]) {
      const value = input();
      value.completion.cose = cose;
      await rejected(value, 'INVALID_SIGNATURE');
    }
    const wrongPurpose = input();
    wrongPurpose.completion.cose = signConsumerCose(
      { ...evidenceExportCoseContext, purposeCode: 349 },
      privateKey,
      spki,
      wrongPurpose.completion.payload,
    );
    await rejected(wrongPurpose, 'INVALID_SIGNATURE');
    const copied = input();
    copied.completion.cose = completion({ ...claims, eventId: id(90) }).cose;
    await rejected(copied, 'INVALID_SIGNATURE');
    const alteredPayload = input();
    alteredPayload.completion.payload = encodeEvidenceExportCompletion({
      ...claims,
      requestDigest: digest(90),
    });
    await rejected(alteredPayload, 'INVALID_SIGNATURE');
  });

  it.each([
    ['participantId', id(90)],
    ['privacyDomainId', id(90)],
    ['streamId', 'FOREIGN'],
    ['evidenceExportId', id(90)],
    ['startOperationId', id(90)],
    ['causationId', id(90)],
    ['requestDigest', digest(90)],
    ['checkpoint', '9007199254740994'],
    ['outputDigest', digest(90)],
    ['recordCount', '2'],
  ] as const)('requires governed source projection %s', async (key, value) => {
    const db = database({ ...source, [key]: value });
    await expect(readNotificationEvidenceExportSource(db.client, input())).rejects.toEqual(
      new NotificationSourceReadError('SOURCE_MISMATCH'),
    );
  });

  it.each([
    ['environmentId', 'other-environment', 'BINDING_MISMATCH'],
    ['sourceId', id(90), 'BINDING_MISMATCH'],
    ['eventId', id(90), 'BINDING_MISMATCH'],
    ['sequence', '1', 'BINDING_MISMATCH'],
    ['recordedAtNs', '1800000000000002000', 'BINDING_MISMATCH'],
    ['authoritySnapshotDigest', digest(90), 'BINDING_MISMATCH'],
    ['signerTrustSnapshotDigest', digest(90), 'BINDING_MISMATCH'],
    ['participantId', id(90), 'BINDING_MISMATCH'],
    ['privacyDomainId', id(90), 'BINDING_MISMATCH'],
    ['evidenceExportId', id(90), 'BINDING_MISMATCH'],
    ['startOperationId', id(90), 'SOURCE_MISMATCH'],
    ['causationId', id(90), 'SOURCE_MISMATCH'],
    ['requestDigest', digest(90), 'SOURCE_MISMATCH'],
    ['checkpoint', '9007199254740994', 'SOURCE_MISMATCH'],
    ['outputDigest', digest(90), 'SOURCE_MISMATCH'],
    ['recordCount', '2', 'SOURCE_MISMATCH'],
  ] as const)(
    'does not accept a validly re-signed replay changing %s',
    async (key, value, reason) => {
      const changed = { ...claims, [key]: value };
      changed.dataDigest = dataDigest(changed);
      const valueInput = input();
      valueInput.completion = completion(changed);
      await expect(
        readNotificationEvidenceExportSource(database().client, valueInput),
      ).rejects.toEqual(new NotificationSourceReadError(reason));
    },
  );

  it('binds every envelope member, including optional members, without narrowing the public parser', async () => {
    const event = evidenceExportCompletionEnvelope(claims);
    const changes = {
      id: id(90),
      source: `urn:openpc:resource:${claims.sourceId}`,
      subject: `urn:openpc:resource:${id(90)}`,
      time: '2027-01-15T08:00:00.000002Z',
      participantid: `urn:openpc:participant:${id(90)}`,
      privacydomainid: `urn:openpc:privacy-domain:${id(90)}`,
      correlationid: id(90),
      causationid: id(90),
      sequence: '0',
      datadigest: digest(90),
      authoritygeneration: digest(90),
      data: { ...event.data, recordCount: '2' },
    };
    for (const [key, value] of Object.entries(changes)) {
      const envelope = { ...event, [key]: value };
      expect(() => parseEvidenceExportCompletedEnvelope(envelope)).not.toThrow();
      const valueInput = input();
      valueInput.completion.envelope = envelope;
      await rejected(valueInput, 'ENVELOPE_MISMATCH');
    }
    for (const key of ['privacydomainid', 'causationid'] as const) {
      const envelope: Record<string, unknown> = { ...event };
      delete envelope[key];
      expect(() => parseEvidenceExportCompletedEnvelope(envelope)).not.toThrow();
      const valueInput = input();
      valueInput.completion.envelope = envelope;
      await rejected(valueInput, 'ENVELOPE_MISMATCH');
    }
    const reordered = input();
    reordered.completion.envelope = Object.fromEntries(Object.entries(event).reverse());
    await expect(
      readNotificationEvidenceExportSource(database().client, reordered),
    ).resolves.toBeDefined();
  });

  it('returns only typed secret-free failures for bounded malformed input', async () => {
    for (const value of [null, [], {}, { ...input(), unknown: 'SECRET' }])
      await rejected(value, 'INVALID_INPUT');
    for (const field of ['scope', 'trust', 'reservation', 'completion'] as const)
      await rejected({ ...input(), [field]: null }, 'INVALID_INPUT');
    for (const sequence of ['0', '01', '-1', '1e2', '18446744073709551616', '9'.repeat(256)]) {
      const value = input();
      value.reservation.sequence = sequence;
      await rejected(value, 'INVALID_INPUT');
    }
    for (const payload of [Buffer.alloc(0), Buffer.from([0xff]), Buffer.alloc(65_537)]) {
      const value = input();
      value.completion.payload = payload;
      await rejected(value, 'INVALID_COMPLETION');
    }
    for (const envelope of [
      null,
      {},
      { ...evidenceExportCompletionEnvelope(claims), secret: 'SECRET' },
    ]) {
      const value = input();
      value.completion.envelope = envelope;
      await rejected(value, 'ENVELOPE_MISMATCH');
    }
    const value = input();
    value.trust.spki = Buffer.from('SECRET invalid SPKI');
    await rejected(value, 'INVALID_SIGNATURE');
  });

  it('requires exactly one real source result and hides database diagnostics', async () => {
    for (const count of [0, 2])
      await expect(
        readNotificationEvidenceExportSource(database(source, count).client, input()),
      ).rejects.toEqual(new NotificationSourceReadError('SOURCE_MISMATCH'));
    for (const projected of [null, {}, { ...source, secret: 'SECRET' }])
      await expect(
        readNotificationEvidenceExportSource(database(projected).client, input()),
      ).rejects.toEqual(new NotificationSourceReadError('SOURCE_MISMATCH'));
    const db = database();
    db.query.mockRejectedValueOnce(new Error('SECRET database statement and credentials'));
    await expect(readNotificationEvidenceExportSource(db.client, input())).rejects.toEqual(
      new NotificationSourceReadError('SOURCE_UNAVAILABLE'),
    );
  });

  it('snapshots original signed bytes and input metadata before the database await', async () => {
    const value = input();
    const original = {
      payload: Buffer.from(value.completion.payload),
      cose: Buffer.from(value.completion.cose),
    };
    const db = database();
    db.query.mockImplementationOnce(async () => {
      value.completion.payload.fill(0);
      value.completion.cose.fill(0);
      value.scope.streamId = 'FOREIGN';
      value.reservation.sequence = '1';
      value.trust.spki.fill(0);
      (value.completion.envelope as Record<string, unknown>).sequence = '1';
      return { rowCount: 1, rows: [{ source: { ...source } }] };
    });
    const result = await readNotificationEvidenceExportSource(db.client, value);
    expect(result.payload).toEqual(original.payload);
    expect(result.cose).toEqual(original.cose);
    expect(result.envelope.sequence).toBe(claims.sequence);
    expect(result.source.streamId).toBe(source.streamId);
  });
});
