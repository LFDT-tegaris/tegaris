import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  encodeFactConsumerProfile,
  signFactConsumerProfile,
  type FactConsumerProfile,
} from '@openpc/security-kernel';
import {
  encodeFactConsumerFailure,
  type FactConsumerFailure,
} from '../../../../packages/security-kernel/src/fact-consumer/failure.js';
import { signFactConsumerFailure } from '../../../../packages/security-kernel/src/fact-consumer/failure-cose.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { verifyFactFailureSource, type FactFailureSourceRow } from './fact-failure-source.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (byte: string) => `sha256:${byte.repeat(32)}`;
function key() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: pair.publicKey.export({ format: 'der', type: 'spki' }),
  };
}
function fixture() {
  const issuer = key(),
    signer = key(),
    now = 1780000000000;
  const scope = { participantId: id(1), privacyDomainId: id(2), streamId: 'fleet-failures' };
  const profile: FactConsumerProfile = {
    environmentId: 'test',
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    profileId: 'failures',
    revision: '1',
    consumerId: 'LS-FLEET-CONTROL',
    subscriptionId: 'SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1',
    validFromMs: now - 1000,
    validUntilMs: now + 1000,
    issuerKeyId: sha256(issuer.spki),
    workloadCredentialId: id(3),
    workloadCredentialEpoch: '1',
    databaseRole: 'openpc_local_control_worker',
    maximumAttempts: 3,
    initialBackoffMs: 1,
    maximumBackoffMs: 100,
  };
  const profilePayload = encodeFactConsumerProfile(profile);
  const profileCose = signFactConsumerProfile(issuer.privateKey, issuer.spki, profilePayload);
  const envelope = { id: id(4), sequence: '1' };
  const event = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    eventId: id(4),
    candidateId: id(5),
    generationId: id(6),
    factType: 'CONTRACT_STATE_CALL' as const,
    sequence: '1',
    consumerId: 'LS-FLEET-CONTROL' as const,
    envelope,
    envelopeDigest: sha256(envelope),
    dataDigest: digest('11'),
  };
  const material = Buffer.from(canonicalJson(event));
  const receipt: FactConsumerFailure = {
    environmentId: profile.environmentId,
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    consumerId: profile.consumerId,
    subscriptionId: profile.subscriptionId,
    eventId: event.eventId,
    candidateId: event.candidateId,
    generationId: event.generationId,
    factType: event.factType,
    sequence: event.sequence,
    envelopeDigest: event.envelopeDigest,
    dataDigest: event.dataDigest,
    materialDigest: sha256(material),
    initialProfileDigest: sha256(profileCose),
    currentProfileDigest: sha256(profileCose),
    failedAttempts: 3,
    maximumAttempts: 3,
    leaseGeneration: '4',
    workloadCredentialId: profile.workloadCredentialId,
    workloadCredentialEpoch: profile.workloadCredentialEpoch,
    workloadPrincipalId: id(7),
    workItemId: id(8),
    problem: 'PC-DATA-6005',
    recordedAtMs: now,
    signerKeyId: sha256(signer.spki),
    receiptId: id(9),
  };
  const payload = encodeFactConsumerFailure(receipt),
    cose = signFactConsumerFailure(signer.privateKey, signer.spki, payload);
  const row: FactFailureSourceRow = {
    claims: receipt,
    payload,
    cose,
    receiptId: receipt.receiptId,
    receiptDigest: sha256(cose),
    outboxDigest: sha256(cose),
    workItemId: receipt.workItemId,
    material,
    materialDigest: Buffer.from(receipt.materialDigest.slice(7), 'hex'),
    eventId: receipt.eventId,
    candidateId: receipt.candidateId,
    generationId: receipt.generationId,
    factType: receipt.factType,
    sequence: receipt.sequence,
    initialProfileDigest: receipt.initialProfileDigest,
    failedAttempts: 3,
    maximumAttempts: 3,
    leaseGeneration: '4',
    historyValid: true,
    committedAtMs: String(now + 1),
    signerKeyId: receipt.signerKeyId,
    signerSpki: signer.spki,
    signerEnvironment: 'test',
    signerRole: 'FACT_CONSUMER_FAILURE',
    signerPurpose: '344',
    signerDatabaseRole: profile.databaseRole,
    signerCredentialId: profile.workloadCredentialId,
    signerCredentialEpoch: profile.workloadCredentialEpoch,
    signerValidFrom: String(now - 1000),
    signerValidUntil: String(now + 1000),
    profile,
    profilePayload,
    profileCose,
    profileIssuer: issuer.spki,
  };
  return { scope, row };
}

describe('historical Fleet failure custody source', () => {
  it('preserves original failure bytes and time after the signing window, without an ACK or authority', () => {
    const { scope, row } = fixture();
    const source = verifyFactFailureSource(row, scope);
    expect(source).toEqual({
      recordId: row.receiptId,
      evidenceClass: 'EFFECT',
      sourceFormat: 'COSE_SIGN1_24007_1_344',
      occurredAt: '2026-05-28T20:26:40.000000Z',
      receiptDigest: sha256(row.cose),
      receiptBase64: row.cose.toString('base64'),
    });
  });
  it.each([
    { receiptId: id(99) },
    { workItemId: id(99) },
    { eventId: id(99) },
    { candidateId: id(99) },
    { generationId: id(99) },
    { factType: 'RELATIONSHIP' },
    { sequence: '2' },
    { outboxDigest: null },
    { receiptDigest: digest('22') },
    { initialProfileDigest: digest('22') },
    { failedAttempts: 2 },
    { maximumAttempts: 4 },
    { leaseGeneration: '5' },
    { historyValid: false },
    { signerEnvironment: 'foreign' },
    { signerRole: 'PROFILE_ISSUER' },
    { signerPurpose: '343' },
    { signerCredentialId: id(99) },
    { signerCredentialEpoch: '2' },
    { signerDatabaseRole: 'foreign' },
    { signerValidFrom: '1780000000001' },
    { signerValidUntil: '1780000000001' },
    { committedAtMs: '1779999999999' },
    { committedAtMs: '1780000001000' },
  ])('rejects changed retained binding %j', (patch) => {
    const { scope, row } = fixture();
    expect(() => verifyFactFailureSource({ ...row, ...patch }, scope)).toThrow('integrity');
  });
  it('rejects crossed scope, forged signatures, missing trust and altered original material', () => {
    const { scope, row } = fixture();
    expect(() => verifyFactFailureSource(row, { ...scope, privacyDomainId: id(99) })).toThrow(
      'integrity',
    );
    for (const field of [
      'payload',
      'cose',
      'material',
      'materialDigest',
      'signerSpki',
      'profilePayload',
      'profileCose',
      'profileIssuer',
    ] as const) {
      const corrupted = Buffer.from(row[field]);
      corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1]! ^ 1;
      expect(() => verifyFactFailureSource({ ...row, [field]: corrupted }, scope)).toThrow(
        'integrity',
      );
    }
    expect(() =>
      verifyFactFailureSource({ ...row, claims: { ...row.claims, workItemId: id(99) } }, scope),
    ).toThrow('integrity');
    expect(() =>
      verifyFactFailureSource({ ...row, profile: null as unknown as FactConsumerProfile }, scope),
    ).toThrow('integrity');
  });
});
