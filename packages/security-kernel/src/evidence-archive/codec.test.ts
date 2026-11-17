import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { evidenceKeyId, signReceiptCose } from '../business-transition/cose.js';
import {
  archiveDigest,
  encodeProtectedArchiveSinkProfile,
  decodeProtectedArchiveSinkProfile,
  encodeProtectedArchiveSinkReceipt,
  decodeProtectedArchiveSinkReceipt,
  type ProtectedArchiveSinkProfileClaims,
  type ProtectedArchiveSinkReceiptClaims,
  encodeArchiveSinkProfile,
  decodeArchiveSinkProfile,
  encodeArchiveSinkReceipt,
  decodeArchiveSinkReceipt,
  type ArchiveSinkProfileClaims,
  type ArchiveSinkReceiptClaims,
} from './codec.js';
import { signArchiveCose, verifyArchiveCose } from './cose.js';

function key() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    private: pair.privateKey.export({ type: 'pkcs8', format: 'der' }),
    public: pair.publicKey.export({ type: 'spki', format: 'der' }),
  };
}
const root = key(),
  worker = key();
const uuid = '018f0000-0000-7000-8000-000000000101';
const digest = archiveDigest(Buffer.from('actual input'));
function profile(): ArchiveSinkProfileClaims {
  return {
    environmentId: 'local',
    participantId: uuid,
    privacyDomainId: uuid,
    profileId: 'archive-profile',
    sinkId: 'remote-sink',
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 2000,
    transportProfileDigest: digest,
    receiptSignerSpki: worker.public.toString('hex'),
    streamIds: ['a', 'b'],
    issuerKeyId: evidenceKeyId(root.public),
    workloadCredentialId: uuid,
    workloadCredentialEpoch: '0',
    databaseRole: 'openpc_archive_worker',
  };
}
function receipt(): ArchiveSinkReceiptClaims {
  return {
    environmentId: 'local',
    participantId: uuid,
    privacyDomainId: uuid,
    receiptId: uuid,
    intentId: uuid,
    attemptId: uuid,
    signedProfileDigest: digest,
    observationDigest: digest,
    attemptBindingDigest: digest,
    objectDigest: digest,
    locatorDigest: digest,
    protectionDigest: digest,
    protectionRevision: '1',
    retentionUntilMicros: '18446744073709551615',
    recordedAtMicros: '1500000',
    previousReceiptDigest: null,
    action: 'PUT',
    signerKeyId: evidenceKeyId(worker.public),
    streamId: 'a',
    segmentId: uuid,
    throughSequence: '18446744073709551615',
    assurance: 'REMOTE_INTERFACE_VERIFIED',
    providerQualification: 'NOT_ESTABLISHED',
  };
}
it('round-trips complete canonical profile and receipt and keeps u64 precision', () => {
  expect(decodeArchiveSinkProfile(encodeArchiveSinkProfile(profile()))).toEqual(profile());
  expect(decodeArchiveSinkReceipt(encodeArchiveSinkReceipt(receipt()))).toEqual(receipt());
});
it('binds actual P-256 keys and keeps profile, archive receipt and business purposes separate', () => {
  const p = encodeArchiveSinkProfile(profile()),
    r = encodeArchiveSinkReceipt(receipt());
  const signedProfile = signArchiveCose('EvidenceSinkProfileV1', root.private, root.public, p);
  const signedReceipt = signArchiveCose('EvidenceSinkReceiptV1', worker.private, worker.public, r);
  expect(verifyArchiveCose('EvidenceSinkProfileV1', root.public, p, signedProfile)).toBe(true);
  expect(verifyArchiveCose('EvidenceSinkReceiptV1', worker.public, r, signedReceipt)).toBe(true);
  expect(verifyArchiveCose('EvidenceSinkProfileV1', worker.public, p, signedProfile)).toBe(false);
  expect(verifyArchiveCose('EvidenceSinkReceiptV1', root.public, r, signedReceipt)).toBe(false);
  expect(verifyArchiveCose('EvidenceSinkReceiptV1', root.public, p, signedProfile)).toBe(false);
  expect(verifyArchiveCose('EvidenceSinkProfileV1', worker.public, r, signedReceipt)).toBe(false);
  expect(
    verifyArchiveCose(
      'EvidenceSinkReceiptV1',
      worker.public,
      r,
      signReceiptCose(worker.private, worker.public, r),
    ),
  ).toBe(false);
  const corrupt = Buffer.from(signedReceipt);
  corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 1;
  expect(verifyArchiveCose('EvidenceSinkReceiptV1', worker.public, r, corrupt)).toBe(false);
  expect(() => signArchiveCose('EvidenceSinkReceiptV1', root.private, worker.public, r)).toThrow();
});
it('rejects missing, extra, reordered, duplicate, unsafe and role-merged profile inputs', () => {
  for (const field of Object.keys(profile())) {
    const value = { ...profile() } as Record<string, unknown>;
    delete value[field];
    expect(() => encodeArchiveSinkProfile(value as unknown as ArchiveSinkProfileClaims)).toThrow();
  }
  for (const patch of [
    { callerApproved: true },
    { streamIds: ['b', 'a'] },
    { streamIds: ['a', 'a'] },
    { streamIds: [] },
    { revision: '0' },
    { revision: '18446744073709551616' },
    { validUntilMs: 1000 },
    { validUntilMs: Number.MAX_SAFE_INTEGER + 1 },
    { workloadCredentialEpoch: '-1' },
    { issuerKeyId: evidenceKeyId(worker.public) },
    { receiptSignerSpki: '00' },
  ])
    expect(() => encodeArchiveSinkProfile({ ...profile(), ...patch })).toThrow();
});
it('rejects altered receipt semantics and noncanonical binary representations', () => {
  for (const patch of [
    { action: 'PROTECTION' },
    { previousReceiptDigest: digest },
    { throughSequence: '01' },
    { recordedAtMicros: '0' },
    { protectionRevision: '18446744073709551616' },
    { assurance: 'LOCAL_FSYNC_READBACK' },
    { providerQualification: 'CERTIFIED' },
    { unexpected: 1 },
  ])
    expect(() =>
      encodeArchiveSinkReceipt({ ...receipt(), ...patch } as ArchiveSinkReceiptClaims),
    ).toThrow();
  const p = encodeArchiveSinkProfile(profile()),
    r = encodeArchiveSinkReceipt(receipt());
  expect(() => decodeArchiveSinkProfile(Buffer.concat([p, Buffer.from([0])]))).toThrow();
  expect(() => decodeArchiveSinkReceipt(Buffer.concat([r, Buffer.from([0])]))).toThrow();
  expect(() => decodeArchiveSinkReceipt(p)).toThrow();
  expect(() => decodeArchiveSinkProfile(r)).toThrow();
  const protection = { ...receipt(), action: 'PROTECTION' as const, previousReceiptDigest: digest };
  expect(decodeArchiveSinkReceipt(encodeArchiveSinkReceipt(protection))).toEqual(protection);
});

it('separates protected profiles/receipts and binds exact immutable proof retention', () => {
  const p: ProtectedArchiveSinkProfileClaims = {
    ...profile(),
    sourceKind: 'PROTECTED_PROOF',
    retentionPolicy: 'SOURCE_DEADLINE_EXACT',
    heldExpiredPolicy: 'PRESERVE_EXISTING_ONLY',
  };
  const ordinary = receipt();
  const r = {
    ...ordinary,
    objectId: uuid,
    objectVersion: '1',
    payloadDigest: digest,
    sourceDigest: digest,
    proofRetainUntilMicros: ordinary.retentionUntilMicros,
  } as unknown as ProtectedArchiveSinkReceiptClaims & {
    segmentId?: string;
    throughSequence?: string;
  };
  delete r.segmentId;
  delete r.throughSequence;
  const payload = encodeProtectedArchiveSinkProfile(p),
    receiptPayload = encodeProtectedArchiveSinkReceipt(r);
  expect(decodeProtectedArchiveSinkProfile(payload)).toEqual(p);
  expect(decodeProtectedArchiveSinkReceipt(receiptPayload)).toEqual(r);
  const signed = signArchiveCose(
    'EvidenceProtectedSinkProfileV1',
    root.private,
    root.public,
    payload,
  );
  const signedReceipt = signArchiveCose(
    'EvidenceProtectedSinkReceiptV1',
    worker.private,
    worker.public,
    receiptPayload,
  );
  expect(verifyArchiveCose('EvidenceProtectedSinkProfileV1', root.public, payload, signed)).toBe(
    true,
  );
  expect(
    verifyArchiveCose(
      'EvidenceProtectedSinkReceiptV1',
      worker.public,
      receiptPayload,
      signedReceipt,
    ),
  ).toBe(true);
  expect(verifyArchiveCose('EvidenceSinkProfileV1', root.public, payload, signed)).toBe(false);
  expect(
    verifyArchiveCose('EvidenceSinkReceiptV1', worker.public, receiptPayload, signedReceipt),
  ).toBe(false);
  expect(() => decodeArchiveSinkProfile(payload)).toThrow();
  expect(() => decodeArchiveSinkReceipt(receiptPayload)).toThrow();
  expect(() => decodeProtectedArchiveSinkProfile(encodeArchiveSinkProfile(profile()))).toThrow();
  expect(() => decodeProtectedArchiveSinkReceipt(encodeArchiveSinkReceipt(ordinary))).toThrow();
  for (const patch of [
    { sourceKind: 'SEGMENT' },
    { retentionPolicy: 'EXTEND_TO_SEGMENT' },
    { heldExpiredPolicy: 'ALLOW_NEW_PUT' },
    { callerApproved: true },
  ])
    expect(() =>
      encodeProtectedArchiveSinkProfile({ ...p, ...patch } as ProtectedArchiveSinkProfileClaims),
    ).toThrow();
  for (const patch of [
    { proofRetainUntilMicros: '1' },
    { retentionUntilMicros: '1' },
    { objectVersion: '0' },
    { segmentId: uuid },
  ])
    expect(() => encodeProtectedArchiveSinkReceipt({ ...r, ...patch })).toThrow();
});
