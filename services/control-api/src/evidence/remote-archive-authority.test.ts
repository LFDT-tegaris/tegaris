import { createHmac, generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  archiveDigest,
  encodeProtectedArchiveSinkProfile,
  type ProtectedArchiveSinkReceiptClaims,
  encodeArchiveSinkProfile,
  evidenceKeyId,
  signArchiveCose,
  type ArchiveSinkProfileClaims,
  type ArchiveSinkReceiptClaims,
} from '@openpc/security-kernel';
import { sha256 } from '../configuration/digest.js';
import {
  RemoteArchiveAuthority,
  verifyArchiveHistory,
  verifyProtectedArchiveHistory,
  type SignedArchiveProfile,
} from './remote-archive-authority.js';
import type { RemoteArchiveProfile } from './remote-archive-contracts.js';

function key() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    private: pair.privateKey.export({ type: 'pkcs8', format: 'der' }),
    public: pair.publicKey.export({ type: 'spki', format: 'der' }),
  };
}
const uuid = '018f0000-0000-7000-8000-000000000101';
const privacy = '018f0000-0000-7000-8000-000000000102';
const root = key();
const trust = {
  environmentId: 'local',
  participantId: uuid,
  privacyDomainId: privacy,
  sinkId: 'remote-sink',
  issuerSpkiHex: root.public.toString('hex'),
};
const transport: RemoteArchiveProfile = {
  profileId: 'archive-profile',
  sinkId: 'remote-sink',
  endpoint: 'http://127.0.0.1:9000',
  transport: 'LOOPBACK_TEST',
  region: 'test-1',
  bucket: 'archive',
  expectedBucketOwner: '123456789012',
  prefix: 'evidence',
  lockMode: 'COMPLIANCE',
  requestTimeoutMs: 1000,
  maxVersionPages: 4,
};
function fixture(revision = '1') {
  const worker = key(),
    commitKey = randomBytes(32);
  const claims: ArchiveSinkProfileClaims = {
    ...trust,
    revision,
    profileId: transport.profileId,
    validFromMs: 1000,
    validUntilMs: 2000,
    transportProfileDigest: sha256(transport),
    receiptSignerSpki: worker.public.toString('hex'),
    streamIds: ['a'],
    issuerKeyId: evidenceKeyId(root.public),
    workloadCredentialId: uuid,
    workloadCredentialEpoch: '0',
    databaseRole: 'archive_worker',
  };
  // The root pin is host configuration, never part of the signed payload.
  delete (claims as ArchiveSinkProfileClaims & { issuerSpkiHex?: string }).issuerSpkiHex;
  const payload = encodeArchiveSinkProfile(claims);
  const signed: SignedArchiveProfile = {
    transport: structuredClone(transport),
    payloadHex: payload.toString('hex'),
    coseHex: signArchiveCose('EvidenceSinkProfileV1', root.private, root.public, payload).toString(
      'hex',
    ),
  };
  const authority = new RemoteArchiveAuthority(trust, signed, worker.private, commitKey);
  const digest = archiveDigest(Buffer.from('persisted authoritative input'));
  const receipt: ArchiveSinkReceiptClaims = {
    environmentId: 'local',
    participantId: uuid,
    privacyDomainId: privacy,
    receiptId: uuid,
    intentId: uuid,
    attemptId: uuid,
    signedProfileDigest: authority.profileDigest,
    observationDigest: digest,
    attemptBindingDigest: digest,
    objectDigest: digest,
    locatorDigest: digest,
    protectionDigest: digest,
    protectionRevision: '1',
    retentionUntilMicros: '9000000',
    recordedAtMicros: '1500000',
    previousReceiptDigest: null,
    action: 'PUT',
    signerKeyId: evidenceKeyId(worker.public),
    streamId: 'a',
    segmentId: uuid,
    throughSequence: '8',
    assurance: 'REMOTE_INTERFACE_VERIFIED',
    providerQualification: 'NOT_ESTABLISHED',
  };
  return { worker, commitKey, claims, signed, authority, receipt };
}

it('pins installed root, transport, scope and separate receipt key before accepting authority', () => {
  const f = fixture();
  for (const changed of [
    { ...trust, issuerSpkiHex: key().public.toString('hex') },
    { ...trust, environmentId: 'other' },
    { ...trust, participantId: privacy },
    { ...trust, privacyDomainId: uuid },
    { ...trust, sinkId: 'other' },
  ])
    expect(
      () => new RemoteArchiveAuthority(changed, f.signed, f.worker.private, f.commitKey),
    ).toThrow();
  expect(
    () =>
      new RemoteArchiveAuthority(
        trust,
        { ...f.signed, transport: { ...transport, bucket: 'another' } },
        f.worker.private,
        f.commitKey,
      ),
  ).toThrow();
  expect(() => new RemoteArchiveAuthority(trust, f.signed, root.private, f.commitKey)).toThrow();
  expect(
    () => new RemoteArchiveAuthority(trust, f.signed, f.worker.private, Buffer.alloc(31)),
  ).toThrow();
  f.signed.transport.bucket = 'mutated';
  f.authority.profile.bucket = 'mutated';
  f.authority.claims.streamIds.push('other');
  expect(f.authority.profile.bucket).toBe('archive');
  expect(() => f.authority.sign({ ...f.receipt, streamId: 'other' })).toThrow();
});

it('verifies historical original profile after rotation while current authority rejects old receipts', () => {
  const original = fixture(),
    successor = fixture('2');
  const receipt = original.authority.sign(original.receipt);
  original.authority.close();
  expect(
    verifyArchiveHistory(trust, original.signed, receipt.payload, receipt.cose).receiptDigest,
  ).toBe(receipt.receiptDigest);
  expect(() => successor.authority.verify(receipt.payload, receipt.cose)).toThrow();
  expect(() =>
    verifyArchiveHistory(trust, successor.signed, receipt.payload, receipt.cose),
  ).toThrow();
  expect(() => original.authority.sign(original.receipt)).toThrow();
  expect(() => original.authority.commitCapability(receipt)).toThrow();
});

it('authenticates exact canonical signed bytes before issuing a fresh domain-bound commit capability', () => {
  const f = fixture(),
    signed = f.authority.sign(f.receipt);
  const proof = f.authority.commitCapability(signed),
    again = f.authority.commitCapability(signed);
  const expected = createHmac('sha256', f.commitKey)
    .update('OPENPC_REMOTE_ARCHIVE_CUSTODY_COMMIT_V1')
    .update(Buffer.from(uuid.replaceAll('-', ''), 'hex'))
    .update(Buffer.from(privacy.replaceAll('-', ''), 'hex'))
    .update(Buffer.from(signed.receiptDigest.slice(7), 'hex'))
    .update(Buffer.from(archiveDigest(signed.payload).slice(7), 'hex'))
    .update(Buffer.from(f.authority.profileDigest.slice(7), 'hex'))
    .update(Buffer.from(f.receipt.attemptBindingDigest.slice(7), 'hex'))
    .update(proof.nonce)
    .digest();
  expect(proof.mac.equals(expected)).toBe(true);
  expect(again.nonce.equals(proof.nonce)).toBe(false);
  const corrupt = Buffer.from(signed.cose);
  corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 1;
  expect(() => f.authority.commitCapability({ ...signed, cose: corrupt })).toThrow();
  for (const patch of [
    { recordedAtMicros: '999999' },
    { recordedAtMicros: '2000000' },
    { privacyDomainId: uuid },
    { environmentId: 'other' },
    { signedProfileDigest: sha256('wrong') },
    { signerKeyId: evidenceKeyId(root.public) },
  ])
    expect(() => f.authority.sign({ ...f.receipt, ...patch })).toThrow();
});

it('requires a protected-only signed profile and never widens segment authority', () => {
  const f = fixture();
  const payload = encodeProtectedArchiveSinkProfile({
    ...f.authority.claims,
    sourceKind: 'PROTECTED_PROOF',
    retentionPolicy: 'SOURCE_DEADLINE_EXACT',
    heldExpiredPolicy: 'PRESERVE_EXISTING_ONLY',
  });
  const signed = {
    ...f.signed,
    payloadHex: payload.toString('hex'),
    coseHex: signArchiveCose(
      'EvidenceProtectedSinkProfileV1',
      root.private,
      root.public,
      payload,
    ).toString('hex'),
  };
  const protectedAuthority = new RemoteArchiveAuthority(
    trust,
    signed,
    f.worker.private,
    f.commitKey,
  );
  const claims = {
    ...f.receipt,
    signedProfileDigest: protectedAuthority.profileDigest,
    objectId: uuid,
    objectVersion: '1',
    payloadDigest: sha256('packet'),
    sourceDigest: sha256('source'),
    proofRetainUntilMicros: f.receipt.retentionUntilMicros,
  } as unknown as ProtectedArchiveSinkReceiptClaims & {
    segmentId?: string;
    throughSequence?: string;
  };
  delete claims.segmentId;
  delete claims.throughSequence;
  expect(protectedAuthority.sourceKind).toBe('PROTECTED_PROOF');
  expect(protectedAuthority.protectedPolicy?.heldExpiredPolicy).toBe('PRESERVE_EXISTING_ONLY');
  expect(() => f.authority.signProtected(claims)).toThrow();
  expect(() => protectedAuthority.sign(f.receipt)).toThrow();
  const receipt = protectedAuthority.signProtected(claims);
  expect(protectedAuthority.verifyProtected(receipt.payload, receipt.cose)).toEqual(receipt);
  expect(protectedAuthority.commitCapability(receipt).mac).toHaveLength(32);
  expect(() => f.authority.commitCapability(receipt)).toThrow();
  expect(() => verifyArchiveHistory(trust, signed, receipt.payload, receipt.cose)).toThrow();
  expect(() =>
    verifyProtectedArchiveHistory(trust, f.signed, receipt.payload, receipt.cose),
  ).toThrow();
  protectedAuthority.close();
  expect(verifyProtectedArchiveHistory(trust, signed, receipt.payload, receipt.cose)).toEqual(
    receipt,
  );
  expect(() => protectedAuthority.signProtected(claims)).toThrow();
  f.authority.close();
});
