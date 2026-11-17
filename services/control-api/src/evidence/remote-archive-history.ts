import type { PoolClient } from 'pg';
import { archiveDigest, encodeCanonicalCbor } from '@openpc/security-kernel';
import { sha256 } from '../configuration/digest.js';
import {
  RemoteArchiveAuthority,
  verifyArchiveHistory,
  verifyProtectedArchiveHistory,
  type SignedProtectedArchiveReceipt,
  type ArchiveHostTrust,
  type SignedArchiveProfile,
  type SignedArchiveReceipt,
} from './remote-archive-authority.js';
import {
  retentionMicros,
  RemoteArchiveError,
  type ArchiveAttemptBinding,
  type RemoteArchiveReceipt,
} from './remote-archive-contracts.js';
import type { EvidenceScope } from './segment.js';

export type ArchiveHistoryAttempt = {
  binding: ArchiveAttemptBinding;
  state: 'STARTED' | 'AMBIGUOUS' | 'OBSERVED';
  observation: RemoteArchiveReceipt | null;
};
const raw = (digest: string) => Buffer.from(digest.slice(7), 'hex');
const uuid = (value: string) => Buffer.from(value.replaceAll('-', ''), 'hex');

export function archiveReceiptReference(receipt: SignedArchiveReceipt) {
  return {
    kind: 'SIGNED_REMOTE_ARCHIVE_V1',
    receiptId: receipt.claims.receiptId,
    receiptDigest: receipt.receiptDigest,
    profileDigest: receipt.claims.signedProfileDigest,
    assurance: 'REMOTE_INTERFACE_VERIFIED',
    providerQualification: 'NOT_ESTABLISHED',
  } as const;
}
export function protectedArchiveReceiptReference(receipt: SignedProtectedArchiveReceipt) {
  return {
    kind: 'SIGNED_REMOTE_PROTECTED_ARCHIVE_V1',
    receiptId: receipt.claims.receiptId,
    receiptDigest: receipt.receiptDigest,
    profileDigest: receipt.claims.signedProfileDigest,
    assurance: 'REMOTE_INTERFACE_VERIFIED',
    providerQualification: 'NOT_ESTABLISHED',
  } as const;
}
export function archiveReceiptEvent(receipt: SignedArchiveReceipt | SignedProtectedArchiveReceipt) {
  const c = receipt.claims;
  return encodeCanonicalCbor(
    new Map<number, string | Buffer>([
      [0, 'pc.evidence.remote-custody.v1'],
      [1, uuid(c.participantId)],
      [2, uuid(c.privacyDomainId)],
      [3, uuid(c.receiptId)],
      [4, raw(receipt.receiptDigest)],
      [5, raw(c.signedProfileDigest)],
      [6, uuid(c.attemptId)],
    ]),
  );
}

async function loadSignedHistoryReceipt(
  sourceKind: 'SEGMENT' | 'PROTECTED_PROOF',
  client: PoolClient,
  scope: EvidenceScope,
  trust: ArchiveHostTrust,
  attempt: ArchiveHistoryAttempt,
) {
  const row = (
    await client.query<{
      payload: Buffer;
      cose: Buffer;
      receiptDigest: string;
      profilePayload: Buffer;
      profileCose: Buffer;
      transport: SignedArchiveProfile['transport'];
      issuerSpki: Buffer;
      event: Buffer;
      eventDigest: string;
    }>(
      `select r.payload,r.cose,r.receipt_digest as "receiptDigest",p.payload as "profilePayload",p.cose as "profileCose",p.transport,t.issuer_spki as "issuerSpki",o.event,o.event_digest as "eventDigest"
     from control.evidence_archive_receipt r join control.evidence_archive_profile p
      on (p.participant_id,p.privacy_domain_id,p.profile_digest)=(r.participant_id,r.privacy_domain_id,r.profile_digest)
     join control.evidence_archive_trust t on (t.participant_id,t.privacy_domain_id,t.environment_id,t.sink_id,t.issuer_key_id)
      =(p.participant_id,p.privacy_domain_id,p.environment_id,p.sink_id,p.issuer_key_id)
     join control.evidence_archive_outbox o on (o.participant_id,o.privacy_domain_id,o.receipt_id)=(r.participant_id,r.privacy_domain_id,r.receipt_id)
     where r.participant_id=$1 and r.privacy_domain_id=$2 and r.attempt_id=$3`,
      [scope.participantId, scope.privacyDomainId, attempt.binding.attemptId],
    )
  ).rows[0];
  if (!row) return null;
  if (row.issuerSpki.toString('hex') !== trust.issuerSpkiHex)
    throw new RemoteArchiveError('INTEGRITY');
  const verified = (
    sourceKind === 'SEGMENT' ? verifyArchiveHistory : verifyProtectedArchiveHistory
  )(
    trust,
    {
      transport: row.transport,
      payloadHex: row.profilePayload.toString('hex'),
      coseHex: row.profileCose.toString('hex'),
    },
    row.payload,
    row.cose,
  );
  const b = attempt.binding,
    c = verified.claims;
  if (
    verified.receiptDigest !== row.receiptDigest ||
    !row.event.equals(archiveReceiptEvent(verified)) ||
    archiveDigest(row.event) !== row.eventDigest ||
    attempt.state !== 'OBSERVED' ||
    !attempt.observation ||
    b.intent.source.kind !== sourceKind ||
    c.attemptBindingDigest !== sha256(b) ||
    c.observationDigest !== sha256(attempt.observation) ||
    c.attemptId !== b.attemptId ||
    c.intentId !== b.intent.intentId ||
    c.action !== b.action ||
    c.protectionDigest !== b.protectionDigest ||
    c.protectionRevision !== b.protection.revision ||
    c.locatorDigest !== sha256(attempt.observation.locator) ||
    c.retentionUntilMicros !==
      retentionMicros(attempt.observation.observedRetention.retainUntil).toString() ||
    c.objectDigest !== b.intent.source.object.objectDigest
  )
    throw new RemoteArchiveError('INTEGRITY');
  if (
    c.participantId !== scope.participantId ||
    c.privacyDomainId !== scope.privacyDomainId ||
    c.streamId !== scope.streamId ||
    (b.intent.source.kind === 'SEGMENT' && b.intent.source.object.streamId !== scope.streamId)
  )
    throw new RemoteArchiveError('INTEGRITY');
  if (b.intent.source.kind === 'SEGMENT') {
    if (
      !('segmentId' in c) ||
      c.segmentId !== b.intent.source.object.segmentId ||
      c.throughSequence !== b.intent.source.object.throughSequence
    )
      throw new RemoteArchiveError('INTEGRITY');
  } else {
    const object = b.intent.source.object;
    if (
      !('objectId' in c) ||
      c.objectId !== object.objectRef.slice(-36) ||
      c.objectVersion !== object.objectVersion ||
      c.payloadDigest !== object.payloadDigest ||
      c.sourceDigest !== sha256(object.source) ||
      c.proofRetainUntilMicros !== retentionMicros(object.retainUntil).toString()
    )
      throw new RemoteArchiveError('INTEGRITY');
  }
  return verified;
}
export async function loadArchiveHistoryReceipt(
  client: PoolClient,
  scope: EvidenceScope,
  trust: ArchiveHostTrust,
  attempt: ArchiveHistoryAttempt,
) {
  return (await loadSignedHistoryReceipt(
    'SEGMENT',
    client,
    scope,
    trust,
    attempt,
  )) as SignedArchiveReceipt | null;
}
export async function loadProtectedArchiveHistoryReceipt(
  client: PoolClient,
  scope: EvidenceScope,
  trust: ArchiveHostTrust,
  attempt: ArchiveHistoryAttempt,
) {
  return (await loadSignedHistoryReceipt(
    'PROTECTED_PROOF',
    client,
    scope,
    trust,
    attempt,
  )) as SignedProtectedArchiveReceipt | null;
}

/** Same atomic receipt/outbox persistence after each source-specific canonical admission. */
export async function persistArchiveReceipt(
  client: PoolClient,
  authority: RemoteArchiveAuthority,
  signed: SignedArchiveReceipt | SignedProtectedArchiveReceipt,
) {
  const capability = authority.commitCapability(signed),
    event = archiveReceiptEvent(signed);
  await client.query(
    `insert into control.evidence_archive_receipt(participant_id,privacy_domain_id,receipt_id,intent_id,attempt_id,
      profile_digest,previous_receipt_digest,receipt_digest,payload,cose,commit_nonce,commit_mac,recorded_at)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,timestamptz 'epoch'+($13||' microseconds')::interval)`,
    [
      signed.claims.participantId,
      signed.claims.privacyDomainId,
      signed.claims.receiptId,
      signed.claims.intentId,
      signed.claims.attemptId,
      signed.claims.signedProfileDigest,
      signed.claims.previousReceiptDigest,
      signed.receiptDigest,
      signed.payload,
      signed.cose,
      capability.nonce,
      capability.mac,
      signed.claims.recordedAtMicros,
    ],
  );
  await client.query(
    `insert into control.evidence_archive_outbox(participant_id,privacy_domain_id,receipt_id,event,event_digest) values($1,$2,$3,$4,$5)`,
    [
      signed.claims.participantId,
      signed.claims.privacyDomainId,
      signed.claims.receiptId,
      event,
      archiveDigest(event),
    ],
  );
}
