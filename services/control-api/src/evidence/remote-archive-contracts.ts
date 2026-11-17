import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { vaultObject, type VaultObject } from './local-vault.js';
import { vaultHold } from './hold-vault.js';
import { digest, inspectSegment, MAX_SEGMENT_BYTES, sequence } from './segment.js';
import {
  protectedCiphertext,
  protectedVaultObject,
  type ProtectedVaultObject,
} from './protected-custody-contracts.js';

/** Interface observations are neither SQL admission nor external WORM qualification. */
export class RemoteArchiveError extends Error {
  constructor(
    readonly code:
      'INVALID' | 'INTEGRITY' | 'CONFLICT' | 'UNAVAILABLE' | 'AMBIGUOUS' | 'PROTECTION_MISMATCH',
  ) {
    super(`Remote archive ${code.toLowerCase()}`);
  }
}

const reference = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u);
export const remoteVersionId = z
  .string()
  .min(1)
  .max(1024)
  .refine(
    (value) =>
      value !== 'null' &&
      ![...value].some((char) => char.charCodeAt(0) <= 32 || char.charCodeAt(0) === 127),
  );

export const remoteArchiveProfile = z
  .strictObject({
    profileId: reference,
    sinkId: reference,
    endpoint: z.url(),
    transport: z.enum(['HTTPS', 'LOOPBACK_TEST']),
    region: z.string().regex(/^[a-z0-9-]{1,63}$/u),
    bucket: z.string().regex(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u),
    expectedBucketOwner: z.string().regex(/^[0-9]{12}$/u),
    // A constrained path-style profile avoids URL normalization and alias ambiguity.
    prefix: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/u),
    lockMode: z.literal('COMPLIANCE'),
    requestTimeoutMs: z.number().int().min(100).max(30000),
    maxVersionPages: z.number().int().min(1).max(32),
  })
  .refine((profile) => {
    const url = new URL(profile.endpoint);
    return (
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      url.pathname === '/' &&
      (profile.transport === 'HTTPS'
        ? url.protocol === 'https:'
        : url.protocol === 'http:' && url.hostname === '127.0.0.1')
    );
  });
export type RemoteArchiveProfile = z.infer<typeof remoteArchiveProfile>;

export type RemoteArchiveSource =
  | Readonly<{ kind: 'SEGMENT'; object: VaultObject }>
  | Readonly<{ kind: 'PROTECTED_PROOF'; object: ProtectedVaultObject }>;

// Reuse the local owner instead of maintaining another segment identity schema.
const segmentObject = z.custom<VaultObject>((value) => {
  try {
    const object = value as VaultObject;
    const parsed = vaultObject(
      object.sinkId,
      { ...object, version: 'OPENPC_EVIDENCE_SEGMENT_V1' },
      object.objectDigest,
    );
    return (
      canonicalJson(parsed) === canonicalJson(object) &&
      BigInt(object.firstSequence) > 0n &&
      BigInt(object.throughSequence) >= BigInt(object.firstSequence) &&
      BigInt(object.throughSequence) - BigInt(object.firstSequence) < 128n &&
      (object.firstSequence === '1') === (object.previousSegmentDigest === null)
    );
  } catch {
    return false;
  }
});
const source = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('SEGMENT'), object: segmentObject }),
  z.strictObject({ kind: z.literal('PROTECTED_PROOF'), object: protectedVaultObject }),
]);

/** A complete, authoritative lifecycle snapshot, not an individual hold toggle.
 * The owner must include every matching rule and fence it across external I/O.
 * The S3 boolean observes effective protection; it does not prove this rule set.
 */
export const archiveProtection = z
  .strictObject({
    revision: sequence.refine((value) => BigInt(value) > 0n),
    rules: z.array(vaultHold).max(1024),
  })
  .refine((value) =>
    value.rules.every((rule, index) => index === 0 || rule.holdId > value.rules[index - 1]!.holdId),
  );
export type ArchiveProtection = z.infer<typeof archiveProtection>;
export const remoteArchiveIntent = z.strictObject({
  intentId: z.uuidv7(),
  profileDigest: digest,
  source,
  payloadDigest: digest,
  payloadBytes: z.number().int().min(1).max(MAX_SEGMENT_BYTES),
  initialProtection: archiveProtection,
});
export type RemoteArchiveIntent = z.infer<typeof remoteArchiveIntent>;
export const remoteArchiveLocator = z.strictObject({
  sinkId: reference,
  profileDigest: digest,
  bucket: remoteArchiveProfile.shape.bucket,
  key: z.string().regex(/^[a-zA-Z0-9_-]{1,64}\/(segment|proof)\/[0-9a-f]{64}$/u),
  versionId: remoteVersionId,
});
export type RemoteArchiveLocator = z.infer<typeof remoteArchiveLocator>;

export const remoteArchiveReceipt = z.strictObject({
  version: z.literal('OPENPC_REMOTE_ARCHIVE_RECEIPT_V1'),
  intent: remoteArchiveIntent,
  intentDigest: digest,
  locator: remoteArchiveLocator,
  assurance: z.literal('REMOTE_INTERFACE_VERIFIED'),
  providerQualification: z.literal('NOT_ESTABLISHED'),
  observedRetention: z.strictObject({
    mode: z.literal('COMPLIANCE'),
    retainUntil: z.iso.datetime(),
  }),
  protection: archiveProtection,
  protectionDigest: digest,
  observedLegalHold: z.enum(['ON', 'OFF']),
  receiptDigest: digest,
});
export type RemoteArchiveReceipt = z.infer<typeof remoteArchiveReceipt>;

export type ArchiveAttemptBinding = Readonly<{
  attemptId: string;
  intent: RemoteArchiveIntent;
  intentDigest: string;
  action: 'PUT' | 'PROTECTION';
  locator: RemoteArchiveLocator | null;
  protection: ArchiveProtection;
  protectionDigest: string;
}>;

export interface ArchiveDispatchWindow {
  signal: AbortSignal;
  /** Monotonic deadline derived from current database admission, not wall-clock credentials. */
  deadlineMs: number;
}

/** REQUIRED integration boundary; this module supplies no implementation.
 * The real owner must:
 * - reload the original intent/attempt under its scope and lifecycle fence;
 * - admit current aggregate holds and any approved release; serialize peers;
 * - commit STARTED before invoking perform('INITIAL_SEND'), exactly once;
 * - invoke only RECONCILE for an already STARTED/AMBIGUOUS attempt;
 * - retain the fence across perform, persist its exact receipt or ambiguity, and
 *   atomically gate subsequent checkpoints on required complete hold coverage.
 * A callback, structural binding or unit-test stub is NOT proof of these SQL,
 * governance, signing, outbox or restart obligations. No public caller may supply it.
 * A lost owner commit must be reconciled by that owner before returning success.
 */
export interface RemoteArchiveAttemptOwner {
  run(
    binding: ArchiveAttemptBinding,
    perform: (
      dispatch: 'INITIAL_SEND' | 'RECONCILE',
      window?: ArchiveDispatchWindow,
    ) => Promise<RemoteArchiveReceipt>,
  ): Promise<RemoteArchiveReceipt>;
}

export function protectionState(protection: ArchiveProtection): 'ON' | 'OFF' {
  return archiveProtection.parse(protection).rules.some((rule) => rule.state === 'ACTIVE')
    ? 'ON'
    : 'OFF';
}
export function retainUntil(intent: RemoteArchiveIntent) {
  return intent.source.kind === 'SEGMENT'
    ? intent.source.object.retentionUntil
    : intent.source.object.retainUntil;
}
export function archiveKey(profile: RemoteArchiveProfile, intent: RemoteArchiveIntent) {
  const kind = intent.source.kind === 'SEGMENT' ? 'segment' : 'proof';
  // Deliberately excludes attempt/intent IDs: a new request cannot replace the
  // same business object's original archive with a differently named copy.
  const object = intent.source.object;
  const identity =
    intent.source.kind === 'SEGMENT'
      ? { streamId: intent.source.object.streamId, segmentId: intent.source.object.segmentId }
      : {
          objectRef: intent.source.object.objectRef,
          objectVersion: intent.source.object.objectVersion,
        };
  return `${profile.prefix}/${kind}/${sha256({
    sinkId: object.sinkId,
    participantId: object.participantId,
    privacyDomainId: object.privacyDomainId,
    ...identity,
  }).slice(7)}`;
}
export function validateArchivePayload(intent: RemoteArchiveIntent, bytes: Buffer) {
  if (bytes.length !== intent.payloadBytes || sha256(bytes) !== intent.payloadDigest)
    throw new RemoteArchiveError('INTEGRITY');
  try {
    if (intent.source.kind === 'SEGMENT') {
      const inspected = inspectSegment(bytes);
      const expected = vaultObject(
        intent.source.object.sinkId,
        inspected.header,
        inspected.objectDigest,
      );
      if (canonicalJson(expected) !== canonicalJson(intent.source.object))
        throw new RemoteArchiveError('INTEGRITY');
    } else {
      const payload = protectedCiphertext.parse(JSON.parse(bytes.toString('utf8')));
      const object = intent.source.object;
      if (
        canonicalJson(payload) !== bytes.toString('utf8') ||
        sha256(payload) !== object.payloadDigest ||
        Buffer.from(payload.ciphertextBase64, 'base64').length !== object.ciphertextBytes ||
        Buffer.from(payload.ciphertextBase64, 'base64').toString('base64') !==
          payload.ciphertextBase64 ||
        Buffer.from(payload.nonceBase64, 'base64').toString('base64') !== payload.nonceBase64
      )
        throw new RemoteArchiveError('INTEGRITY');
    }
  } catch {
    throw new RemoteArchiveError('INTEGRITY');
  }
}

/** Exact microsecond comparison; never round a required retention deadline down. */
export function retentionMicros(value: string): bigint {
  const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,6}))?Z$/u.exec(value);
  if (!match || !z.iso.datetime({ offset: false }).safeParse(value).success)
    throw new RemoteArchiveError('INTEGRITY');
  return BigInt(Date.parse(`${match[1]}Z`)) * 1000n + BigInt((match[2] ?? '').padEnd(6, '0'));
}
