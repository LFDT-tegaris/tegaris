import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { protectedCustodyScope } from './protected-custody.js';
import { protectedCiphertext, protectedVaultObject } from './protected-custody-contracts.js';
import {
  archiveProtection,
  remoteArchiveIntent,
  retentionMicros,
  validateArchivePayload,
  RemoteArchiveError,
  type RemoteArchiveIntent,
} from './remote-archive-contracts.js';
import { sequence } from './segment.js';

const timestamp = z.iso.datetime({ precision: 6 });
const request = protectedCustodyScope.extend({
  objectRef: protectedVaultObject.shape.objectRef,
  sinkId: protectedVaultObject.shape.sinkId,
  originalIntentId: z.uuidv7().optional(),
});
const unknown = z.strictObject({
  state: z.literal('UNKNOWN'),
  reason: z.enum([
    'OBJECT_UNAVAILABLE',
    'PAYLOAD_UNAVAILABLE',
    'LINEAGE_UNAVAILABLE',
    'HOLD_LINEAGE_UNAVAILABLE',
    'TOO_MANY_HOLDS',
  ]),
});
const bound = z.strictObject({
  state: z.literal('BOUND'),
  object: protectedVaultObject,
  packet: protectedCiphertext.nullable(),
  payloadBytes: z.number().int().positive(),
  proofCreatedAt: timestamp,
  observedAt: timestamp,
  lineage: z.strictObject({
    evidenceId: protectedVaultObject.shape.objectRef,
    streamId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
    sequence: sequence.refine((value) => BigInt(value) > 0n),
    sourceReceiptDigest: protectedVaultObject.shape.payloadDigest,
  }),
  // This is the proof's own deadline. The signed archive profile is a separate,
  // integration-owned admission, including any held-but-expired proof policy.
  retention: z.strictObject({
    state: z.literal('UNKNOWN'),
    reason: z.enum(['PROFILE_NOT_ADMITTED', 'PROOF_DEADLINE_ELAPSED']),
  }),
  // No aggregate protection revision is allocated here. The common attempt
  // owner compares these rules with its original durable protection snapshot.
  rules: archiveProtection.shape.rules,
});
const factsSchema = z.discriminatedUnion('state', [unknown, bound]);
export type ProtectedRemoteArchiveSourceFacts = z.infer<typeof factsSchema>;
export type BoundProtectedRemoteArchiveSource = z.infer<typeof bound>;

/** Validate the SQL projection without treating it as authorization. Exported
 * for the small malformed-producer corpus; only the real SQL reader supplies
 * authoritative facts. No decryption or historical-assertion admission occurs. */
export function parseProtectedRemoteArchiveSource(
  value: unknown,
): ProtectedRemoteArchiveSourceFacts {
  const parsed = factsSchema.safeParse(value);
  if (!parsed.success) throw new RemoteArchiveError('INTEGRITY');
  const facts = parsed.data;
  if (facts.state === 'UNKNOWN') return facts;
  const { object, packet, lineage } = facts;
  const bytes = packet ? Buffer.from(canonicalJson(packet)) : null;
  const nonce = packet ? Buffer.from(packet.nonceBase64, 'base64') : null;
  const ciphertext = packet ? Buffer.from(packet.ciphertextBase64, 'base64') : null;
  const expired = retentionMicros(object.retainUntil) <= retentionMicros(facts.observedAt);
  if (
    (packet !== null &&
      (!bytes ||
        !nonce ||
        !ciphertext ||
        object.payloadDigest !== sha256(bytes) ||
        facts.payloadBytes !== bytes.length ||
        nonce.length !== 12 ||
        nonce.toString('base64') !== packet.nonceBase64 ||
        ciphertext.length !== object.ciphertextBytes ||
        ciphertext.toString('base64') !== packet.ciphertextBase64)) ||
    lineage.evidenceId !== object.source.evidenceId ||
    lineage.sourceReceiptDigest !== object.source.sourceReceiptDigest ||
    retentionMicros(facts.proofCreatedAt) >= retentionMicros(object.retainUntil) ||
    retentionMicros(facts.proofCreatedAt) > retentionMicros(facts.observedAt) ||
    facts.retention.reason !== (expired ? 'PROOF_DEADLINE_ELAPSED' : 'PROFILE_NOT_ADMITTED') ||
    !archiveProtection.safeParse({ revision: '1', rules: facts.rules }).success
  )
    throw new RemoteArchiveError('INTEGRITY');
  return facts;
}

/** Caller owns the real worker connection, transaction and participant lifecycle
 * fence for the complete attempt. This function neither starts/commits a
 * transaction nor locks, dispatches, signs, advances a checkpoint or deletes.
 * The SQL function independently checks role, action and exact request scope.
 * BOUND establishes source identity only: retention remains UNKNOWN until the
 * common signed-profile owner admits it. Missing payload never resurrects bytes.
 */
export async function loadProtectedRemoteArchiveSource(
  client: PoolClient,
  value: z.infer<typeof request>,
): Promise<ProtectedRemoteArchiveSourceFacts> {
  const parsed = request.safeParse(value);
  if (!parsed.success) throw new RemoteArchiveError('INVALID');
  const input = parsed.data;
  const result = await client.query<{ facts: unknown }>(
    'select openpc.protected_remote_archive_source($1,$2,$3,$4,$5) facts',
    [
      input.participantId,
      input.privacyDomainId,
      input.objectRef.slice(-36),
      input.sinkId,
      input.originalIntentId ?? null,
    ],
  );
  if (result.rowCount !== 1) throw new RemoteArchiveError('INTEGRITY');
  const facts = parseProtectedRemoteArchiveSource(result.rows[0]!.facts);
  if (
    facts.state === 'BOUND' &&
    (facts.object.participantId !== input.participantId ||
      facts.object.privacyDomainId !== input.privacyDomainId ||
      facts.object.objectRef !== input.objectRef ||
      facts.object.sinkId !== input.sinkId)
  )
    throw new RemoteArchiveError('INTEGRITY');
  return facts;
}

/** Compare a common-owner intent with a fresh source read; return exact packet
 * bytes, never a ready/eligible decision. The common owner MUST still admit the
 * original durable intent, signed profile, current aggregate protection and
 * transport attempt. An expired proof stays observable for preservation and
 * reconciliation; it cannot acquire fresh PUT authority from this comparison.
 */
export function protectedRemoteArchiveIntentBytes(
  value: ProtectedRemoteArchiveSourceFacts,
  input: RemoteArchiveIntent,
): Buffer {
  const facts = parseProtectedRemoteArchiveSource(value);
  if (facts.state !== 'BOUND' || facts.packet === null) throw new RemoteArchiveError('UNAVAILABLE');
  const parsed = remoteArchiveIntent.safeParse(input);
  if (!parsed.success || parsed.data.source.kind !== 'PROTECTED_PROOF')
    throw new RemoteArchiveError('INVALID');
  const intent = parsed.data;
  const bytes = Buffer.from(canonicalJson(facts.packet));
  if (
    canonicalJson(intent.source.object) !== canonicalJson(facts.object) ||
    intent.payloadDigest !== facts.object.payloadDigest ||
    intent.payloadBytes !== facts.payloadBytes
  )
    throw new RemoteArchiveError('INTEGRITY');
  validateArchivePayload(intent, bytes);
  return bytes;
}
