import type { PoolClient } from 'pg';
import { z } from 'zod';
import {
  decodeEvidenceExportCompletion,
  encodeEvidenceExportCompletion,
  evidenceExportCompletionEnvelope,
  verifyEvidenceExportCompletion,
  type EvidenceExportCompletionClaims,
} from '@openpc/security-kernel';
import { canonicalJson } from '../configuration/digest.js';
import {
  readEvidenceExportCompletionSource,
  type EvidenceExportCompletionSource,
} from '../evidence/export-completion-source.js';
import { evidenceScope, EvidenceCustodyError } from '../evidence/segment.js';
import {
  parseEvidenceExportCompletedEnvelope,
  type EvidenceExportCompletedEnvelope,
} from './event-input.js';

const sourceInput = z.strictObject({
  scope: evidenceScope,
  evidenceExportId: z.uuidv7(),
  completion: z.strictObject({
    payload: z.instanceof(Buffer),
    cose: z.instanceof(Buffer),
    envelope: z.unknown(),
  }),
  trust: z.strictObject({
    spki: z.instanceof(Buffer),
    environmentId: z.string(),
    sourceId: z.string(),
    signerKeyId: z.string(),
    authoritySnapshotDigest: z.string(),
    signerTrustSnapshotDigest: z.string(),
  }),
  reservation: z.strictObject({
    eventId: z.string(),
    sequence: z.string(),
    recordedAtNs: z.string(),
  }),
});

/** Trust and reservation MUST come from their independently validated owners,
 * never from the supplied envelope or decoded completion. The signed completion
 * is the owner's retained original record, not a newly signed reconstruction. */
export type NotificationEvidenceExportSourceInput = z.infer<typeof sourceInput>;

export interface BoundNotificationEvidenceExportSource {
  readonly source: EvidenceExportCompletionSource;
  readonly claims: EvidenceExportCompletionClaims;
  readonly envelope: EvidenceExportCompletedEnvelope;
  readonly payload: Buffer;
  readonly cose: Buffer;
}

export class NotificationSourceReadError extends Error {
  constructor(
    readonly reason:
      | 'INVALID_INPUT'
      | 'INVALID_COMPLETION'
      | 'INVALID_SIGNATURE'
      | 'BINDING_MISMATCH'
      | 'ENVELOPE_MISMATCH'
      | 'SOURCE_MISMATCH'
      | 'SOURCE_UNAVAILABLE',
  ) {
    super(`Notification source ${reason}`);
  }
}

function checked<T>(reason: NotificationSourceReadError['reason'], operation: () => T): T {
  try {
    return operation();
  } catch {
    // Neither parser/crypto diagnostics nor database errors may expose inputs.
    throw new NotificationSourceReadError(reason);
  }
}

/** Historical signature and source consistency only. The caller owns the real
 * scoped transaction and lifecycle fence through commit. This adapter reuses the
 * governed export-source query; it does not read nonexistent signed-record storage.
 * It grants no current producer/workload/key admission, publication, routing,
 * delivery readiness, durable replay admission or cursor advancement. */
export async function readNotificationEvidenceExportSource(
  client: Pick<PoolClient, 'query'>,
  value: NotificationEvidenceExportSourceInput,
): Promise<BoundNotificationEvidenceExportSource> {
  const input = checked('INVALID_INPUT', () => sourceInput.parse(value));
  const claims = checked('INVALID_COMPLETION', () =>
    decodeEvidenceExportCompletion(input.completion.payload),
  );
  const { spki, ...trustClaims } = input.trust;
  // Let the canonical codec validate every trusted field's exact wire contract.
  // No implicit source namespace, environment, timestamp or authority fallback.
  const boundPayload = checked('INVALID_INPUT', () =>
    encodeEvidenceExportCompletion({
      ...claims,
      ...trustClaims,
      ...input.reservation,
      participantId: input.scope.participantId,
      privacyDomainId: input.scope.privacyDomainId,
    }),
  );
  if (
    claims.evidenceExportId !== input.evidenceExportId ||
    !boundPayload.equals(input.completion.payload)
  )
    throw new NotificationSourceReadError('BINDING_MISMATCH');
  if (!verifyEvidenceExportCompletion(claims, spki, input.completion.cose))
    throw new NotificationSourceReadError('INVALID_SIGNATURE');
  const envelope = checked('ENVELOPE_MISMATCH', () =>
    parseEvidenceExportCompletedEnvelope(input.completion.envelope),
  );
  const expectedEnvelope = checked('INVALID_COMPLETION', () =>
    evidenceExportCompletionEnvelope(claims),
  );
  if (canonicalJson(envelope) !== canonicalJson(expectedEnvelope))
    throw new NotificationSourceReadError('ENVELOPE_MISMATCH');

  // Snapshot original bytes before yielding to SQL. Never re-sign or reconstruct
  // the proof, and do not return aliases that can mutate the retained input.
  const payload = Buffer.from(input.completion.payload);
  const cose = Buffer.from(input.completion.cose);
  let governed: Awaited<ReturnType<typeof readEvidenceExportCompletionSource>>;
  try {
    governed = await readEvidenceExportCompletionSource(
      client,
      input.scope,
      input.evidenceExportId,
    );
  } catch (error) {
    throw new NotificationSourceReadError(
      error instanceof EvidenceCustodyError && error.code === 'INTEGRITY'
        ? 'SOURCE_MISMATCH'
        : 'SOURCE_UNAVAILABLE',
    );
  }
  const { source } = governed;
  // The shared reader binds stream and scope and authenticates the original
  // governed start/output through its real SQL owner. Stream is not a signed
  // completion field; do not extend the registered schema to manufacture one.
  for (const key of [
    'participantId',
    'privacyDomainId',
    'evidenceExportId',
    'startOperationId',
    'causationId',
    'requestDigest',
    'checkpoint',
    'outputDigest',
    'recordCount',
  ] as const)
    if (claims[key] !== source[key]) throw new NotificationSourceReadError('SOURCE_MISMATCH');
  if (claims.dataDigest !== governed.dataDigest)
    throw new NotificationSourceReadError('SOURCE_MISMATCH');
  return { source, claims, envelope, payload, cose };
}
