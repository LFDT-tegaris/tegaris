import type { PoolClient } from 'pg';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import { readPreparedEvidenceExportCompletion } from '../evidence/export-completion.js';
import { validateEvidenceExportProducerInstallation } from '../evidence/export-producer-installation.js';
import { evidenceScope } from '../evidence/segment.js';
import {
  readNotificationEvidenceExportSource,
  type BoundNotificationEvidenceExportSource,
} from './source-reader.js';

const selector = z.strictObject({
  scope: evidenceScope.strict(),
  evidenceExportId: z.uuidv7(),
  eventId: z.uuidv7(),
});
export type PublishedNotificationSourceSelector = z.infer<typeof selector>;

export class PublishedNotificationSourceError extends Error {
  constructor(
    readonly reason: 'INVALID_SELECTOR' | 'CONTEXT_UNAVAILABLE' | 'PUBLICATION_UNAVAILABLE',
  ) {
    super(`Notification published source ${reason}`);
  }
}

/** Historical integrity only, using the original installed trust and reservation.
 * The caller owns an explicit runtime transaction, matching export-action context
 * and the transaction-scoped Evidence lifecycle fence through completion. No role,
 * context, transaction boundary or authority is installed here. The existing SQL
 * checker requires openpc_control_runtime; worker/reader access is NOT implied.
 * This read grants no current producer, routing, KMS, occurrence or delivery right.
 */
export async function readPublishedNotificationSource(
  client: PoolClient,
  value: PublishedNotificationSourceSelector,
): Promise<BoundNotificationEvidenceExportSource> {
  const parsed = selector.safeParse(value);
  if (!parsed.success) throw new PublishedNotificationSourceError('INVALID_SELECTOR');
  const { scope, evidenceExportId, eventId } = parsed.data;
  try {
    // SAVEPOINT fails outside an explicit transaction. It neither starts nor ends
    // the caller's transaction; SQL errors remain for the owner to roll back.
    await client.query('savepoint notification_published_source_context');
    await client.query('release savepoint notification_published_source_context');
    const context = await client.query<{ allowed: boolean }>(
      `select openpc.assert_request_context(true),
       not r.rolsuper and not r.rolbypassrls
       and current_setting('row_security')='on'
       and pg_has_role(current_user,'openpc_control_runtime','USAGE')
       and openpc.current_participant_id()=$1::uuid
       and openpc.current_privacy_domain_id()=$2::uuid
       and openpc.current_action_intent_id()='ACT-EVIDENCE_EXPORT_RECORDS-V1'
       and exists(select 1 from pg_locks l where l.pid=pg_backend_pid()
         and l.locktype='advisory' and l.mode='ExclusiveLock' and l.granted
         and l.database=(select oid from pg_database where datname=current_database())
         and l.classid=((hashtextextended($3,0)>>32)&4294967295)::oid
         and l.objid=(hashtextextended($3,0)&4294967295)::oid and l.objsubid=1)
       allowed from pg_roles r where r.rolname=current_user`,
      [scope.participantId, scope.privacyDomainId, `evidence-lifecycle:${scope.participantId}`],
    );
    if (context.rowCount !== 1 || context.rows[0]?.allowed !== true) throw new Error();
  } catch {
    throw new PublishedNotificationSourceError('CONTEXT_UNAVAILABLE');
  }
  try {
    const original = await readPreparedEvidenceExportCompletion(client, scope, evidenceExportId);
    if (
      !original ||
      original.state !== 'PUBLISHED' ||
      !original.coseSign1 ||
      original.claims.eventId !== eventId ||
      original.claims.sequence !== '1'
    )
      throw new Error();

    const installed = await client.query<{ trust: Record<string, unknown>; trust_bytes: Buffer }>(
      `select trust,trust_bytes from control.evidence_export_producer_installation
       where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3`,
      [scope.participantId, scope.privacyDomainId, original.trustDigest],
    );
    if (installed.rowCount !== 1) throw new Error();
    const { schema, schemaDefinitionDigest, signerKeyId, ...pins } = installed.rows[0]!.trust;
    const valid = validateEvidenceExportProducerInstallation(pins);
    if (
      schema !== valid.trust.schema ||
      schemaDefinitionDigest !== valid.trust.schemaDefinitionDigest ||
      signerKeyId !== valid.signerKeyId ||
      valid.digest !== original.trustDigest ||
      !valid.bytes.equals(installed.rows[0]!.trust_bytes) ||
      valid.pins.participantId !== scope.participantId ||
      valid.pins.privacyDomainId !== scope.privacyDomainId
    )
      throw new Error();

    // The shared SQL owner checks exact data bytes/digest, aggregate/sequence,
    // source, envelope metadata and receipt framing. Require its actual row, not
    // merely successful execution of a SELECT that may have returned no event.
    const publication = await client.query(
      `select openpc.check_evidence_export_completion_event(e)
       from control.outbox_event e where e.participant_id=$1 and e.privacy_domain_id=$2
       and e.event_id=$3 and e.aggregate_id=$4`,
      [scope.participantId, scope.privacyDomainId, eventId, evidenceExportId],
    );
    if (publication.rowCount !== 1) throw new Error();
    return await readNotificationEvidenceExportSource(client, {
      scope,
      evidenceExportId,
      completion: {
        payload: original.receiptPayload,
        cose: original.coseSign1,
        envelope: JSON.parse(original.eventPayload.toString('utf8')) as unknown,
      },
      trust: {
        spki: Buffer.from(valid.pins.publicKeySpkiHex, 'hex'),
        environmentId: valid.pins.environmentId,
        sourceId: valid.pins.sourceId,
        signerKeyId: valid.signerKeyId,
        authoritySnapshotDigest: sha256(original.authoritySnapshot),
        signerTrustSnapshotDigest: valid.digest,
      },
      reservation: {
        eventId: original.claims.eventId,
        sequence: original.claims.sequence,
        recordedAtNs: original.claims.recordedAtNs,
      },
    });
  } catch {
    // Minimize absence, integrity, permission and signature failures alike. Do
    // not expose SQL diagnostics, retained authority or foreign source details.
    throw new PublishedNotificationSourceError('PUBLICATION_UNAVAILABLE');
  }
}
