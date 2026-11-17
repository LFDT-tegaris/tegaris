import type { PoolClient } from 'pg';
import { z } from 'zod';
import { deploymentLineage, type DeploymentHoldLineage } from './deployment-lineage.js';
import { sha256 } from '../configuration/digest.js';
import { readDeploymentRejection } from '../configuration/deployment/rejection-readback.js';
import { selectDeploymentResultSource } from '../configuration/deployment/result-source.js';
import { verifyDeploymentResult } from '../configuration/deployment/result-verification.js';
import { EvidenceCustodyError, type EvidenceScope, type SourceReceipt } from './segment.js';

/** Catalogue time is microsecond UTC; the untouched signed receipt retains any
 * finer source precision. Never replace its event time with custody admission. */
export function effectOccurrenceTime(value: string) {
  z.iso.datetime({ offset: true }).parse(value);
  const fraction = /\.(\d+)(?:Z|[+-]\d{2}:\d{2})$/u.exec(value)?.[1] ?? '';
  return new Date(value)
    .toISOString()
    .replace(/\.\d{3}Z$/u, `.${fraction.padEnd(6, '0').slice(0, 6)}Z`);
}

/** Archive every retained signed observation, including ambiguity, denial and
 * reorg. Neither command acceptance nor archival is evidence of success. */
export async function readEffectEvidenceBatch(
  client: PoolClient,
  scope: EvidenceScope,
  reconcileOnly = false,
): Promise<{ source: SourceReceipt; lineage: DeploymentHoldLineage | null }[]> {
  const selected = await client.query<{
    command_id: string;
    sequence: string;
    signed_bytes: Buffer;
    result_digest: string;
  }>(
    `select r.command_id::text,r.sequence::text,r.signed_bytes,r.result_digest
     from control.deployment_result r where r.participant_id=$1 and r.privacy_domain_id=$2
      and ((not $4::boolean and not exists(select 1 from control.evidence_catalogue c where c.participant_id=r.participant_id
       and c.privacy_domain_id=r.privacy_domain_id and c.stream_id=$3
       and c.record_id='deployment:'||r.command_id::text||':'||r.sequence::text))
       or ($4::boolean and exists(select 1 from control.evidence_catalogue c where c.participant_id=r.participant_id
        and c.privacy_domain_id=r.privacy_domain_id and c.stream_id=$3
        and c.record_id='deployment:'||r.command_id::text||':'||r.sequence::text
        and c.source_format='PC-DEPLOYMENT-JOURNAL-PROJECTION-1'
        and (not exists(select 1 from control.evidence_deployment_lineage l
         where l.participant_id=c.participant_id and l.privacy_domain_id=c.privacy_domain_id
          and l.stream_id=c.stream_id and l.record_id=c.record_id)
         or (not exists(select 1 from control.evidence_deployment_provenance p
          where p.participant_id=c.participant_id and p.privacy_domain_id=c.privacy_domain_id
           and p.stream_id=c.stream_id and p.record_id=c.record_id)
          and not exists(select 1 from control.evidence_projection_retirement retired
           where retired.participant_id=c.participant_id and retired.privacy_domain_id=c.privacy_domain_id
            and retired.stream_id=c.stream_id and retired.record_id=c.record_id
            and retired.data_class='NORMALIZED_JSON_PROJECTION'))))))
     order by r.created_at,r.command_id,r.sequence limit 8`,
    [scope.participantId, scope.privacyDomainId, scope.streamId, reconcileOnly],
  );
  const records: { source: SourceReceipt; lineage: DeploymentHoldLineage | null }[] = [];
  for (const row of selected.rows) {
    try {
      const source = await selectDeploymentResultSource(
        client,
        row.command_id,
        scope.participantId,
        scope.privacyDomainId,
      );
      if (source.rowCount !== 0 && source.rowCount !== 1)
        throw new EvidenceCustodyError('INTEGRITY');
      const binding = source.rows[0];
      const verified = binding
        ? verifyDeploymentResult(
            { ...binding, ...row },
            row.command_id,
            scope.participantId,
            scope.privacyDomainId,
            false,
          )
        : await readDeploymentRejection(
            client,
            row.command_id,
            scope.participantId,
            scope.privacyDomainId,
          );
      if (
        !verified ||
        verified.sequence !== row.sequence ||
        `sha256:${verified.resultDigest}` !== row.result_digest ||
        sha256(row.signed_bytes) !== row.result_digest
      )
        throw new EvidenceCustodyError('INTEGRITY');
      // Keep terminal no-handoff receipts separate from target observations.
      // Stop at the first format boundary without dropping or reordering any
      // source; the next worker tick resumes from the remaining original row.
      if (records.length > 0 && records[0]!.source.sourceFormat !== verified.identity) break;
      records.push({
        lineage: binding
          ? deploymentLineage(verified as ReturnType<typeof verifyDeploymentResult>, binding)
          : null,
        source: {
          recordId: `deployment:${row.command_id}:${row.sequence}`,
          evidenceClass: 'EFFECT',
          sourceFormat: verified.identity,
          occurredAt: effectOccurrenceTime(verified.observedAt),
          receiptDigest: row.result_digest,
          receiptBase64: row.signed_bytes.toString('base64'),
        },
      });
    } catch {
      throw new EvidenceCustodyError('INTEGRITY');
    }
  }
  return records;
}

/** Compatibility entry used by the existing source isolation checks. */
export async function readEffectEvidenceSources(
  client: PoolClient,
  scope: EvidenceScope,
): Promise<SourceReceipt[]> {
  return (await readEffectEvidenceBatch(client, scope)).map((entry) => entry.source);
}
