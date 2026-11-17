import type { PoolClient } from 'pg';
import type { ReadContext } from '../configuration/persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type OperationRecord,
} from '../configuration/persistence/types.js';

/** An accepted command is never sufficient evidence of a completed export. */
export async function readEvidenceExportResult(client: PoolClient, context: ReadContext) {
  const result = await client.query<{
    state: string;
    validOutput: boolean;
    lastErrorCode: string | null;
    updatedAt: string;
    revision: string;
  }>(
    `
    select e.state,(o.output_digest=e.output_digest and o.output_digest='sha256:'||encode(sha256(o.artifact),'hex')) as "validOutput",
      e.last_error_code as "lastErrorCode",e.updated_at::text as "updatedAt",e.revision::text
    from control.evidence_export_request e left join control.evidence_export_output o
      using(participant_id,privacy_domain_id,stream_id,evidence_export_id)
    where e.participant_id=$1 and e.privacy_domain_id=$2 and e.start_operation_id=$3`,
    [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.resourceId,
    ],
  );
  const row = result.rows[0];
  if (!row || result.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
  let truth: Pick<OperationRecord, 'state' | 'truthState'>;
  if (row.state === 'SUCCEEDED' && row.validOutput && row.lastErrorCode === null)
    truth = { state: 'SUCCEEDED', truthState: 'SUCCESS' };
  else if (row.state === 'FAILED' && row.lastErrorCode === 'PC-OPS-9002')
    truth = { state: 'FAILED', truthState: 'FAILED' };
  else if (row.state === 'RUNNING' || row.state === 'BACKLOGGED')
    truth = { state: 'ACCEPTED', truthState: 'UNKNOWN' };
  else throw new ConfigurationRepositoryError('PC-FACT-4001');
  return { ...truth, updatedAt: row.updatedAt, revision: row.revision };
}
