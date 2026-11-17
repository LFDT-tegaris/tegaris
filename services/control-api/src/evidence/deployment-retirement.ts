import { Client, type Pool } from 'pg';
import type { z } from 'zod';
import type { MutationCommitFence } from '../configuration/persistence/atomic-mutation.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import { readDeploymentProvenance } from './deployment-provenance.js';
import type { projectionDeletionSelection } from './projection-deletion-contracts.js';

const unavailable = () => new ConfigurationRepositoryError('PC-DATA-6007');

/** A fresh source transaction is necessary: the business transaction already
 * has a SERIALIZABLE snapshot before it can wait for a queued source writer.
 * This source-owned shared fence blocks both observation and successor writers
 * until the physical effect, signed receipt and outbox have committed. */
export async function acquireDeploymentRetirementFence(
  pool: Pool,
  selection: z.infer<typeof projectionDeletionSelection>,
): Promise<MutationCommitFence> {
  if (
    selection.sourceKind !== 'DEPLOYMENT_PROVENANCE' ||
    selection.dataClass !== 'NORMALIZED_JSON_PROJECTION'
  )
    throw unavailable();
  // Each admitted mutation already occupies a pool slot. Borrowing a second
  // slot can deadlock when concurrent mutations fill that pool. A dedicated
  // short-lived connection is bounded by those admitted mutations and its
  // connect/statement/transaction deadlines; it never holds a spare pool slot.
  const client = new Client({
    ...pool.options,
    // pg-pool deliberately makes this property non-enumerable.
    password: pool.options.password,
    connectionTimeoutMillis: Math.min(pool.options.connectionTimeoutMillis || 5000, 5000),
  });
  let connected = false;
  let failed = false;
  const fail = () => {
    failed = true;
  };
  client.on('error', fail);
  const started = performance.now();
  const release = async () => {
    if (connected) await client.query('rollback').catch(fail);
    await client.end().catch(fail);
    client.off('error', fail);
  };
  try {
    await client.connect();
    connected = true;
    await client.query('begin isolation level read committed');
    await client.query("set local idle_in_transaction_session_timeout='6s'");
    await client.query("set local statement_timeout='5s'");
    await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
      selection.participantId.slice(-36),
      selection.privacyDomainId,
      uuidv7(),
      'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1',
    ]);
    const rows = await client.query<{
      recordId: string;
      recordDigest: string;
      occurredAt: string;
      blockers: string[];
    }>(
      `select c.record_id as "recordId",c.receipt_digest as "recordDigest",
       to_char(c.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt",
       openpc.deployment_projection_retirement_blockers(c,p.projection) blockers
       from control.evidence_catalogue c join control.evidence_deployment_provenance p
        using(participant_id,privacy_domain_id,stream_id,record_id)
       where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and c.evidence_id=$4
        and c.record_id=$5 and c.receipt_digest=$6 and p.projection_digest=$7`,
      [
        selection.participantId.slice(-36),
        selection.privacyDomainId,
        selection.streamId,
        selection.evidenceId.slice(-36),
        selection.recordId,
        selection.sourceReceiptDigest,
        selection.projectionDigest,
      ],
    );
    const source = rows.rows[0];
    if (rows.rowCount !== 1 || !source || source.blockers.length > 0) throw unavailable();
    if (
      !(await readDeploymentProvenance(client, {
        ...source,
        participantId: selection.participantId.slice(-36),
        privacyDomainId: selection.privacyDomainId,
        streamId: selection.streamId,
      }))
    )
      throw unavailable();
    const revalidate = async () => {
      if (failed || performance.now() - started >= 5000) throw unavailable();
      await client.query('select 1');
      if (failed || performance.now() - started >= 5000) throw unavailable();
    };
    await revalidate();
    return { revalidate, release };
  } catch (error) {
    await release();
    throw error;
  }
}
