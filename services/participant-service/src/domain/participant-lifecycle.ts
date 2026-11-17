import { transferContractAdministration } from '../../../control-api/src/configuration/repositories/contract-administration.js';
import type { PoolClient } from 'pg';
import type { AuthenticatedActor } from './participant-kernel.js';
import { ParticipantKernelError } from './participant-errors.js';
import type {
  ParticipantLifecycleChange,
  ParticipantLifecycleReadback,
} from '../contracts/participant-lifecycle.js';

const denied = () => new ParticipantKernelError('PC-IDENTITY-1008');
export async function readParticipantLifecycle(
  client: PoolClient,
  target: string,
  privacy: string,
): Promise<ParticipantLifecycleReadback> {
  const rows = await client.query<{
    participant_id: string;
    display_name: string;
    state: string;
    authority_epoch: string;
    row_version: string;
    archived_at: Date | null;
    operation_id: string | null;
    transfer: ParticipantLifecycleReadback['transfer'] | null;
  }>(
    `select p.participant_id,p.display_name,p.state,p.authority_epoch::text,p.row_version::text,p.archived_at,
    (select operation_id from control.participant_lifecycle_transition t where t.participant_id=p.participant_id
      order by new_epoch desc limit 1) operation_id,
    (select jsonb_build_object('logicalContractId',transfer.logical_contract_id,'successorParticipantId',transfer.successor_participant_id,
      'successorLogicalContractId',transfer.successor_logical_contract_id,'successorEpoch',transfer.successor_epoch,'bindings',transfer.binding_map)
      from control.contract_administration_transfer transfer join control.participant_lifecycle_transition history
        on history.participant_id=transfer.participant_id and history.operation_id=transfer.operation_id
      where history.participant_id=p.participant_id and history.new_epoch=p.authority_epoch) transfer
    from control.participant p where p.participant_id=$1 and p.root_privacy_domain_id=$2 for share of p`,
    [target, privacy],
  );
  if (rows.rowCount !== 1) throw denied();
  const row = rows.rows[0]!;
  return {
    participantId: row.participant_id,
    displayName: row.display_name,
    state: row.state,
    lifecycleState: row.archived_at ? 'ARCHIVED' : 'LIVE',
    epoch: row.authority_epoch,
    revision: row.row_version,
    archivedAt: row.archived_at?.toISOString() ?? null,
    operationId: row.operation_id,
    ...(row.transfer ? { transfer: row.transfer } : {}),
  };
}

/** Source Platform authority is fenced by mutationTx before this target write lock. */
export async function changeParticipantLifecycle(
  client: PoolClient,
  actor: AuthenticatedActor,
  candidate: ParticipantLifecycleChange,
  operationId: string,
) {
  const proof = actor.mutationAuthorization;
  if (!actor.platform || !proof || actor.participantId === candidate.participantId) throw denied();
  await client.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
    candidate.participantId,
    candidate.privacyDomainId,
    operationId,
    proof.actionIntentId,
  ]);
  await client.query(
    'select participant_id from control.participant where participant_id=$1 for update',
    [candidate.participantId],
  );
  const current = await readParticipantLifecycle(
    client,
    candidate.participantId,
    candidate.privacyDomainId,
  );
  const archive = candidate.mutation === 'ARCHIVE';
  if (
    current.epoch !== candidate.expectedEpoch ||
    current.revision !== candidate.expectedRevision ||
    (candidate.mutation === 'RESTORE'
      ? current.state !== 'SUSPENDED' || current.lifecycleState !== 'ARCHIVED'
      : current.state !== 'ACTIVE' || current.lifecycleState !== 'LIVE') ||
    BigInt(current.epoch) >= 18446744073709551615n
  )
    throw new ParticipantKernelError('PC-IDENTITY-1009');
  const transfer =
    candidate.mutation === 'TRANSFER'
      ? await transferContractAdministration(client, candidate, operationId, proof)
      : undefined;
  if (candidate.mutation === 'SHRINK') {
    // Retire only the selected envelope bounds; keep unrelated envelopes and their grants.
    const selected = await client.query(
      `select authority_envelope_id from control.authority_envelope
      where participant_id=$1 and authority_envelope_id=any($2::uuid[]) and state='ACTIVE' order by authority_envelope_id for update`,
      [candidate.participantId, candidate.envelopeIds],
    );
    if (selected.rowCount !== candidate.envelopeIds.length)
      throw new ParticipantKernelError('PC-IDENTITY-1009');
    await client.query(
      `with recursive descendants as (
      select d.delegation_id from control.delegation d join control.assignment a on a.participant_id=d.participant_id
        and a.assignment_id=d.parent_assignment_id where d.participant_id=$1 and a.authority_envelope_id=any($2::uuid[])
      union select child.delegation_id from control.delegation child join descendants parent on child.parent_delegation_id=parent.delegation_id
        where child.participant_id=$1
    ) update control.delegation set state='REVOKED',row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$3
      where participant_id=$1 and delegation_id in (select delegation_id from descendants) and state::text in ('ACTIVE','SUSPENDED')`,
      [candidate.participantId, candidate.envelopeIds, operationId],
    );
    for (const table of ['assignment', 'authority_envelope']) {
      await client.query(
        `update control.${table} set state='REVOKED',row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$3
        where participant_id=$1 and authority_envelope_id=any($2::uuid[]) and state::text in ('ACTIVE','SUSPENDED')`,
        [candidate.participantId, candidate.envelopeIds, operationId],
      );
    }
    await client.query(
      `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='PARTICIPANT_AUTHORITY_SHRUNK',
      session_epoch=session_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and state='ACTIVE'`,
      [candidate.participantId],
    );
  }
  if (candidate.mutation === 'TRANSFER') {
    await client.query(
      `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='CONTRACT_ADMINISTRATION_TRANSFER',session_epoch=session_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and state='ACTIVE'`,
      [candidate.participantId],
    );
  }
  if (archive) {
    // History is retained. Restoration never changes these terminal carrier states.
    for (const table of ['assignment', 'delegation', 'authority_envelope']) {
      await client.query(
        `update control.${table} set state='REVOKED',row_version=row_version+1,
        updated_at=clock_timestamp(),last_mutation_operation_id=$2
        where participant_id=$1 and state::text in ('ACTIVE','SUSPENDED','DRAFT','SUBMITTED','APPROVED')`,
        [candidate.participantId, operationId],
      );
    }
    await client.query(
      `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='PARTICIPANT_ARCHIVED',
      session_epoch=session_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and state='ACTIVE'`,
      [candidate.participantId],
    );
    await client.query(
      `update control.participant_invitation set state='REVOKED',row_version=row_version+1,
      updated_at=clock_timestamp(),last_mutation_operation_id=$2 where participant_id=$1 and state='PENDING'`,
      [candidate.participantId, operationId],
    );
    await client.query(
      `update control.mutation_candidate set state='CANCELLED',updated_at=clock_timestamp()
      where participant_id=$1 and state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED')`,
      [candidate.participantId],
    );
  }
  await client.query(
    `update control.participant set state=$2,archived_at=case when $3 then clock_timestamp() else null end,
    authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1`,
    [candidate.participantId, archive ? 'SUSPENDED' : 'ACTIVE', archive],
  );
  await client.query(
    `insert into control.participant_lifecycle_transition
    (operation_id,participant_id,source_participant_id,source_privacy_domain_id,privacy_domain_id,mutation,prior_epoch,new_epoch,revision)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      operationId,
      candidate.participantId,
      actor.participantId,
      proof.privacyDomainId,
      candidate.privacyDomainId,
      candidate.mutation,
      current.epoch,
      String(BigInt(current.epoch) + 1n),
      String(BigInt(current.revision) + 1n),
    ],
  );
  await client.query(
    `with sequence as (insert into control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence)
    values($1,'participant',$1,1) on conflict(participant_id,aggregate_type,aggregate_id) do update
      set last_sequence=control.outbox_aggregate_head.last_sequence+1,updated_at=clock_timestamp() returning last_sequence)
    insert into control.outbox_event(participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,aggregate_sequence,
      payload_cbor,payload_digest,cose_sign1,webauthn_assertion_binding_digest,occurred_at)
    select $1,$2,$3,'openpc.identity.participant.epoch.advanced.v1','participant',$1,last_sequence,$4,$5,$6,$7,clock_timestamp() from sequence`,
    [
      candidate.participantId,
      candidate.privacyDomainId,
      operationId,
      proof.evidenceCbor,
      proof.evidenceDigest,
      proof.coseSign1,
      proof.webauthnAssertionBindingDigest,
    ],
  );
  return {
    operationId,
    result: {
      ...(await readParticipantLifecycle(
        client,
        candidate.participantId,
        candidate.privacyDomainId,
      )),
      ...(transfer ? { transfer } : {}),
    },
  };
}
