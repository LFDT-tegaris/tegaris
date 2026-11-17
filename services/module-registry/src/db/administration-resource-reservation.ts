import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  administrationReservationSchema,
  reservationAction,
  type AdministrationReservation,
  type ReservationBinding,
} from '../administration-resource-reservation-contract.js';
import { canonicalJson } from '../domain/digest.js';
import { ContractError } from '../domain/errors.js';
import type { PublicApprovalScope } from './public-approval-store.js';

export function assertReservationBinding(
  reservation: AdministrationReservation,
  scope: Pick<PublicApprovalScope, 'participantId' | 'privacyDomainId' | 'principalId'>,
  binding: ReservationBinding,
  now: Date,
  phase: 'consume' | 'renew' = 'consume',
): void {
  if (
    !Number.isFinite(now.getTime()) ||
    reservation.participantId !== scope.participantId ||
    reservation.privacyDomainId !== scope.privacyDomainId ||
    reservation.makerPrincipalId !== scope.principalId ||
    canonicalJson(binding) !==
      canonicalJson({
        purpose: reservation.purpose,
        businessActionIntentId: reservation.businessActionIntentId,
        businessResourceId: reservation.businessResourceId,
        expectedBusinessRevision: reservation.expectedBusinessRevision,
        checkerPrincipalId: reservation.checkerPrincipalId,
      }) ||
    Date.parse(reservation.createdAt) > now.getTime() ||
    (phase === 'consume'
      ? Date.parse(reservation.validUntil) <= now.getTime()
      : Date.parse(reservation.validUntil) > now.getTime()) ||
    Date.parse(reservation.validUntil) > Date.parse(reservation.createdAt) + 3_600_000
  )
    throw new ContractError('PC-POLICY-2003');
}

/** Names carry no authority. Consumption happens in the fresh, fenced effect transaction. */
export async function readAdministrationReservation(
  client: PoolClient,
  scope: Pick<PublicApprovalScope, 'participantId' | 'privacyDomainId' | 'principalId'>,
  operationId: string,
): Promise<{ reservation: AdministrationReservation; now: Date }> {
  const selected = await client.query<{
    payload: unknown;
    resultDigest: Buffer;
    actionIntentId: string;
    now: Date;
  }>(
    `select result_payload as payload,result_digest as "resultDigest",
            action_intent_id as "actionIntentId",clock_timestamp() as now
       from control.idempotency_record
      where participant_id=$1 and privacy_domain_id=$2 and principal_id=$3
        and operation_id=$4 and catalog_operation_id='LEGACY'
        and terminal_state='COMMITTED' and expires_at>clock_timestamp()
      for share`,
    [scope.participantId, scope.privacyDomainId, scope.principalId, operationId],
  );
  const row = selected.rows[0];
  const parsed = administrationReservationSchema.safeParse(row?.payload);
  if (
    selected.rowCount !== 1 ||
    !row ||
    !parsed.success ||
    parsed.data.operationId !== operationId ||
    row.actionIntentId !== reservationAction(parsed.data.purpose) ||
    !Buffer.isBuffer(row.resultDigest) ||
    !createHash('sha256').update(canonicalJson(parsed.data)).digest().equals(row.resultDigest)
  )
    throw new ContractError('PC-POLICY-2001');
  return { reservation: parsed.data, now: new Date(row.now) };
}

export async function lockUnusedAdministrationName(
  client: PoolClient,
  reservation: AdministrationReservation,
): Promise<void> {
  const lock = await client.query<{ held: boolean }>(
    `select pg_try_advisory_xact_lock(hashtextextended('administration-name:'||$1::text,0)) as held`,
    [reservation.reservedResourceId],
  );
  if (lock.rows[0]?.held !== true) throw new ContractError('PC-POLICY-2002');
  const used = await client.query<{ used: boolean }>(
    reservation.purpose === 'APPROVAL_REQUEST'
      ? 'select exists(select 1 from control.approval_request where approval_request_id=$1) as used'
      : 'select exists(select 1 from control.policy_activation_occurrence where activation_occurrence_id=$1) as used',
    [reservation.reservedResourceId],
  );
  if (used.rowCount !== 1 || used.rows[0]?.used !== false)
    throw new ContractError('PC-POLICY-2002');
}

export async function consumeAdministrationReservation(
  client: PoolClient,
  scope: PublicApprovalScope,
  operationId: string,
  binding: ReservationBinding,
): Promise<string> {
  const { reservation, now } = await readAdministrationReservation(client, scope, operationId);
  assertReservationBinding(reservation, scope, binding, now);
  // The actual table's primary key is the single-use fence. No fabricated
  // approval/occurrence is inserted at reservation time. An already used name
  // cannot be rebound, even after its original effect leaves the initial state.
  await lockUnusedAdministrationName(client, reservation);
  return reservation.reservedResourceId;
}
