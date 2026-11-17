import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import { policyAuthoritySelectionSql } from '../../../identity-service/src/db/policy-authority-selection.js';
import {
  administrationReservationSchema,
  reservationAction,
  type AdministrationReservation,
  type ReservationBinding,
} from '../administration-resource-reservation-contract.js';
import { canonicalJson } from '../domain/digest.js';
import { ContractError } from '../domain/errors.js';
import { uuidV7 } from '../domain/operation-id.js';
import {
  assertActionIntent,
  inScope,
  reserveOperation,
  type PublicApprovalScope,
} from './public-approval-store.js';
import {
  readAdministrationReservation,
  assertReservationBinding,
  lockUnusedAdministrationName,
} from './administration-resource-reservation.js';

const hash = (value: unknown) => createHash('sha256').update(canonicalJson(value)).digest();

export async function reserveAdministrationResourceName(
  pool: Pool,
  scope: PublicApprovalScope,
  binding: ReservationBinding,
  request: unknown,
  predecessorOperationId?: string,
): Promise<AdministrationReservation> {
  return inScope(pool, scope, async (client) => {
    if (scope.actionIntentId !== reservationAction(binding.purpose))
      throw new ContractError('PC-POLICY-2000');
    await assertActionIntent(client, scope, 'CREATE', [
      binding.purpose === 'APPROVAL_REQUEST' ? 'approval-requests' : 'activation-occurrences',
    ]);
    const replay = await reserveOperation<AdministrationReservation>(
      client,
      scope,
      hash(request),
      '0',
    );
    if (replay !== undefined) {
      const { reservation, now } = await readAdministrationReservation(
        client,
        scope,
        replay.operationId,
      );
      assertReservationBinding(reservation, scope, binding, now);
      return reservation;
    }
    const current = await client.query<{
      assignmentId: string;
      authorityEnvelopeId: string;
      sessionAbsoluteExpiresAt: Date;
      sessionIdleExpiresAt: Date;
      authorityValidUntil: Date | null;
    }>(policyAuthoritySelectionSql, [
      scope.participantId,
      scope.privacyDomainId,
      scope.actionIntentId,
      scope.authority.resourceId,
      scope.principalId,
      scope.authority.sessionId,
      false,
      false,
      true,
      null,
      null,
    ]);
    const authority = current.rows[0];
    if (
      current.rowCount !== 1 ||
      !authority ||
      authority.assignmentId !== scope.authority.assignmentId ||
      authority.authorityEnvelopeId !== scope.authority.authorityEnvelopeId
    )
      throw new ContractError('PC-POLICY-2004');
    const clock = await client.query<{ now: Date }>('select clock_timestamp() as now');
    const now = new Date(clock.rows[0]!.now);
    const deadlines = [
      now.getTime() + 3_600_000,
      new Date(authority.sessionAbsoluteExpiresAt).getTime(),
      new Date(authority.sessionIdleExpiresAt).getTime(),
      ...(authority.authorityValidUntil === null
        ? []
        : [new Date(authority.authorityValidUntil).getTime()]),
    ];
    const validUntil = Math.min(...deadlines);
    if (!Number.isFinite(validUntil) || validUntil <= now.getTime())
      throw new ContractError('PC-POLICY-2004');
    const intent = await client.query(
      'select 1 from control.action_intent where action_intent_id=$1',
      [binding.businessActionIntentId],
    );
    if (intent.rowCount !== 1) throw new ContractError('PC-POLICY-2000');
    if (binding.checkerPrincipalId !== null) {
      const checker = await client.query(
        "select 1 from control.principal where participant_id=$1 and principal_id=$2 and state='ACTIVE'",
        [scope.participantId, binding.checkerPrincipalId],
      );
      if (checker.rowCount !== 1 || binding.checkerPrincipalId === scope.principalId)
        throw new ContractError('PC-POLICY-2004');
    }
    let predecessor: AdministrationReservation | undefined;
    if (predecessorOperationId !== undefined) {
      const original = await readAdministrationReservation(client, scope, predecessorOperationId);
      predecessor = original.reservation;
      assertReservationBinding(predecessor, scope, binding, original.now, 'renew');
      await lockUnusedAdministrationName(client, predecessor);
      const prior = await client.query<{ present: boolean }>(
        `select exists(select 1 from control.idempotency_record where participant_id=$1 and privacy_domain_id=$2
          and result_payload->>'kind'='ADMINISTRATION_RESOURCE_NAME'
          and result_payload->>'predecessorOperationId'=$3) as present`,
        [scope.participantId, scope.privacyDomainId, predecessorOperationId],
      );
      if (prior.rowCount !== 1 || prior.rows[0]?.present !== false)
        throw new ContractError('PC-POLICY-2002');
      const exact = await client.query<{ assignmentId: string; authorityEnvelopeId: string }>(
        policyAuthoritySelectionSql,
        [
          scope.participantId,
          scope.privacyDomainId,
          scope.actionIntentId,
          predecessor.reservedResourceId,
          scope.principalId,
          scope.authority.sessionId,
          false,
          false,
          true,
          null,
          null,
        ],
      );
      if (
        exact.rowCount !== 1 ||
        exact.rows[0]?.assignmentId !== authority.assignmentId ||
        exact.rows[0]?.authorityEnvelopeId !== authority.authorityEnvelopeId
      )
        throw new ContractError('PC-POLICY-2004');
    }
    const reservation = administrationReservationSchema.parse({
      ...binding,
      kind: 'ADMINISTRATION_RESOURCE_NAME',
      version: 1,
      operationId: scope.operationId,
      reservedResourceId: predecessor?.reservedResourceId ?? uuidV7(),
      ...(predecessorOperationId === undefined ? {} : { predecessorOperationId }),
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      makerPrincipalId: scope.principalId,
      createdAt: now.toISOString(),
      validUntil: new Date(validUntil).toISOString(),
      authorityEffect: 'NONE',
      requiresFreshAuthority: true,
    });
    const updated = await client.query(
      `update control.idempotency_record
          set result_aggregate_version=0,result_digest=$3,result_payload=$4,terminal_state='COMMITTED'
        where participant_id=$1 and privacy_domain_id=$5 and principal_id=$6
          and operation_id=$2 and terminal_state is null`,
      [
        scope.participantId,
        scope.operationId,
        hash(reservation),
        reservation,
        scope.privacyDomainId,
        scope.principalId,
      ],
    );
    if (updated.rowCount !== 1) throw new ContractError('PC-POLICY-2005');
    return (await readAdministrationReservation(client, scope, scope.operationId)).reservation;
  });
}

export async function getAdministrationResourceName(
  pool: Pool,
  scope: PublicApprovalScope,
  operationId: string,
): Promise<AdministrationReservation> {
  return inScope(pool, scope, async (client) => {
    await assertActionIntent(client, scope, 'READ', ['participants']);
    return (await readAdministrationReservation(client, scope, operationId)).reservation;
  });
}
