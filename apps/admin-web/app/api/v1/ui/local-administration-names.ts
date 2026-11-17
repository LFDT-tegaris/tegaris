import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  administrationReservationSchema,
  reservationBindingSchema,
  createAdministrationReservationSchema,
  reservationAction,
} from '../../../../../../services/module-registry/src/administration-resource-reservation-contract';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  readPublicCommand,
  safeProblem,
  sameOrigin,
} from './local-runtime';
import {
  approvalCreateAction,
  csrf,
  isResponse,
  logOwnerFailure,
  ownerJson,
  publicHeaders,
} from './local-governance-api';

const noStore = { 'Cache-Control': 'no-store' };
const creationActions = {
  APPROVAL_REQUEST: approvalCreateAction,
  POLICY_ACTIVATION_OCCURRENCE: {
    id: 'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1',
    digest: 'sha256:ab25e0e1acc4faa65753906943f99e359ef60e4f90cd70f8cfb72bfd4e9c0dfd',
  },
} as const;
const command = reservationBindingSchema.extend({
  command: z.literal('RESERVE'),
  predecessorOperationId: z.uuidv7().optional(),
  requestKey: z.uuid(),
});
async function context(request: NextRequest, mutation = false) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
  if (mutation && !sameOrigin(request)) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', request);
  return { runtime, session };
}
export async function readAdministrationNames(request: NextRequest) {
  const current = await context(request);
  if (isResponse(current)) return current;
  const { runtime, session } = current;
  const actor = {
    principalId: session.principalId,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    sessionId: session.sessionId,
    contextEpoch: session.contextEpoch,
  };
  const query = z
    .strictObject({ operationId: z.uuidv7().optional() })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (!query.success || request.nextUrl.searchParams.size !== Object.keys(query.data).length)
    return safeProblem('PC-DATA-6004', request);
  if (!query.data.operationId) return NextResponse.json({ actor }, { headers: noStore });
  const reservation = await ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/api/v1/administration-resource-reservations/${query.data.operationId}`,
      {
        cache: 'no-store',
        headers: publicHeaders(runtime, session),
        signal: AbortSignal.timeout(15000),
      },
    ).catch(() => undefined),
    administrationReservationSchema,
    request,
  );
  if (isResponse(reservation)) return reservation;
  if (
    reservation.operationId !== query.data.operationId ||
    reservation.participantId !== session.participantId ||
    reservation.privacyDomainId !== session.privacyDomainId ||
    reservation.makerPrincipalId !== session.principalId
  )
    return safeProblem('PC-AUTH-0005', request);
  return NextResponse.json({ actor, reservation }, { headers: noStore });
}
export async function reserveAdministrationName(request: NextRequest) {
  if (!hasJsonContentType(request.headers.get('content-type')))
    return safeProblem('PC-DATA-6004', request);
  const current = await context(request, true);
  if (isResponse(current)) return current;
  const { runtime, session } = current;
  const parsed = command.safeParse(await readPublicCommand(request, 8192));
  if (!parsed.success) return safeProblem('PC-DATA-6004', request);
  const input = parsed.data,
    action = creationActions[input.purpose];
  const body = createAdministrationReservationSchema.safeParse({
    purpose: input.purpose,
    businessActionIntentId: input.businessActionIntentId,
    businessResourceId: input.businessResourceId,
    expectedBusinessRevision: input.expectedBusinessRevision,
    checkerPrincipalId: input.checkerPrincipalId,
    command: 'RESERVE_RESOURCE_NAME',
    predecessorOperationId: input.predecessorOperationId,
    makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
    actionIntentId: reservationAction(input.purpose),
    actionIntentDigest: action.digest,
  });
  if (!body.success) return safeProblem('PC-DATA-6004', request);
  const token = await csrf(runtime, session, action.id);
  if (!token) return safeProblem('PC-AUTH-0005', request);
  const response = await fetch(
    `${runtime.publicApiUrl}/api/v1/administration-resource-reservations`,
    {
      method: 'POST',
      cache: 'no-store',
      headers: {
        ...publicHeaders(runtime, session),
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
        'Idempotency-Key': `administration-name-${input.requestKey}`,
        'X-OpenPC-Action-Intent-Digest': action.digest,
      },
      body: JSON.stringify(body.data),
      signal: AbortSignal.timeout(15000),
    },
  ).catch(() => undefined);
  const reservation = await ownerJson(response, administrationReservationSchema, request);
  if (isResponse(reservation)) {
    await logOwnerFailure('reserve-administration-name', response);
    return reservation;
  }
  if (
    reservation.participantId !== session.participantId ||
    reservation.privacyDomainId !== session.privacyDomainId ||
    reservation.makerPrincipalId !== session.principalId ||
    reservation.purpose !== input.purpose ||
    reservation.businessActionIntentId !== input.businessActionIntentId ||
    reservation.businessResourceId !== input.businessResourceId ||
    reservation.expectedBusinessRevision !== input.expectedBusinessRevision ||
    reservation.checkerPrincipalId !== input.checkerPrincipalId ||
    reservation.predecessorOperationId !== input.predecessorOperationId ||
    Date.parse(reservation.validUntil) <= Date.now()
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json({ reservation }, { status: 201, headers: noStore });
}
