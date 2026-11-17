import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { recoveryReview } from '../../../../lib/recovery-workflow';
import { digest, isResponse, participantAction, uuidSchema } from './local-governance-api';
import { responseIds, safeProblem, type IdentitySession, type LocalConfig } from './local-runtime';
import {
  actorBinding,
  noStore,
  previewSchema,
  responseReview,
  sealedReview,
  newReviewCustody,
} from './local-recovery-model';
import { readOwner, caseReadback, qualificationReadback } from './local-recovery-owner';
const revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
export async function preview(
  runtime: LocalConfig,
  session: IdentitySession,
  input: z.infer<typeof previewSchema>,
  request: NextRequest,
) {
  if (input.checkerPrincipalId === session.principalId) return safeProblem('PC-DATA-6004', request);
  let candidate: z.infer<typeof recoveryReview>['candidate'];
  let resourceId: string;
  let expectedRevision = '0';
  if (input.mutation === 'QUALIFY' || input.mutation === 'REVOKE') {
    resourceId = input.principalId;
    const current = await qualificationReadback(runtime, session, resourceId, request);
    if (isResponse(current) && (current.status !== 404 || input.mutation === 'REVOKE'))
      return current;
    if (!isResponse(current)) expectedRevision = current.effect.revision;
    if (input.mutation === 'QUALIFY') {
      const principal = await readOwner(
        runtime,
        session,
        `principals/${resourceId}`,
        z.object({
          effect: z.object({
            principalId: uuidSchema,
            participantId: uuidSchema,
            identityEpoch: revision,
            state: z.string(),
          }),
        }),
        request,
      );
      if (isResponse(principal)) return principal;
      if (
        principal.effect.principalId !== resourceId ||
        principal.effect.participantId !== session.participantId ||
        principal.effect.state !== 'ACTIVE'
      )
        return safeProblem('PC-DATA-6007', request);
      candidate = {
        principalId: resourceId,
        credentialId: input.credentialId,
        credentialEpoch: input.credentialEpoch,
        principalEpoch: principal.effect.identityEpoch,
      };
    } else candidate = { principalId: resourceId, state: 'REVOKED' };
  } else if (input.mutation === 'BEGIN') {
    resourceId = input.recoveryId ?? responseIds().requestId;
    if (
      new Set([input.subjectId, input.recoveryPrincipalId, ...input.custodianPrincipalIds]).size !==
      4
    )
      return safeProblem('PC-DATA-6004', request);
    const qualified = await qualificationReadback(
      runtime,
      session,
      input.recoveryPrincipalId,
      request,
    );
    if (isResponse(qualified)) return qualified;
    if (!qualified.effect.current) return safeProblem('PC-DATA-6007', request);
    candidate = {
      recoveryId: resourceId,
      participantId: session.participantId,
      subjectId: input.subjectId,
      recoveryPrincipalId: input.recoveryPrincipalId,
      custodianPrincipalIds: input.custodianPrincipalIds,
      purposeDigest: input.purposeDigest ?? digest(input.reason),
      actionIntentId: participantAction.id,
    };
  } else {
    resourceId = input.recoveryId;
    const current = await caseReadback(runtime, session, resourceId, request);
    if (isResponse(current)) return current;
    expectedRevision = current.effect.revision;
    if ('purpose' in current.effect) {
      if (
        input.mutation !== 'POST_REVIEW' ||
        !['COMPLETED', 'REVOKED', 'EXPIRED'].includes(current.effect.state) ||
        !current.effect.activationOperationId ||
        current.effect.postReviewStatus !== 'REQUIRED' ||
        [current.effect.issuerPrincipalId, current.effect.executorPrincipalId].some(
          (id) => id === session.principalId || id === input.checkerPrincipalId,
        )
      )
        return safeProblem('PC-DATA-6007', request);
      candidate = { recoveryId: resourceId, note: 'note' in input ? input.note : '' };
    } else {
      if ((input.purposeDigest ?? digest(input.reason)) !== current.effect.purposeDigest)
        return safeProblem('PC-DATA-6007', request);
      candidate =
        input.mutation === 'CUSTODY'
          ? { recoveryId: resourceId, purposeDigest: current.effect.purposeDigest }
          : input.mutation === 'COMPLETE'
            ? { recoveryId: resourceId, state: 'COMPLETED' }
            : { recoveryId: resourceId, note: 'note' in input ? input.note : '' };
    }
  }
  const candidateDigest = digest(candidate);
  const value = sealedReview.parse({
    actor: actorBinding(session),
    ...newReviewCustody(),
    idempotencyKey: `recovery-workbench-${responseIds().requestId}`,
    mutation: input.mutation,
    resourceId,
    candidate,
    candidateDigest,
    expectedRevision,
    reason: input.reason,
    checkerPrincipalId: input.checkerPrincipalId,
    stepUp: {
      actionIntentId: participantAction.id,
      actionIntentDigest: participantAction.digest,
      resourceId,
      resourceDigest: candidateDigest,
    },
  });
  return NextResponse.json(responseReview(value, runtime), { status: 201, headers: noStore });
}
