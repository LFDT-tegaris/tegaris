import type { NextRequest } from 'next/server';
import { platformScopeReplacementPreparation } from '../../../../../../services/participant-service/src/contracts/platform-scope-replacement';
import { platformScopeReadinessSchema } from '../../../../../../services/participant-service/src/contracts/platform-scope-readback';
import { approvalCandidateResponseSchema } from '../../../../../../services/module-registry/src/approval-candidate-contract';
import {
  approval,
  digest,
  isResponse,
  ownerJson,
  participantAction,
  publicHeaders,
} from './local-governance-api';
import {
  localOwnerFetch,
  safeProblem,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';

/** Selector-only read through two authorized owners. Consumed preparation is
 * immutable provenance, while current pending readiness fences this handoff.
 * New envelopes/assignments still need their own ordinary governed mutations. */
export async function readPendingAdministratorPreparation(
  runtime: LocalConfig,
  session: IdentitySession,
  request: NextRequest,
  approvalRequestId: string,
  principalId: string,
) {
  const selected = await approval(
    runtime,
    session,
    approvalRequestId,
    request,
    'platform-handoff-approval',
  );
  if (isResponse(selected)) return selected;
  if (!selected.checkerSubjectRef || selected.checkerSubjectRef === selected.makerSubjectRef)
    return safeProblem('PC-AUTH-0005', request);
  const candidate = await ownerJson(
    await localOwnerFetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests/${encodeURIComponent(selected.approvalRequestId)}/candidate`,
      {
        cache: 'no-store',
        headers: publicHeaders(runtime, session),
        signal: request.signal,
      },
    ).catch(() => undefined),
    approvalCandidateResponseSchema,
    request,
    'platform-handoff-preparation',
  );
  if (isResponse(candidate)) return candidate;
  const plan = platformScopeReplacementPreparation.safeParse(candidate.candidate);
  if (
    !plan.success ||
    selected.actionIntentId !== participantAction.id ||
    candidate.actionIntentId !== participantAction.id ||
    candidate.state !== 'CONSUMED' ||
    !candidate.operationRef ||
    candidate.redactedFields.length !== 0 ||
    selected.candidateDigest !== candidate.candidateDigest ||
    digest(plan.data) !== candidate.candidateDigest ||
    candidate.approvalRequestId !== selected.approvalRequestId ||
    candidate.resourceRef !== `urn:openpc:resource:${plan.data.replacementId}`
  )
    return safeProblem('PC-AUTH-0005', request);
  const admin = plan.data.administrators.find((entry) => entry.principalId === principalId);
  if (
    !admin ||
    admin.usable.administration.participantIds.length !== 1 ||
    admin.usable.administration.participantIds[0] !== session.participantId ||
    admin.usable.administration.privacyDomainIds.length !== 1 ||
    admin.usable.administration.privacyDomainIds[0] !== session.privacyDomainId
  )
    return safeProblem('PC-AUTH-0005', request);
  return {
    plan: plan.data,
    administrator: admin,
    checkerPrincipalId: selected.checkerSubjectRef.slice(-36),
  };
}

export async function readPendingAdministrator(
  runtime: LocalConfig,
  session: IdentitySession,
  request: NextRequest,
  approvalRequestId: string,
  principalId: string,
) {
  const prepared = await readPendingAdministratorPreparation(
    runtime,
    session,
    request,
    approvalRequestId,
    principalId,
  );
  if (isResponse(prepared)) return prepared;
  const { plan, administrator: admin } = prepared;
  const readiness = await ownerJson(
    await localOwnerFetch(
      `${runtime.publicApiUrl}/v1/platform-contexts/${plan.platformContextId}/scope-replacements/${plan.replacementId}/readiness`,
      {
        cache: 'no-store',
        headers: {
          ...publicHeaders(runtime, session),
          Authorization: `Bearer ${session.sessionToken}`,
        },
        signal: request.signal,
      },
    ).catch(() => undefined),
    platformScopeReadinessSchema,
    request,
    'platform-handoff-readiness',
  );
  if (isResponse(readiness)) return readiness;
  if (
    readiness.state !== 'WITHDRAWING' ||
    readiness.platformContextId !== plan.platformContextId ||
    readiness.replacementId !== plan.replacementId ||
    readiness.predecessorEpoch !== plan.predecessorEpoch ||
    readiness.predecessorDigest !== plan.predecessorDigest ||
    readiness.rootRevision !== plan.expectedRootRevision ||
    BigInt(readiness.sourceExpiresAtNs) <= BigInt(readiness.nowNs) ||
    admin.usable.administration.participantIds.length !== 1 ||
    admin.usable.administration.participantIds[0] !== session.participantId ||
    admin.usable.administration.privacyDomainIds.length !== 1 ||
    admin.usable.administration.privacyDomainIds[0] !== session.privacyDomainId ||
    !readiness.administrators.some(
      (entry) =>
        entry.principalId === admin.principalId &&
        entry.envelopeId === admin.envelopeId &&
        entry.assignmentId === admin.assignmentId,
    )
  )
    return safeProblem('PC-RUNTIME-3007', request);
  return prepared;
}
