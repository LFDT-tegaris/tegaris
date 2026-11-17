import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { typedEnvelopeCreateCandidate } from '../../../../../../services/participant-service/src/contracts/envelope';
import { approvalCandidateResponseSchema } from '../../../../../../services/module-registry/src/approval-candidate-contract';
import {
  digest,
  digestSchema,
  isResponse,
  ownerJson,
  publicHeaders,
  uuidSchema,
} from './local-governance-api';
import { safeProblem, type IdentitySession, type LocalConfig } from './local-runtime';

/** Browser persistence contains selectors only. Both disclosure owners must
 * authorize the current session every time; these IDs never confer authority. */
export const envelopeRecoverySelection = z.strictObject({
  envelopeId: uuidSchema,
  targetParticipantId: uuidSchema,
  issuerPrivacyDomainId: uuidSchema,
  creationApprovalRequestId: uuidSchema,
});

const envelopeReadback = z.strictObject({
  operationId: uuidSchema,
  effect: z.strictObject({
    id: uuidSchema,
    participantId: uuidSchema,
    authorityEpoch: z.string().regex(/^(0|[1-9][0-9]*)$/u),
    state: z.enum(['DRAFT', 'SUBMITTED', 'APPROVED']),
    semanticDigest: digestSchema,
    privacyDomainIds: z.array(uuidSchema),
    actionIntentIds: z.array(z.string()),
    capabilityIds: z.array(z.string()).optional(),
    resourceIds: z.array(z.string()),
    riskClasses: z.array(z.string()),
    validFrom: z.iso.datetime({ offset: true }),
    validUntil: z.iso.datetime({ offset: true }).nullable(),
    makerCheckerRequired: z.boolean(),
    stepUpRequired: z.boolean(),
    onwardDelegationDepth: z.number().int().nonnegative(),
  }),
});

export async function readParticipantEnvelopeRecovery(
  runtime: LocalConfig,
  session: IdentitySession,
  request: NextRequest,
) {
  if (session.contextMode !== 'PLATFORM') return safeProblem('PC-AUTH-0005', request);
  const selectors = Object.fromEntries(request.nextUrl.searchParams);
  if (request.nextUrl.searchParams.size !== Object.keys(selectors).length)
    return safeProblem('PC-DATA-6004', request);
  const selected = envelopeRecoverySelection.safeParse(selectors);
  if (!selected.success) return safeProblem('PC-DATA-6004', request);
  const selection = selected.data;
  const [effectResponse, creationResponse] = await Promise.all([
    fetch(
      `${runtime.publicApiUrl}/v1/participants/${selection.targetParticipantId}/envelopes/${selection.envelopeId}`,
      {
        cache: 'no-store',
        headers: {
          'Authorization': `Bearer ${session.sessionToken}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${selection.issuerPrivacyDomainId}`,
        },
        signal: AbortSignal.timeout(15_000),
      },
    ).catch(() => undefined),
    fetch(
      `${runtime.publicApiUrl}/api/v1/approval-requests/urn:openpc:resource:${selection.creationApprovalRequestId}/candidate`,
      {
        cache: 'no-store',
        headers: {
          ...publicHeaders(runtime, session),
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${selection.issuerPrivacyDomainId}`,
        },
        signal: AbortSignal.timeout(15_000),
      },
    ).catch(() => undefined),
  ]);
  const effect = await ownerJson(effectResponse, envelopeReadback, request);
  if (isResponse(effect)) return effect;
  const creation = await ownerJson(creationResponse, approvalCandidateResponseSchema, request);
  if (isResponse(creation)) return creation;
  const candidate = typedEnvelopeCreateCandidate.safeParse(creation.candidate);
  if (
    !candidate.success ||
    candidate.data.id !== selection.envelopeId ||
    candidate.data.participantId !== selection.targetParticipantId ||
    digest(candidate.data) !== creation.candidateDigest ||
    creation.approvalRequestId !== `urn:openpc:resource:${selection.creationApprovalRequestId}` ||
    creation.resourceRef !== `urn:openpc:resource:${selection.envelopeId}` ||
    creation.actionIntentId !== 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' ||
    creation.state !== 'CONSUMED' ||
    creation.runtimePermission !== 'NONE' ||
    !creation.operationRef ||
    effect.effect.id !== selection.envelopeId ||
    effect.effect.participantId !== selection.targetParticipantId ||
    (effect.effect.state === 'DRAFT' &&
      creation.operationRef !== `urn:openpc:operation:${effect.operationId}`) ||
    effect.effect.privacyDomainIds.some(
      (privacy) =>
        privacy !== selection.issuerPrivacyDomainId ||
        !candidate.data.usable.administration.privacyDomainIds.includes(privacy),
    )
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json(
    {
      selection,
      actor: {
        principalId: session.principalId,
        participantId: session.participantId,
        contextEpoch: session.contextEpoch,
      },
      state: effect.effect.state,
      semanticDigest: effect.effect.semanticDigest,
      lastOperationId: effect.operationId,
      creationOperationId: creation.operationRef.slice('urn:openpc:operation:'.length),
      disclosurePrivacyDomainIds: effect.effect.privacyDomainIds,
      usable: candidate.data.usable,
      grantable: candidate.data.grantable,
      runtimePermission: 'NONE',
    },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}
