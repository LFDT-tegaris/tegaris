import { type NextRequest } from 'next/server';
import { z } from 'zod';
import {
  recoveryCandidates,
  recoveryCaseReadback,
  recoveryQualification,
  recoveryMutation,
} from '../../../../lib/recovery-workflow';
import {
  csrf,
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
import { operations, proposalSchema, type Review } from './local-recovery-model';
export async function readOwner<T>(
  runtime: LocalConfig,
  session: IdentitySession,
  path: string,
  schema: z.ZodType<T>,
  request: NextRequest,
) {
  return ownerJson(
    await localOwnerFetch(`${runtime.publicApiUrl}/v1/identity/${path}`, {
      cache: 'no-store',
      headers: publicHeaders(runtime, session),
    }).catch(() => undefined),
    schema,
    request,
  );
}
export async function caseReadback(
  runtime: LocalConfig,
  session: IdentitySession,
  id: string,
  request: NextRequest,
) {
  const value = await readOwner(
    runtime,
    session,
    `recoveries/${id}`,
    recoveryCaseReadback,
    request,
  );
  if (isResponse(value)) return value;
  return value.effect.recoveryId === id &&
    value.effect.participantId === session.participantId &&
    value.effect.privacyDomainId === session.privacyDomainId
    ? value
    : safeProblem('PC-INTEGRATION-5001', request);
}
export async function qualificationReadback(
  runtime: LocalConfig,
  session: IdentitySession,
  id: string,
  request: NextRequest,
) {
  const value = await readOwner(
    runtime,
    session,
    `recovery-principals/${id}`,
    recoveryQualification,
    request,
  );
  if (isResponse(value)) return value;
  return value.effect.principalId === id &&
    value.effect.participantId === session.participantId &&
    value.effect.privacyDomainId === session.privacyDomainId
    ? value
    : safeProblem('PC-INTEGRATION-5001', request);
}
export async function readProposal(
  runtime: LocalConfig,
  session: IdentitySession,
  candidateDigest: string,
  binding: { approvalRequestId: string } | { expectedRevision: string; makerPrincipalId: string },
  request: NextRequest,
) {
  const value = await readOwner(
    runtime,
    session,
    `recovery-proposals/${encodeURIComponent(candidateDigest)}?${new URLSearchParams(binding)}`,
    proposalSchema,
    request,
  );
  if (isResponse(value)) return value;
  const mutation = recoveryMutation.options.find(
    (key) => operations[key] === value.catalogOperationId,
  );
  const candidate = mutation && recoveryCandidates[mutation].safeParse(value.candidate);
  if (
    !candidate ||
    !candidate.success ||
    value.candidateDigest !== candidateDigest ||
    digest(candidate.data) !== candidateDigest ||
    ('approvalRequestId' in binding &&
      value.approval?.approvalRequestId !== binding.approvalRequestId)
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return { ...value, mutation: mutation! };
}
function ownerCommand(value: Review) {
  const candidate = value.candidate;
  switch (value.mutation) {
    case 'QUALIFY':
      return { path: 'recovery-principals', body: recoveryCandidates.QUALIFY.parse(candidate) };
    case 'REVOKE':
      return { path: `recovery-principals/${value.resourceId}/revoke`, body: {} };
    case 'BEGIN': {
      const body = recoveryCandidates.BEGIN.omit({ participantId: true }).strip().parse(candidate);
      return { path: 'recoveries', body };
    }
    case 'CUSTODY':
      return {
        path: `recoveries/${value.resourceId}/approve`,
        body: { purposeDigest: recoveryCandidates.CUSTODY.parse(candidate).purposeDigest },
      };
    case 'COMPLETE':
      return { path: `recoveries/${value.resourceId}/complete`, body: {} };
    case 'POST_REVIEW':
      return {
        path: `recoveries/${value.resourceId}/post-review`,
        body: { note: recoveryCandidates.POST_REVIEW.parse(candidate).note },
      };
  }
}
export async function writeOwner(
  runtime: LocalConfig,
  session: IdentitySession,
  value: Review,
  approvalId: string,
) {
  const token = await csrf(runtime, session, participantAction.id);
  if (!token) return undefined;
  const command = ownerCommand(value);
  return localOwnerFetch(`${runtime.publicApiUrl}/v1/identity/${command.path}`, {
    method: 'POST',
    cache: 'no-store',
    headers: {
      ...publicHeaders(runtime, session),
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
      'Idempotency-Key': value.idempotencyKey,
      'X-OpenPC-Aggregate-Version': value.expectedRevision,
      'X-OpenPC-Approval-Request-ID': approvalId,
      'OpenPC-Action-Intent-Digest': participantAction.digest,
    },
    body: JSON.stringify(command.body),
  }).catch(() => undefined);
}
