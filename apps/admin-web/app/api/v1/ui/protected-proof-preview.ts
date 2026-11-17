import { z } from 'zod';
import type { NextRequest } from 'next/server';
import {
  protectedObjectView,
  protectedProofSource,
} from '../../../../../../services/control-api/src/evidence/protected-contracts';
import {
  authenticated,
  safeProblem,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import { ownerJson, publicHeaders, isResponse, digest } from './local-governance-api';

const reference = z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u);
const common = { purpose: z.string().min(1).max(256), caseReference: z.string().min(1).max(256) };
const actor = (session: IdentitySession) => ({
  participantId: session.participantId,
  privacyDomainId: session.privacyDomainId,
  principalId: session.principalId,
  sessionId: session.sessionId,
  contextEpoch: session.contextEpoch,
});
/** Resolve authoritative source/version on the server, before the shared review is sealed. */
export async function protectedProofPreview(
  request: NextRequest,
  runtime: LocalConfig,
  session: IdentitySession,
  kind: 'protected-proof-retention' | 'protected-proof-access',
  fields: Record<string, unknown>,
) {
  const parsed =
    kind === 'protected-proof-retention'
      ? z
          .strictObject({
            ...common,
            evidenceId: reference,
            retainUntil: z.iso.datetime({ precision: 6 }),
          })
          .parse(fields)
      : z
          .strictObject({
            ...common,
            objectRef: reference,
            expiresAt: z.iso.datetime({ precision: 6 }),
          })
          .parse(fields);
  const path =
    'evidenceId' in parsed
      ? `evidence-records/${encodeURIComponent(parsed.evidenceId)}/protected-proof-source`
      : `protected-proofs/${encodeURIComponent(parsed.objectRef)}`;
  const response = await fetch(`${runtime.publicApiUrl}/api/v1/${path}`, {
    cache: 'no-store',
    headers: publicHeaders(runtime, session),
    signal: AbortSignal.any([request.signal, AbortSignal.timeout(15000)]),
  }).catch(() => undefined);
  const resolved = await ownerJson(
    response,
    z.union([protectedProofSource, protectedObjectView]),
    request,
  );
  if (isResponse(resolved)) return resolved;
  const current = await authenticated(request, runtime);
  if (
    !current ||
    current.contextMode !== 'PARTICIPANT' ||
    digest(actor(current)) !== digest(actor(session))
  )
    return safeProblem('PC-AUTH-0005', request);
  if ('evidenceId' in parsed) {
    const source = protectedProofSource.parse(resolved);
    if (source.evidenceId !== parsed.evidenceId) return safeProblem('PC-INTEGRATION-5001', request);
    return {
      source,
      purpose: parsed.purpose,
      caseReference: parsed.caseReference,
      retainUntil: parsed.retainUntil,
    };
  }
  const object = protectedObjectView.parse(resolved);
  if (
    object.objectRef !== parsed.objectRef ||
    object.participantId !== `urn:openpc:participant:${session.participantId}` ||
    object.privacyDomainId !== session.privacyDomainId
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return {
    object: {
      objectRef: object.objectRef,
      objectVersion: object.objectVersion,
      objectDigest: object.objectDigest,
      source: object.source,
    },
    purpose: parsed.purpose,
    caseReference: parsed.caseReference,
    expiresAt: parsed.expiresAt,
    recipientPrincipalId: session.principalId,
  };
}
