import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { accessReviewCursor, accessReviewPage } from '../../../../lib/access-review';
import { actorBinding } from './local-recovery-model';
import { isResponse, ownerJson, publicHeaders } from './local-governance-api';
import { authenticated, localRuntimeConfig, safeProblem } from './local-runtime';

export async function readAccessReview(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-AUTH-0005', request);
  const session = await authenticated(request, runtime),
    actor = session && actorBinding(session);
  if (!session || !actor) return safeProblem('PC-AUTH-0005', request);
  const query = z
    .strictObject({
      subjectId: z.uuid(),
      after: accessReviewCursor.optional(),
      limit: z.coerce.number().int().min(1).max(50).default(25),
    })
    .safeParse(Object.fromEntries(request.nextUrl.searchParams));
  if (
    !query.success ||
    [...request.nextUrl.searchParams].length !== new Set(request.nextUrl.searchParams.keys()).size
  )
    return safeProblem('PC-DATA-6004', request);
  const parameters = new URLSearchParams({
    limit: String(query.data.limit),
    ...(query.data.after ? { after: query.data.after } : {}),
  });
  const page = await ownerJson(
    await fetch(
      `${runtime.publicApiUrl}/v1/participants/${session.participantId}/access-review/${query.data.subjectId}?${parameters}`,
      {
        cache: 'no-store',
        headers: {
          ...publicHeaders(runtime, session),
          Authorization: `Bearer ${session.sessionToken}`,
        },
      },
    ).catch(() => undefined),
    accessReviewPage,
    request,
  );
  if (isResponse(page)) return page;
  if (
    page.participantId !== actor.participantId ||
    page.privacyDomainId !== actor.privacyDomainId ||
    page.subject.id !== query.data.subjectId ||
    page.authorizedEmpty !== (page.items.length === 0) ||
    (page.completeness === 'MORE') !== (page.nextCursor !== null) ||
    page.items.some((item) => {
      const grant = item.grant.effect;
      return (
        grant.participantId !== actor.participantId ||
        item.constraints.participantId !== actor.participantId ||
        item.constraints.privacyDomainIds[0] !== actor.privacyDomainId ||
        grant.privacyDomainIds[0] !== actor.privacyDomainId ||
        ('principalId' in grant ? grant.principalId : grant.granteeId) !== page.subject.id ||
        item.current !== (item.reasons.length === 0) ||
        item.ancestry[0]?.id !== item.assignmentId ||
        item.ancestry.at(-1)?.id !== grant.id ||
        (item.remediation !== null &&
          (item.remediation.id !== grant.id ||
            item.remediation.revision !== item.grant.revision ||
            (item.remediation.kind === 'assignment') !== 'principalId' in grant))
      );
    })
  )
    return safeProblem('PC-INTEGRATION-5001', request);
  return NextResponse.json({ actor, page }, { headers: { 'Cache-Control': 'no-store' } });
}
