import { NextResponse, NextRequest } from 'next/server';
import { routes } from '@openpc/ui-shell';
import { publicModulePageSchema } from '../../../../../../services/module-registry/src/public-module-list-pagination';
import {
  moduleExtensionQuery,
  moduleExtensionSnapshot,
  moduleExtensionEventName,
  moduleExtensionObservationOf,
  sameModuleExtensionObservation,
} from '../../../../lib/module-extensions';
import {
  authenticated,
  localRuntimeConfig,
  safeProblem,
  type IdentitySession,
} from './local-runtime';
import { digest, isResponse, ownerJson, publicHeaders } from './local-governance-api';

const noStore = { 'Cache-Control': 'no-store' };
function actorKey(session: IdentitySession): string {
  // Equality binding only. Actual owner reauthorization is still required.
  return digest({
    sessionId: session.sessionId,
    principalId: session.principalId,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    contextEpoch: session.contextEpoch,
    sessionEpoch: session.sessionEpoch,
    participantEpoch: session.participantEpoch,
    principalEpoch: session.principalEpoch,
    assignmentId: session.assignmentId,
    assignmentRowVersion: session.assignmentRowVersion,
    authorityEnvelopeId: session.authorityEnvelopeId,
    authorityEpoch: session.authorityEpoch,
    delegationEpoch: session.delegationEpoch,
  });
}

/** Current public collection readback is only an eligibility prerequisite.
 * This function deliberately cannot turn a supplied list/manifest/key into UI
 * admission. Canonical must publish the actual publisher-trust/bundle binding,
 * registered query adapters and dispatch fences before the positive branch. */
export async function readModuleExtensions(request: NextRequest): Promise<NextResponse> {
  try {
    const entries = [...request.nextUrl.searchParams];
    const query = moduleExtensionQuery.safeParse(Object.fromEntries(entries));
    if (new Set(entries.map(([key]) => key)).size !== entries.length || !query.success)
      return safeProblem('PC-DATA-6004', request);
    if (!routes.some((route) => route.id === query.data.routeId))
      return safeProblem('PC-AUTH-0005', request);
    const runtime = await localRuntimeConfig();
    if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
    const session = await authenticated(request, runtime);
    if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
      return safeProblem('PC-AUTH-0005', request);
    const response = await fetch(`${runtime.publicApiUrl}/api/v1/modules?limit=200&sort=moduleId`, {
      headers: publicHeaders(runtime, session),
      cache: 'no-store',
      redirect: 'error',
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(15_000)]),
    }).catch(() => undefined);
    const page = await ownerJson(response, publicModulePageSchema, request);
    if (isResponse(page)) return page;
    if (
      page.completeness !== 'COMPLETE' ||
      page.nextCursor !== null ||
      page.total !== String(page.items.length) ||
      page.authorizedEmpty !== (page.items.length === 0) ||
      new Set(page.items.map((item) => item.moduleId)).size !== page.items.length ||
      new Set(page.items.map((item) => item.name)).size !== page.items.length
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    const fresh = await authenticated(request, runtime);
    if (
      !fresh ||
      fresh.contextMode !== 'PARTICIPANT' ||
      !fresh.privacyDomainId ||
      actorKey(fresh) !== actorKey(session) ||
      fresh.sessionToken !== session.sessionToken
    )
      return safeProblem('PC-AUTH-0005', request);
    // Publication prerequisite, not an empty catalogue or an opt-in bypass.
    // No clock-derived generation, fixture event, global key cache, injected
    // allowlist, name/version match, or browser flag may open this branch.
    return safeProblem('PC-INTEGRATION-5001', request);
  } catch {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
}

/** Each observation goes through the same real read/admission owner. Until the
 * positive owner above is published, this returns its typed failure, not SSE.
 * No Last-Event-ID or client payload can suppress reauthorization. */
export async function observeModuleExtensions(request: NextRequest): Promise<Response> {
  const lifetime = new AbortController();
  const observed = new NextRequest(request, {
    signal: AbortSignal.any([request.signal, lifetime.signal]),
  });
  const initial = await readModuleExtensions(observed);
  if (!initial.ok) {
    lifetime.abort();
    return initial;
  }
  const parsed = moduleExtensionSnapshot.safeParse(await initial.json().catch(() => undefined));
  if (!parsed.success) {
    lifetime.abort();
    return safeProblem('PC-INTEGRATION-5001', request);
  }
  const encoder = new TextEncoder();
  const observation = moduleExtensionObservationOf(parsed.data);
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;
  const stop = () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    if (onAbort) observed.signal.removeEventListener('abort', onAbort);
    lifetime.abort();
  };
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      const close = () => {
        if (stopped) return;
        stop();
        controller.close();
      };
      onAbort = close;
      observed.signal.addEventListener('abort', close, { once: true });
      const frame = (type: 'CURRENT' | 'INVALIDATED' | 'REOBSERVE', value: typeof observation) => {
        if (!stopped)
          controller.enqueue(
            encoder.encode(
              `event: ${moduleExtensionEventName}\ndata: ${JSON.stringify({ type, ...value })}\n\n`,
            ),
          );
      };
      if (observed.signal.aborted) {
        close();
        return;
      }
      frame('CURRENT', observation);
      // Finite transport budget, not a freshness/SLA or successful-disable claim.
      let remaining = 8;
      const next = async () => {
        if (stopped) return;
        try {
          const response = await readModuleExtensions(observed);
          if (stopped) return;
          if (!response.ok) {
            close();
            return;
          }
          const current = moduleExtensionSnapshot.parse(await response.json());
          if (stopped) return;
          const nextObservation = moduleExtensionObservationOf(current);
          const changed = !sameModuleExtensionObservation(nextObservation, observation);
          const renew = --remaining === 0;
          frame(changed ? 'INVALIDATED' : renew ? 'REOBSERVE' : 'CURRENT', nextObservation);
          if (changed || renew) {
            close();
            return;
          }
          timer = setTimeout(() => {
            void next();
          }, 1500);
        } catch {
          close();
        }
      };
      timer = setTimeout(() => {
        void next();
      }, 1500);
    },
    cancel() {
      stop();
    },
  });
  return new Response(body, {
    headers: {
      ...noStore,
      'Content-Type': 'text/event-stream; charset=utf-8',
      'X-Accel-Buffering': 'no',
    },
  });
}
