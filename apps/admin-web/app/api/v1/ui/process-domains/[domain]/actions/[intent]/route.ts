import { invokeProcessAction } from '@openpc/ui-shell';
import { NextResponse, type NextRequest } from 'next/server';

import { fixtureFor, noStoreHeaders } from '../../../../fixture';
import { localPolicyAction } from '../../../../local-policy-runtime';
import { localAction } from '../../../../local-runtime';

interface RouteContext {
  readonly params: Promise<{ readonly domain: string; readonly intent: string }>;
}

function actionInput(value: unknown): { actionIntentId?: string; actionIntentDigest?: string } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const input = value as Record<string, unknown>;
  if (
    Object.keys(input).length !== 2 ||
    typeof input.actionIntentId !== 'string' ||
    typeof input.actionIntentDigest !== 'string'
  ) {
    return {};
  }
  return { actionIntentId: input.actionIntentId, actionIntentDigest: input.actionIntentDigest };
}

export async function POST(request: NextRequest, context: RouteContext) {
  const { domain, intent } = await context.params;
  const policy = await localPolicyAction(request, domain, intent);
  if (policy) return policy;
  const local = await localAction(request, domain, intent);
  if (local) return local;
  const body = actionInput(await request.json().catch(() => undefined));
  const result = invokeProcessAction(domain, intent, fixtureFor(request), {
    csrfToken: request.headers.get('x-csrf-token') ?? undefined,
    idempotencyKey: request.headers.get('idempotency-key') ?? undefined,
    etag: request.headers.get('if-match') ?? undefined,
    ...body,
  });
  return NextResponse.json(result.body, { status: result.status, headers: noStoreHeaders });
}
