import { readProcessSnapshot } from '@openpc/ui-shell';
import { NextResponse, type NextRequest } from 'next/server';

import { fixtureFor, noStoreHeaders } from '../../fixture';
import { localPolicySnapshot } from '../../local-policy-runtime';
import { localSnapshot } from '../../local-runtime';

interface RouteContext {
  readonly params: Promise<{ readonly domain: string }>;
}

export async function GET(request: NextRequest, context: RouteContext) {
  const { domain } = await context.params;
  const policy = await localPolicySnapshot(request, domain);
  if (policy) return policy;
  const local = await localSnapshot(request, domain);
  if (local) return local;
  const result = readProcessSnapshot(domain, fixtureFor(request));
  return NextResponse.json(result.body, { status: result.status, headers: noStoreHeaders });
}
