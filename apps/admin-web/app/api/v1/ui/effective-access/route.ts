import type { NextRequest } from 'next/server';

import { localEffectiveAccess } from '../local-policy-runtime';

export async function GET(request: NextRequest) {
  return (await localEffectiveAccess(request)) ?? new Response(null, { status: 404 });
}
