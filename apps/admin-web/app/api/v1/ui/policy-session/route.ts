import { type NextRequest } from 'next/server';

import { localPolicyBootstrap } from '../local-policy-runtime';

export async function GET(request: NextRequest) {
  return (await localPolicyBootstrap(request)) ?? new Response(null, { status: 404 });
}
