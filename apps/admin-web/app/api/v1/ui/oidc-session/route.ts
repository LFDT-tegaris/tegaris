import { type NextRequest } from 'next/server';

import { beginLocalOidc } from '../local-oidc-runtime';

export const dynamic = 'force-dynamic';

export function POST(request: NextRequest) {
  return beginLocalOidc(request);
}
