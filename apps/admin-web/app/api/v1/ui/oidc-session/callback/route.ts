import { type NextRequest } from 'next/server';

import { completeLocalOidc } from '../../local-oidc-runtime';

export const dynamic = 'force-dynamic';

export function GET(request: NextRequest) {
  return completeLocalOidc(request);
}
