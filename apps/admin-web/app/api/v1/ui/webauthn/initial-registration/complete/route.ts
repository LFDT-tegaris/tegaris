import type { NextRequest } from 'next/server';

import { completeInitialWebAuthnRegistration } from '../../../local-bootstrap-runtime';

export const dynamic = 'force-dynamic';

export function POST(request: NextRequest) {
  return completeInitialWebAuthnRegistration(request);
}
