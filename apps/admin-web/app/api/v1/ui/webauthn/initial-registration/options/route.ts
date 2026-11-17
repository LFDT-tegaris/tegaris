import type { NextRequest } from 'next/server';

import { beginInitialWebAuthnRegistration } from '../../../local-bootstrap-runtime';

export const dynamic = 'force-dynamic';

export function POST(request: NextRequest) {
  return beginInitialWebAuthnRegistration(request);
}
