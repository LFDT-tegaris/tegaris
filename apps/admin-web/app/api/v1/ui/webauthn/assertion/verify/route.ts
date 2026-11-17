import type { NextRequest } from 'next/server';

import { completeLocalWebAuthnAssertion } from '../../../local-webauthn-runtime';

export const dynamic = 'force-dynamic';

export function POST(request: NextRequest) {
  return completeLocalWebAuthnAssertion(request);
}
