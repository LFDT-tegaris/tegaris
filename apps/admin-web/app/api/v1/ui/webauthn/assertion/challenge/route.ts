import type { NextRequest } from 'next/server';

import { beginLocalWebAuthnAssertion } from '../../../local-webauthn-runtime';

export const dynamic = 'force-dynamic';

export function POST(request: NextRequest) {
  return beginLocalWebAuthnAssertion(request);
}
