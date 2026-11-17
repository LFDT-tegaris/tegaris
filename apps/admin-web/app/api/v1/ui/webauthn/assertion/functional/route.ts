import type { NextRequest } from 'next/server';
import { completeFunctionalTestAssertion } from '../../../local-webauthn-runtime';

export const dynamic = 'force-dynamic';
export function POST(request: NextRequest) {
  return completeFunctionalTestAssertion(request);
}
