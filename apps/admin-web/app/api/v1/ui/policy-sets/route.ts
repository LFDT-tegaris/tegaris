import type { NextRequest } from 'next/server';
import { createPolicySet, readPolicySets } from '../local-policy-set-workbench';

export const dynamic = 'force-dynamic';
export function GET(request: NextRequest) {
  return readPolicySets(request);
}
export function POST(request: NextRequest) {
  return createPolicySet(request);
}
