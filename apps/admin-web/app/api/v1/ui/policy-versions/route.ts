import type { NextRequest } from 'next/server';
import { readPolicyVersions } from '../local-policy-version-workbench';

export const dynamic = 'force-dynamic';
export function GET(request: NextRequest) {
  return readPolicyVersions(request);
}
