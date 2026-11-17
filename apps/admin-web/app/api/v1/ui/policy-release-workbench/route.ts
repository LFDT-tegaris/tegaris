import { type NextRequest } from 'next/server';

import {
  mutatePolicyReleaseWorkbench,
  readPolicyReleaseWorkbench,
} from '../local-policy-release-workbench';

export const dynamic = 'force-dynamic';

export function GET(request: NextRequest) {
  return readPolicyReleaseWorkbench(request);
}

export function POST(request: NextRequest) {
  return mutatePolicyReleaseWorkbench(request);
}
