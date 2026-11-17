import type { NextRequest } from 'next/server';
import { mutateRecoveryWorkbench, readRecoveryWorkbench } from '../local-recovery-workbench';
export const dynamic = 'force-dynamic';
export function GET(request: NextRequest) {
  return readRecoveryWorkbench(request);
}
export function POST(request: NextRequest) {
  return mutateRecoveryWorkbench(request);
}
