import type { NextRequest } from 'next/server';
import { mutateWorkloadWorkbench, readWorkloadWorkbench } from '../local-workload-workbench';
export const dynamic = 'force-dynamic';
export function GET(request: NextRequest) {
  return readWorkloadWorkbench(request);
}
export function POST(request: NextRequest) {
  return mutateWorkloadWorkbench(request);
}
