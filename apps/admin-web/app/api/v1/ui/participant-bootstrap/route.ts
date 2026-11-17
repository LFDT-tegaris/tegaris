import type { NextRequest } from 'next/server';
import { participantBootstrapWorkbench } from '../local-participant-bootstrap';
export const dynamic = 'force-dynamic';
export function POST(request: NextRequest) {
  return participantBootstrapWorkbench(request);
}
