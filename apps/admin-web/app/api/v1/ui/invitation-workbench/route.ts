import type { NextRequest } from 'next/server';
import { mutateInvitationWorkbench, readInvitationWorkbench } from '../local-invitation-workbench';
export const dynamic = 'force-dynamic';
export function POST(request: NextRequest) {
  return mutateInvitationWorkbench(request);
}
export function GET(request: NextRequest) {
  return readInvitationWorkbench(request);
}
