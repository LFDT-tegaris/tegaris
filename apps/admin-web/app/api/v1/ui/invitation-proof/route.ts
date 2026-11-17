import type { NextRequest } from 'next/server';
import { beginInvitationProof, readInvitationResult } from '../local-invitation-proof';
export const dynamic = 'force-dynamic';
export function POST(request: NextRequest) {
  return beginInvitationProof(request);
}
export function GET(request: NextRequest) {
  return readInvitationResult(request);
}
