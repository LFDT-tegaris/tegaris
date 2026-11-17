import { type NextRequest } from 'next/server';

import { localLogin, localLogout, localRefreshSession, localRuntimeStatus } from '../local-runtime';

export const dynamic = 'force-dynamic';

export function GET(request: NextRequest) {
  return localRuntimeStatus(request);
}

export function POST(request: NextRequest) {
  return localLogin(request);
}

export function DELETE(request: NextRequest) {
  return localLogout(request);
}

export function PATCH(request: NextRequest) {
  return localRefreshSession(request);
}
