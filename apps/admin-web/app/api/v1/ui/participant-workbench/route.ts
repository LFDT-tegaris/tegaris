import type { NextRequest } from 'next/server';

import {
  mutateParticipantWorkbench,
  readParticipantWorkbench,
} from '../local-participant-workbench';

export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
  return (await readParticipantWorkbench(request)) ?? new Response(null, { status: 404 });
}

export function POST(request: NextRequest) {
  return mutateParticipantWorkbench(request);
}
