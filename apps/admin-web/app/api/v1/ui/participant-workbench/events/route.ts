import type { NextRequest } from 'next/server';

import { participantWorkbenchEvent } from '../../local-participant-workbench';

export const dynamic = 'force-dynamic';

export function GET(request: NextRequest) {
  return participantWorkbenchEvent(request);
}
