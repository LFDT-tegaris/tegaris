import type { NextRequest } from 'next/server';

import { selectLocalParticipantContext } from '../../local-bootstrap-runtime';

export const dynamic = 'force-dynamic';

export function POST(request: NextRequest) {
  return selectLocalParticipantContext(request);
}
