import { processEvents } from '@openpc/ui-shell';
import { NextResponse, type NextRequest } from 'next/server';

import { fixtureFor, noStoreHeaders } from '../fixture';

export function GET(request: NextRequest) {
  const result = processEvents(fixtureFor(request));
  if (result.status !== 200) {
    return NextResponse.json(result.body, { status: result.status, headers: noStoreHeaders });
  }
  const frame = `event: ui-process\ndata: ${JSON.stringify(result.body)}\n\n`;
  return new Response(frame, {
    headers: {
      ...noStoreHeaders,
      'Connection': 'keep-alive',
      'Content-Type': 'text/event-stream; charset=utf-8',
      'X-Accel-Buffering': 'no',
    },
  });
}
