import { NextResponse, type NextRequest } from 'next/server';

import { bootstrapFor, fixtureFor, noStoreHeaders } from '../fixture';
import { localBootstrap } from '../local-runtime';

export async function GET(request: NextRequest) {
  const local = await localBootstrap(request);
  if (local) return local;
  const bootstrap = bootstrapFor(fixtureFor(request));
  if (!bootstrap) {
    return NextResponse.json(
      {
        code: 'PC-INTEGRATION-5001',
        title: 'The requested process is unavailable.',
        retryable: false,
      },
      { status: 503, headers: noStoreHeaders },
    );
  }
  return NextResponse.json(bootstrap, { headers: noStoreHeaders });
}
