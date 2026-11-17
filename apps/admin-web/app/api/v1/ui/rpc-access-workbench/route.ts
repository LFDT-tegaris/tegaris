import type { NextRequest } from 'next/server';

import { mutateRpcAccessWorkbench, readRpcAccessWorkbench } from '../local-rpc-access-workbench';

export const dynamic = 'force-dynamic';
export const GET = readRpcAccessWorkbench;
export const POST = (request: NextRequest) => mutateRpcAccessWorkbench(request);
