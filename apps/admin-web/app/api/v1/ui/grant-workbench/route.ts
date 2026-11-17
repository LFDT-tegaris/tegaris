import type { NextRequest } from 'next/server';
import { readGrantWorkbench, mutateGrantWorkbench } from '../local-grant-workbench';
export const dynamic = 'force-dynamic';
export async function GET(request: NextRequest) {
  return (await readGrantWorkbench(request)) ?? new Response(null, { status: 404 });
}
export function POST(request: NextRequest) {
  return mutateGrantWorkbench(request);
}
