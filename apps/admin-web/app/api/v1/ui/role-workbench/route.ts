import type { NextRequest } from 'next/server';
import { readRoleWorkbench, mutateRoleWorkbench } from '../local-role-workbench';
export const dynamic = 'force-dynamic';
export async function GET(request: NextRequest) {
  return (await readRoleWorkbench(request)) ?? new Response(null, { status: 404 });
}
export function POST(request: NextRequest) {
  return mutateRoleWorkbench(request);
}
