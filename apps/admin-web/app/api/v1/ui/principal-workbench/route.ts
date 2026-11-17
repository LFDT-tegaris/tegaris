import type { NextRequest } from 'next/server';
import { readPrincipalWorkbench, mutatePrincipalWorkbench } from '../local-principal-workbench';
export const dynamic = 'force-dynamic';
export async function GET(request: NextRequest) {
  return (await readPrincipalWorkbench(request)) ?? new Response(null, { status: 404 });
}
export function POST(request: NextRequest) {
  return mutatePrincipalWorkbench(request);
}
