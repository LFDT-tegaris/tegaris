import type { NextRequest } from 'next/server';
import { mutateCredentialWorkbench, readCredentialWorkbench } from '../local-credential-workbench';
export const dynamic = 'force-dynamic';
export function GET(request: NextRequest) {
  return readCredentialWorkbench(request);
}
export function POST(request: NextRequest) {
  return mutateCredentialWorkbench(request);
}
