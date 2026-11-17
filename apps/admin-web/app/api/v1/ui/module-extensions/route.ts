import type { NextRequest } from 'next/server';
import { readModuleExtensions } from '../local-module-extensions';
export const dynamic = 'force-dynamic';
export function GET(request: NextRequest) {
  return readModuleExtensions(request);
}
