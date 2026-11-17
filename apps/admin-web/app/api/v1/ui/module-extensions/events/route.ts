import type { NextRequest } from 'next/server';
import { observeModuleExtensions } from '../../local-module-extensions';
export const dynamic = 'force-dynamic';
export function GET(request: NextRequest) {
  return observeModuleExtensions(request);
}
