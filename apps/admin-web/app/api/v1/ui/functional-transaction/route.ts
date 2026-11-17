import type { NextRequest } from 'next/server';
import { applyFunctionalTransaction } from '../functional-transaction';

export const dynamic = 'force-dynamic';
export function POST(request: NextRequest) {
  return applyFunctionalTransaction(request);
}
