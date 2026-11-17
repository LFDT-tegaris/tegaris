import type { NextRequest } from 'next/server';
import {
  readTransactionWorkbench,
  mutateTransactionWorkbench,
} from '../local-transaction-workbench';

export const dynamic = 'force-dynamic';
export function GET(request: NextRequest) {
  return readTransactionWorkbench(request);
}
export function POST(request: NextRequest) {
  return mutateTransactionWorkbench(request);
}
