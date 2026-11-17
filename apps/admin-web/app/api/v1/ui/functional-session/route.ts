import type { NextRequest } from 'next/server';
import { selectFunctionalActor } from '../functional-session';

export const dynamic = 'force-dynamic';
export function POST(request: NextRequest) {
  return selectFunctionalActor(request);
}
