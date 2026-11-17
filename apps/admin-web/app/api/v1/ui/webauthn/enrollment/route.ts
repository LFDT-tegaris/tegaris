import type { NextRequest } from 'next/server';
import { readLocalWebAuthnEnrollment } from '../../local-bootstrap-runtime';

export const dynamic = 'force-dynamic';

export function GET(request: NextRequest) {
  return readLocalWebAuthnEnrollment(request);
}
