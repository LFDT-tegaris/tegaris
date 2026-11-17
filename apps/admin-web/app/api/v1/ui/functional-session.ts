import { NextResponse, type NextRequest } from 'next/server';
import { z } from 'zod';
import { functionalActorCookie, functionalContextCookie } from './functional-test-profile';
import {
  functionalIdentitySession,
  localRuntimeConfig,
  parsePublicCommand,
  safeProblem,
  sameOrigin,
} from './local-runtime';

export async function selectFunctionalActor(request: NextRequest) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime?.functionalTest) return safeProblem('PC-AUTH-0005', request);
  if (!sameOrigin(request)) return safeProblem('PC-AUTH-0002', request);
  if (request.headers.get('content-type')?.split(';', 1)[0]?.trim() !== 'application/json')
    return safeProblem('PC-DATA-6004', request);
  const text = await request.text();
  if (Buffer.byteLength(text) > 256) return safeProblem('PC-DATA-6004', request);
  const input = z
    .strictObject({
      role: z.enum(['operator', 'viewer']),
      context: z.enum(['PARTICIPANT', 'PLATFORM']).optional(),
    })
    .safeParse(parsePublicCommand(text));
  if (!input.success) return safeProblem('PC-DATA-6004', request);
  const session = await functionalIdentitySession(runtime, input.data.role, input.data.context);
  if (!session) return safeProblem('PC-AUTH-0005', request);
  const response = NextResponse.json(
    {
      status: 'selected',
      role: session.role,
      ...(input.data.context === undefined ? {} : { contextMode: session.contextMode }),
    },
    { headers: { 'Cache-Control': 'no-store' } },
  );
  response.cookies.set(functionalActorCookie, session.role, {
    httpOnly: true,
    secure: request.nextUrl.protocol === 'https:',
    sameSite: 'strict',
    path: '/',
  });
  response.cookies.set(functionalContextCookie, session.contextMode, {
    httpOnly: true,
    secure: request.nextUrl.protocol === 'https:',
    sameSite: 'strict',
    path: '/',
  });
  return response;
}
