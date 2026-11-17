import { redirects, routes } from '@openpc/ui-shell';
import { z } from 'zod';

export const workspaceHome = '/home/session';

export function isWorkspaceReturnPath(value: string): boolean {
  if (
    value.length > 2048 ||
    !value.startsWith('/') ||
    value.startsWith('//') ||
    /[\\\s#]/u.test(value) ||
    [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  )
    return false;
  try {
    const url = new URL(value, 'https://workspace.invalid');
    return (
      url.origin === 'https://workspace.invalid' &&
      `${url.pathname}${url.search}` === value &&
      (routes.some((route) => route.path === url.pathname) ||
        Object.hasOwn(redirects, url.pathname)) &&
      !(
        url.pathname === '/govern/memberships' &&
        url.searchParams.get('view') === 'invitation-acceptance'
      )
    );
  } catch {
    return false;
  }
}

export function workspaceReturnPath(value: unknown): string {
  return typeof value === 'string' && isWorkspaceReturnPath(value) ? value : workspaceHome;
}

export function signInParticipant(value: unknown): string | null | undefined {
  if (value === undefined) return undefined;
  const participant = z.uuid().safeParse(value);
  return participant.success ? participant.data : null;
}

export function signInHref(returnPath: string, expired = false, participantId?: string): string {
  const query = new URLSearchParams({ returnTo: workspaceReturnPath(returnPath) });
  if (expired) query.set('reason', 'session-ended');
  if (participantId !== undefined) query.set('participantId', z.uuid().parse(participantId));
  return `/signin?${query}`;
}
