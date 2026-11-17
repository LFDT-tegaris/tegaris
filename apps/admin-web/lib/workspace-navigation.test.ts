import { expect, it } from 'vitest';
import {
  isWorkspaceReturnPath,
  signInHref,
  signInParticipant,
  workspaceReturnPath,
} from './workspace-navigation';

it.each([
  'https://evil.test',
  '//evil.test',
  '/\\evil.test',
  '/signin',
  '/api/v1/ui/local-session',
  '/unknown',
  '/home/../home/session',
  '/%2f%2fevil.test',
  '/home/session#secret',
  '/home/session\n',
  '/govern/memberships?view=invitation-acceptance',
])('rejects unsafe or non-workspace destinations: %s', (path) => {
  expect(isWorkspaceReturnPath(path)).toBe(false);
  expect(workspaceReturnPath(path)).toBe('/home/session');
});
it('preserves a recognized deep link and encodes it inside the sign-in destination', () => {
  const path = '/configure/policies?view=simulation&name=Quarterly%20review';
  expect(workspaceReturnPath(path)).toBe(path);
  const url = new URL(signInHref(path, true), 'https://tegaris.test');
  expect(url.pathname).toBe('/signin');
  expect(url.searchParams.get('returnTo')).toBe(path);
  expect(url.searchParams.get('reason')).toBe('session-ended');
  expect(workspaceReturnPath(['/operate/evidence'])).toBe('/home/session');
});

it('keeps the organization independent from the safe workspace return destination', () => {
  const participantId = '018f0000-0000-7000-8000-000000000102';
  const url = new URL(
    signInHref('https://evil.test', false, participantId),
    'https://tegaris.test',
  );
  expect(url.pathname).toBe('/signin');
  expect(url.searchParams.get('returnTo')).toBe('/home/session');
  expect(url.searchParams.get('participantId')).toBe(participantId);
  expect(signInParticipant(participantId)).toBe(participantId);
  expect(signInParticipant(undefined)).toBeUndefined();
});

it.each([
  { value: '' },
  { value: 'not-an-organization' },
  { value: ['018f0000-0000-7000-8000-000000000101'] },
  { value: ['018f0000-0000-7000-8000-000000000101', '018f0000-0000-7000-8000-000000000102'] },
  { value: null },
])('rejects an invalid or repeated organization context: %j', ({ value }) => {
  expect(signInParticipant(value)).toBeNull();
});

it('refuses to generate an organization link with a malformed identifier', () => {
  expect(() => signInHref('/home/session', false, 'invalid')).toThrow();
});
