import { expect, it } from 'vitest';
import {
  validOidcAuthorizationEndpoint,
  validOidcProviderResponse,
} from './oidc-provider-response';

const issuer = 'https://idp.example/realms/tegaris';
const state = 'S'.repeat(43);
const response = (extra = '') => new URLSearchParams(`code=opaque-code&state=${state}${extra}`);

it.each([
  'https://idp.example/realms/tegaris/protocol/openid-connect/auth',
  'https://localhost:53007/realms/tegaris/protocol/openid-connect/auth',
  'http://localhost:53006/authorize',
  'http://127.0.0.1:53006/authorize',
  'http://[::1]:53006/authorize',
])('admits an installed secured endpoint or loopback fixture: %s', (url) => {
  expect(validOidcAuthorizationEndpoint(url)).toBe(true);
});
it.each([
  'http://idp.example/authorize',
  'http://127.0.0.1.example/authorize',
  'http://localhost:53006/other',
  'https://user:password@idp.example/auth',
  'https://idp.example/auth?redirect_uri=https://attacker.example',
  'https://idp.example/auth#fragment',
  ' https://idp.example/auth',
  'https://idp.example/au\nth',
  'https://idp.example\\auth',
  'javascript:alert(1)',
  'not-a-url',
  '',
])('rejects unsafe or malformed installed endpoints: %s', (url) => {
  expect(validOidcAuthorizationEndpoint(url)).toBe(false);
});
it('accepts only the exact issuer and optional bounded provider session metadata', () => {
  expect(
    validOidcProviderResponse(response(`&iss=${encodeURIComponent(issuer)}`), issuer, 4096),
  ).toBe(true);
  expect(
    validOidcProviderResponse(
      response(`&iss=${encodeURIComponent(issuer)}&session_state=provider-session_1`),
      issuer,
      4096,
    ),
  ).toBe(true);
});
it.each([
  '',
  '&iss=https://attacker.example',
  `&iss=${encodeURIComponent(issuer + '/')}`,
  `&iss=${encodeURIComponent(issuer)}&iss=${encodeURIComponent(issuer)}`,
  `&iss=${encodeURIComponent(issuer)}&state=${state}`,
  `&iss=${encodeURIComponent(issuer)}&code=another-code`,
  `&iss=${encodeURIComponent(issuer)}&sessionToken=forged-session`,
  `&iss=${encodeURIComponent(issuer)}&role=admin`,
  `&iss=${encodeURIComponent(issuer)}&session_state=`,
  `&iss=${encodeURIComponent(issuer)}&session_state=${'s'.repeat(257)}`,
  `&iss=${encodeURIComponent(issuer)}&session_state=line%0Abreak`,
])('rejects issuer substitution, duplicates and injected callback metadata (%s)', (extra) => {
  expect(validOidcProviderResponse(response(extra), issuer, 4096)).toBe(false);
});
it('preserves two-field local and pre-existing custody callbacks without accepting extra identity claims', () => {
  for (const prior of [undefined, 'http://oidc-emulator:3006']) {
    expect(validOidcProviderResponse(response(), prior, 4096)).toBe(true);
    expect(validOidcProviderResponse(response('&iss=https://attacker.example'), prior, 4096)).toBe(
      false,
    );
    expect(validOidcProviderResponse(response('&session_state=state'), prior, 4096)).toBe(false);
  }
});
it('enforces the existing code and state bounds', () => {
  expect(
    validOidcProviderResponse(
      new URLSearchParams({ code: 'c'.repeat(4097), state, iss: issuer }),
      issuer,
      4096,
    ),
  ).toBe(false);
  expect(
    validOidcProviderResponse(
      new URLSearchParams({ code: 'c', state: 'short', iss: issuer }),
      issuer,
      4096,
    ),
  ).toBe(false);
});
