import assert from 'node:assert/strict';

export const localQaIssuer = 'http://oidc-emulator:3006';

export function qaPublicOrigin(value) {
  if (value === undefined) return undefined;
  const url = new URL(value);
  assert.equal(url.protocol, 'https:', 'The public demo origin must use HTTPS');
  assert.equal(url.origin, value, 'Use an origin without credentials, a path or parameters');
  return value;
}

export function qaPublicServices(value, services = {}) {
  const origin = qaPublicOrigin(value);
  const result = structuredClone(services);
  if (origin === undefined) return result;
  const redirect = origin + '/api/v1/ui/oidc-session/callback';
  const environments = {
    'identity-service': {
      IDENTITY_OIDC_ISSUER: origin,
      IDENTITY_OIDC_REDIRECT_URI: redirect,
    },
    'admin-web': { OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL: origin + '/authorize' },
    'oidc-emulator': {
      OIDC_EMULATOR_ISSUER: origin,
      OIDC_EMULATOR_QA_REDIRECT_URI: redirect,
    },
  };
  for (const [name, environment] of Object.entries(environments)) {
    result[name] = {
      ...result[name],
      environment: { ...result[name]?.environment, ...environment },
    };
  }
  return result;
}

export function qaIssuerFromCompose(compose) {
  const issuer = compose.services?.['oidc-emulator']?.environment?.OIDC_EMULATOR_ISSUER;
  if (issuer === undefined) {
    const publicSettings = qaPublicServices('https://demo.example');
    for (const [name, service] of Object.entries(publicSettings)) {
      for (const key of Object.keys(service.environment)) {
        assert.equal(
          compose.services?.[name]?.environment?.[key],
          undefined,
          'Incomplete demo identity configuration',
        );
      }
    }
    return localQaIssuer;
  }
  const expected = qaPublicServices(issuer);
  for (const [name, service] of Object.entries(expected)) {
    for (const [key, value] of Object.entries(service.environment)) {
      assert.equal(
        compose.services?.[name]?.environment?.[key],
        value,
        'Inconsistent demo identity configuration',
      );
    }
  }
  return issuer;
}
