export function validOidcAuthorizationEndpoint(value: string | undefined): boolean {
  if (!value || value.length > 2048 || /[\s\\]/u.test(value)) return false;
  try {
    const url = new URL(value);
    return (
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      (url.protocol === 'https:' ||
        (url.protocol === 'http:' &&
          ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) &&
          url.pathname === '/authorize'))
    );
  } catch {
    return false;
  }
}

export function oidcProviderTransportMatches(endpoint: string, issuer: string): boolean {
  try {
    const url = new URL(issuer);
    return (
      issuer.length <= 2048 &&
      !/[\s\\]/u.test(issuer) &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash &&
      ['https:', 'http:'].includes(url.protocol) &&
      url.protocol === new URL(endpoint).protocol
    );
  } catch {
    return false;
  }
}

/** Bind secured provider responses to the issuer retained from the native begin response. */
export function validOidcProviderResponse(
  params: URLSearchParams,
  issuer: string | undefined,
  maximumCodeLength: number,
): boolean {
  const keys = [...params.keys()];
  const code = params.get('code'),
    state = params.get('state');
  if (
    keys.length < 2 ||
    keys.length > 4 ||
    new Set(keys).size !== keys.length ||
    !code ||
    code.length > maximumCodeLength ||
    !state ||
    state.length < 32 ||
    state.length > 256
  )
    return false;
  if (issuer === undefined || issuer.startsWith('http://'))
    return keys.length === 2 && keys.includes('code') && keys.includes('state');
  try {
    const url = new URL(issuer);
    if (
      url.protocol !== 'https:' ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      params.get('iss') !== issuer ||
      keys.some((key) => !['code', 'state', 'iss', 'session_state'].includes(key))
    )
      return false;
    // Provider session metadata is bounded, never an OpenPC session or authority.
    return (
      !params.has('session_state') || /^[A-Za-z0-9._~-]{1,256}$/u.test(params.get('session_state')!)
    );
  } catch {
    return false;
  }
}
