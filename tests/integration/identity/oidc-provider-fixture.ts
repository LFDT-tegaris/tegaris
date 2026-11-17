import { createServer } from 'node:http';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { exportJWK, SignJWT } from 'jose';

/** External IdP only: real discovery, signed claims, one-use codes and PKCE S256. */
export async function oidcProviderFixture(
  participantId: string,
  principalId: string,
  subject = principalId,
  options: { readonly membershipHints?: boolean; readonly listenPort?: number } = {},
) {
  const listenPort = options.listenPort ?? 0;
  if (!Number.isInteger(listenPort) || listenPort < 0 || listenPort > 65535)
    throw new Error('Invalid external fixture port');
  const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...(await exportJWK(keys.publicKey)), kid: 'recovery-external-test', alg: 'RS256' };
  const codes = new Map<string, Record<string, string>>();
  let issuer = '';
  let tokenExchanges = 0;
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', issuer);
    const send = (status: number, body: unknown) => {
      response.writeHead(status, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    if (url.pathname === '/.well-known/openid-configuration')
      return send(200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
      });
    if (url.pathname === '/jwks') return send(200, { keys: [jwk] });
    if (url.pathname === '/authorize') {
      if (url.searchParams.get('code_challenge_method') !== 'S256') return send(400, {});
      const code = randomBytes(32).toString('base64url');
      codes.set(code, Object.fromEntries(url.searchParams));
      const next = new URL(url.searchParams.get('redirect_uri')!);
      next.searchParams.set('code', code);
      next.searchParams.set('state', url.searchParams.get('state')!);
      response.writeHead(302, { Location: next.href });
      response.end();
      return;
    }
    if (url.pathname === '/token' && request.method === 'POST') {
      tokenExchanges += 1;
      let body = '';
      for await (const chunk of request) body += chunk;
      const form = new URLSearchParams(body),
        code = form.get('code') ?? '',
        grant = codes.get(code);
      if (
        !grant ||
        form.get('client_id') !== grant.client_id ||
        form.get('redirect_uri') !== grant.redirect_uri ||
        form.get('grant_type') !== 'authorization_code' ||
        createHash('sha256')
          .update(form.get('code_verifier') ?? '')
          .digest('base64url') !== grant.code_challenge
      )
        return send(400, {});
      codes.delete(code);
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({
        sub: subject,
        azp: grant.client_id,
        nonce: grant.nonce,
        ...(grant.auth_time === 'missing'
          ? {}
          : { auth_time: grant.auth_time === undefined ? now : Number(grant.auth_time) }),
        ...(options.membershipHints === false
          ? {}
          : {
              openpc_principal_id: principalId,
              openpc_participant_id: participantId,
            }),
      })
        .setProtectedHeader({ alg: 'RS256', kid: jwk.kid })
        .setIssuer(issuer)
        .setAudience(grant.client_id)
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(keys.privateKey);
      return send(200, { token_type: 'Bearer', id_token: token });
    }
    send(404, {});
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(listenPort, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('OIDC fixture listen failed');
  issuer = `http://127.0.0.1:${address.port}`;
  return {
    issuer,
    clientId: 'recovery-public-test',
    redirectUri: `${issuer}/callback`,
    setSubject(value: string) {
      subject = value;
    },
    tokenExchanges: () => tokenExchanges,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}
