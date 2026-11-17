import type { OidcTransactionCustody } from './domain/oidc-authorization.js';
type Purpose = 'SESSION' | 'INVITATION';
const name = (purpose: Purpose) =>
  purpose === 'SESSION' ? '__Host-openpc_oidc' : '__Host-openpc_invitation_oidc';
export function oidcCustodyCookie(
  transactionId: string,
  custody: OidcTransactionCustody,
  purpose: Purpose = 'SESSION',
  expiresAt?: string,
): string {
  const maxAge =
    expiresAt === undefined ? 300 : Math.floor((Date.parse(expiresAt) - Date.now()) / 1000);
  if (!Number.isSafeInteger(maxAge) || maxAge < 1 || maxAge > 3000)
    throw new Error('Invalid OIDC custody expiry');
  return `${name(purpose)}=${transactionId}.${custody.browserSession}.${custody.codeVerifier}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
export function oidcCustodyFromCookie(
  cookie: string | undefined,
  purpose: Purpose = 'SESSION',
): { readonly transactionId: string; readonly custody: OidcTransactionCustody } | undefined {
  const prefix = `${name(purpose)}=`;
  const value = cookie
    ?.split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix))
    ?.slice(prefix.length);
  if (value === undefined) return undefined;
  const [transactionId, browserSession, codeVerifier, extra] = value.split('.');
  if (!transactionId || !browserSession || !codeVerifier || extra !== undefined) return undefined;
  return { transactionId, custody: { browserSession, codeVerifier } };
}
