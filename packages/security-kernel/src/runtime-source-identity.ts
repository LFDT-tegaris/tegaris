import { createHash } from 'node:crypto';

/** Stable native installer identity, not authority to create or use the login. */
export function runtimeSourceLogin(participantId: string, privacyDomainId: string): string {
  for (const value of [participantId, privacyDomainId]) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value))
      throw new Error('Invalid runtime source scope');
  }
  const suffix = createHash('sha256')
    .update(JSON.stringify(['openpc:runtime-source-scope:v1', participantId, privacyDomainId]))
    .digest('base64url');
  return `openpc_rs_login_${suffix}`;
}

/** Preserve legacy simple identifiers; the additional form is bound to exactly
 * one source scope, never arbitrary PostgreSQL quoted identifiers. */
export function isFactConsumerDatabaseRole(
  role: string,
  participantId: string,
  privacyDomainId: string,
): boolean {
  if (/^[a-z_][a-z0-9_]{0,62}$/u.test(role)) return true;
  try {
    return role === runtimeSourceLogin(participantId, privacyDomainId);
  } catch {
    return false;
  }
}
