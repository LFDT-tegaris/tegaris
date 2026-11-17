import type { Pool } from 'pg';
import type { PlatformEnvelopeScopeAdmission } from '../../packages/security-kernel/src/identity-envelope/platform-scope.js';
export function installInitialPlatformEnvelopeScope(
  pool: Pool,
  input: PlatformEnvelopeScopeAdmission,
): Promise<{
  platformContextId: string;
  platformAuthorityEpoch: string;
  platformAuthorityDigest: string;
}>;
