import { z } from 'zod';
import { AuthorityFenceError } from './authority-fence.js';
import { PlatformScopeReplacementError } from '../domain/platform-scope-replacement.js';

export type PlatformScopeOwnerStage =
  | 'approval_binding'
  | 'current_actor_root'
  | 'current_root_and_cohort'
  | 'current_webauthn_credentials'
  | 'scope_and_source_bounds'
  | 'administrator_role_binding'
  | 'withdrawal_and_handoff_readiness'
  | 'atomic_prepare'
  | 'atomic_commit'
  | 'effect_readback';

/** Closed diagnostic metadata survives rollback. Never retain the original
 * error, its message, query, parameters, driver details or signed authority. */
export class PlatformScopeOwnerFailure extends AuthorityFenceError {
  readonly code: 'PC-IDENTITY-1001' | 'PC-IDENTITY-1009';
  readonly sqlstate: string | undefined;
  readonly disposition: PlatformScopeReplacementError['disposition'] | undefined;

  constructor(
    readonly ownerStage: PlatformScopeOwnerStage,
    error: unknown,
  ) {
    super();
    this.code =
      error instanceof PlatformScopeReplacementError || error instanceof z.ZodError
        ? 'PC-IDENTITY-1009'
        : 'PC-IDENTITY-1001';
    const code =
      error !== null && typeof error === 'object' && 'code' in error ? error.code : undefined;
    this.sqlstate = typeof code === 'string' && /^[0-9A-Z]{5}$/u.test(code) ? code : undefined;
    this.disposition =
      error instanceof PlatformScopeReplacementError ? error.disposition : undefined;
  }
}
