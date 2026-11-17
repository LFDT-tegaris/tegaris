import type { PlatformEnvelopeScopeAdmission } from '../../packages/security-kernel/src/identity-envelope/platform-scope.js';
export function localQaRpcAuthority(
  environment: Readonly<Record<string, string | undefined>>,
  bindings: {
    participantId: string;
    privacyDomainId: string;
    runtimeBindingId: string;
    targetProfileId: string;
  },
  nowMs?: number,
): PlatformEnvelopeScopeAdmission['grantable'];
