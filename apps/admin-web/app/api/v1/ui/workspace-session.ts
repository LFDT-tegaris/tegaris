import { localSessionStatusSchema } from '../../../../lib/local-session-status';
import {
  decodeBffSession,
  localRuntimeConfig,
  functionalIdentitySession,
  validateIdentitySessionToken,
} from './local-runtime';

// A sealed browser cookie is custody, not proof that the native session is still live.
export async function readWorkspaceSession(
  cookie: string | undefined,
  functionalActor?: string,
  functionalContext?: string,
) {
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return undefined;
  if (runtime.functionalTest)
    return functionalIdentitySession(runtime, functionalActor, functionalContext);
  if (!cookie) return undefined;
  const local = decodeBffSession(cookie, runtime.cookieKey);
  if (!local) return undefined;
  const native = await validateIdentitySessionToken(runtime, local.sessionToken);
  if (!native || native.role !== local.role) return undefined;
  const parsed = localSessionStatusSchema.safeParse({
    ...native,
    enabled: true,
    authenticated: true,
    availableContexts: native.availableContexts ?? [],
  });
  return parsed.success &&
    parsed.data.enabled &&
    'authenticated' in parsed.data &&
    parsed.data.authenticated
    ? parsed.data
    : undefined;
}
