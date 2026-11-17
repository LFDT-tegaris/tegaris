import type { FastifyReply } from 'fastify';
import type { BoundAuthority } from './db/authority-fence.js';
import type { AuthenticatedIdentityActor } from './domain/identity-kernel.js';

export type IdentityRouteHeaders = Record<string, string | string[] | undefined>;
/** Routes share the actual service authentication and governance owners. */
export interface IdentityRouteHelpers {
  authenticate(cookie: string | undefined): Promise<AuthenticatedIdentityActor>;
  authorizeRead(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    resourceId: string,
  ): Promise<BoundAuthority>;
  prepare(
    actor: AuthenticatedIdentityActor,
    headers: IdentityRouteHeaders,
    intent: string,
    operation: string,
    resourceId: string,
    candidate: unknown,
    makerChecker: boolean,
  ): Promise<{ aggregateVersion: string; digest: string; idempotencyKey: string }>;
  authorize(
    actor: AuthenticatedIdentityActor,
    headers: IdentityRouteHeaders,
    intent: string,
    operation: string,
    resourceId: string,
    candidate: unknown,
  ): Promise<AuthenticatedIdentityActor>;
  problem(reply: FastifyReply, error: unknown): unknown;
}
