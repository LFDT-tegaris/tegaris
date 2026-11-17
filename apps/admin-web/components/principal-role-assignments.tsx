'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { accessReviewPage, type AccessReviewPage } from '../lib/access-review';
import { assignmentGrant, delegationGrant, grantReadback } from './grant-workflow-contract';
import type { PolicyWorkflowActorBinding as ActorBinding } from './policy-workflow-storage';

const panel = 'rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60';
const rolePrefix = 'urn:openpc:role:';
const readFailure = 'Role assignments could not be confirmed. Reopen the principal to retry.';
const roleFailure = 'An assigned role could not be confirmed. Reopen the principal to retry.';
class RoleReadError extends Error {}

const actorBinding = z.object({
  sessionId: z.string(),
  principalId: z.string(),
  participantId: z.string(),
  privacyDomainId: z.string(),
  contextEpoch: z.string(),
});
const displayedGrant = z.union([
  assignmentGrant
    .loose()
    .refine((value) => !('parentId' in value || 'grantorId' in value || 'granteeId' in value)),
  delegationGrant.loose().refine((value) => !('principalId' in value)),
]);
const displayedPage = accessReviewPage
  .pick({
    participantId: true,
    privacyDomainId: true,
    nextCursor: true,
    completeness: true,
    authorizedEmpty: true,
  })
  .extend({
    subject: accessReviewPage.shape.subject.pick({ id: true }).loose(),
    items: z
      .array(z.object({ grant: grantReadback.loose().extend({ effect: displayedGrant }) }))
      .max(50),
  })
  .loose()
  .refine(
    (page) =>
      page.authorizedEmpty === (page.items.length === 0) &&
      (page.completeness === 'MORE') === (page.nextCursor !== null),
  );
const accessReviewResponse = z.object({ actor: actorBinding, page: displayedPage });
const displayedRole = z.object({
  id: z.string().min(1),
  roleId: z.string().min(1),
  displayName: z.string().min(1).max(160),
  state: z.enum(['ACTIVE', 'ARCHIVED']),
  revision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  origin: z.enum(['GOVERNED', 'MIGRATED_ASSIGNMENT', 'BOOTSTRAP']),
});
const roleWorkbench = z.object({
  actor: actorBinding,
  effect: z.object({ effect: displayedRole }),
});
type Role = z.infer<typeof displayedRole>;
interface AssignedRole {
  assignment: Extract<
    AccessReviewPage['items'][number]['grant']['effect'],
    { principalId: string }
  >;
  assignmentRevision: string;
  role: Role;
}

function sameActor(left: ActorBinding, right: ActorBinding | undefined) {
  return (
    right !== undefined &&
    (
      ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const
    ).every((key) => left[key] === right[key])
  );
}
async function json<T>(response: Response, failure = readFailure): Promise<T> {
  const value = await response.json().catch(() => undefined);
  if (!response.ok) throw new RoleReadError(failure);
  return value as T;
}

export function PrincipalRoleAssignments({
  actor,
  principalId,
}: {
  actor: ActorBinding;
  principalId: string;
}) {
  const [projection, setProjection] = useState<{
    actor: ActorBinding;
    principalId: string;
    items: AssignedRole[];
    nextCursor: string | null;
  }>();
  const [status, setStatus] = useState('Loading assigned roles.');
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const activeController = useRef<AbortController | undefined>(undefined);
  const load = useCallback(
    async (after?: string) => {
      const requestGeneration = ++generation.current;
      activeController.current?.abort();
      const controller = new AbortController();
      activeController.current = controller;
      const current = () => requestGeneration === generation.current && !controller.signal.aborted;
      setProjection(undefined);
      setBusy(true);
      setStatus('Reading governed role assignments.');
      try {
        const value = await json<unknown>(
          await fetch(
            `/api/v1/ui/access-review?${new URLSearchParams({ subjectId: principalId, limit: '25', ...(after ? { after } : {}) })}`,
            { cache: 'no-store', signal: controller.signal },
          ),
        );
        if (!current()) return;
        const parsed = accessReviewResponse.safeParse(value);
        if (!parsed.success) throw new RoleReadError(readFailure);
        const response = parsed.data;
        if (
          !sameActor(actor, response.actor) ||
          response.page.subject.id !== principalId ||
          response.page.participantId !== actor.participantId ||
          response.page.privacyDomainId !== actor.privacyDomainId ||
          response.page.items.some(
            ({ grant: { effect } }) =>
              effect.participantId !== actor.participantId ||
              effect.privacyDomainIds[0] !== actor.privacyDomainId ||
              ('principalId' in effect ? effect.principalId : effect.granteeId) !== principalId,
          )
        )
          throw new RoleReadError(
            'The working context changed. Reopen the principal before continuing.',
          );
        const direct = response.page.items.filter(
          (item) =>
            'principalId' in item.grant.effect &&
            item.grant.effect.principalId === principalId &&
            item.grant.effect.roleId !== undefined,
        );
        const resolved = await Promise.all(
          direct.map(async (item): Promise<AssignedRole | undefined> => {
            if (!current()) return;
            const assignment = item.grant.effect as AssignedRole['assignment'];
            const roleUuid = assignment.roleId?.startsWith(rolePrefix)
              ? assignment.roleId.slice(rolePrefix.length)
              : '';
            if (!roleUuid) throw new RoleReadError('An assigned role reference is invalid.');
            const roleValue = await json<unknown>(
              await fetch(`/api/v1/ui/role-workbench?roleId=${encodeURIComponent(roleUuid)}`, {
                cache: 'no-store',
                signal: controller.signal,
              }),
              roleFailure,
            );
            if (!current()) return;
            const parsedRole = roleWorkbench.safeParse(roleValue);
            if (!parsedRole.success) throw new RoleReadError(roleFailure);
            const role = parsedRole.data;
            if (
              !sameActor(actor, role.actor) ||
              !role.effect ||
              role.effect.effect.id !== roleUuid ||
              role.effect.effect.roleId !== assignment.roleId
            )
              throw new RoleReadError(
                'An assigned role could not be reconciled with its current record.',
              );
            return {
              assignment,
              assignmentRevision: item.grant.revision,
              role: role.effect.effect,
            };
          }),
        );
        if (!current()) return;
        const roles = resolved.filter((item): item is AssignedRole => item !== undefined);
        setProjection({ actor, principalId, items: roles, nextCursor: response.page.nextCursor });
        setStatus(
          roles.length > 0
            ? 'Assigned roles loaded from current governed records.'
            : response.page.nextCursor
              ? 'No direct role assignments appear on this authority page.'
              : 'No roles are assigned to this principal in the current privacy context.',
        );
      } catch (error) {
        if (current()) {
          setStatus(error instanceof RoleReadError ? error.message : readFailure);
          controller.abort();
        }
      } finally {
        if (requestGeneration === generation.current) setBusy(false);
        if (activeController.current === controller) activeController.current = undefined;
      }
    },
    [actor, principalId],
  );
  useEffect(() => {
    void load();
    return () => {
      generation.current++;
      activeController.current?.abort();
      activeController.current = undefined;
    };
  }, [load]);
  const visibleProjection =
    projection && sameActor(actor, projection.actor) && projection.principalId === principalId
      ? projection
      : undefined;
  return (
    <section className={`${panel} mt-4`} aria-label="Assigned roles">
      <h3 className="font-semibold">Assigned roles</h3>
      <p className="mt-2 text-sm text-[color:var(--muted)]">
        Direct governed assignments are shown here. Delegated authority does not create role
        membership.
      </p>
      <p className="mt-3 break-words" role="status">
        {status}
      </p>
      {visibleProjection?.items.map(({ assignment, assignmentRevision, role }) => (
        <article
          className="mt-4 grid gap-2 border-t border-[color:var(--border)] pt-4 text-sm"
          key={assignment.id}
        >
          <h4 className="text-base font-semibold">{role.displayName}</h4>
          <p>
            Role {role.state} · revision {role.revision} · {role.origin}
          </p>
          <p className="break-all">Role ID: {role.id}</p>
          <p className="break-all">Role reference: {role.roleId}</p>
          <p>
            Assignment {assignment.state} · revision {assignmentRevision}
          </p>
          <p className="break-all">Assignment ID: {assignment.id}</p>
          <p>
            Valid from {assignment.validFrom} until {assignment.validUntil ?? 'no fixed end date'}
          </p>
        </article>
      ))}
      {visibleProjection?.nextCursor ? (
        <button
          className={`${button} mt-4`}
          disabled={busy}
          onClick={() => void load(visibleProjection.nextCursor!)}
          type="button"
        >
          Next role assignment page
        </button>
      ) : null}
    </section>
  );
}
