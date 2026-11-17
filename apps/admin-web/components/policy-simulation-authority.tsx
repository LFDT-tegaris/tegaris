'use client';

import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { participantAction } from '../lib/participant-action';
import type { PolicyWorkflowActorBinding } from './policy-workflow-storage';
import { CopyReference } from './copy-reference';
import { SecondaryPanel } from './secondary-panel';

const actorSchema = z.object({
  sessionId: z.string().min(1),
  principalId: z.string().min(1),
  participantId: z.string().min(1),
  privacyDomainId: z.string().min(1),
  contextEpoch: z.string().min(1),
  contextMode: z.literal('PARTICIPANT'),
});
const proofSchema = z.object({
  actionIntentId: z.literal(participantAction.id),
  actionIntentDigest: z.literal(participantAction.digest),
  resourceId: z.string().uuid(),
  resourceDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
});
const catalogueSchema = z.object({
  actor: actorSchema,
  requiresStepUp: proofSchema.optional(),
  workloads: z
    .array(
      z.object({
        effect: z.object({ principalId: z.string().uuid(), displayLabel: z.string().min(1) }),
      }),
    )
    .optional(),
  modules: z.object({
    simulationAuthorities: z.array(
      z.object({
        assignmentId: z.string().uuid(),
        workloadId: z.string().min(1),
        principalId: z.string().uuid(),
        roleId: z.string().min(1),
        workloadDisplayLabel: z.string().min(1).max(160).optional(),
        roleDisplayName: z.string().min(1).max(160).optional(),
        envelopeId: z.string().uuid(),
      }),
    ),
  }),
});
type Catalogue = z.infer<typeof catalogueSchema>;
const field = 'min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
function distinctReference(reference: string, references: readonly string[]): string {
  for (let length = 8; length < reference.length; length += 4) {
    const suffix = reference.slice(-length);
    if (!references.some((other) => other !== reference && other.endsWith(suffix)))
      return `…${suffix}`;
  }
  return reference;
}
const sameActor = (left: z.infer<typeof actorSchema>, right: PolicyWorkflowActorBinding) =>
  (['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'] as const).every(
    (key) => left[key] === right[key],
  );

export function PolicySimulationAuthority({
  actor,
  contextKey,
  onChange,
}: Readonly<{
  actor: PolicyWorkflowActorBinding | undefined;
  contextKey: string;
  onChange: (workloadId: string, assignmentId: string) => void;
}>) {
  const [catalogue, setCatalogue] = useState<Catalogue>();
  const loadedContext = useRef('');
  const [workload, setWorkload] = useState('');
  const [assignment, setAssignment] = useState('');
  const [message, setMessage] = useState('Loading current workload assignments.');
  const [busy, setBusy] = useState(false);
  const current = useRef({ actor, contextKey });
  current.current = { actor, contextKey };
  const request = useRef<{ generation: number; controller?: AbortController }>({ generation: 0 });
  const load = useCallback(
    async (proof?: z.infer<typeof proofSchema>) => {
      request.current.controller?.abort();
      const controller = new AbortController();
      const generation = request.current.generation + 1;
      request.current = { generation, controller };
      const captured = current.current;
      const valid = () =>
        !controller.signal.aborted &&
        request.current.generation === generation &&
        current.current.actor === captured.actor &&
        current.current.contextKey === captured.contextKey;
      setCatalogue(undefined);
      setWorkload('');
      setAssignment('');
      onChange('', '');
      if (!captured.actor) {
        setBusy(false);
        setMessage('Load a Participant session to choose a workload.');
        return;
      }
      setBusy(true);
      setMessage(proof ? 'Verifying your authenticator.' : 'Loading current workload assignments.');
      const session = async () => {
        const response = await fetch('/api/v1/ui/local-session', {
          cache: 'no-store',
          credentials: 'same-origin',
          signal: controller.signal,
        });
        if (!response.ok) throw new Error('Session unavailable');
        const value = z
          .object({ authenticated: z.literal(true) })
          .and(actorSchema)
          .parse(await response.json());
        if (!valid() || !sameActor(value, captured.actor!)) throw new Error('Session changed');
      };
      try {
        await session();
        if (proof) {
          if (proof.resourceId !== captured.actor.participantId) throw new Error('Scope changed');
          await performWebAuthnStepUp(
            { ...proof, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
            { resourceId: proof.resourceId, resourceDigest: proof.resourceDigest },
            { signal: controller.signal, isCurrent: valid },
          );
          await session();
        }
        const response = await fetch('/api/v1/ui/rpc-access-workbench?mode=simulation', {
          cache: 'no-store',
          credentials: 'same-origin',
          signal: controller.signal,
        });
        if (!response.ok) throw new Error('Catalogue unavailable');
        const next = catalogueSchema.parse(await response.json());
        await session();
        if (!valid() || !sameActor(next.actor, captured.actor)) throw new Error('Scope changed');
        if (next.requiresStepUp && next.requiresStepUp.resourceId !== captured.actor.participantId)
          throw new Error('Verification scope changed');
        loadedContext.current = captured.contextKey;
        setCatalogue(next);
        const options = next.requiresStepUp ? [] : next.modules.simulationAuthorities;
        // Multiple assignments require an explicit choice. Never borrow the
        // first available workload's permissions for a different selection.
        if (options.length === 1) {
          setWorkload(options[0]!.workloadId);
          setAssignment(options[0]!.assignmentId);
          onChange(options[0]!.workloadId, options[0]!.assignmentId);
        }
        setMessage(
          next.requiresStepUp
            ? 'Verify your authenticator to load current workload assignments.'
            : options.length
              ? 'Choose the workload and exact assignment to evaluate.'
              : 'No current assignments are available for contract simulation in this privacy context.',
        );
      } catch {
        if (valid()) setMessage('Workload assignments could not be loaded. Refresh to try again.');
      } finally {
        if (valid()) setBusy(false);
      }
    },
    [onChange],
  );
  useEffect(() => {
    void load();
    return () => {
      request.current.controller?.abort();
    };
  }, [actor, contextKey, load]);
  const visible =
    catalogue && actor && loadedContext.current === contextKey && sameActor(catalogue.actor, actor)
      ? catalogue
      : undefined;
  const options = visible?.requiresStepUp ? [] : (visible?.modules.simulationAuthorities ?? []);
  const workloads = [...new Set(options.map((option) => option.workloadId))];
  const assignments = options.filter((option) => option.workloadId === workload);
  const selected = assignments.find((option) => option.assignmentId === assignment);
  return (
    <div className="grid gap-3 lg:col-span-2">
      <p className="text-sm text-[color:var(--muted)]" role="status">
        {message}
      </p>
      <button
        type="button"
        disabled={busy || !actor}
        className="w-fit rounded border border-[color:var(--border)] px-3 py-2 font-medium disabled:opacity-60"
        onClick={() => void load(visible?.requiresStepUp)}
      >
        {visible?.requiresStepUp
          ? 'Verify authenticator and load assignments'
          : 'Refresh workload assignments'}
      </button>
      <label className="grid gap-1 font-medium">
        Workload
        <select
          className={field}
          value={workload}
          required
          disabled={busy || !options.length}
          onChange={(event) => {
            const value = event.target.value;
            const choices = options.filter((option) => option.workloadId === value);
            const selected = choices.length === 1 ? choices[0]!.assignmentId : '';
            setWorkload(value);
            setAssignment(selected);
            onChange(value, selected);
          }}
        >
          <option value="">Select an assigned workload</option>
          {workloads.map((value) => (
            <option key={value} value={value}>
              {options.find((option) => option.workloadId === value)?.workloadDisplayLabel ??
                visible?.workloads?.find((entry) =>
                  options.some(
                    (option) =>
                      option.workloadId === value &&
                      option.principalId === entry.effect.principalId,
                  ),
                )?.effect.displayLabel ??
                'Workload'}
              {' · '}
              {distinctReference(value, workloads)}
            </option>
          ))}
        </select>
      </label>
      <label className="grid gap-1 font-medium">
        Role assignment
        <select
          className={field}
          value={assignment}
          required
          disabled={busy || !workload}
          onChange={(event) => {
            setAssignment(event.target.value);
            onChange(workload, event.target.value);
          }}
        >
          <option value="">Select an assignment</option>
          {assignments.map((option) => (
            <option key={option.assignmentId} value={option.assignmentId}>
              {option.roleDisplayName ?? 'Role assignment'}
              {' · '}
              {distinctReference(
                option.assignmentId,
                assignments.map((row) => row.assignmentId),
              )}
            </option>
          ))}
        </select>
      </label>
      {selected && (
        <SecondaryPanel title="Access references" closeOnChange={contextKey}>
          <CopyReference label="Workload reference" value={selected.workloadId} />
          <CopyReference label="Assignment reference" value={selected.assignmentId} />
          <CopyReference label="Role reference" value={selected.roleId} />
        </SecondaryPanel>
      )}
      <p className="text-sm text-[color:var(--muted)]">
        This preview evaluates the selected workload and its current assignment. It does not grant
        runtime access.
      </p>
    </div>
  );
}
