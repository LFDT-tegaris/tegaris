'use client';

import { useId } from 'react';
import { SecondaryPanel } from './secondary-panel';

const recipients = [
  ['ROLE', 'Role', 'Role reference'],
  ['USER', 'User', 'User identifier'],
  ['GROUP', 'Group', 'Group identifier'],
  ['WORKLOAD', 'Workload', 'Workload reference'],
  ['PARTICIPANT', 'Participant', 'Participant identifier'],
  ['ANY_AUTHENTICATED', 'Any authenticated subject', ''],
] as const;
const surfaces = [
  ['ETH_CALL', 'Read a contract (eth_call)'],
  ['ETH_ESTIMATE_GAS', 'Estimate gas (eth_estimateGas)'],
  ['PREPARE_WRITE', 'Prepare a write'],
  ['RAW_SUBMISSION', 'Submit a signed transaction'],
  ['DEPLOYMENT_CONSTRUCTOR', 'Deploy a contract'],
  ['RUNTIME_WRITE_TRACE', 'Trace a write'],
] as const;
const fields = new Set(['runtimeBindingId', 'selector', 'subject', 'surface', 'effect']);
type Definition = {
  runtimeBindingId?: string;
  selector?: string;
  subject?: { kind?: string; id?: string };
  surface?: string;
  effect?: string;
};

function readDefinition(value: string): Definition | undefined {
  if (!value.trim()) return {};
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
    for (const [name, field] of Object.entries(parsed)) {
      if (!fields.has(name)) return undefined;
      if (name === 'subject') {
        if (!field || typeof field !== 'object' || Array.isArray(field)) return undefined;
        if (
          Object.entries(field).some(
            ([key, entry]) => !['kind', 'id'].includes(key) || typeof entry !== 'string',
          )
        )
          return undefined;
        const subject = field as NonNullable<Definition['subject']>;
        if (subject?.kind !== undefined && !recipients.some(([kind]) => kind === subject.kind))
          return undefined;
        if (subject?.kind === 'ANY_AUTHENTICATED' && subject.id !== undefined) return undefined;
      } else if (typeof field !== 'string') return undefined;
      else if (name === 'surface' && !surfaces.some(([surface]) => surface === field))
        return undefined;
      else if (name === 'effect' && !['ALLOW', 'DENY'].includes(field)) return undefined;
    }
    return parsed as Definition;
  } catch {
    return undefined;
  }
}

/** A controlled view of the existing grant definition; the workflow owns submission. */
export function InteractionGrantFields({
  value,
  onChange,
}: Readonly<{ value: string; onChange(value: string): void }>) {
  const id = useId();
  const definition = readDefinition(value);
  const update = (next: Definition) => onChange(JSON.stringify(next, null, 2));
  const recipient = recipients.find(([kind]) => kind === definition?.subject?.kind);
  const controlClass =
    'mt-2 min-w-0 w-full rounded-md border border-[color:var(--border)] bg-[color:var(--surface)] p-3 text-sm';
  const sectionClass = 'min-w-0 rounded-lg border border-[color:var(--border)] p-4 sm:p-5';
  return (
    <div className="min-w-0 space-y-4">
      {definition ? (
        <>
          <fieldset className={sectionClass}>
            <legend className="px-1 font-semibold">Contract and method</legend>
            <p className="mb-4 text-sm text-[color:var(--muted)]">
              Identify the deployed contract binding and the exact method selector.
            </p>
            <div className="grid min-w-0 gap-4 lg:grid-cols-2">
              {(
                [
                  ['runtimeBindingId', 'Runtime binding reference', 'The complete resource URN.'],
                  [
                    'selector',
                    'Method selector',
                    'A lowercase 0x prefix and eight hexadecimal digits.',
                  ],
                ] as const
              ).map(([name, label, help]) => (
                <div key={name} className="min-w-0">
                  <label htmlFor={`${id}-${name}`} className="block text-sm font-medium">
                    {label}
                  </label>
                  <input
                    id={`${id}-${name}`}
                    className={`${controlClass} font-mono`}
                    required
                    autoComplete="off"
                    spellCheck={false}
                    pattern={name === 'selector' ? '0x[0-9a-f]{8}' : undefined}
                    aria-describedby={`${id}-${name}-help`}
                    value={definition[name] ?? ''}
                    onChange={(event) =>
                      update({ ...definition, [name]: event.currentTarget.value })
                    }
                  />
                  <p id={`${id}-${name}-help`} className="mt-2 text-xs text-[color:var(--muted)]">
                    {help}
                  </p>
                </div>
              ))}
            </div>
          </fieldset>
          <fieldset className={sectionClass}>
            <legend className="px-1 font-semibold">Recipient</legend>
            <p className="mb-4 text-sm text-[color:var(--muted)]">
              Choose who this rule concerns. Changing the recipient type clears its reference.
            </p>
            <label htmlFor={`${id}-recipient`} className="block text-sm font-medium">
              Recipient type
            </label>
            <select
              id={`${id}-recipient`}
              className={controlClass}
              required
              value={definition.subject?.kind ?? ''}
              onChange={(event) =>
                update({ ...definition, subject: { kind: event.currentTarget.value } })
              }
            >
              <option value="" disabled>
                Select a recipient type
              </option>
              {recipients.map(([kind, label]) => (
                <option key={kind} value={kind}>
                  {label}
                </option>
              ))}
            </select>
            {definition.subject?.kind === 'ANY_AUTHENTICATED' ? (
              <p className="mt-3 text-sm text-[color:var(--muted)]">
                This rule concerns any authenticated subject in its scope. It does not activate a
                grant.
              </p>
            ) : (
              <div className="mt-4">
                <label htmlFor={`${id}-subject`} className="block text-sm font-medium">
                  {recipient?.[2] || 'Recipient reference'}
                </label>
                <input
                  id={`${id}-subject`}
                  className={`${controlClass} font-mono`}
                  required
                  autoComplete="off"
                  spellCheck={false}
                  aria-describedby={`${id}-subject-help`}
                  value={definition.subject?.id ?? ''}
                  onChange={(event) =>
                    update({
                      ...definition,
                      subject: { ...definition.subject, id: event.currentTarget.value },
                    })
                  }
                />
                <p id={`${id}-subject-help`} className="mt-2 text-xs text-[color:var(--muted)]">
                  Roles and workloads use their complete URNs. Users, groups and participants use
                  their UUIDs.
                </p>
              </div>
            )}
          </fieldset>
          <fieldset className={sectionClass}>
            <legend className="px-1 font-semibold">Interface and decision</legend>
            <p className="mb-4 text-sm text-[color:var(--muted)]">
              Select the interface and decision explicitly. A new shared grant starts disabled.
            </p>
            <div className="grid min-w-0 gap-4 lg:grid-cols-2">
              <div className="min-w-0">
                <label htmlFor={`${id}-surface`} className="block text-sm font-medium">
                  Interface
                </label>
                <select
                  id={`${id}-surface`}
                  className={controlClass}
                  required
                  value={definition.surface ?? ''}
                  onChange={(event) =>
                    update({ ...definition, surface: event.currentTarget.value })
                  }
                >
                  <option value="" disabled>
                    Select an interface
                  </option>
                  {surfaces.map(([surface, label]) => (
                    <option key={surface} value={surface}>
                      {label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="min-w-0">
                <label htmlFor={`${id}-effect`} className="block text-sm font-medium">
                  Decision
                </label>
                <select
                  id={`${id}-effect`}
                  className={controlClass}
                  required
                  value={definition.effect ?? ''}
                  onChange={(event) => update({ ...definition, effect: event.currentTarget.value })}
                >
                  <option value="" disabled>
                    Select a decision
                  </option>
                  <option value="ALLOW">Allow</option>
                  <option value="DENY">Deny</option>
                </select>
              </div>
            </div>
          </fieldset>
        </>
      ) : (
        <p
          role="alert"
          className="rounded-md border border-[color:var(--border)] bg-[color:var(--canvas)] p-4 text-sm"
        >
          This definition needs JSON editing. Open Edit grant JSON to correct its fields. Its
          original contents are preserved.
        </p>
      )}
      <SecondaryPanel title="Edit grant JSON">
        <label htmlFor={`${id}-json`} className="block text-sm font-medium">
          Grant definition
        </label>
        <p id={`${id}-json-help`} className="my-2 text-sm text-[color:var(--muted)]">
          This is the same definition used by the form. Editing it replaces the current draft; the
          request is validated when you review it.
        </p>
        <textarea
          id={`${id}-json`}
          aria-describedby={`${id}-json-help`}
          className={`${controlClass} font-mono`}
          rows={12}
          value={value}
          spellCheck={false}
          onChange={(event) => onChange(event.currentTarget.value)}
        />
      </SecondaryPanel>
    </div>
  );
}
