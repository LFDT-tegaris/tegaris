'use client';

import { useId } from 'react';
import { SecondaryPanel } from './secondary-panel';

const groups = [
  {
    title: 'Runtime configuration',
    help: 'Use the target and generation currently installed in this workspace.',
    fields: [
      ['targetRuntimeId', 'Runtime target reference', 'The complete resource URN.'],
      [
        'expectedGenerationDigest',
        'Installed generation digest',
        'The sha256: digest from current target readback.',
      ],
    ],
  },
  {
    title: 'Contract and method',
    help: 'Pin the deployed contract and method to their current revisions.',
    fields: [
      [
        'runtimeBindingId',
        'Runtime binding reference',
        'The resource URN for the deployed contract binding.',
      ],
      [
        'expectedRuntimeBindingRevision',
        'Runtime binding revision',
        'The current revision, entered as a decimal string.',
      ],
      [
        'contractMethodPolicyId',
        'Method policy reference',
        'The resource URN for the registered method policy.',
      ],
      [
        'expectedMethodRevision',
        'Method policy revision',
        'The current revision, entered as a decimal string.',
      ],
    ],
  },
  {
    title: 'Transaction to analyse',
    help: 'Identify the exact workload transaction and the time available to complete its analysis.',
    fields: [
      ['workloadId', 'Workload reference', 'The complete urn:openpc:workload: reference.'],
      [
        'transactionHash',
        'Transaction hash',
        'The lowercase 0x-prefixed transaction hash, with 64 hexadecimal digits.',
      ],
      [
        'expiresInSeconds',
        'Analysis lifetime (seconds)',
        '30–900 seconds. The returned expiry determines how long the analysis remains usable.',
      ],
    ],
  },
] as const;

const names = new Set<string>(groups.flatMap((group) => group.fields.map(([name]) => name)));

function readDraft(value: string): Record<string, string | number | undefined> | undefined {
  if (!value.trim()) return {};
  try {
    const result: unknown = JSON.parse(value);
    if (!result || typeof result !== 'object' || Array.isArray(result)) return undefined;
    for (const [name, field] of Object.entries(result)) {
      if (!names.has(name)) return undefined;
      if (name === 'expiresInSeconds' ? typeof field !== 'number' : typeof field !== 'string')
        return undefined;
    }
    return result as Record<string, string | number | undefined>;
  } catch {
    return undefined;
  }
}

/** A controlled view of the existing definition; no separate request or draft store. */
export function InteractionAnalysisFields({
  value,
  onChange,
}: Readonly<{ value: string; onChange(value: string): void }>) {
  const id = useId();
  const draft = readDraft(value);
  return (
    <div className="min-w-0 space-y-4">
      {draft ? (
        groups.map((group) => (
          <fieldset
            key={group.title}
            className="min-w-0 rounded-lg border border-[color:var(--border)] p-4 sm:p-5"
          >
            <legend className="px-1 font-semibold">{group.title}</legend>
            <p className="mb-4 text-sm text-[color:var(--muted)]">{group.help}</p>
            <div className="grid min-w-0 gap-4 lg:grid-cols-2">
              {group.fields.map(([name, label, help]) => (
                <div key={name} className="min-w-0">
                  <label htmlFor={`${id}-${name}`} className="block text-sm font-medium">
                    {label}
                  </label>
                  <input
                    id={`${id}-${name}`}
                    className="mt-2 min-w-0 w-full rounded-md border border-[color:var(--border)] bg-[color:var(--surface)] p-3 font-mono text-sm"
                    required
                    type={name === 'expiresInSeconds' ? 'number' : 'text'}
                    min={name === 'expiresInSeconds' ? 30 : undefined}
                    max={name === 'expiresInSeconds' ? 900 : undefined}
                    step={name === 'expiresInSeconds' ? 1 : undefined}
                    spellCheck={false}
                    autoComplete="off"
                    aria-describedby={`${id}-${name}-help`}
                    value={draft[name] ?? ''}
                    onChange={(event) => {
                      const next = { ...draft };
                      if (name === 'expiresInSeconds') {
                        if (!event.currentTarget.value) delete next[name];
                        else if (Number.isFinite(event.currentTarget.valueAsNumber))
                          next[name] = event.currentTarget.valueAsNumber;
                        else return;
                      } else next[name] = event.currentTarget.value;
                      onChange(JSON.stringify(next, null, 2));
                    }}
                  />
                  <p
                    id={`${id}-${name}-help`}
                    className="mt-2 text-xs leading-relaxed text-[color:var(--muted)]"
                  >
                    {help}
                  </p>
                </div>
              ))}
            </div>
          </fieldset>
        ))
      ) : (
        <p
          role="alert"
          className="rounded-md border border-[color:var(--border)] bg-[color:var(--canvas)] p-4 text-sm"
        >
          This definition needs JSON editing. Open Edit analysis JSON to correct its fields. Its
          original contents are preserved.
        </p>
      )}
      <SecondaryPanel title="Edit analysis JSON">
        <label htmlFor={`${id}-json`} className="block text-sm font-medium">
          Analysis definition
        </label>
        <p id={`${id}-json-help`} className="my-2 text-sm text-[color:var(--muted)]">
          This is the same definition used by the form. Editing it replaces the current draft; the
          request is validated when you review it.
        </p>
        <textarea
          id={`${id}-json`}
          aria-describedby={`${id}-json-help`}
          className="min-w-0 w-full rounded-md border border-[color:var(--border)] bg-[color:var(--surface)] p-3 font-mono text-sm"
          rows={12}
          value={value}
          spellCheck={false}
          onChange={(event) => onChange(event.currentTarget.value)}
        />
      </SecondaryPanel>
    </div>
  );
}
