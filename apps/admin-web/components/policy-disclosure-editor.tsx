'use client';

import { useId } from 'react';
import {
  disclosureDimensionLabels,
  type DisclosureDraftChange,
  type DisclosureDraftRule,
} from '../lib/policy-disclosure-draft';

const names = {
  STATE_READ: 'Contract results',
  EVENT: 'Event data',
  TRANSACTION: 'Transaction data',
  RECEIPT: 'Transaction receipt',
  DISCLOSURE: 'Profile data',
} as const;

export function PolicyDisclosureEditor({
  rules,
  original,
  onChange,
}: Readonly<{
  rules: DisclosureDraftRule[];
  original: DisclosureDraftRule[];
  onChange(policyId: string, change: DisclosureDraftChange): void;
}>) {
  const id = useId();
  if (!rules.length) return null;
  return (
    <section
      className="mt-6 border-t border-[color:var(--border)] pt-5"
      aria-label="Disclosure permissions"
    >
      <h4 className="text-lg font-semibold">Disclosure permissions</h4>
      <p className="mt-1 text-sm text-[color:var(--muted)]">
        Change the draft’s response permissions. Only fields and dimensions in the imported rule are
        available. Subjects, roles and conditions stay attached to the rule.
      </p>
      <div className="mt-4 grid gap-4">
        {rules.slice(0, 12).map((rule, index) => {
          const base = original.find((value) => value.policyId === rule.policyId);
          if (!base) return null;
          const denied = rule.effect === 'DENY';
          return (
            <fieldset
              key={rule.policyId}
              className="min-w-0 rounded-lg border border-[color:var(--border)] p-4"
            >
              <legend className="px-1 font-semibold">
                {names[rule.selector.kind]} · {index + 1}
              </legend>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-sm">
                  Purpose: <span className="font-medium">{rule.purpose}</span> ·{' '}
                  {rule.mode === 'DYNAMIC' ? 'Conditions required' : 'Static rule'}
                </p>
                <label className="grid gap-1 text-sm font-medium" htmlFor={`${id}-${index}-effect`}>
                  Response permission
                  <select
                    id={`${id}-${index}-effect`}
                    value={rule.effect}
                    onChange={(event) =>
                      onChange(rule.policyId, {
                        effect: event.currentTarget.value as 'ALLOW' | 'DENY',
                      })
                    }
                    className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
                  >
                    <option value="ALLOW">Allow selected data</option>
                    <option value="DENY">Deny disclosure</option>
                  </select>
                </label>
              </div>
              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <fieldset disabled={denied} className="grid content-start gap-2">
                  <legend className="mb-2 text-sm font-medium">Response dimensions</legend>
                  {base.dimensions.map((dimension) => (
                    <label key={dimension} className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={rule.dimensions.includes(dimension)}
                        onChange={(event) =>
                          onChange(rule.policyId, {
                            dimensions: event.currentTarget.checked
                              ? [...rule.dimensions, dimension]
                              : rule.dimensions.filter((value) => value !== dimension),
                          })
                        }
                      />
                      {disclosureDimensionLabels[dimension]}
                    </label>
                  ))}
                  {!base.dimensions.length && (
                    <p className="text-sm text-[color:var(--muted)]">No dimensions in this rule.</p>
                  )}
                </fieldset>
                <fieldset disabled={denied} className="grid content-start gap-2">
                  <legend className="mb-2 text-sm font-medium">Response fields</legend>
                  {base.fields.map((field) => (
                    <label key={field} className="flex min-w-0 items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={rule.fields.includes(field)}
                        onChange={(event) =>
                          onChange(rule.policyId, {
                            fields: event.currentTarget.checked
                              ? [...rule.fields, field]
                              : rule.fields.filter((value) => value !== field),
                          })
                        }
                      />
                      <span className="break-all">{field}</span>
                    </label>
                  ))}
                  {rule.selector.kind === 'RECEIPT' ? (
                    <p className="text-sm text-[color:var(--muted)]">
                      Receipt payload is disclosed as a whole or withheld.
                    </p>
                  ) : (
                    !base.fields.length && (
                      <p className="text-sm text-[color:var(--muted)]">No fields in this rule.</p>
                    )
                  )}
                </fieldset>
              </div>
              {denied && (
                <p className="mt-3 text-sm">
                  This rule withholds disclosure. Its role and condition checks remain part of the
                  policy.
                </p>
              )}
              <details className="mt-4 text-sm">
                <summary className="cursor-pointer font-medium">
                  Subject and rule references
                </summary>
                <dl className="mt-3 grid gap-2 break-all">
                  <div>
                    <dt className="text-[color:var(--muted)]">Subject</dt>
                    <dd>
                      {rule.subject.kind === 'PRINCIPAL'
                        ? rule.subject.principalId
                        : rule.subject.workloadId}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-[color:var(--muted)]">Required roles (all)</dt>
                    <dd>{rule.requiredRoles.join(', ') || 'None'}</dd>
                  </div>
                  <div>
                    <dt className="text-[color:var(--muted)]">Conditions</dt>
                    <dd>{rule.conditions.length}</dd>
                  </div>
                  <div>
                    <dt className="text-[color:var(--muted)]">Policy reference</dt>
                    <dd>{rule.policyId}</dd>
                  </div>
                </dl>
              </details>
            </fieldset>
          );
        })}
      </div>
      {rules.length > 12 && (
        <p className="mt-3 text-sm text-[color:var(--muted)]">
          Showing 12 of {rules.length} disclosure rules. The remaining rules are preserved in the
          complete document below.
        </p>
      )}
    </section>
  );
}
