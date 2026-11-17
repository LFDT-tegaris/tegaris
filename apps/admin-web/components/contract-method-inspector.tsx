'use client';

import { useEffect, useRef, useState } from 'react';
import {
  contractMethodInspectionSchema,
  inspectionActorKey,
  inspectionReferencesMatch,
  methodPolicyReference,
  type ContractMethodInspection,
} from '../lib/contract-method-inspection';
import type { PolicyWorkflowActorBinding } from './policy-workflow-storage';

type InspectionState = {
  key: string;
  status: 'loading' | 'loaded' | 'unavailable';
  view?: ContractMethodInspection;
  traceId?: string;
};

export function ContractMethodInspector({
  methodPolicyId,
  actor,
  authorityContextKey,
}: Readonly<{
  methodPolicyId: string;
  actor?: PolicyWorkflowActorBinding;
  authorityContextKey: string;
}>) {
  const ref = methodPolicyReference(methodPolicyId);
  const key = `${authorityContextKey}:${actor ? inspectionActorKey(actor) : ''}:${methodPolicyId}`;
  const activeKey = useRef(key);
  activeKey.current = key;
  const pending = useRef<AbortController | undefined>(undefined);
  const [state, setState] = useState<InspectionState | undefined>();
  const visible = state?.key === key ? state : undefined;
  useEffect(() => {
    pending.current?.abort();
    setState(undefined);
    return () => pending.current?.abort();
  }, [key]);

  async function inspect() {
    if (!actor || !ref) return;
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;
    const current = () => !controller.signal.aborted && activeKey.current === key;
    setState({ key, status: 'loading' });
    let traceId: string | undefined;
    try {
      const response = await fetch(
        `/api/v1/ui/contract-method-inspector?${new URLSearchParams({ methodPolicyId: ref })}`,
        {
          credentials: 'same-origin',
          cache: 'no-store',
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(60_000)]),
        },
      );
      const trace = response.headers.get('x-request-id');
      if (trace && /^[0-9a-f-]{36}$/u.test(trace)) traceId = trace;
      if (!response.ok) throw new Error('Method read unavailable');
      const view = contractMethodInspectionSchema.parse(await response.json());
      if (
        view.method.contractMethodPolicyId !== ref ||
        inspectionActorKey(view.actor) !== inspectionActorKey(actor) ||
        !inspectionReferencesMatch(view)
      )
        throw new Error('Method read changed');
      if (current()) setState({ key, status: 'loaded', view });
    } catch {
      if (current()) setState({ key, status: 'unavailable', traceId });
    }
  }
  const view = visible?.view;
  return (
    <section
      aria-label="Configured contract method"
      className="min-w-0 rounded border border-[color:var(--border)] p-4 lg:col-span-2"
    >
      <h3 className="text-lg font-semibold">Configured method and argument rules</h3>
      <p className="mt-1 text-sm text-[color:var(--muted)]">
        These are configured requirements. This readback does not grant permission to call the
        method.
      </p>
      <button
        type="button"
        onClick={() => void inspect()}
        disabled={!actor || !ref || visible?.status === 'loading'}
        className="my-3 rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-60"
      >
        Inspect configured method
      </button>
      <p role="status" aria-live="polite">
        {!actor
          ? 'Reload the authenticated Participant context to inspect a method.'
          : !ref
            ? 'Enter a contract method policy UUID or resource reference above.'
            : visible?.status === 'loading'
              ? 'Loading configured method and argument rules…'
              : visible?.status === 'loaded'
                ? 'Configured method loaded.'
                : visible?.status === 'unavailable'
                  ? 'Method details are unavailable in the current context. Retry the read when the service is available.'
                  : 'Inspect the selected method to review its configured requirements.'}
      </p>
      {visible?.traceId ? (
        <p className="mt-1 break-all text-sm">Diagnostic request: {visible.traceId}</p>
      ) : null}
      {view ? (
        <>
          <dl className="mt-4 grid min-w-0 gap-3 sm:grid-cols-2">
            {(
              [
                ['Contract', `${view.contract.displayName} (${view.contract.logicalName})`],
                ['Contract address', view.binding.contractAddress],
                ['Network', `${view.binding.networkId} · chain ${view.binding.chainId}`],
                ['Canonical signature', view.method.canonicalSignature],
                ['Selector', view.method.selector],
                ['Effect', view.method.effect],
                ['Method lifecycle', `${view.method.state} · revision ${view.method.revision}`],
                ['Binding lifecycle', `${view.binding.state} · revision ${view.binding.revision}`],
                ['Approval requirement', view.method.approvalRequirement],
                ['Authentication requirement', view.method.mfaRequirement],
                ['Environments', view.method.environments.join(', ')],
                ['ABI resource', view.method.abiArtifactId],
              ] as const
            ).map(([label, value]) => (
              <div key={label} className="min-w-0">
                <dt className="text-sm font-semibold">{label}</dt>
                <dd className="break-all font-mono text-sm">{value}</dd>
              </div>
            ))}
          </dl>
          <h4 className="mt-4 font-semibold">Required roles</h4>
          {view.method.requiredRoles.length ? (
            <ul className="list-inside list-disc break-all text-sm">
              {view.method.requiredRoles.map((role, index) => (
                <li key={`${index}:${role}`}>{role}</li>
              ))}
            </ul>
          ) : (
            <p>No roles are listed by this method policy.</p>
          )}
          <h4 className="mt-4 font-semibold">Argument rules</h4>
          {view.argumentRules ? (
            <>
              <p className="text-sm">
                {view.argumentRules.state} · version {view.argumentRules.version} · revision{' '}
                {view.argumentRules.revision}
              </p>
              {view.argumentRules.rules.length ? (
                <ol className="mt-2 grid min-w-0 gap-3">
                  {view.argumentRules.rules.map((rule, index) => (
                    <li
                      key={`${index}:${rule.parameterPath}`}
                      className="min-w-0 rounded border border-[color:var(--border)] p-3"
                    >
                      <p className="break-all font-mono">
                        {rule.parameterPath} · {rule.operandType} · {rule.operator}
                      </p>
                      <ul className="mt-1 list-inside list-disc break-all font-mono text-sm">
                        {rule.values.map((value, valueIndex) => (
                          <li key={valueIndex}>{value}</li>
                        ))}
                      </ul>
                    </li>
                  ))}
                </ol>
              ) : (
                <p>No argument rules are listed in this version.</p>
              )}
            </>
          ) : (
            <p>
              No argument-rule version is attached to this method policy. Other configured
              requirements still apply.
            </p>
          )}
        </>
      ) : null}
    </section>
  );
}
