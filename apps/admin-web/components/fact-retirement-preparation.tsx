'use client';

import { useEffect, useId, useRef, useState } from 'react';
import type {
  FactRetirementHosts,
  CandidateRetirementHosts,
  RetentionPoliciesPage,
} from '../app/api/v1/ui/local-evidence-workbench';

interface Binding {
  actorKey: string;
  actor: { participantId: string; privacyDomainId: string };
}
interface Hosts extends Binding {
  evidenceId: string;
  hosts: FactRetirementHosts | CandidateRetirementHosts;
}
const button = 'rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-50';
const field =
  'mt-1 w-full rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-2';

export function FactRetirementPreparation({
  binding,
  evidenceId,
  policies,
  onPrepare,
  source = 'fact',
}: {
  binding: Binding;
  evidenceId: string;
  policies: RetentionPoliciesPage | null;
  source?: 'fact' | 'candidate';
  onPrepare: (fields: {
    evidenceId: string;
    hostDigest: string;
    retentionPolicyId: string;
  }) => void;
}) {
  const id = useId();
  const label = source === 'fact' ? 'Fact' : 'candidate';
  const dataClass = source === 'fact' ? 'ADMITTED_FACT' : 'CANDIDATE_PROJECTION';
  const deletionMode = source === 'fact' ? 'ROW_DELETE' : 'PROJECTION_DELETE';
  const [hosts, setHosts] = useState<FactRetirementHosts | CandidateRetirementHosts>();
  const [target, setTarget] = useState('');
  const [policy, setPolicy] = useState('');
  const [error, setError] = useState('');
  const [prepared, setPrepared] = useState(false);
  const alert = useRef<HTMLParagraphElement>(null);
  const active =
    policies?.items.filter(
      (item) =>
        item.state === 'ACTIVE' &&
        item.dataClass === dataClass &&
        item.deletionMode === deletionMode,
    ) ?? [];
  useEffect(() => {
    const abort = new AbortController();
    setHosts(undefined);
    setTarget('');
    setPolicy('');
    setPrepared(false);
    setError('');
    void (async () => {
      try {
        const response = await fetch(
          `/api/v1/ui/evidence-workbench?${new URLSearchParams({ [source === 'fact' ? 'factRetirementRecordId' : 'candidateRetirementRecordId']: evidenceId.slice(-36) })}`,
          {
            cache: 'no-store',
            signal: abort.signal,
          },
        );
        const value = await response.json();
        if (!response.ok)
          throw new Error(
            `${label} retirement targets are unavailable${value?.code ? ` (${value.code})` : ''}.`,
          );
        const current = value as Hosts;
        if (
          current.actorKey !== binding.actorKey ||
          current.evidenceId !== evidenceId ||
          current.actor.participantId !== binding.actor.participantId ||
          current.actor.privacyDomainId !== binding.actor.privacyDomainId ||
          current.hosts.authority !== 'NONE' ||
          current.hosts.items.some(
            (host) =>
              host.store !== (source === 'fact' ? 'openpc_facts' : 'openpc_candidate_index'),
          )
        )
          throw new Error('Context changed. Reload the evidence catalogue.');
        if (!abort.signal.aborted) setHosts(current.hosts);
      } catch (cause) {
        if (!abort.signal.aborted)
          setError(cause instanceof Error ? cause.message : 'Retirement targets are unavailable.');
      }
    })();
    return () => abort.abort();
  }, [
    binding.actorKey,
    binding.actor.participantId,
    binding.actor.privacyDomainId,
    evidenceId,
    source,
    label,
  ]);
  useEffect(() => {
    if (error) alert.current?.focus();
  }, [error]);
  const chosen = hosts?.items.find((item) => item.hostDigest === target);
  const selectedPolicy = active.find((item) => item.retentionPolicyId === policy);
  return (
    <section
      className="space-y-3 rounded border border-[color:var(--border)] p-4"
      aria-labelledby={`${id}-heading`}
    >
      <h2 id={`${id}-heading`} className="text-xl font-semibold">
        Prepare {label} payload retirement
      </h2>
      <p className="break-all">Evidence: {evidenceId}</p>
      <p>
        Choose an installed {label} store and an active {label} retention policy. The next review
        binds the exact source and its archive. Current native conditions are checked at admission
        and execution. Source custody, identity and lineage stay retained.
      </p>
      {error ? (
        <p ref={alert} tabIndex={-1} role="alert">
          {error}
        </p>
      ) : null}
      {!hosts && !error ? <p role="status">Loading installed targets.</p> : null}
      {hosts?.items.length === 0 ? (
        <p>No installed {label} retirement target is available for this record and context.</p>
      ) : null}
      <label className="block">
        Installed {label} target
        <select
          className={field}
          value={target}
          disabled={!hosts || prepared}
          onChange={(event) => setTarget(event.target.value)}
        >
          <option value="">Choose a target</option>
          {hosts?.items.map((host) => (
            <option key={host.hostDigest} value={host.hostDigest}>
              {host.targetId} · {host.store}
            </option>
          ))}
        </select>
      </label>
      <label className="block">
        Active {label} retention policy
        <select
          className={field}
          value={policy}
          disabled={prepared}
          onChange={(event) => setPolicy(event.target.value)}
        >
          <option value="">Choose a policy</option>
          {active.map((item) => (
            <option key={item.retentionPolicyId} value={item.retentionPolicyId}>
              {item.policyVersion} · {item.retentionPolicyId}
            </option>
          ))}
        </select>
      </label>
      {!active.length ? (
        <p>
          No active {deletionMode} policy for {dataClass} is present on the loaded retention-policy
          page. Load the required page below or govern a {label} retention policy first.
        </p>
      ) : null}
      {selectedPolicy ? (
        <p>
          Retention: {selectedPolicy.retentionPeriodMs} ms; grace: {selectedPolicy.localGraceMs} ms;
          required archive acknowledgements: {selectedPolicy.sinkQuorum}.
        </p>
      ) : null}
      <button
        className={button}
        disabled={!chosen || !selectedPolicy || prepared}
        onClick={() => {
          if (!chosen || !selectedPolicy) return;
          setPrepared(true);
          onPrepare({
            evidenceId,
            hostDigest: chosen.hostDigest,
            retentionPolicyId: selectedPolicy.retentionPolicyId,
          });
        }}
      >
        Review this {label} retirement
      </button>
      {prepared ? (
        <p role="status">
          The governed request form below is prepared with this record, target and policy.
        </p>
      ) : null}
    </section>
  );
}
