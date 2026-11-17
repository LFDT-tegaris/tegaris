'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import type { EnvelopeScope } from '../../../packages/security-kernel/src/identity-envelope/types';

const storageKey = 'openpc:participant-envelope-recovery:v1';
const fields = [
  ['envelopeId', 'Envelope ID'],
  ['targetParticipantId', 'Recipient Participant ID'],
  ['issuerPrivacyDomainId', 'Issuer privacy domain ID'],
  ['creationApprovalRequestId', 'Creation approval ID'],
] as const;
type Selection = Record<(typeof fields)[number][0], string>;
interface Recovery {
  selection: Selection;
  actor: { principalId: string; participantId: string; contextEpoch: string };
  state: 'DRAFT' | 'SUBMITTED' | 'APPROVED';
  semanticDigest: string;
  lastOperationId: string;
  creationOperationId: string;
  disclosurePrivacyDomainIds: string[];
  usable: EnvelopeScope;
  grantable: EnvelopeScope;
  runtimePermission: 'NONE';
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const readFailure =
  'The proposal is unavailable. Check current access and the saved identifiers before refreshing.';
const identifier = z.string().regex(uuid);
const revision = z.string().regex(/^(0|[1-9][0-9]*)$/u);
const sessionSchema = z.object({
  enabled: z.literal(true),
  authenticated: z.literal(true),
  sessionId: identifier,
  principalId: identifier,
  participantId: identifier,
  contextMode: z.literal('PLATFORM'),
  contextEpoch: revision,
  role: z.enum(['operator', 'viewer']),
  privacyDomainId: identifier.optional(),
});
const finiteSet = <T extends z.ZodType<string>>(item: T, limit = 256) =>
  z
    .array(item)
    .max(limit)
    .refine((values) => values.every((value, index) => index === 0 || values[index - 1]! < value));
const dimensionId = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}$/u);
const dimensions = {
  participantIds: finiteSet(identifier),
  privacyDomainIds: finiteSet(identifier),
  resourceIds: finiteSet(dimensionId),
  dataClasses: finiteSet(dimensionId),
  targetProfileIds: finiteSet(dimensionId),
  riskClasses: finiteSet(z.enum(['BREAK_GLASS', 'HIGH', 'LOW', 'STANDARD']), 4),
};
const nanosPattern = /^(0|[1-9][0-9]{0,19})$/u;
const nanos = z
  .string()
  .regex(nanosPattern)
  .refine(
    (value) =>
      nanosPattern.test(value) &&
      BigInt(value) <= 18_446_744_073_709_551_615n &&
      BigInt(value) % 1000n === 0n,
  );
// This validates historical display data, never current execution authority.
const scopeSchema = z
  .object({
    administration: z.object({
      ...dimensions,
      actionIntentIds: finiteSet(z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u)),
    }),
    runtime: z.object({
      ...dimensions,
      capabilityIds: finiteSet(
        z.enum([
          'CALL_RESULT_DISCLOSURE',
          'GAS_ESTIMATE_DISCLOSURE',
          'ACCESS_LIST_DISCLOSURE',
          'UNSIGNED_TRANSACTION_PREPARATION',
          'SIGNED_TRANSACTION_SUBMISSION',
          'OPERATION_STATUS_DISCLOSURE',
          'MULTI_CALL_SIMULATION_DISCLOSURE',
        ]),
        7,
      ),
    }),
    validFromNs: nanos,
    validUntilNs: nanos,
    makerCheckerRequired: z.boolean(),
    stepUpRequired: z.boolean(),
    onwardDelegationDepth: z.number().int().min(0).max(32),
  })
  .refine(
    (value) =>
      nanos.safeParse(value.validFromNs).success &&
      nanos.safeParse(value.validUntilNs).success &&
      BigInt(value.validUntilNs) > BigInt(value.validFromNs),
  );
const recoverySchema = z.object({
  selection: z.object({
    envelopeId: identifier,
    targetParticipantId: identifier,
    issuerPrivacyDomainId: identifier,
    creationApprovalRequestId: identifier,
  }),
  actor: z.object({ principalId: identifier, participantId: identifier, contextEpoch: revision }),
  state: z.enum(['DRAFT', 'SUBMITTED', 'APPROVED']),
  semanticDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  lastOperationId: identifier,
  creationOperationId: identifier,
  disclosurePrivacyDomainIds: finiteSet(identifier),
  usable: scopeSchema,
  grantable: scopeSchema,
  runtimePermission: z.literal('NONE'),
});
async function currentSession(signal: AbortSignal) {
  const response = await fetch('/api/v1/ui/local-session', {
    credentials: 'same-origin',
    cache: 'no-store',
    signal,
  });
  if (!response.ok) throw new Error(readFailure);
  return sessionSchema.parse(await response.json());
}
function sessionKey(session: z.infer<typeof sessionSchema>) {
  return JSON.stringify(session);
}
function identifiers(value: unknown): Selection | undefined {
  if (!value || typeof value !== 'object') return;
  const result = {} as Selection;
  for (const [key] of fields) {
    const field = (value as Record<string, unknown>)[key];
    if (typeof field !== 'string' || !uuid.test(field)) return;
    result[key] = field;
  }
  return result;
}

function Scope({ title, scope }: { title: string; scope: EnvelopeScope }) {
  const dimensions = [
    ['participantIds', 'Participants'],
    ['privacyDomainIds', 'Privacy domains'],
    ['resourceIds', 'Resources'],
    ['dataClasses', 'Data classes'],
    ['targetProfileIds', 'Target profiles'],
    ['riskClasses', 'Risk classes'],
  ] as const;
  return (
    <details className="rounded border border-[color:var(--border)] p-3" open>
      <summary className="cursor-pointer font-semibold">{title}</summary>
      <div className="mt-3 grid gap-4 lg:grid-cols-2">
        {(['administration', 'runtime'] as const).map((kind) => (
          <div key={kind}>
            <h4 className="font-medium">
              {kind === 'administration' ? 'Administration' : 'Runtime'}
            </h4>
            <dl className="mt-2 space-y-2 text-sm">
              {dimensions.map(([key, label]) => (
                <div key={key}>
                  <dt className="font-medium">{label}</dt>
                  <dd className="break-all">{scope[kind][key].join(', ') || 'None'}</dd>
                </div>
              ))}
              <div>
                <dt className="font-medium">
                  {kind === 'administration' ? 'Actions' : 'Capabilities'}
                </dt>
                <dd className="break-all">
                  {(kind === 'administration'
                    ? scope.administration.actionIntentIds
                    : scope.runtime.capabilityIds
                  ).join(', ') || 'None'}
                </dd>
              </div>
            </dl>
          </div>
        ))}
      </div>
      <dl className="mt-4 grid gap-2 text-sm sm:grid-cols-2">
        <div>
          <dt className="font-medium">Valid from</dt>
          <dd>{new Date(Number(BigInt(scope.validFromNs) / 1_000_000n)).toISOString()}</dd>
        </div>
        <div>
          <dt className="font-medium">Valid until</dt>
          <dd>{new Date(Number(BigInt(scope.validUntilNs) / 1_000_000n)).toISOString()}</dd>
        </div>
        <div>
          <dt className="font-medium">Independent approval</dt>
          <dd>{scope.makerCheckerRequired ? 'Required' : 'Not required'}</dd>
        </div>
        <div>
          <dt className="font-medium">Step-up verification</dt>
          <dd>{scope.stepUpRequired ? 'Required' : 'Not required'}</dd>
        </div>
        <div>
          <dt className="font-medium">Further delegation depth</dt>
          <dd>{scope.onwardDelegationDepth}</dd>
        </div>
      </dl>
    </details>
  );
}

export function ParticipantEnvelopeRecovery() {
  const [selection, setSelection] = useState<Selection>();
  const [view, setView] = useState<Recovery>();
  const [status, setStatus] = useState('Enter the saved identifiers to recover a proposal.');
  const [busy, setBusy] = useState(false);
  const [edited, setEdited] = useState(false);
  const generation = useRef(0);
  const mounted = useRef(false);
  const pending = useRef<AbortController | undefined>(undefined);
  const recover = useCallback(async (next: Selection) => {
    if (!mounted.current) return;
    const current = ++generation.current;
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;
    setView(undefined);
    setBusy(true);
    setStatus('Checking current access and reading the committed proposal.');
    try {
      const session = await currentSession(controller.signal);
      if (current !== generation.current) return;
      const response = await fetch(
        `/api/v1/ui/participant-workbench?${new URLSearchParams(next)}`,
        {
          credentials: 'same-origin',
          cache: 'no-store',
          signal: controller.signal,
        },
      );
      if (!response.ok) throw new Error(readFailure);
      const body = recoverySchema.parse(await response.json());
      if (
        fields.some(([key]) => body.selection[key] !== next[key]) ||
        body.actor.principalId !== session.principalId ||
        body.actor.participantId !== session.participantId ||
        body.actor.contextEpoch !== session.contextEpoch ||
        body.disclosurePrivacyDomainIds.some((value) => value !== next.issuerPrivacyDomainId)
      )
        throw new Error(readFailure);
      if (current !== generation.current) return;
      const confirmed = await currentSession(controller.signal);
      if (sessionKey(confirmed) !== sessionKey(session)) throw new Error(readFailure);
      if (current !== generation.current) return;
      setView(body);
      setStatus('Proposal recovered from the current authorized owners.');
    } catch {
      if (current !== generation.current) return;
      setView(undefined);
      setStatus(readFailure);
    } finally {
      if (current === generation.current) setBusy(false);
    }
  }, []);
  useEffect(() => {
    mounted.current = true;
    try {
      const stored = localStorage.getItem(storageKey);
      const saved = stored ? identifiers(JSON.parse(stored)) : undefined;
      if (saved) {
        // Discard any injected/stale fields, retaining identifiers only.
        localStorage.setItem(storageKey, JSON.stringify(saved));
        setSelection(saved);
        void recover(saved);
      } else if (stored) localStorage.removeItem(storageKey);
    } catch {
      localStorage.removeItem(storageKey);
    }
    return () => {
      mounted.current = false;
      generation.current++;
      pending.current?.abort();
    };
  }, [recover]);
  useEffect(() => {
    if (!selection || edited) return;
    const refresh = () => {
      void recover(selection);
    };
    window.addEventListener('focus', refresh);
    window.addEventListener('pageshow', refresh);
    return () => {
      window.removeEventListener('focus', refresh);
      window.removeEventListener('pageshow', refresh);
    };
  }, [edited, recover, selection]);
  function edit() {
    generation.current++;
    pending.current?.abort();
    setView(undefined);
    setBusy(false);
    setEdited(true);
    setStatus('Identifiers changed. Recover the proposal to check current access.');
  }
  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const next = identifiers(Object.fromEntries(new FormData(event.currentTarget)));
    if (!next) {
      generation.current++;
      pending.current?.abort();
      setView(undefined);
      setBusy(false);
      setStatus('Enter a valid identifier in each field.');
      return;
    }
    setSelection(next);
    setEdited(false);
    localStorage.setItem(storageKey, JSON.stringify(next));
    void recover(next);
  }
  return (
    <section
      aria-labelledby="envelope-recovery-title"
      className="mt-6 space-y-4 rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
    >
      <h2 id="envelope-recovery-title" className="text-xl font-semibold">
        Recover an envelope proposal
      </h2>
      <p>
        Use the identifiers returned when the proposal was created. Current access is checked each
        time you open or refresh it.
      </p>
      <form
        className="grid gap-3 sm:grid-cols-2"
        onSubmit={submit}
        onChange={edit}
        key={selection ? JSON.stringify(selection) : 'new'}
      >
        {fields.map(([name, label]) => (
          <label className="grid gap-1" key={name}>
            {label}
            <input
              className="min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
              name={name}
              defaultValue={selection?.[name] ?? ''}
              required
              pattern={uuid.source}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
        ))}
        <button
          className="justify-self-start rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white disabled:opacity-60"
          type="submit"
          disabled={busy}
        >
          {busy ? 'Checking access…' : 'Recover proposal'}
        </button>
        {selection && (
          <button
            className="justify-self-start rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-60"
            type="button"
            disabled={busy || edited}
            onClick={() => void recover(selection)}
          >
            Refresh from server
          </button>
        )}
      </form>
      <p role="status" aria-live="polite">
        {status}
      </p>
      {view && (
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">Proposal {view.state}</h3>
          <p>This proposal does not authorize runtime work.</p>
          <dl className="space-y-2 text-sm">
            <div>
              <dt className="font-medium">Proposal digest</dt>
              <dd className="break-all">{view.semanticDigest}</dd>
            </div>
            <div>
              <dt className="font-medium">Creation operation</dt>
              <dd className="break-all">{view.creationOperationId}</dd>
            </div>
            <div>
              <dt className="font-medium">Last committed operation</dt>
              <dd className="break-all">{view.lastOperationId}</dd>
            </div>
            <div>
              <dt className="font-medium">Privacy domains in this disclosure</dt>
              <dd className="break-all">
                {view.disclosurePrivacyDomainIds.join(', ') ||
                  'None in the selected issuer privacy domain'}
              </dd>
            </div>
          </dl>
          <p>The scopes below come from the separately authorized creation review.</p>
          <Scope title="Usable scope" scope={view.usable} />
          <Scope title="Grantable scope" scope={view.grantable} />
        </div>
      )}
    </section>
  );
}
