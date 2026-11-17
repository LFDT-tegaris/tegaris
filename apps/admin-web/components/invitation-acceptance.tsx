'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { invitationAcceptance, invitationProofInput } from '../lib/invitation-workflow';
import { signInHref, workspaceHome } from '../lib/workspace-navigation';
import { FirstAdministratorAcceptance } from './first-administrator-acceptance';
const field =
  'min-w-0 w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const receipt = z
  .strictObject({
    acceptance: invitationAcceptance.nullable(),
    firstAdministrator: z.literal(true).optional(),
  })
  .refine((value) => value.acceptance !== null || value.firstAdministrator === undefined);
const unavailable = 'The acceptance result is unavailable. Retry the acceptance result read.';
class InvitationAcceptanceFailure extends Error {}
const emptyProof = {
  invitationId: '',
  participantId: '',
  privacyDomainId: '',
  tokenVersion: '',
  token: '',
};
export function InvitationAcceptanceWorkflow() {
  const [input, setInput] = useState({
    invitationId: '',
    participantId: '',
    privacyDomainId: '',
    tokenVersion: '1',
    token: '',
  });
  const [accepted, setAccepted] = useState<z.infer<typeof invitationAcceptance>>();
  const [firstAdministrator, setFirstAdministrator] = useState(false);
  const [loginHint, setLoginHint] = useState('');
  const [busy, setBusy] = useState(false),
    [error, setError] = useState('');
  const [resultMode, setResultMode] = useState(true);
  const [reading, setReading] = useState(false);
  const reader = useRef({ live: false, generation: 0, resultMode: true });
  const alert = useRef<HTMLParagraphElement>(null);
  const invalidateReceiptRead = useCallback(() => {
    reader.current.generation += 1;
    reader.current.resultMode = false;
    setResultMode(false);
    setReading(false);
    setAccepted(undefined);
    setFirstAdministrator(false);
  }, []);
  const readReceipt = useCallback(async () => {
    if (!reader.current.live || !reader.current.resultMode) return;
    const generation = ++reader.current.generation;
    const current = () =>
      reader.current.live && reader.current.resultMode && reader.current.generation === generation;
    setReading(true);
    setAccepted(undefined);
    setFirstAdministrator(false);
    setError('');
    try {
      const response = await fetch('/api/v1/ui/invitation-proof', { cache: 'no-store' });
      if (response.status !== 200) throw new Error(unavailable);
      const parsed = receipt.parse(await response.json());
      if (!current()) return;
      setAccepted(parsed.acceptance ?? undefined);
      setFirstAdministrator(parsed.firstAdministrator === true);
    } catch {
      if (current()) setError(unavailable);
    } finally {
      if (current()) setReading(false);
    }
  }, []);
  useEffect(() => {
    if (error) alert.current?.focus();
  }, [error]);
  useEffect(() => {
    reader.current.live = true;
    const consumeLink = () => {
      if (!window.location.hash) return false;
      invalidateReceiptRead();
      setInput({ ...emptyProof });
      setLoginHint('');
      const parsed = invitationProofInput.safeParse(
        Object.fromEntries(new URLSearchParams(window.location.hash.slice(1))),
      );
      const destination = new URL(window.location.href);
      destination.searchParams.delete('invitationError');
      window.history.replaceState(null, '', `${destination.pathname}${destination.search}`);
      setAccepted(undefined);
      setFirstAdministrator(false);
      setError('');
      setBusy(false);
      if (parsed.success) setInput(parsed.data);
      else setError('The invitation link is incomplete. Ask its sender for a current link.');
      return true;
    };
    const linkConsumed = consumeLink();
    const changed = () => {
      consumeLink();
    };
    window.addEventListener('hashchange', changed);
    if (!linkConsumed) {
      const destination = new URL(window.location.href);
      if (destination.searchParams.get('invitationError') === 'identity_not_verified') {
        invalidateReceiptRead();
        setInput({ ...emptyProof });
        setLoginHint('');
        destination.searchParams.delete('invitationError');
        window.history.replaceState(null, '', `${destination.pathname}${destination.search}`);
        setError(
          'We could not verify this invitation. Reopen the latest invitation link and sign in with the account selected by its sender.',
        );
      } else void readReceipt();
    }
    return () => {
      reader.current.live = false;
      reader.current.generation += 1;
      window.removeEventListener('hashchange', changed);
    };
  }, [invalidateReceiptRead, readReceipt]);
  async function begin(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    invalidateReceiptRead();
    const generation = reader.current.generation;
    const current = () => reader.current.live && reader.current.generation === generation;
    setBusy(true);
    setError('');
    setAccepted(undefined);
    try {
      const parsed = invitationProofInput.safeParse(input);
      if (!parsed.success)
        throw new InvitationAcceptanceFailure(
          'Check the invitation, Participant, privacy domain, token version and secret.',
        );
      const response = await fetch('/api/v1/ui/invitation-proof', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...parsed.data,
          ...(loginHint.trim() ? { loginHint: loginHint.trim() } : {}),
        }),
      });
      if (!current()) return;
      if (!response.ok)
        throw new InvitationAcceptanceFailure(
          response.status === 401 || response.status === 403
            ? 'This invitation cannot be accepted in the current authenticated context. Check the invitation before retrying.'
            : response.status === 409 || response.status === 412
              ? 'The invitation has changed. Check its current state before retrying.'
              : 'The invitation identity check could not start. Retry after checking the invitation.',
        );
      const value = await response.json().catch(() => undefined);
      if (!current()) return;
      const target = z.strictObject({ authorizationUri: z.url() }).parse(value);
      setInput((previous) => ({ ...previous, token: '' }));
      window.location.assign(target.authorizationUri);
    } catch (cause) {
      if (!current()) return;
      setError(
        cause instanceof InvitationAcceptanceFailure
          ? cause.message
          : 'The identity check could not start.',
      );
      setBusy(false);
    }
  }
  return (
    <section className="invitation-verification" aria-labelledby="invitation-acceptance-heading">
      <h2 id="invitation-acceptance-heading" className="text-xl font-semibold">
        Confirm your identity
      </h2>
      <p className="invitation-introduction">
        Sign in with the exact identity account chosen by the sender. Acceptance records your
        membership; access is approved separately.
      </p>
      {error && (
        <p
          ref={alert}
          role="alert"
          tabIndex={-1}
          className="rounded border border-[color:var(--border)] p-3"
        >
          {error}
        </p>
      )}
      {reading ? <p role="status">Reading acceptance result…</p> : null}
      {resultMode ? (
        <button
          type="button"
          disabled={reading || busy}
          className="invitation-read-retry disabled:opacity-60"
          onClick={() => void readReceipt()}
        >
          Retry acceptance result read
        </button>
      ) : null}
      {accepted && firstAdministrator ? (
        <FirstAdministratorAcceptance
          participantId={accepted.participantId}
          invitationId={accepted.invitationId}
        />
      ) : accepted ? (
        <article className="invitation-confirmation" aria-label="Invitation accepted">
          <span className="invitation-status">Invitation accepted</span>
          <h3>
            {accepted.membershipStateAtAcceptance === 'PROVISIONED'
              ? 'Your membership is recorded'
              : 'Your membership is confirmed'}
          </h3>
          <p className="invitation-next-step">
            {accepted.membershipStateAtAcceptance === 'PROVISIONED'
              ? 'Your administrator must activate the membership and approve its access.'
              : 'Your existing membership was retained. This invitation granted no additional access.'}
          </p>
          <p className="invitation-session-notice">
            No sign-in session was created by accepting this invitation.
          </p>
          <a
            className="invitation-primary-action"
            href={signInHref(workspaceHome, false, accepted.participantId)}
          >
            Continue to sign in
          </a>
          <section className="invitation-references" aria-label="Invitation reference details">
            <h4>Reference details</h4>
            <dl>
              <div>
                <dt>Participant</dt>
                <dd>{accepted.participantId}</dd>
              </div>
              <div>
                <dt>Membership</dt>
                <dd>{accepted.membershipId}</dd>
              </div>
              <div>
                <dt>Membership state at acceptance</dt>
                <dd>{accepted.membershipStateAtAcceptance}</dd>
              </div>
              <div>
                <dt>Requested role</dt>
                <dd>{accepted.roleIntent.roleId}</dd>
              </div>
              <div>
                <dt>Operation</dt>
                <dd>{accepted.operationId}</dd>
              </div>
              <div>
                <dt>Accepted at</dt>
                <dd>
                  <time dateTime={accepted.acceptedAt} title={accepted.acceptedAt}>
                    {new Date(accepted.acceptedAt).toLocaleString()}
                  </time>
                </dd>
              </div>
            </dl>
          </section>
        </article>
      ) : (
        <form onSubmit={(event) => void begin(event)} className="invitation-verification-form">
          <h3>Check your invitation</h3>
          {(
            [
              ['invitationId', 'Invitation ID'],
              ['participantId', 'Participant ID'],
              ['privacyDomainId', 'Privacy domain ID'],
              ['tokenVersion', 'Token version'],
              ['token', 'Invitation secret'],
            ] as const
          ).map(([key, label]) => (
            <label
              key={key}
              className={`grid min-w-0 gap-1 ${key === 'token' || key === 'invitationId' ? 'invitation-field-wide' : ''}`}
            >
              {label}
              <input
                required
                autoComplete="off"
                type={key === 'token' ? 'password' : 'text'}
                className={field}
                value={input[key]}
                onChange={(event) => {
                  invalidateReceiptRead();
                  setInput({ ...input, [key]: event.target.value });
                }}
                disabled={busy}
              />
            </label>
          ))}
          <label className="invitation-field-wide grid gap-1">
            Identity account hint (optional)
            <input
              autoComplete="off"
              className={field}
              value={loginHint}
              onChange={(event) => {
                invalidateReceiptRead();
                setLoginHint(event.target.value);
              }}
              disabled={busy}
            />
          </label>
          <button disabled={busy} className="invitation-primary-action disabled:opacity-60">
            {busy ? 'Opening identity provider…' : 'Verify identity and accept'}
          </button>
        </form>
      )}
    </section>
  );
}
