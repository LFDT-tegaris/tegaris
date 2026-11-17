'use client';
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { z } from 'zod';
import { LocalSessionSurface } from './local-session';

import {
  firstAdministratorState as state,
  firstAdministratorAssertionOptions,
} from '../lib/first-administrator-contract';
const unavailable =
  'First-administrator acceptance is unavailable. Retry to check its current state.';
class FirstAdministratorFailure extends Error {}
function safeFailure(cause: unknown, fallback: string) {
  return cause instanceof FirstAdministratorFailure ? cause.message : fallback;
}
async function command(body: unknown) {
  const response = await fetch('/api/v1/ui/invitation-proof/first-administrator', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    cache: 'no-store',
  });
  if (!response.ok)
    throw new FirstAdministratorFailure(
      response.status === 401 || response.status === 403
        ? 'Administrator acceptance is not authorized in the current context. Refresh to check its current state.'
        : response.status === 409 || response.status === 412
          ? 'Administrator acceptance has changed. Refresh to check for a committed result.'
          : unavailable,
    );
  return response.json().catch(() => {
    throw new FirstAdministratorFailure(
      'The administrator acceptance response is invalid. Refresh to check its current state.',
    );
  });
}
const from = (value: string) =>
  Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0));
const to = (value: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(value)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');

export function FirstAdministratorAcceptance({
  participantId,
  invitationId,
}: {
  participantId: string;
  invitationId: string;
}) {
  const context = `${participantId}:${invitationId}`;
  const [view, setView] = useState<{
    context: string;
    current?: z.infer<typeof state>;
    error: string;
    busy: boolean;
  }>({ context, error: '', busy: false });
  const current = view.context === context ? view.current : undefined;
  const error = view.context === context ? view.error : '';
  const busy = view.context === context ? view.busy : false;
  const owner = useRef({ context, live: false, generation: 0 });
  const adopt = useCallback(
    (value: unknown) => {
      const parsed = state.parse(value);
      if (parsed.participantId !== participantId || parsed.invitationId !== invitationId)
        throw new FirstAdministratorFailure(
          'The acceptance context changed. Open the current invitation again.',
        );
      return parsed;
    },
    [participantId, invitationId],
  );
  useLayoutEffect(() => {
    owner.current.context = context;
    owner.current.live = true;
    owner.current.generation += 1;
    return () => {
      owner.current.live = false;
      owner.current.generation += 1;
    };
  }, [context]);
  useEffect(() => {
    if (!owner.current.live || owner.current.context !== context) return;
    const generation = ++owner.current.generation;
    const owns = () =>
      owner.current.live &&
      owner.current.context === context &&
      owner.current.generation === generation;
    setView({ context, error: '', busy: false });
    void command({ command: 'READ' })
      .then((value) => {
        if (owns()) setView({ context, current: adopt(value), error: '', busy: false });
      })
      .catch((cause) => {
        if (owns()) setView({ context, error: safeFailure(cause, unavailable), busy: false });
      });
    return () => {
      if (owns()) owner.current.generation += 1;
    };
  }, [adopt, context]);
  async function run(action: 'refresh' | 'enroll' | 'accept') {
    if (!owner.current.live || owner.current.context !== context) return;
    const generation = ++owner.current.generation;
    const owns = () =>
      owner.current.live &&
      owner.current.context === context &&
      owner.current.generation === generation;
    setView({ context, current, error: '', busy: true });
    try {
      if (action === 'enroll') {
        const options = await command({ command: 'ENROLL_OPTIONS' });
        if (!owns()) return;
        const credential = await navigator.credentials.create({
          publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey),
        });
        if (!owns()) return;
        if (!(credential instanceof PublicKeyCredential))
          throw new FirstAdministratorFailure('Authenticator registration was cancelled.');
        await command({
          command: 'ENROLL_COMPLETE',
          enrollmentId: options.enrollmentId,
          response: credential.toJSON(),
        });
        if (!owns()) return;
      } else if (action === 'accept') {
        const value = await command({ command: 'ACCEPT_OPTIONS' });
        if (!owns()) return;
        const options = firstAdministratorAssertionOptions.parse(value);
        if (current?.state !== 'CLAIM_PENDING' || options.intentDigest !== current.intentDigest)
          throw new FirstAdministratorFailure(
            'The reviewed invitation changed. Refresh it before accepting.',
          );
        const credential = await navigator.credentials.get({
          publicKey: {
            challenge: from(options.challenge),
            rpId: options.rpId,
            allowCredentials: options.credentialIds.map((id: string) => ({
              type: 'public-key' as const,
              id: from(id),
            })),
            userVerification: 'required',
          },
        });
        if (!owns()) return;
        if (!(credential instanceof PublicKeyCredential))
          throw new FirstAdministratorFailure('Administrator acceptance was cancelled.');
        const response = credential.response as AuthenticatorAssertionResponse;
        const assertion = JSON.stringify({
          credentialId: credential.id,
          authenticatorData: to(response.authenticatorData),
          clientDataJson: to(response.clientDataJSON),
          signature: to(response.signature),
        });
        const accepted = await command({
          command: 'ACCEPT',
          intentDigest: options.intentDigest,
          challenge: options.challenge,
          assertion,
        });
        if (!owns()) return;
        setView({ context, current: adopt(accepted), error: '', busy: true });
      }
      const value = await command({ command: 'READ' });
      if (!owns()) return;
      setView({ context, current: adopt(value), error: '', busy: false });
    } catch (cause) {
      if (!owns()) return;
      setView({
        context,
        error: safeFailure(
          cause,
          'The ceremony could not finish. Refresh to check for a committed result.',
        ),
        busy: false,
      });
    } finally {
      if (owns()) setView((previous) => ({ ...previous, busy: false }));
    }
  }
  return (
    <article
      aria-label="First-administrator acceptance"
      className="administrator-acceptance grid min-w-0 gap-3 rounded border border-[color:var(--border)] p-4 [overflow-wrap:anywhere]"
      data-state={current?.state}
    >
      <h3 className="text-lg font-semibold">
        {current?.state === 'ACCEPTED'
          ? 'Participant administration accepted'
          : 'Become the first Participant administrator'}
      </h3>
      {error ? <p role="alert">{error}</p> : null}
      {current?.state === 'CLAIM_PENDING' ? (
        <>
          <p>
            Your identity is verified. Accept the independently approved administrator role with
            your authenticator.
          </p>
          <p>Participant: {current.participantId}</p>
          <p>Administrator: {current.displayName}</p>
          <p>Invitation expires: {current.expiresAt}</p>
          <details>
            <summary>Review administrator capabilities</summary>
            <ul>
              {current.actionIntentIds.map((action) => (
                <li key={action}>{action}</li>
              ))}
            </ul>
          </details>
          <p>
            Acceptance activates your membership and administrator access together and ends
            temporary Platform bootstrap authority.
          </p>
          <button
            disabled={busy}
            className="onboarding-primary w-fit rounded border px-3 py-2"
            onClick={() => void run(current.enrollmentRequired ? 'enroll' : 'accept')}
          >
            {busy
              ? 'Working…'
              : current.enrollmentRequired
                ? 'Register administrator authenticator'
                : 'Accept Participant administration'}
          </button>
        </>
      ) : null}
      {current?.state === 'ACCEPTED' ? (
        <>
          <p>
            Your membership and administrator assignment are active. Temporary Platform bootstrap
            authority is closed.
          </p>
          <p>Participant: {current.participantId}</p>
          <p>Membership: {current.membershipId}</p>
          <p>Accepted at: {current.acceptedAt}</p>
          <p>Sign in and select this Participant to continue.</p>
          <LocalSessionSurface participantId={current.participantId} />
        </>
      ) : null}
      <button disabled={busy} className="w-fit underline" onClick={() => void run('refresh')}>
        Refresh administrator acceptance
      </button>
    </article>
  );
}
