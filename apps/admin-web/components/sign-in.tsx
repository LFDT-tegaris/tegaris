'use client';
import { ShieldCheck, ArrowRight, LoaderCircle } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { localSessionStatusSchema } from '../lib/local-session-status';
import { workspaceReturnPath } from '../lib/workspace-navigation';
import { clearTransactionWorkflowStorage } from './policy-workflow-storage';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';

export function SignIn({
  returnPath,
  authenticationFailed = false,
  sessionEnded = false,
  participantId,
  organizationContextInvalid = false,
}: {
  readonly returnPath: string;
  readonly authenticationFailed?: boolean;
  readonly sessionEnded?: boolean;
  readonly participantId?: string;
  readonly organizationContextInvalid?: boolean;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(
    organizationContextInvalid
      ? 'Your organization sign-in link is invalid. Contact your administrator for a new link.'
      : authenticationFailed
        ? 'Sign-in could not be completed. Please try again or contact your administrator.'
        : '',
  );
  const inFlight = useRef(false);
  const signInController = useRef<AbortController | undefined>(undefined);
  const invalidateRead = useRef(() => {});
  useEffect(() => {
    inFlight.current = false;
    setBusy(false);
    setError(
      organizationContextInvalid
        ? 'Your organization sign-in link is invalid. Contact your administrator for a new link.'
        : authenticationFailed
          ? 'Sign-in could not be completed. Please try again or contact your administrator.'
          : '',
    );
    let live = true,
      generation = 0,
      pending = isSessionTransitionPending();
    let controller: AbortController | undefined;
    const invalidate = () => {
      generation++;
      controller?.abort();
    };
    const read = () => {
      invalidate();
      if (pending || inFlight.current || organizationContextInvalid) return;
      const selected = generation;
      controller = new AbortController();
      const signal = controller.signal;
      void fetch('/api/v1/ui/local-session', { cache: 'no-store', signal })
        .then(async (response) => {
          if (!response.ok) throw new Error();
          return localSessionStatusSchema.parse(await response.json());
        })
        .then((session) => {
          if (!live || selected !== generation || signal.aborted || pending || !session.enabled)
            return;
          if (session.authenticated) {
            if (participantId === undefined || session.participantId === participantId)
              router.replace(workspaceReturnPath(returnPath));
          } else clearTransactionWorkflowStorage();
        })
        .catch(() => {
          /* An unavailable session does not prove sign-out. */
        });
    };
    invalidateRead.current = invalidate;
    read();
    const stop = observeSessionTransitions(
      () => {
        pending = true;
        invalidate();
      },
      (changing) => {
        pending = changing;
        read();
      },
    );
    return () => {
      live = false;
      invalidate();
      signInController.current?.abort();
      stop();
    };
  }, [returnPath, router, participantId, organizationContextInvalid, authenticationFailed]);

  async function signIn() {
    if (inFlight.current || organizationContextInvalid) return;
    inFlight.current = true;
    const controller = new AbortController();
    signInController.current = controller;
    invalidateRead.current();
    setBusy(true);
    setError('');
    try {
      const response = await fetch('/api/v1/ui/oidc-session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          returnPath,
          ...(participantId === undefined ? {} : { participantId }),
        }),
        signal: controller.signal,
      });
      const result: unknown = await response.json();
      if (controller.signal.aborted) return;
      if (
        !response.ok ||
        !result ||
        typeof result !== 'object' ||
        !('authorizationUri' in result) ||
        typeof result.authorizationUri !== 'string'
      )
        throw new Error();
      const destination = new URL(result.authorizationUri);
      if (
        !['http:', 'https:'].includes(destination.protocol) ||
        destination.username ||
        destination.password
      )
        throw new Error();
      window.location.assign(destination.href);
    } catch {
      if (controller.signal.aborted) return;
      inFlight.current = false;
      setBusy(false);
      setError('The sign-in service is unavailable. Please try again.');
    }
  }

  return (
    <main className="tegaris-signin">
      <div className="signin-brand">
        <ShieldCheck aria-hidden size={32} />
        <span>Tegaris</span>
      </div>
      <section className="signin-card" aria-labelledby="signin-title">
        <div className="signin-emblem">
          <ShieldCheck aria-hidden size={28} />
        </div>
        <p className="signin-eyebrow">APPLICATION LAYER PRIVACY</p>
        <h1 id="signin-title">Sign in to Tegaris</h1>
        <p className="signin-description">
          Manage access, policies and privacy in your organization’s workspace.
        </p>
        {sessionEnded && !error && (
          <p className="signin-message" role="status">
            Your session has ended. Sign in to continue.
          </p>
        )}
        {error && (
          <p className="signin-error" role="alert">
            {error}
          </p>
        )}
        <button
          className="signin-submit"
          type="button"
          disabled={busy || organizationContextInvalid}
          onClick={() => void signIn()}
        >
          {busy ? (
            <>
              <LoaderCircle aria-hidden className="animate-spin" size={18} />
              Connecting…
            </>
          ) : (
            <>
              Sign in
              <ArrowRight aria-hidden size={18} />
            </>
          )}
        </button>
        <p className="signin-help">Continue securely with your organization’s account.</p>
      </section>
      <footer className="signin-footer">Tegaris · Application Layer Privacy</footer>
    </main>
  );
}
