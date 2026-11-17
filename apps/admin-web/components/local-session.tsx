'use client';

import { useCallback, useContext, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { AccountMenu } from './account-menu';
import { CentralSessionContext } from './central-session-context';
import { z } from 'zod';

import {
  clearPolicyWorkflowStorage,
  clearTransactionWorkflowStorage,
} from './policy-workflow-storage';
import { AuthenticatorEnrollment } from './authenticator-enrollment';
import {
  localSessionStatusSchema,
  type AuthenticatedLocalSession,
} from '../lib/local-session-status';
import { notifySessionTransition, observeSessionTransitions } from './session-transition';

const loginResultSchema = z.object({
  status: z.literal('authenticated'),
  role: z.enum(['operator', 'viewer']),
});
const sessionOperationSchema = z.object({
  operationId: z.uuidv7(),
  resourceRef: z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u),
  actionIntentId: z.enum(['ACT-IDENTITY_DELETE_SESSION-V1', 'ACT-IDENTITY_CREATE_SESSION-V1']),
  intentDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/u),
  idempotencyKey: z.string().min(16).max(128),
  state: z.literal('SUCCEEDED'),
  truthState: z.literal('SUCCESS'),
  createdAt: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u),
  updatedAt: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u),
  revision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
});

interface SessionSurfaceProps {
  participantId?: string;
  compactAuthenticated?: boolean;
  showAccountSettings?: boolean;
  appearance?: 'panel' | 'menu';
}

export function LocalSessionSurface(props: SessionSurfaceProps = {}) {
  const centralized = useContext(CentralSessionContext);
  if (centralized && !props.showAccountSettings && props.appearance !== 'menu') return null;
  return <SessionSurface {...props} centralized={centralized} />;
}

function SessionSurface({
  participantId,
  compactAuthenticated = true,
  showAccountSettings = false,
  appearance = 'panel',
  centralized,
}: SessionSurfaceProps & { centralized: boolean }) {
  const [enabled, setEnabled] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [role, setRole] = useState<'operator' | 'viewer'>('operator');
  const [credential, setCredential] = useState('');
  const [loginHint, setLoginHint] = useState('');
  const [selectedParticipant, setSelectedParticipant] = useState(participantId ?? '');
  const [status, setStatus] = useState('');
  const [session, setSession] = useState<AuthenticatedLocalSession>();
  const [checking, setChecking] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const runtimeEnabled = useRef(false);
  const retryRead = useRef<(clearStatus?: boolean) => void>(() => {});
  const checkingRef = useRef(true);
  const emittingTransition = useRef(false);
  const transitionPendingRef = useRef(false);
  const sessionRef = useRef<AuthenticatedLocalSession | undefined>(undefined);
  const [freshAuthentication, setFreshAuthentication] = useState(false);
  const [oidcBusy, setOidcBusy] = useState(false);
  const [localBusy, setLocalBusy] = useState(false);
  const oidcInFlight = useRef(false);
  const localInFlight = useRef(false);
  const mounted = useRef(false);
  const generation = useRef(0);
  const activeRead = useRef<AbortController | undefined>(undefined);
  const previousParticipant = useRef(participantId);
  const busy = oidcBusy || localBusy || checking;
  const compact = compactAuthenticated && authenticated;
  const SettingsContainer = showAccountSettings ? 'div' : 'details';
  const SecurityContainer = showAccountSettings ? 'section' : 'details';
  const current = useCallback(
    (requestGeneration: number) => mounted.current && generation.current === requestGeneration,
    [],
  );

  useEffect(() => {
    const parameters = new URLSearchParams(window.location.search);
    if (parameters.get('oidcError') !== 'authentication_failed') return;
    setStatus(
      'Sign-in failed. Start a new attempt. Leave the Participant field blank unless you are intentionally restricting sign-in to a known Participant ID.',
    );
    parameters.delete('oidcError');
    const query = parameters.toString();
    window.history.replaceState(
      null,
      '',
      `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash}`,
    );
  }, []);

  useEffect(() => {
    mounted.current = true;
    const conceal = () => {
      generation.current++;
      activeRead.current?.abort();
      checkingRef.current = true;
      setChecking(true);
      setCredential('');
      setLoginHint('');
      setSelectedParticipant(participantId ?? '');
      setFreshAuthentication(false);
      setStatus('Checking the current account and workspace.');
    };
    const read = (clearStatus = false, transitionPending = false) => {
      const requestGeneration = ++generation.current;
      activeRead.current?.abort();
      const controller = new AbortController();
      let retainedFailure = false;
      activeRead.current = controller;
      checkingRef.current = true;
      setChecking(true);
      void fetch('/api/v1/ui/local-session', { cache: 'no-store', signal: controller.signal })
        .then(async (response) => {
          if (!response.ok) throw new Error();
          return localSessionStatusSchema.parse(await response.json());
        })
        .then((result) => {
          if (!current(requestGeneration) || controller.signal.aborted) return;
          runtimeEnabled.current = result.enabled;
          setEnabled(result.enabled);
          setUnavailable(false);
          const signedIn = 'authenticated' in result && result.authenticated === true;
          if (result.enabled && 'authenticated' in result && result.authenticated === false)
            clearTransactionWorkflowStorage();
          setAuthenticated(signedIn);
          if (signedIn) setRole(result.role);
          const previous = sessionRef.current;
          const next = signedIn ? result : undefined;
          if (previous && JSON.stringify(previous) !== JSON.stringify(next)) {
            setCredential('');
            setLoginHint('');
            setFreshAuthentication(false);
            setSelectedParticipant(participantId ?? '');
          }
          // Keep unchanged security controls mounted during a focus check.
          const selected = JSON.stringify(previous) === JSON.stringify(next) ? previous : next;
          sessionRef.current = selected;
          setSession(selected);
          if (localInFlight.current || oidcInFlight.current) {
            setStatus(
              'The session was rechecked while a request was pending. Check its current status before trying again.',
            );
          } else if (clearStatus) setStatus('');
        })
        .catch(() => {
          if (!current(requestGeneration) || controller.signal.aborted) return;
          if (runtimeEnabled.current) {
            retainedFailure = true;
            setUnavailable(true);
          } else {
            setEnabled(false);
            setAuthenticated(false);
            sessionRef.current = undefined;
            setSession(undefined);
            setCredential('');
            setLoginHint('');
          }
        })
        .finally(() => {
          if (
            !current(requestGeneration) ||
            controller.signal.aborted ||
            retainedFailure ||
            transitionPending
          )
            return;
          checkingRef.current = false;
          setChecking(false);
        });
    };
    retryRead.current = (clearStatus = true) => read(clearStatus, transitionPendingRef.current);
    transitionPendingRef.current = false;
    runtimeEnabled.current = false;
    setUnavailable(false);
    setEnabled(false);
    setAuthenticated(false);
    sessionRef.current = undefined;
    setSession(undefined);
    if (previousParticipant.current !== participantId) {
      previousParticipant.current = participantId;
      setStatus('');
      setCredential('');
      setLoginHint('');
      setSelectedParticipant(participantId ?? '');
      setFreshAuthentication(false);
    }
    read();
    const stopObserving = observeSessionTransitions(
      () => {
        transitionPendingRef.current = true;
        if (!emittingTransition.current) conceal();
      },
      (pending) => {
        transitionPendingRef.current = pending;
        if (!emittingTransition.current) read(true, pending);
      },
    );
    return () => {
      mounted.current = false;
      generation.current++;
      activeRead.current?.abort();
      stopObserving();
    };
  }, [participantId, current]);

  function publishTransition(phase: 'changing' | 'settled', owner?: string) {
    emittingTransition.current = true;
    try {
      return notifySessionTransition(phase, owner);
    } finally {
      emittingTransition.current = false;
    }
  }

  if (!enabled) return null;

  async function localMutation(
    request: () => Promise<Response>,
    pending: string,
    failure: string,
    clearCustody: boolean,
    confirm: (value: unknown) => void,
    destination?: string,
  ) {
    if (!mounted.current || checkingRef.current || localInFlight.current || oidcInFlight.current)
      return;
    const transitionOwner = publishTransition('changing');
    localInFlight.current = true;
    const requestGeneration = ++generation.current;
    activeRead.current?.abort();
    setLocalBusy(true);
    setStatus(pending);
    let confirmed = false;
    try {
      const response = await request();
      if (!current(requestGeneration)) return;
      if (!response.ok) throw new Error();
      const result: unknown = await response.json();
      if (!current(requestGeneration)) return;
      confirm(result);
      confirmed = true;
      if (clearCustody) {
        clearPolicyWorkflowStorage();
        clearTransactionWorkflowStorage();
        try {
          sessionStorage.removeItem('openpc:first-admin-review');
          localStorage.removeItem('openpc:role-workflow:v1');
          localStorage.removeItem('openpc:grant-workflow:v1');
          localStorage.removeItem('openpc:principal-workflow:v1');
          localStorage.removeItem('openpc:recovery-workflow:v1');
        } catch {
          /* Optional browser persistence. */
        }
      }
      if (destination) window.location.assign(destination);
      else window.location.reload();
    } catch {
      if (current(requestGeneration)) setStatus(failure);
    } finally {
      const settled = publishTransition('settled', transitionOwner);
      localInFlight.current = false;
      if (mounted.current) {
        setLocalBusy(false);
        if (settled && checkingRef.current) {
          if (!confirmed) setStatus(failure);
          retryRead.current(false);
        }
      }
    }
  }

  async function login(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await localMutation(
      () =>
        fetch('/api/v1/ui/local-session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ role, credential }),
        }),
      'Signing in…',
      'Sign-in could not be confirmed. Reload the page to check your current session.',
      false,
      (value) => {
        if (loginResultSchema.parse(value).role !== role) throw new Error();
      },
    );
  }

  async function loginWithOidc() {
    if (!mounted.current || checkingRef.current || oidcInFlight.current || localInFlight.current)
      return;
    const transitionOwner = publishTransition('changing');
    oidcInFlight.current = true;
    const requestGeneration = ++generation.current;
    activeRead.current?.abort();
    setOidcBusy(true);
    setStatus('Connecting to your sign-in provider…');
    let navigating = false;
    try {
      const response = await fetch('/api/v1/ui/oidc-session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          returnPath: `${window.location.pathname}${window.location.search}`,
          ...(selectedParticipant.trim() ? { participantId: selectedParticipant.trim() } : {}),
          ...(loginHint.trim() ? { loginHint: loginHint.trim() } : {}),
          ...(freshAuthentication ? { freshAuthentication: true } : {}),
        }),
      });
      const result: unknown = await response.json().catch(() => undefined);
      const authorizationUri =
        result &&
        typeof result === 'object' &&
        'authorizationUri' in result &&
        typeof result.authorizationUri === 'string'
          ? result.authorizationUri
          : undefined;
      if (!current(requestGeneration)) return;
      if (response.ok && authorizationUri) {
        window.location.assign(authorizationUri);
        navigating = true;
        return;
      }
    } catch {
      /* The actionable, non-sensitive status below covers unavailable local services. */
    } finally {
      const settled = publishTransition('settled', transitionOwner);
      if (!navigating) {
        oidcInFlight.current = false;
        if (mounted.current) {
          setOidcBusy(false);
          if (settled && checkingRef.current) {
            setStatus('Sign-in could not be started. Try again or contact your administrator.');
            retryRead.current(false);
          }
        }
      }
    }
    if (current(requestGeneration))
      setStatus('Sign-in could not be started. Try again or contact your administrator.');
  }

  async function logout() {
    await localMutation(
      () => fetch('/api/v1/ui/local-session', { method: 'DELETE' }),
      'Signing out…',
      centralized
        ? 'Sign-out could not be confirmed. Retry the session check before continuing.'
        : 'Sign-out could not be confirmed. Reload the page to check your current session.',
      true,
      (value) => confirmSessionOperation(value, 'ACT-IDENTITY_DELETE_SESSION-V1'),
    );
  }

  async function selectTestRole(
    role: 'operator' | 'viewer',
    context: 'PARTICIPANT' | 'PLATFORM' = session?.contextMode ?? 'PARTICIPANT',
  ) {
    await localMutation(
      () =>
        fetch('/api/v1/ui/functional-session', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ role, context }),
        }),
      'Changing workspace…',
      'The workspace could not be changed. Retry the workspace check.',
      true,
      (value) => {
        const result = z
          .strictObject({
            status: z.literal('selected'),
            role: z.enum(['operator', 'viewer']),
            contextMode: z.enum(['PARTICIPANT', 'PLATFORM']),
          })
          .parse(value);
        if (result.role !== role || result.contextMode !== context) throw new Error();
      },
      context === session?.contextMode
        ? undefined
        : context === 'PLATFORM'
          ? '/govern/participants?view=rpc-access'
          : '/develop/modules',
    );
  }

  async function refreshSession() {
    await localMutation(
      () => fetch('/api/v1/ui/local-session', { method: 'PATCH' }),
      'Refreshing your session…',
      'Session refresh could not be confirmed. Reload the page to check your current session.',
      true,
      (value) => confirmSessionOperation(value, 'ACT-IDENTITY_CREATE_SESSION-V1'),
    );
  }

  function confirmSessionOperation(
    value: unknown,
    action: z.infer<typeof sessionOperationSchema>['actionIntentId'],
  ) {
    const operation = sessionOperationSchema.parse(value);
    if (
      !session ||
      operation.actionIntentId !== action ||
      operation.resourceRef !== `urn:openpc:resource:${session.sessionId}`
    )
      throw new Error();
  }

  if (appearance === 'menu') {
    return (
      <div className="workspace-account-bar">
        <span>
          {checking
            ? 'Checking session…'
            : session?.functionalTest
              ? 'Private test workspace'
              : session?.contextMode === 'PARTICIPANT'
                ? 'Organization workspace'
                : 'Platform workspace'}
        </span>
        <AccountMenu hidden={checking || !authenticated}>
          <div>
            {session?.functionalTest ? (
              <>
                <p>Role: {session.role === 'operator' ? 'Administrator' : 'Reviewer'}</p>
                <p>
                  {session.contextMode === 'PLATFORM'
                    ? 'Platform workspace'
                    : 'Organization workspace'}
                </p>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    void selectTestRole(session.role === 'operator' ? 'viewer' : 'operator')
                  }
                >
                  Switch to {session.role === 'operator' ? 'Reviewer' : 'Administrator'}
                </button>
                {session.functionalPlatformConfigured && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() =>
                      void selectTestRole(
                        session.role,
                        session.contextMode === 'PLATFORM' ? 'PARTICIPANT' : 'PLATFORM',
                      )
                    }
                  >
                    {session.contextMode === 'PLATFORM'
                      ? 'Switch to Organization workspace'
                      : 'Switch to Platform workspace'}
                  </button>
                )}
              </>
            ) : (
              <>
                <Link href="/home/session">Account & security</Link>
                <button type="button" disabled={busy} onClick={() => void logout()}>
                  Sign out
                </button>
              </>
            )}
          </div>
        </AccountMenu>
        {status && <p role="status">{status}</p>}
        {unavailable && (
          <button type="button" onClick={() => retryRead.current()}>
            Retry session check
          </button>
        )}
      </div>
    );
  }

  if (session?.functionalTest)
    return (
      <section
        className="rounded border border-[color:var(--border)] p-5"
        aria-label="Test workspace"
      >
        <h2>Private test workspace</h2>
        <p>
          Administrator and Reviewer are managed test accounts. Sign-in and security-key prompts are
          deferred.
        </p>
        <button
          type="button"
          disabled={busy}
          onClick={() => void selectTestRole(session.role === 'operator' ? 'viewer' : 'operator')}
        >
          Switch to {session.role === 'operator' ? 'Reviewer' : 'Administrator'}
        </button>
        {status && <p role="status">{status}</p>}
      </section>
    );

  return (
    <section aria-labelledby="account-workspace-heading" className="account-session">
      <header className="account-session-header">
        <div>
          <h2 id="account-workspace-heading">
            {showAccountSettings ? 'Your account' : 'Account & workspace'}
          </h2>
          <p>
            {checking
              ? 'Checking session…'
              : authenticated
                ? session?.contextMode === 'PARTICIPANT'
                  ? 'Organization workspace'
                  : 'Platform workspace'
                : 'Sign in to continue'}
          </p>
        </div>
        <div className="account-session-actions" hidden={checking || centralized}>
          <button
            className="session-primary"
            disabled={busy}
            onClick={() => void loginWithOidc()}
            type="button"
          >
            {oidcBusy ? 'Starting sign-in…' : authenticated ? 'Switch account' : 'Sign in'}
          </button>
          {authenticated && (
            <button disabled={busy} onClick={() => void logout()} type="button">
              Sign out
            </button>
          )}
        </div>
      </header>
      <p aria-live="polite" className="account-session-status" role="status">
        {status}
      </p>
      {unavailable && (
        <div className="account-session-unavailable" role="alert">
          <p>
            Session unavailable. Your previous controls remain concealed. Retry to confirm the
            current account before continuing.
          </p>
          <button type="button" onClick={() => retryRead.current()}>
            Retry session check
          </button>
        </div>
      )}
      <fieldset disabled={checking || busy} hidden={checking} className="account-session-controls">
        <SettingsContainer
          className="account-session-settings"
          {...(!showAccountSettings ? { open: !compactAuthenticated } : {})}
        >
          {!showAccountSettings && <summary>Account settings</summary>}
          {!centralized && (
            <p className="account-session-note">
              Evaluation environment. Use synthetic accounts only.
            </p>
          )}
          {!centralized && (
            <details className="account-session-details" open={!compactAuthenticated}>
              <summary>Sign-in options</summary>
              <div className="mt-4 flex flex-wrap items-end gap-3">
                <div className="grid max-w-sm gap-1">
                  <label htmlFor="oidc-expected-participant">
                    Expected Participant/organization ID (optional)
                  </label>
                  <input
                    aria-describedby="oidc-expected-participant-help"
                    className="min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
                    disabled={busy}
                    id="oidc-expected-participant"
                    value={selectedParticipant}
                    maxLength={36}
                    onChange={(event) => setSelectedParticipant(event.target.value)}
                  />
                  <span
                    className="text-sm text-[color:var(--muted)]"
                    id="oidc-expected-participant-help"
                  >
                    Leave blank for normal sign-in. This is the Participant ID, not the
                    user/principal ID.
                  </span>
                </div>
                <label className="grid gap-1">
                  OIDC account hint (optional)
                  <input
                    className="min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
                    value={loginHint}
                    maxLength={256}
                    autoComplete="username"
                    disabled={busy}
                    onChange={(event) => setLoginHint(event.target.value)}
                  />
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={freshAuthentication}
                    disabled={busy}
                    onChange={(event) => setFreshAuthentication(event.target.checked)}
                  />
                  Require fresh authentication after account recovery
                </label>
              </div>
            </details>
          )}
          {session && (
            <SecurityContainer
              className={
                showAccountSettings ? 'account-security-section' : 'account-session-details'
              }
              {...(showAccountSettings
                ? { 'aria-label': 'Security & workspace' }
                : { open: !compact })}
            >
              {showAccountSettings ? (
                <h3>Security & workspace</h3>
              ) : (
                <summary>Security & workspace</summary>
              )}
              {!showAccountSettings && (
                <button
                  className="mt-4"
                  disabled={busy}
                  onClick={() => void refreshSession()}
                  type="button"
                >
                  Refresh session
                </button>
              )}
              <AuthenticatorEnrollment
                key={`${session.sessionId}:${session.contextEpoch}`}
                session={session}
                onSessionTransition={(phase, owner) => {
                  const settled = publishTransition(phase, owner);
                  if (phase === 'settled' && settled && mounted.current) retryRead.current(false);
                  return settled;
                }}
              />
            </SecurityContainer>
          )}
          {session && (
            <details
              className={
                showAccountSettings ? 'account-reference-section' : 'account-session-details'
              }
              {...(showAccountSettings
                ? { 'aria-label': 'Account references' }
                : { open: !compactAuthenticated })}
            >
              {showAccountSettings ? (
                <>
                  <summary>Account references</summary>
                  <p>Use these references when you contact your workspace administrator.</p>
                </>
              ) : (
                <summary>Account details</summary>
              )}
              <dl>
                <div>
                  <dt>Account reference</dt>
                  <dd>
                    {!showAccountSettings && 'Signed-in account: '}
                    {session.principalId}
                  </dd>
                </div>
                <div>
                  <dt>Organization reference</dt>
                  <dd>{session.participantId}</dd>
                </div>
                {session.privacyDomainId && (
                  <div>
                    <dt>Workspace reference</dt>
                    <dd>{session.privacyDomainId}</dd>
                  </div>
                )}
              </dl>
              {showAccountSettings && (
                <button
                  className="account-reference-refresh"
                  disabled={busy}
                  onClick={() => void refreshSession()}
                  type="button"
                >
                  Refresh session
                </button>
              )}
            </details>
          )}
          {!centralized && (
            <details className="account-session-details" open={!compactAuthenticated}>
              <summary>Local account sign-in</summary>
              <p className="account-session-note">
                Local access credentials are for isolated evaluation environments.
              </p>
              <form
                className="mt-4 flex flex-wrap items-end gap-3 border-t border-[color:var(--border)] pt-4"
                onSubmit={(event) => void login(event)}
              >
                <label className="grid gap-1">
                  Account role
                  <select
                    className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
                    disabled={busy}
                    onChange={(event) => setRole(event.target.value as 'operator' | 'viewer')}
                    value={role}
                  >
                    <option value="operator">Operator</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </label>
                <label className="grid gap-1">
                  Local access credential
                  <input
                    autoComplete="current-password"
                    disabled={busy}
                    className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
                    onChange={(event) => setCredential(event.target.value)}
                    required
                    type="password"
                    value={credential}
                  />
                </label>
                <button
                  className="rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)]"
                  disabled={busy}
                  type="submit"
                >
                  Sign in with local credential
                </button>
              </form>
            </details>
          )}
        </SettingsContainer>
      </fieldset>
    </section>
  );
}
