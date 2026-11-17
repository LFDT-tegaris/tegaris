'use client';

import { notifySessionTransition, observeSessionTransitions } from './session-transition';

import { useEffect, useId, useRef, useState } from 'react';
import { z } from 'zod';
import { Fingerprint, Layers3 } from 'lucide-react';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { CopyReference } from './copy-reference';
import {
  enrollmentReadbackSchema,
  type EnrollmentReadback,
  type EnrollmentSession,
} from '../lib/authenticator-enrollment';

function encode(bytes: ArrayBuffer) {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

async function readEnrollment(enrollmentId: string, session: EnrollmentSession) {
  const response = await fetch(
    `/api/v1/ui/webauthn/enrollment?enrollmentId=${encodeURIComponent(enrollmentId)}`,
    { cache: 'no-store' },
  );
  if (!response.ok)
    throw new Error(
      'Registration status could not be read. Sign in again if your session has changed.',
    );
  const value = enrollmentReadbackSchema.parse(await response.json());
  if (
    value.enrollmentId !== enrollmentId ||
    value.principalId !== session.principalId ||
    value.participantId !== session.participantId
  )
    throw new Error('The signed-in account has changed. Reload before continuing.');
  return value;
}

const selectedSessionSchema = z.object({
  sessionId: z.uuid(),
  participantId: z.uuid(),
  contextMode: z.literal('PARTICIPANT'),
  privacyDomainId: z.uuid(),
  contextEpoch: z.string().regex(/^[1-9][0-9]*$/u),
});

export function AuthenticatorEnrollment({
  session,
  onSessionTransition = notifySessionTransition,
}: {
  session: EnrollmentSession;
  onSessionTransition?: typeof notifySessionTransition;
}) {
  const contextSelectId = useId();
  const storageKey = `openpc:authenticator-enrollment:${session.sessionId}`;
  const [enrollmentId, setEnrollmentId] = useState('');
  const [readback, setReadback] = useState<EnrollmentReadback>();
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [hardwareAttestation, setHardwareAttestation] = useState(false);
  const currentContext =
    session.contextMode === 'PARTICIPANT' && session.privacyDomainId
      ? { participantId: session.participantId, privacyDomainId: session.privacyDomainId }
      : undefined;
  const [selectedContext, setSelectedContext] = useState(
    () =>
      currentContext?.privacyDomainId ??
      (session.availableContexts.length === 1 ? session.availableContexts[0]!.privacyDomainId : ''),
  );
  const selectedIsCurrent = currentContext?.privacyDomainId === selectedContext;
  const selectedWorkspace = selectedIsCurrent
    ? currentContext
    : session.availableContexts.find((context) => context.privacyDomainId === selectedContext);
  const currentIsListed = session.availableContexts.some(
    (context) =>
      context.participantId === currentContext?.participantId &&
      context.privacyDomainId === currentContext?.privacyDomainId,
  );
  const workspaceReferences = [
    ...new Set([
      ...session.availableContexts.map((context) => context.privacyDomainId),
      ...(currentContext ? [currentContext.privacyDomainId] : []),
    ]),
  ];
  function workspaceLabel(reference: string) {
    const label = reference === currentContext?.privacyDomainId ? 'Current workspace' : 'Workspace';
    if (workspaceReferences.length === 1) return label;
    const suffix = reference.slice(-12);
    const unique = workspaceReferences.every(
      (other) => other === reference || !other.endsWith(suffix),
    );
    return `${label} · ${unique ? suffix : reference}`;
  }
  const mounted = useRef(false);
  const contextGeneration = useRef(0);
  const contextRequest = useRef<AbortController | undefined>(undefined);
  const publishingTransition = useRef(false);

  useEffect(() => {
    mounted.current = true;
    const stopObserving = observeSessionTransitions(
      () => {
        if (publishingTransition.current) return;
        contextGeneration.current++;
        contextRequest.current?.abort();
      },
      () => {},
    );
    return () => {
      mounted.current = false;
      contextGeneration.current++;
      contextRequest.current?.abort();
      stopObserving();
    };
  }, [
    session.sessionId,
    session.principalId,
    session.participantId,
    session.contextMode,
    session.privacyDomainId,
  ]);

  useEffect(() => {
    let active = true;
    async function restore() {
      let saved: string | null = null;
      try {
        saved = sessionStorage.getItem(storageKey);
      } catch {
        /* Optional persistence. */
      }
      if (!saved || !z.uuid().safeParse(saved).success) return;
      if (active) setEnrollmentId(saved);
      try {
        const value = await readEnrollment(saved, session);
        if (active) setReadback(value);
      } catch (error) {
        if (active)
          setStatus(error instanceof Error ? error.message : 'Registration status is unavailable.');
      }
    }
    void restore();
    return () => {
      active = false;
    };
  }, [session, storageKey]);

  async function refresh() {
    if (busy || !enrollmentId) return;
    setBusy(true);
    setStatus('Checking saved registration.');
    try {
      setReadback(await readEnrollment(enrollmentId, session));
      setStatus('Registration status is up to date.');
    } catch (error) {
      setReadback(undefined);
      setStatus(error instanceof Error ? error.message : 'Registration status is unavailable.');
    } finally {
      setBusy(false);
    }
  }

  async function register() {
    if (busy) return;
    setBusy(true);
    setStatus('Follow your browser’s authenticator prompt.');
    let startedId = '';
    try {
      const optionsResponse = await fetch('/api/v1/ui/webauthn/initial-registration/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hardwareAttestation, expectedSessionId: session.sessionId }),
      });
      if (!optionsResponse.ok)
        throw new Error(
          'Registration could not start. Sign in again, or use your existing authenticator to verify workspace access.',
        );
      const ceremony = z
        .object({ enrollmentId: z.uuid(), publicKey: z.unknown() })
        .parse(await optionsResponse.json());
      startedId = ceremony.enrollmentId;
      setEnrollmentId(startedId);
      setReadback(undefined);
      try {
        sessionStorage.setItem(storageKey, startedId);
      } catch {
        /* Readback remains available by registration ID. */
      }
      const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
        ceremony.publicKey as PublicKeyCredentialCreationOptionsJSON,
      );
      const credential = await navigator.credentials.create({ publicKey });
      if (
        !(credential instanceof PublicKeyCredential) ||
        !(credential.response instanceof AuthenticatorAttestationResponse)
      )
        throw new Error('Your browser did not return an authenticator registration.');
      const attestation = credential.response;
      const completed = await fetch('/api/v1/ui/webauthn/initial-registration/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentId: startedId,
          expectedSessionId: session.sessionId,
          response: {
            id: credential.id,
            rawId: encode(credential.rawId),
            type: credential.type,
            response: {
              attestationObject: encode(attestation.attestationObject),
              clientDataJSON: encode(attestation.clientDataJSON),
              transports: attestation.getTransports(),
            },
            clientExtensionResults: credential.getClientExtensionResults(),
            authenticatorAttachment: credential.authenticatorAttachment,
          },
        }),
      });
      if (!completed.ok)
        throw new Error(
          'The registration response was not accepted. Checking whether a credential was saved.',
        );
      const saved = await readEnrollment(startedId, session);
      setReadback(saved);
      setStatus(
        saved.state === 'COMPLETED' && saved.credential?.active
          ? 'Authenticator saved and confirmed by Identity.'
          : 'Registration has not completed. Check its status before trying again.',
      );
    } catch (error) {
      let reconciled: EnrollmentReadback | undefined;
      if (startedId) reconciled = await readEnrollment(startedId, session).catch(() => undefined);
      setReadback(reconciled);
      setStatus(
        reconciled?.state === 'COMPLETED' && reconciled.credential?.active
          ? 'Authenticator saved. The interrupted response was reconciled from Identity.'
          : error instanceof Error
            ? error.message
            : 'Registration was interrupted. Check its status before trying again.',
      );
    } finally {
      setBusy(false);
    }
  }

  function publishTransition(phase: 'changing' | 'settled', owner?: string) {
    publishingTransition.current = true;
    try {
      return onSessionTransition(phase, owner);
    } finally {
      publishingTransition.current = false;
    }
  }

  async function selectContext(
    context: { participantId: string; privacyDomainId: string } | undefined,
  ) {
    if (busy || !context || !mounted.current || contextRequest.current) return;
    const controller = new AbortController();
    const requestGeneration = ++contextGeneration.current;
    contextRequest.current = controller;
    const isCurrent = () =>
      mounted.current &&
      contextGeneration.current === requestGeneration &&
      !controller.signal.aborted;
    const transitionOwner = publishTransition('changing');
    setBusy(true);
    setStatus('Verify your authenticator to enter the selected Participant context.');
    try {
      const resourceDigest = `sha256:${Array.from(
        new Uint8Array(
          await crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode(
              JSON.stringify({
                participantId: context.participantId,
                privacyDomainId: context.privacyDomainId,
              }),
            ),
          ),
        ),
      )
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('')}`;
      if (!isCurrent()) return;
      await performWebAuthnStepUp(
        {
          actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
          actionIntentDigest:
            'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
          stepUp: 'FRESH_WEBAUTHN_MAX_5M',
        },
        { resourceId: context.participantId, resourceDigest },
        { signal: controller.signal, isCurrent },
      );
      if (!isCurrent()) return;
      const response = await fetch('/api/v1/ui/session/context', {
        method: 'POST',
        signal: controller.signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...context, expectedSessionId: session.sessionId }),
      });
      if (!isCurrent()) return;
      if (response.status !== 201)
        throw new Error(
          'Context selection was not confirmed. Your session or authenticator verification may have expired.',
        );
      const selected = selectedSessionSchema.safeParse(await response.json());
      if (!isCurrent()) return;
      if (
        !selected.success ||
        selected.data.sessionId === session.sessionId ||
        selected.data.participantId !== context.participantId ||
        selected.data.privacyDomainId !== context.privacyDomainId
      )
        throw new Error('The new session could not be confirmed. Reload to check your account.');
      window.location.reload();
    } catch (error) {
      if (isCurrent())
        setStatus(
          error instanceof Error
            ? error.message
            : 'Context selection was interrupted. Reload to check your session.',
        );
    } finally {
      publishTransition('settled', transitionOwner);
      if (contextRequest.current === controller) contextRequest.current = undefined;
      if (mounted.current) setBusy(false);
    }
  }

  return (
    <section aria-labelledby="authenticator-enrollment-title" className="authenticator-settings">
      <div className="authenticator-introduction">
        <h3 id="authenticator-enrollment-title">Account verification</h3>
        <p>
          Use an authenticator to verify sensitive actions and access your organization’s workspace.
          Complete approved account recovery before replacing a lost authenticator.
        </p>
      </div>
      <div className="authenticator-panel-grid">
        {!currentContext && session.availableContexts.length === 0 && (
          <section
            className="authenticator-card"
            aria-labelledby={`${contextSelectId}-unavailable-title`}
          >
            <header>
              <span className="authenticator-card-icon">
                <Layers3 aria-hidden size={21} />
              </span>
              <div>
                <h4 id={`${contextSelectId}-unavailable-title`}>
                  No organization workspace available
                </h4>
                <p>
                  Your account is signed in, but no organization workspace is currently available.
                </p>
              </div>
            </header>
            <p>Ask your workspace administrator to check your organization access.</p>
            <p className="authenticator-workspace-help">
              Registering another authenticator does not grant workspace access.
            </p>
          </section>
        )}
        {(currentContext || session.availableContexts.length > 0) && (
          <section
            className="authenticator-card"
            aria-labelledby={`${contextSelectId}-workspace-title`}
          >
            <header>
              <span className="authenticator-card-icon">
                <Layers3 aria-hidden size={21} />
              </span>
              <div>
                <h4 id={`${contextSelectId}-workspace-title`}>
                  {selectedIsCurrent ? 'Current workspace' : 'Workspace access'}
                </h4>
                <p>
                  {selectedIsCurrent
                    ? 'You are working in this organization workspace.'
                    : 'Verify your existing authenticator to enter your workspace.'}
                </p>
              </div>
            </header>
            {session.availableContexts.length > 0 ? (
              <div className="grid gap-1">
                <label htmlFor={contextSelectId}>Organization workspace</label>
                <select
                  id={contextSelectId}
                  aria-describedby={`${contextSelectId}-workspace-help`}
                  value={selectedContext}
                  onChange={(event) => setSelectedContext(event.target.value)}
                  disabled={busy}
                  className="min-w-0 rounded border bg-[color:var(--surface)] p-2"
                >
                  <option value="">Choose a workspace</option>
                  {currentContext && !currentIsListed && (
                    <option value={currentContext.privacyDomainId}>
                      {workspaceLabel(currentContext.privacyDomainId)}
                    </option>
                  )}
                  {session.availableContexts.map((context) => (
                    <option key={context.privacyDomainId} value={context.privacyDomainId}>
                      {workspaceLabel(context.privacyDomainId)}
                    </option>
                  ))}
                </select>
                {selectedWorkspace && (
                  <div className="grid min-w-0 gap-1 text-sm">
                    <span>Workspace reference</span>
                    <CopyReference
                      label="Workspace reference"
                      value={selectedWorkspace.privacyDomainId}
                    />
                  </div>
                )}
              </div>
            ) : (
              <div className="grid gap-1 text-sm">
                <span>Workspace reference</span>
                {currentContext && (
                  <CopyReference
                    label="Workspace reference"
                    value={currentContext.privacyDomainId}
                  />
                )}
              </div>
            )}
            <p id={`${contextSelectId}-workspace-help`} className="authenticator-workspace-help">
              {selectedIsCurrent
                ? 'Renewing verifies your authenticator and starts a new session. Sensitive actions may require their own verification.'
                : selectedWorkspace
                  ? 'Use your existing authenticator to continue. For first-time registration, use the Authenticator registration panel.'
                  : 'Choose a workspace to enable verification.'}
            </p>
            <button
              type="button"
              className="workflow-primary"
              disabled={busy || !selectedWorkspace}
              onClick={() => void selectContext(selectedWorkspace)}
            >
              {selectedIsCurrent ? 'Verify and renew session' : 'Verify and enter workspace'}
            </button>
          </section>
        )}
        <section className="authenticator-card" aria-labelledby={`${contextSelectId}-key-title`}>
          <header>
            <span className="authenticator-card-icon">
              <Fingerprint aria-hidden size={21} />
            </span>
            <div>
              <h4 id={`${contextSelectId}-key-title`}>Authenticator registration</h4>
              <p>Register a security key or check a saved registration.</p>
            </div>
          </header>
          <div className="authenticator-attestation">
            <label>
              <input
                type="checkbox"
                checked={hardwareAttestation}
                disabled={busy}
                aria-describedby={`${contextSelectId}-attestation-help`}
                onChange={(event) => setHardwareAttestation(event.target.checked)}
              />
              Request hardware attestation
            </label>
            <p id={`${contextSelectId}-attestation-help`}>
              Required for approved recovery executors.
            </p>
          </div>
          <button
            type="button"
            className={currentContext ? 'authenticator-registration-button' : 'workflow-primary'}
            disabled={busy || readback?.state === 'COMPLETED'}
            onClick={() => void register()}
          >
            Register authenticator
          </button>
          <div className="authenticator-saved-registration">
            <label className="grid gap-1">
              Registration ID
              <input
                className="min-w-0 rounded border bg-[color:var(--surface)] p-2"
                value={enrollmentId}
                disabled={busy}
                onChange={(event) => {
                  setEnrollmentId(event.target.value);
                  setReadback(undefined);
                }}
              />
            </label>
            <button
              type="button"
              disabled={busy || !z.uuid().safeParse(enrollmentId).success}
              onClick={() => void refresh()}
            >
              Check registration status
            </button>
          </div>
          {readback && (
            <div className="authenticator-registration-result" aria-label="Saved registration">
              <p>
                Registration: <strong>{readback.state}</strong>
              </p>
              {readback.credential && (
                <>
                  <p className="break-all">Authenticator: {readback.credential.credentialId}</p>
                  <p>
                    {readback.credential.active ? 'Active' : 'Inactive'} · Credential epoch{' '}
                    {readback.credential.credentialEpoch} · Account epoch {readback.principalEpoch}
                  </p>
                </>
              )}
            </div>
          )}
        </section>
      </div>
      <p role="status" aria-live="polite" className="authenticator-status">
        {status}
      </p>
    </section>
  );
}
