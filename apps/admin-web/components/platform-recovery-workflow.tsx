'use client';
import {
  DiscoveryCertificateRecoveryWorkflow,
  type DiscoveryRecoveryView,
} from './discovery-certificate-recovery-workflow';
import {
  LocalRootExpiryRecoveryWorkflow,
  type RootExpiryRecoveryView,
} from './local-root-expiry-recovery-workflow';
import { useEffect, useRef, useState } from 'react';
import {
  IdentityEnvelopeRecoveryWorkflow,
  type EnvelopeRecoveryView,
} from './identity-envelope-recovery-workflow';
import type { z } from 'zod';
import type {
  platformRecoverySourceView,
  platformRecoveryDraftView,
  platformRecoveryReceiptView,
  platformRecoveryChallengeView,
  platformRecoveryCommand,
} from '../../../services/identity-service/src/contracts/platform-recovery';
const endpoint = '/api/v1/ui/platform-recovery-workbench';
const savedKey = 'openpc:platform-recovery-case:v1';
const field = 'w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button = 'rounded bg-[color:var(--accent)] px-3 py-2 text-white disabled:opacity-60';
interface Actor {
  sessionId: string;
  principalId: string;
  participantId: string;
  contextEpoch: string;
}
const decode = (value: string) =>
  Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0))
    .buffer;
const encode = (value: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(value)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
async function assertion(challenge: z.infer<typeof platformRecoveryChallengeView>) {
  if (typeof PublicKeyCredential === 'undefined' || !navigator.credentials)
    throw new Error('A WebAuthn authenticator is required.');
  if (challenge.rpId !== window.location.hostname)
    throw new Error('The authenticator origin does not match this page.');
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: decode(challenge.challenge),
      rpId: challenge.rpId,
      allowCredentials: challenge.credentialIds.map((id) => ({
        type: 'public-key' as const,
        id: decode(id),
      })),
      userVerification: 'required',
      timeout: Math.max(1, Math.min(300000, Date.parse(challenge.expiresAt) - Date.now())),
    },
  });
  if (!(credential instanceof PublicKeyCredential))
    throw new Error('No authenticator assertion was returned.');
  const response = credential.response as AuthenticatorAssertionResponse;
  if (
    !(response.authenticatorData instanceof ArrayBuffer) ||
    !(response.clientDataJSON instanceof ArrayBuffer) ||
    !(response.signature instanceof ArrayBuffer)
  )
    throw new Error('The authenticator assertion is invalid.');
  return JSON.stringify({
    credentialId: encode(credential.rawId),
    authenticatorData: encode(response.authenticatorData),
    clientDataJson: encode(response.clientDataJSON),
    signature: encode(response.signature),
  });
}
export function PlatformRecoveryWorkflow() {
  const scopeGeneration = useRef(0);
  const [purpose, setPurpose] = useState<'ADMINISTRATION' | 'DISCOVERY_CERTIFICATE_REPLACEMENT'>(
    'ADMINISTRATION',
  );
  const [discoveryView, setDiscoveryView] = useState<DiscoveryRecoveryView>();
  const [enrollmentId, setEnrollmentId] = useState('');
  const [privacyDomainId, setPrivacyDomainId] = useState('');
  const [recoveryId, setRecoveryId] = useState('');
  const [actor, setActor] = useState<Actor>();
  const [source, setSource] = useState<z.infer<typeof platformRecoverySourceView>>();
  const [receipt, setReceipt] = useState<z.infer<typeof platformRecoveryReceiptView>>();
  const [draft, setDraft] = useState<z.infer<typeof platformRecoveryDraftView>>();
  const [rootExpiryView, setRootExpiryView] = useState<RootExpiryRecoveryView>();
  const [signerView, setSignerView] = useState<EnvelopeRecoveryView>();
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState(
    'Sign in with an enrolled recovery identity in Platform context.',
  );
  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(savedKey) ?? 'null');
      if (
        saved &&
        typeof saved.enrollmentId === 'string' &&
        typeof saved.privacyDomainId === 'string' &&
        typeof saved.recoveryId === 'string'
      ) {
        setPurpose(
          saved.purpose === 'DISCOVERY_CERTIFICATE_REPLACEMENT'
            ? 'DISCOVERY_CERTIFICATE_REPLACEMENT'
            : 'ADMINISTRATION',
        );
        setEnrollmentId(saved.enrollmentId);
        setPrivacyDomainId(saved.privacyDomainId);
        setRecoveryId(saved.recoveryId);
      }
    } catch {
      localStorage.removeItem(savedKey);
    }
  }, []);
  const post = async (command: z.infer<typeof platformRecoveryCommand>) => {
    const generation = scopeGeneration.current;
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentId,
          privacyDomainId,
          command,
          ...(purpose === 'DISCOVERY_CERTIFICATE_REPLACEMENT' ? { purpose } : {}),
        }),
      });
      const body = await response.json().catch(() => undefined);
      if (generation !== scopeGeneration.current)
        throw new Error('The recovery context changed. Read the original case again.');
      if (!response.ok) {
        setSource(undefined);
        setReceipt(undefined);
        setDraft(undefined);
        setSignerView(undefined);
        setRootExpiryView(undefined);
        setDiscoveryView(undefined);
        throw new Error(
          `${body?.title ?? 'Recovery was not completed.'} (${body?.code ?? 'PC-INTEGRATION-5001'})`,
        );
      }
      if (
        actor &&
        (actor.sessionId !== body.actor?.sessionId ||
          actor.contextEpoch !== body.actor?.contextEpoch ||
          actor.principalId !== body.actor?.principalId ||
          actor.participantId !== body.actor?.participantId)
      ) {
        setSource(undefined);
        setReceipt(undefined);
        setDraft(undefined);
        setSignerView(undefined);
        setRootExpiryView(undefined);
        setDiscoveryView(undefined);
      }
      setActor(body.actor);
      return body.view as unknown;
    } catch (error) {
      if (command.kind === 'CLOSE' && generation === scopeGeneration.current) {
        // A lost response may follow a durable closure. Keep original custody,
        // but discard every displayed authority until its public readback.
        setSource(undefined);
        setReceipt(undefined);
        setDraft(undefined);
        setSignerView(undefined);
        setRootExpiryView(undefined);
        setDiscoveryView(undefined);
        throw new Error('Case closure could not be confirmed. Read the original case again.');
      }
      throw error;
    }
  };
  const run = async (work: () => Promise<void>) => {
    const generation = scopeGeneration.current;
    setBusy(true);
    try {
      await work();
    } catch (error) {
      if (generation === scopeGeneration.current)
        setStatus(error instanceof Error ? error.message : 'Recovery was not completed.');
    } finally {
      setBusy(false);
    }
  };
  const storeCase = (id: string) => {
    setRecoveryId(id);
    localStorage.setItem(
      savedKey,
      JSON.stringify({ enrollmentId, privacyDomainId, recoveryId: id, purpose }),
    );
  };
  const read = async () => {
    const next = (await post({ kind: 'READ', recoveryId })) as
      EnvelopeRecoveryView | RootExpiryRecoveryView | z.infer<typeof platformRecoveryReceiptView>;
    if (purpose === 'DISCOVERY_CERTIFICATE_REPLACEMENT') {
      setSource(undefined);
      setReceipt(undefined);
      setDraft(undefined);
      setSignerView(undefined);
      setRootExpiryView(undefined);
      setDiscoveryView(next as unknown as DiscoveryRecoveryView);
      setStatus('Original discovery certificate recovery case loaded.');
      return;
    }
    if (
      'purpose' in next &&
      (next.purpose === 'LOCAL_ROOT_EXPIRY_RECOVERY_ONLY' ||
        next.purpose === 'LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY' ||
        next.purpose === 'LOCAL_ROOT_EXPIRY_PENDING_ANCESTRY_RECOVERY_ONLY')
    ) {
      setSource(undefined);
      setDraft(undefined);
      setReceipt(undefined);
      setSignerView(undefined);
      setRootExpiryView(next as RootExpiryRecoveryView);
      setStatus('Original local Root expiry case loaded.');
      return;
    }
    if (
      'intent' in next &&
      next.intent.schema === 'pc.identity.identity-envelope-recovery-intent'
    ) {
      setSignerView(next as EnvelopeRecoveryView);
      setSource(undefined);
      setDraft(undefined);
      setReceipt(undefined);
      setStatus(`Original signer case ${'state' in next ? next.state : 'unavailable'} loaded.`);
      return;
    }
    setSignerView(undefined);
    setRootExpiryView(undefined);
    setDiscoveryView(undefined);
    setReceipt(next as z.infer<typeof platformRecoveryReceiptView>);
    setDraft(undefined);
    setStatus(
      `Original case ${(next as z.infer<typeof platformRecoveryReceiptView>).state} loaded.`,
    );
  };
  const prove = async (phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE') => {
    const challenge = (await post({ kind: 'CHALLENGE', recoveryId, phase })) as z.infer<
      typeof platformRecoveryChallengeView
    >;
    const signed = await assertion(challenge);
    const next = (await post({
      kind: 'PROVE',
      recoveryId,
      phase,
      proof: {
        challengeId: challenge.challengeId,
        challenge: challenge.challenge,
        intentDigest: challenge.intentDigest,
        assertion: signed,
      },
    })) as z.infer<typeof platformRecoveryReceiptView>;
    setReceipt(next);
    setDraft(undefined);
    setStatus(`${phase} proof recorded. Original case ${next.state}.`);
  };
  const intent = receipt?.intent ?? draft?.intent;
  const live = !!intent && now < Date.parse(intent.validUntil);
  const executor =
    actor?.principalId ===
    (receipt?.actors.executorPrincipalId ?? source?.source.executorPrincipalId);
  const custodian = !!actor && receipt?.actors.custodianPrincipalIds.includes(actor.principalId);
  const currentAuthority = live ? (receipt?.authority ?? draft?.authority) : 'NONE';
  const approvals = receipt?.proofs.filter((p) => p.phase === 'APPROVE') ?? [];
  const changeScope = () => {
    scopeGeneration.current++;
    setSource(undefined);
    setReceipt(undefined);
    setDraft(undefined);
    setActor(undefined);
    setSignerView(undefined);
    setRootExpiryView(undefined);
    setDiscoveryView(undefined);
  };
  useEffect(() => {
    if (!actor) return;
    let current = true;
    const refresh = () => {
      void fetch('/api/v1/ui/local-session', { credentials: 'same-origin', cache: 'no-store' })
        .then(async (response) => (response.ok ? response.json() : undefined))
        .catch(() => undefined)
        .then((session) => {
          if (!current) return;
          if (
            !session?.authenticated ||
            session.contextMode !== 'PLATFORM' ||
            session.sessionId !== actor.sessionId ||
            session.principalId !== actor.principalId ||
            session.participantId !== actor.participantId ||
            session.contextEpoch !== actor.contextEpoch
          ) {
            scopeGeneration.current++;
            setSource(undefined);
            setReceipt(undefined);
            setDraft(undefined);
            setSignerView(undefined);
            setRootExpiryView(undefined);
            setDiscoveryView(undefined);
            setActor(undefined);
            setStatus('The recovery context changed. Sign in and read the original case again.');
          }
        });
    };
    window.addEventListener('focus', refresh);
    return () => {
      current = false;
      window.removeEventListener('focus', refresh);
    };
  }, [actor]);
  return (
    <section
      className="mt-6 space-y-4 rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
      aria-label="Platform recovery"
    >
      <h2 className="text-xl font-semibold">Platform recovery</h2>
      <p>
        Use the enrolled executor and two independent custodians for the recovery purpose shown by
        the authenticated source. Administrator handoff and envelope signer repair use separate
        bounded cases and authority.
      </p>
      <p>
        No provider, policy or RPC business action is granted by this ceremony. Virtual
        authenticator assurance is explicitly limited to local QA.
      </p>
      <label className="block">
        Recovery purpose
        <select
          className={field}
          value={purpose}
          disabled={busy}
          onChange={(event) => {
            changeScope();
            setPurpose(event.target.value as typeof purpose);
          }}
        >
          <option value="ADMINISTRATION">Administration, Root or signer recovery</option>
          <option value="DISCOVERY_CERTIFICATE_REPLACEMENT">
            Discovery certificate replacement
          </option>
        </select>
      </label>
      <div className="grid gap-4 sm:grid-cols-2">
        <label>
          Recovery enrollment ID
          <input
            className={field}
            value={enrollmentId}
            disabled={busy}
            onChange={(e) => {
              setEnrollmentId(e.target.value);
              changeScope();
            }}
          />
        </label>
        <label>
          Privacy domain ID
          <input
            className={field}
            value={privacyDomainId}
            disabled={busy}
            onChange={(e) => {
              setPrivacyDomainId(e.target.value);
              changeScope();
            }}
          />
        </label>
      </div>
      <div className="flex flex-wrap gap-3">
        <button
          className={button}
          disabled={busy || !enrollmentId || !privacyDomainId}
          onClick={() =>
            void run(async () => {
              const next = (await post({ kind: 'SOURCE' })) as
                | EnvelopeRecoveryView
                | RootExpiryRecoveryView
                | z.infer<typeof platformRecoverySourceView>;
              if (purpose === 'DISCOVERY_CERTIFICATE_REPLACEMENT') {
                setSource(undefined);
                setReceipt(undefined);
                setDraft(undefined);
                setSignerView(undefined);
                setRootExpiryView(undefined);
                setDiscoveryView(next as unknown as DiscoveryRecoveryView);
                setStatus('Exact enrolled discovery certificate source loaded.');
                return;
              }
              setReceipt(undefined);
              setDraft(undefined);
              if (
                'purpose' in next &&
                (next.purpose === 'LOCAL_ROOT_EXPIRY_RECOVERY_ONLY' ||
                  next.purpose === 'LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY' ||
                  next.purpose === 'LOCAL_ROOT_EXPIRY_PENDING_ANCESTRY_RECOVERY_ONLY')
              ) {
                setSource(undefined);
                setSignerView(undefined);
                setRootExpiryView(next as RootExpiryRecoveryView);
                setStatus('Expired local Root source loaded. Review its exact successor.');
                return;
              }
              if ('purpose' in next && next.purpose === 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY') {
                setSignerView(next as EnvelopeRecoveryView);
                setSource(undefined);
                setStatus(
                  'Signer recovery source loaded. Review its exact request before creating a case.',
                );
                return;
              }
              setSignerView(undefined);
              setRootExpiryView(undefined);
              setDiscoveryView(undefined);
              setSource(next as z.infer<typeof platformRecoverySourceView>);
              setStatus(
                'Current expired administration source loaded. Review the exact handoff before creating a case.',
              );
            })
          }
        >
          Read recovery source
        </button>
        <button
          className={button}
          disabled={busy || !source || !executor}
          onClick={() =>
            void run(async () => {
              if (!source || Date.now() >= Date.parse(source.proposalBefore))
                throw new Error('Read the recovery source again before creating this case.');
              const next = (await post({
                kind: 'CREATE',
                preparation: source.preparation,
              })) as z.infer<typeof platformRecoveryDraftView>;
              setDraft(next);
              setReceipt(undefined);
              storeCase(next.intent.recoveryId);
              setSource(undefined);
              setStatus(
                'Draft created without authority. The executor must provide the request proof.',
              );
            })
          }
        >
          Create reviewed recovery case
        </button>
      </div>
      {source ? (
        <div className="space-y-2">
          <p>
            Root epoch {source.source.rootEpoch}, revision {source.source.rootRevision}. Assurance:{' '}
            {source.assurance}.
          </p>
          <p className="break-all">
            Executor: {source.source.executorPrincipalId}. Custodians:{' '}
            {source.source.custodianPrincipalIds.join(', ')}.
          </p>
          {source.supersession ? (
            <p className="break-all">
              Fresh governed handoff supersedes expired preparation{' '}
              {source.supersession.replacementId}. Closed recovery source:{' '}
              {source.supersession.recoveryId}. Original evidence remains retained.
            </p>
          ) : null}
          {source.approvalContinuation ? (
            <p>
              Continue the original handoff with fresh independent custody and approval. Its
              original record IDs, permission bounds and administrator deadlines remain unchanged.
            </p>
          ) : source.pendingExpiry ? (
            <p>
              Create a new governed handoff for the two existing administrators with fresh
              independent custody. The expired handoff and its recorded effects remain preserved.
            </p>
          ) : null}
          {source.lifetimes ? (
            <p>
              {source.lifetimes.profile === 'LOCAL_QA' ? 'Local QA' : 'Normal'} custody limit:{' '}
              {source.lifetimes.leaseMs / 60000} minutes. New administrator scope limit:{' '}
              {source.lifetimes.administratorMs / 3600000} hours. Current source validity may
              shorten these limits.
            </p>
          ) : null}
          <details>
            <summary>Review the proposed handoff and permission bounds</summary>
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all">
              {JSON.stringify(source.preparation, null, 2)}
            </pre>
          </details>
        </div>
      ) : null}
      <label className="block">
        Recovery case ID
        <input
          className={field}
          value={recoveryId}
          disabled={busy}
          onChange={(e) => {
            scopeGeneration.current++;
            setRecoveryId(e.target.value);
            setReceipt(undefined);
            setDraft(undefined);
            setSignerView(undefined);
            setRootExpiryView(undefined);
            setDiscoveryView(undefined);
          }}
        />
      </label>
      <button className={button} disabled={busy || !recoveryId} onClick={() => void run(read)}>
        Read original recovery case
      </button>
      {discoveryView ? (
        <DiscoveryCertificateRecoveryWorkflow
          key={JSON.stringify([
            purpose,
            enrollmentId,
            privacyDomainId,
            actor?.sessionId,
            actor?.principalId,
            actor?.contextEpoch,
          ])}
          view={discoveryView}
          actor={actor}
          enrollmentId={enrollmentId}
          privacyDomainId={privacyDomainId}
          recoveryId={recoveryId}
          busy={busy}
          now={now}
          post={post}
          assertion={assertion}
          run={run}
          onView={setDiscoveryView}
          onCase={storeCase}
          onStatus={setStatus}
        />
      ) : null}
      {rootExpiryView ? (
        <LocalRootExpiryRecoveryWorkflow
          key={JSON.stringify([
            enrollmentId,
            privacyDomainId,
            actor?.sessionId,
            actor?.principalId,
            actor?.contextEpoch,
          ])}
          view={rootExpiryView}
          actor={actor}
          recoveryId={recoveryId}
          busy={busy}
          now={now}
          post={post}
          assertion={assertion}
          run={run}
          onView={setRootExpiryView}
          onCase={storeCase}
          onStatus={setStatus}
        />
      ) : null}
      {signerView ? (
        <IdentityEnvelopeRecoveryWorkflow
          key={JSON.stringify([
            enrollmentId,
            privacyDomainId,
            actor?.sessionId,
            actor?.principalId,
            actor?.participantId,
            actor?.contextEpoch,
          ])}
          view={signerView}
          actor={actor}
          enrollmentId={enrollmentId}
          privacyDomainId={privacyDomainId}
          recoveryId={recoveryId}
          busy={busy}
          now={now}
          post={post}
          assertion={assertion}
          run={run}
          onView={setSignerView}
          onCase={storeCase}
          onStatus={setStatus}
        />
      ) : null}
      {intent ? (
        <div className="space-y-3">
          <p>
            Case {receipt?.state ?? draft?.state}. Authority: {currentAuthority}. Assurance:{' '}
            {receipt?.assurance ?? draft?.assurance}.
          </p>
          <p>
            Lease deadline: {intent.validUntil}. Custodian approvals: {approvals.length}/2.
          </p>
          <p className="break-all">
            Reviewed intent: {receipt?.intentDigest ?? draft?.intentDigest}. Root handoff:{' '}
            {intent.preparation.replacementId}.
          </p>
          <details>
            <summary>Review the immutable recovery intent</summary>
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all">
              {JSON.stringify(intent, null, 2)}
            </pre>
          </details>
          <div className="flex flex-wrap gap-3">
            <button
              className={button}
              disabled={
                busy ||
                !live ||
                (!executor && !!receipt) ||
                (receipt?.state ?? draft?.state) !== 'DRAFT'
              }
              onClick={() => void run(() => prove('REQUEST'))}
            >
              Executor: verify request
            </button>
            <button
              className={button}
              disabled={
                busy ||
                !live ||
                !custodian ||
                receipt?.state !== 'REQUESTED' ||
                approvals.some((p) => p.principalId === actor?.principalId)
              }
              onClick={() => void run(() => prove('APPROVE'))}
            >
              Custodian: approve with authenticator
            </button>
            <button
              className={button}
              disabled={
                busy ||
                !live ||
                !executor ||
                receipt?.state !== 'REQUESTED' ||
                approvals.length !== 2
              }
              onClick={() => void run(() => prove('ACTIVATE'))}
            >
              Executor: activate handoff lease
            </button>
            <button
              className={button}
              disabled={
                busy ||
                (!executor && !custodian) ||
                !receipt ||
                ['COMPLETED', 'REVOKED', 'EXPIRED'].includes(receipt.state)
              }
              onClick={() =>
                void run(async () => {
                  const next = (await post({ kind: 'CLOSE', recoveryId })) as z.infer<
                    typeof platformRecoveryReceiptView
                  >;
                  setReceipt(next);
                  setStatus(`Case ${next.state}; current authority: ${next.authority}.`);
                })
              }
            >
              Close recovery case
            </button>
          </div>
          {receipt?.activation ? (
            <div className="space-y-2">
              <p>
                Activation operation: {receipt.activation.operationId}. The affected administrators
                must sign in again, then complete the normal governed handoff.
              </p>
              <a className="underline" href="/govern/participants?view=platform-ceiling">
                Continue governed Root handoff
              </a>
              <p>
                The original activation receipt remains readable after expiry or Root replacement.
                It does not renew authority.
              </p>
            </div>
          ) : null}
        </div>
      ) : null}
      <p role="status" aria-live="polite">
        {status}
      </p>
    </section>
  );
}
