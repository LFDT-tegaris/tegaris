'use client';
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import type { ProtectedConsumption } from '../app/api/v1/ui/protected-proof-workbench';
import {
  protectedAccessSelectionSchema,
  protectedObjectSelectionSchema,
  protectedProofTime,
  type ProtectedAccessSelection,
  type ProtectedObjectSelection,
} from '../lib/protected-proof-catalogue';
import { ProtectedProofCatalogue, type ProtectedProofBinding } from './protected-proof-catalogue';
import { WorkflowDetails } from './workflow-details';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';
const endpoint = '/api/v1/ui/protected-proof-workbench';
const button = 'rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-50';
const resource =
  /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
async function response<T>(r: Response): Promise<T> {
  const body = await r.json().catch(() => undefined);
  if (!r.ok)
    throw new Error(
      `${body?.title ?? 'Protected proof unavailable.'}${body?.code ? ` (${body.code})` : ''}`,
    );
  return body;
}
export function ProtectedProofWorkflow({
  guided = false,
  active = true,
  binding,
  onPrepareAccess,
}: {
  guided?: boolean;
  active?: boolean;
  binding?: ProtectedProofBinding;
  onPrepareAccess?(objectRef: string): void;
}) {
  const field = useId(),
    generation = useRef(0),
    pending = useRef<AbortController | undefined>(undefined),
    changing = useRef(false),
    detailHeading = useRef<HTMLHeadingElement>(null),
    focusDetail = useRef(false);
  const [reference, setReference] = useState(''),
    [selection, setSelection] = useState<ProtectedAccessSelection>(),
    [object, setObject] = useState<ProtectedObjectSelection>();
  const [status, setStatus] = useState(''),
    [busy, setBusy] = useState(false),
    [hydrated, setHydrated] = useState(false),
    [refreshToken, setRefreshToken] = useState(0),
    [contextChanging, setContextChanging] = useState(false);
  const clear = useCallback((forgetReference = false) => {
    generation.current++;
    pending.current?.abort();
    focusDetail.current = false;
    setSelection(undefined);
    setObject(undefined);
    setBusy(false);
    setStatus('');
    if (forgetReference) setReference('');
  }, []);
  useEffect(() => {
    setHydrated(true);
    clear(true);
    changing.current = isSessionTransitionPending();
    setContextChanging(changing.current);
    const stop = observeSessionTransitions(
      () => {
        changing.current = true;
        setContextChanging(true);
        clear(true);
      },
      (blocked) => {
        changing.current = blocked;
        setContextChanging(blocked);
        clear(true);
      },
    );
    const blur = () => clear(true),
      hidden = () => {
        if (document.visibilityState !== 'visible') clear(true);
      };
    window.addEventListener('blur', blur);
    document.addEventListener('visibilitychange', hidden);
    return () => {
      generation.current++;
      pending.current?.abort();
      stop();
      window.removeEventListener('blur', blur);
      document.removeEventListener('visibilitychange', hidden);
    };
  }, [clear, active, binding?.actorKey]);
  const usable =
    hydrated && active && !contextChanging && !changing.current && (!guided || !!binding);
  const bound = <
    T extends { actorKey: string; actor: { participantId: string; privacyDomainId: string } },
  >(
    value: T,
  ) =>
    !binding ||
    (value.actorKey === binding.actorKey &&
      value.actor.participantId === binding.actor.participantId &&
      value.actor.privacyDomainId === binding.actor.privacyDomainId);
  const selectedAccess = selection && bound(selection) && usable ? selection : undefined;
  const selectedObject = object && bound(object) && usable ? object : undefined;
  useLayoutEffect(() => {
    if (!busy && focusDetail.current && (selectedAccess || selectedObject)) {
      focusDetail.current = false;
      detailHeading.current?.focus();
    }
  }, [busy, selectedAccess, selectedObject]);
  async function read(ref = reference) {
    if (!usable || changing.current || isSessionTransitionPending() || busy) return;
    clear();
    const current = generation.current,
      controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    setReference(ref);
    try {
      if (!resource.test(ref)) throw new Error('Enter the approved protected access reference.');
      const value = await response<unknown>(
        await fetch(`${endpoint}?${new URLSearchParams({ accessId: ref.slice(-36) })}`, {
          cache: 'no-store',
          credentials: 'same-origin',
          signal: controller.signal,
        }),
      );
      if (current !== generation.current || controller.signal.aborted) return;
      const parsed = protectedAccessSelectionSchema.safeParse(value);
      if (!parsed.success) throw new Error('Protected access could not be confirmed.');
      const next = parsed.data;
      if (
        !bound(next) ||
        next.access.accessRef !== ref ||
        next.access.participantId !== `urn:openpc:participant:${next.actor.participantId}` ||
        next.access.privacyDomainId !== next.actor.privacyDomainId
      )
        throw new Error('The workspace changed. Refresh evidence.');
      focusDetail.current = guided;
      setSelection(next);
      setStatus(
        next.access.state === 'CONSUMED'
          ? 'Delivery was consumed. Raw proof bytes are not replayed.'
          : next.access.state === 'EXPIRED'
            ? 'This access has expired. A new disclosure requires separate approval.'
            : 'Review the approved purpose. Delivery checks the original session and current source availability.',
      );
    } catch (error) {
      if (current === generation.current && !controller.signal.aborted)
        setStatus(error instanceof Error ? error.message : 'Protected access unavailable.');
    } finally {
      if (current === generation.current) setBusy(false);
    }
  }
  async function readObject(ref: string) {
    if (!usable || changing.current || isSessionTransitionPending() || busy) return;
    clear(true);
    const current = generation.current,
      controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    try {
      const value = await response<unknown>(
        await fetch(`${endpoint}?${new URLSearchParams({ objectId: ref.slice(-36) })}`, {
          cache: 'no-store',
          credentials: 'same-origin',
          signal: controller.signal,
        }),
      );
      if (current !== generation.current || controller.signal.aborted) return;
      const parsed = protectedObjectSelectionSchema.safeParse(value);
      if (!parsed.success || !bound(parsed.data) || parsed.data.object.objectRef !== ref)
        throw new Error('The proof record could not be confirmed in this workspace.');
      focusDetail.current = true;
      setObject(parsed.data);
      setStatus('Proof record loaded. Access requires its own purpose and independent approval.');
    } catch (error) {
      if (current === generation.current && !controller.signal.aborted)
        setStatus(error instanceof Error ? error.message : 'Protected proof unavailable.');
    } finally {
      if (current === generation.current) setBusy(false);
    }
  }
  async function consume() {
    if (
      !selectedAccess ||
      changing.current ||
      isSessionTransitionPending() ||
      busy ||
      selectedAccess.access.state !== 'AVAILABLE' ||
      selectedAccess.access.recipientPrincipalId !== selectedAccess.actor.principalId
    )
      return;
    const current = ++generation.current,
      controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    try {
      const result = await response<ProtectedConsumption | { truthState: 'UNKNOWN' }>(
        await fetch(endpoint, {
          method: 'POST',
          cache: 'no-store',
          credentials: 'same-origin',
          signal: controller.signal,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            actorKey: selectedAccess.actorKey,
            accessId: selectedAccess.access.accessRef.slice(-36),
            accessDigest: selectedAccess.accessDigest,
            requestKey: crypto.randomUUID(),
          }),
        }),
      );
      if (current !== generation.current || controller.signal.aborted) return;
      setSelection(undefined);
      setRefreshToken((value) => value + 1);
      if ('truthState' in result) {
        setStatus(
          'Delivery outcome is unknown. Read the same access to reconcile it before any further action.',
        );
        return;
      }
      if (!result.disclosure) {
        setStatus('This delivery was already consumed. Raw proof bytes are not replayed.');
        return;
      }
      const objectUrl = URL.createObjectURL(
        new Blob([JSON.stringify(result.disclosure, null, 2)], { type: 'application/json' }),
      );
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = `protected-proof-${selectedAccess.access.accessRef.slice(-36)}.json`;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      setStatus('Delivery consumed and download started. Read the same access for durable status.');
    } catch (error) {
      if (current === generation.current && !controller.signal.aborted) {
        setSelection(undefined);
        setStatus(
          `${error instanceof Error ? error.message : 'Delivery unavailable.'} Read the same access to reconcile its state.`,
        );
      }
    } finally {
      if (current === generation.current) setBusy(false);
    }
  }
  return (
    <section className="space-y-4" aria-label="Protected proof delivery">
      {!guided ? (
        <>
          <h2 className="text-lg font-semibold">Protected proof delivery</h2>
          <p className="text-sm">
            Delivery requires independently approved access and is bound to its original actor and
            session. It can be consumed once.
          </p>
        </>
      ) : null}
      <p role="status" aria-live="polite" className="break-words text-sm">
        {status}
      </p>
      <div className={guided ? 'proof-workspace' : undefined}>
        {guided && binding ? (
          <ProtectedProofCatalogue
            binding={binding}
            enabled={usable}
            disabled={busy}
            refreshToken={refreshToken}
            selectedRef={selectedAccess?.access.accessRef ?? selectedObject?.object.objectRef}
            onSelect={(kind, ref) => {
              if (kind === 'objects') void readObject(ref);
              else void read(ref);
            }}
          />
        ) : null}
        {guided ? (
          <section className="proof-workspace-detail" aria-label="Selected protected proof record">
            <h2 ref={detailHeading} tabIndex={-1} className="text-xl font-semibold">
              {selectedObject
                ? 'Selected proof'
                : selectedAccess
                  ? 'Selected access'
                  : 'Proof details'}
            </h2>
            {selectedObject ? (
              <>
                <h3>{selectedObject.object.purpose}</h3>
                <p>Case {selectedObject.object.caseReference}</p>
                <p>Retention until {protectedProofTime(selectedObject.object.retainUntil)}</p>
                <p>
                  This is historical authentication evidence. It does not grant current authority.
                </p>
                <WorkflowDetails enabled summary="Proof record reference">
                  <p className="break-all">{selectedObject.object.objectRef}</p>
                  <p>Version {selectedObject.object.objectVersion}</p>
                </WorkflowDetails>
                {onPrepareAccess ? (
                  <button
                    className={button}
                    disabled={
                      busy || !usable || Date.parse(selectedObject.object.retainUntil) <= Date.now()
                    }
                    onClick={() => onPrepareAccess(selectedObject.object.objectRef)}
                  >
                    Prepare access request
                  </button>
                ) : null}
                {Date.parse(selectedObject.object.retainUntil) <= Date.now() ? (
                  <p>
                    The retention period has ended. Current proof availability requires owner
                    verification.
                  </p>
                ) : null}
              </>
            ) : selectedAccess ? (
              <>
                <h3>{selectedAccess.access.purpose}</h3>
                <p>Case {selectedAccess.access.caseReference}</p>
                <p>
                  {selectedAccess.access.state === 'CONSUMED'
                    ? 'Delivery consumed'
                    : selectedAccess.access.state === 'EXPIRED'
                      ? 'Access expired'
                      : 'Access recorded'}
                </p>
                <p>Expires {protectedProofTime(selectedAccess.access.expiresAt)}</p>
                <WorkflowDetails enabled summary="Access and operation references">
                  <p className="break-all">{selectedAccess.access.accessRef}</p>
                  <p className="break-all">
                    Object {selectedAccess.access.object.objectRef} · Version{' '}
                    {selectedAccess.access.object.objectVersion}
                  </p>
                  <p className="break-all">
                    Recipient {selectedAccess.access.recipientPrincipalId}
                  </p>
                  {selectedAccess.access.consumptionOperationId ? (
                    <p className="break-all">
                      Consumption operation {selectedAccess.access.consumptionOperationId}
                    </p>
                  ) : null}
                </WorkflowDetails>
                {selectedAccess.access.state === 'AVAILABLE' &&
                selectedAccess.access.recipientPrincipalId === selectedAccess.actor.principalId ? (
                  <button
                    className={button}
                    disabled={busy || !usable}
                    onClick={() => void consume()}
                  >
                    Consume once and download proof
                  </button>
                ) : null}
                {selectedAccess.access.recipientPrincipalId !== selectedAccess.actor.principalId ? (
                  <p>This access belongs to another approved recipient.</p>
                ) : null}
                <button
                  className={button}
                  disabled={busy || !usable}
                  onClick={() => void read(selectedAccess.access.accessRef)}
                >
                  Read current delivery status
                </button>
              </>
            ) : (
              <p className="text-sm text-[color:var(--muted)]">
                Choose a proof record or approved access to review its purpose and current state.
              </p>
            )}
          </section>
        ) : null}
      </div>
      {guided && reference && !selectedAccess ? (
        <button className={button} disabled={busy || !usable} onClick={() => void read(reference)}>
          Reconcile this access
        </button>
      ) : null}
      <WorkflowDetails enabled={guided} summary="Find approved access by reference">
        <div className="space-y-3 rounded border border-[color:var(--border)] p-4">
          <label className="block" htmlFor={field}>
            Protected access reference
          </label>
          <input
            id={field}
            className="w-full rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-2"
            disabled={busy || !usable}
            value={reference}
            onChange={(event) => {
              clear();
              setReference(event.target.value);
            }}
          />
          <button className={button} disabled={busy || !usable} onClick={() => void read()}>
            Read protected access
          </button>
        </div>
      </WorkflowDetails>
      {!guided && selectedAccess ? (
        <div className="space-y-2 break-words text-sm">
          <p>State: {selectedAccess.access.state}</p>
          <p>Purpose: {selectedAccess.access.purpose}</p>
          <p>Case: {selectedAccess.access.caseReference}</p>
          <p className="break-all">
            Object: {selectedAccess.access.object.objectRef} · Version{' '}
            {selectedAccess.access.object.objectVersion}
          </p>
          <p className="break-all">Recipient: {selectedAccess.access.recipientPrincipalId}</p>
          <p>Expires: {selectedAccess.access.expiresAt}</p>
          {selectedAccess.access.consumptionOperationId ? (
            <p className="break-all">
              Consumption operation: {selectedAccess.access.consumptionOperationId}
            </p>
          ) : null}
          <button
            className={button}
            disabled={
              busy ||
              !usable ||
              selectedAccess.access.state !== 'AVAILABLE' ||
              selectedAccess.access.recipientPrincipalId !== selectedAccess.actor.principalId
            }
            onClick={() => void consume()}
          >
            Consume once and download proof
          </button>
        </div>
      ) : null}
    </section>
  );
}
