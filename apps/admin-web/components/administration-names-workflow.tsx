'use client';
import { useEffect, useId, useRef, useState } from 'react';
import type { AdministrationReservation } from '../../../services/module-registry/src/administration-resource-reservation-contract';
import { SecondaryPanel } from './secondary-panel';

const endpoint = '/api/v1/ui/administration-names';
const field = 'w-full rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button = 'rounded bg-[color:var(--accent)] px-3 py-2 text-white disabled:opacity-60';
async function json<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => undefined);
  if (!response.ok)
    throw new Error(
      `${body?.title ?? 'Name reservation unavailable.'} (${body?.code ?? 'PC-INTEGRATION-5001'})`,
    );
  return body as T;
}
export function AdministrationNamesWorkflow() {
  const renewalHelpId = useId();
  const [items, setItems] = useState<AdministrationReservation[]>([]);
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState('Choose the action and resource, then reserve a reference.');
  const retry = useRef<{ identity: string; requestKey: string } | undefined>(undefined);
  useEffect(() => {
    let current = true;
    void fetch(endpoint, { cache: 'no-store', credentials: 'same-origin' })
      .then(
        json<{
          actor: {
            participantId: string;
            privacyDomainId: string;
            principalId: string;
          };
        }>,
      )
      .then(async (result) => {
        const storage = `openpc:administration-names:v1:${result.actor.participantId}:${result.actor.privacyDomainId}:${result.actor.principalId}`;
        const raw = localStorage.getItem(storage);
        const selectors: unknown = raw ? JSON.parse(raw) : [];
        if (
          !Array.isArray(selectors) ||
          selectors.length > 64 ||
          selectors.some((id) => typeof id !== 'string')
        )
          throw new Error('Stored name selectors are invalid.');
        const restored = [];
        let unavailable = 0;
        for (const operationId of selectors) {
          const response = await fetch(`${endpoint}?${new URLSearchParams({ operationId })}`, {
            cache: 'no-store',
            credentials: 'same-origin',
          });
          // A saved selector is not authority. The owner hides expired or
          // unavailable names with 404; fresh creation still authorizes anew.
          if (response.status === 404) {
            unavailable += 1;
            continue;
          }
          const state = await json<{ reservation: AdministrationReservation }>(response);
          restored.push(state.reservation);
        }
        if (current) {
          setKey(storage);
          setItems(restored);
          if (unavailable)
            setStatus(
              `${unavailable} saved names are no longer available. Reserve fresh names for new intent.`,
            );
        }
      })
      .catch((error: unknown) => {
        if (current)
          setStatus(error instanceof Error ? error.message : 'Name readback unavailable.');
      });
    return () => {
      current = false;
    };
  }, []);
  return (
    <section
      className="rounded border border-[color:var(--border)] p-4"
      aria-label="Approval and activation reference reservations"
    >
      <h2 className="text-lg font-semibold">Reserve a workflow reference</h2>
      <p className="mt-2">
        Reserve an approval or activation reference before assigning access to that resource. The
        reservation grants no permission. Creating the operation still requires current authority,
        and the reservation expires within the issuing authority and session limits.
      </p>
      <form
        className="mt-4 grid gap-3 md:grid-cols-2"
        onSubmit={(event) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          setBusy(true);
          const input = {
            command: 'RESERVE',
            predecessorOperationId: String(data.get('predecessorOperationId') ?? '') || undefined,
            purpose: data.get('purpose'),
            businessActionIntentId: data.get('businessActionIntentId'),
            businessResourceId: data.get('businessResourceId'),
            expectedBusinessRevision: data.get('expectedBusinessRevision'),
            checkerPrincipalId: String(data.get('checkerPrincipalId') ?? '') || null,
          };
          const identity = JSON.stringify(input);
          if (retry.current?.identity !== identity)
            retry.current = { identity, requestKey: crypto.randomUUID() };
          const selected = { ...input, requestKey: retry.current.requestKey };
          void fetch(endpoint, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(selected),
          })
            .then(json<{ reservation: AdministrationReservation }>)
            .then((result) => {
              const next = [
                ...items.filter((item) => item.operationId !== result.reservation.operationId),
                result.reservation,
              ];
              setItems(next);
              if (key)
                localStorage.setItem(key, JSON.stringify(next.map((item) => item.operationId)));
              retry.current = undefined;
              setStatus(
                'Name reserved and read back. Include its resource ID in the explicit grants, then use its operation ID at business creation.',
              );
            })
            .catch((error: unknown) =>
              setStatus(
                error instanceof Error ? error.message : 'Read name state before retrying.',
              ),
            )
            .finally(() => setBusy(false));
        }}
      >
        <label>
          Reference purpose
          <select className={field} name="purpose">
            <option value="APPROVAL_REQUEST">Approval request</option>
            <option value="POLICY_ACTIVATION_OCCURRENCE">Policy activation</option>
          </select>
        </label>
        <label>
          Exact business action ID
          <input className={field} name="businessActionIntentId" required />
        </label>
        <label>
          Exact business resource ID
          <input className={field} name="businessResourceId" required />
        </label>
        <label>
          Expected business revision
          <input
            className={field}
            name="expectedBusinessRevision"
            required
            pattern="(?:0|[1-9][0-9]*)"
          />
        </label>
        <label>
          Distinct checker principal ID
          <input className={field} name="checkerPrincipalId" />
        </label>
        <SecondaryPanel title="Renew an unused reservation" className="md:col-span-2">
          <div className="mt-3 grid gap-2">
            <label>
              Previous reservation operation ID (optional)
              <input
                className={field}
                name="predecessorOperationId"
                aria-describedby={renewalHelpId}
              />
            </label>
            <p id={renewalHelpId} className="text-sm text-[color:var(--muted)]">
              Use this only for an expired, unused reservation with unchanged business inputs.
              Renewal keeps the original reference and requires current authority. A consumed
              reservation cannot be renewed.
            </p>
          </div>
        </SecondaryPanel>
        <button type="submit" className={button} disabled={busy || !key || items.length >= 64}>
          Reserve reference
        </button>
      </form>
      {items.map((item) => (
        <article className="contract-record-summary mt-4" key={item.operationId}>
          <h3>{item.purpose === 'APPROVAL_REQUEST' ? 'Approval request' : 'Policy activation'}</h3>
          <dl>
            <div>
              <dt>Business action</dt>
              <dd>{item.businessActionIntentId}</dd>
            </div>
            <div>
              <dt>Business resource</dt>
              <dd>{item.businessResourceId}</dd>
            </div>
            <div>
              <dt>Expected revision</dt>
              <dd>{item.expectedBusinessRevision}</dd>
            </div>
            <div>
              <dt>Reserved resource for access grants</dt>
              <dd>{item.reservedResourceId}</dd>
            </div>
            <div>
              <dt>Operation reference for creation</dt>
              <dd>{item.operationId}</dd>
            </div>
            <div>
              <dt>Valid until</dt>
              <dd>
                <time dateTime={item.validUntil}>{item.validUntil}</time>
              </dd>
            </div>
          </dl>
          <p>
            This reservation grants no access. Creating the operation requires current authority.
          </p>
        </article>
      ))}
      <p className="mt-3" role="status" aria-live="polite">
        {status}
      </p>
    </section>
  );
}
