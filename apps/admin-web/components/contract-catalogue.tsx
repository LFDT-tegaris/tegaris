'use client';

import { useEffect, useId, useRef, useState } from 'react';
import Link from 'next/link';
import { z } from 'zod';
import { SecondaryPanel } from './secondary-panel';
import { WorkspaceStatus } from './workspace-status';
import type { TransactionKind } from '../lib/transaction-workflow';
import {
  contractCataloguePage,
  type ContractCatalogueKind,
  type ContractCatalogueMethod,
  type ContractCataloguePage,
  type ContractCatalogueSelection,
} from '../lib/contract-catalogue';
import { inspectionActorKey } from '../lib/contract-method-inspection';
import type { PolicyWorkflowActorBinding } from './policy-workflow-storage';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';

const titles = {
  contracts: 'Contracts',
  bindings: 'Network bindings',
  methods: 'Methods',
  abis: 'ABI artifacts',
} as const;
const searchLabels = {
  contracts: 'Contract display name',
  bindings: 'Contract address',
  methods: 'Method signature',
  abis: 'ABI digest',
} as const;
const abiSourceLabels: Record<string, string> = {
  LOCAL_FIXTURE: 'Imported from a local file',
  SOURCE_REPOSITORY: 'Source repository',
  AUTHENTICATED_REGISTRY: 'Authenticated registry',
};
type Query = {
  kind: ContractCatalogueKind;
  search: string;
  parent?: { id: string };
  cursors: (string | undefined)[];
};
type Read = {
  key: string;
  status: 'loading' | 'loaded' | 'unavailable';
  page?: ContractCataloguePage;
  trace?: string;
  denied?: boolean;
};

export function ContractCatalogue({
  actor,
  authorityContextKey,
  initialKind = 'contracts',
  headingLevel = 3,
  onSelectMethod,
  onSelectResource,
  selectionKinds = ['contracts', 'bindings', 'abis'],
  selectionDisabled = false,
  refreshToken,
  onCreate,
  creationDisabled = false,
}: Readonly<{
  actor?: PolicyWorkflowActorBinding;
  authorityContextKey: string;
  initialKind?: ContractCatalogueKind;
  headingLevel?: 2 | 3;
  onSelectMethod?: (method: ContractCatalogueMethod) => void;
  onSelectResource?: (selection: ContractCatalogueSelection) => void;
  selectionKinds?: readonly ContractCatalogueKind[];
  selectionDisabled?: boolean;
  refreshToken?: string;
  onCreate?: (kind: TransactionKind) => void;
  creationDisabled?: boolean;
}>) {
  const LibraryHeading = headingLevel === 2 ? 'h2' : 'h3';
  const RecordHeading = headingLevel === 2 ? 'h3' : 'h4';
  const searchId = useId();
  const [query, setQuery] = useState<Query>({
    kind: initialKind,
    search: '',
    cursors: [undefined],
  });
  const [draftSearch, setDraftSearch] = useState('');
  const [revision, setRevision] = useState(0);
  const [paused, setPaused] = useState(false);
  const [read, setRead] = useState<Read>();
  const pending = useRef<AbortController | undefined>(undefined);
  const actorKey = actor ? inspectionActorKey(actor) : '';
  const contextKey = `${authorityContextKey}:${actorKey}`;
  const key = JSON.stringify([contextKey, query, revision, paused, refreshToken]);
  const activeKey = useRef(key);
  activeKey.current = key;
  const changing = paused || isSessionTransitionPending();
  const visible = read?.key === key && !changing && actor ? read : undefined;

  useEffect(() => {
    if (refreshToken === undefined) return;
    pending.current?.abort();
    setRead(undefined);
    setQuery((previous) =>
      previous.cursors.length === 1 && previous.cursors[0] === undefined
        ? previous
        : { ...previous, cursors: [undefined] },
    );
  }, [refreshToken]);

  useEffect(() => {
    pending.current?.abort();
    setRead(undefined);
    setDraftSearch('');
    setQuery((previous) =>
      previous.kind === initialKind &&
      previous.search === '' &&
      previous.parent === undefined &&
      previous.cursors.length === 1 &&
      previous.cursors[0] === undefined
        ? previous
        : { kind: initialKind, search: '', cursors: [undefined] },
    );
  }, [contextKey, initialKind]);

  useEffect(() => {
    const refresh = () => {
      pending.current?.abort();
      setRead(undefined);
      setDraftSearch('');
      setQuery((previous) => ({ ...previous, search: '', cursors: [undefined] }));
      setRevision((value) => value + 1);
    };
    const stop = observeSessionTransitions(
      () => {
        setPaused(true);
        refresh();
      },
      (pending) => {
        setPaused(pending);
        refresh();
      },
    );
    return () => {
      pending.current?.abort();
      stop();
    };
  }, []);

  useEffect(() => {
    pending.current?.abort();
    setRead(undefined);
    if (!actorKey || changing) return;
    const controller = new AbortController();
    pending.current = controller;
    const current = () => !controller.signal.aborted && activeKey.current === key;
    const params = new URLSearchParams({ kind: query.kind });
    if (query.search) params.set('search', query.search);
    if (query.parent) params.set('parentId', query.parent.id);
    const cursor = query.cursors.at(-1);
    if (cursor) params.set('cursor', cursor);
    setRead({ key, status: 'loading' });
    void (async () => {
      let trace: string | undefined;
      let denied = false;
      try {
        const response = await fetch(`/api/v1/ui/contract-catalogue?${params}`, {
          credentials: 'same-origin',
          cache: 'no-store',
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(20_000)]),
        });
        const diagnostic = response.headers.get('x-request-id');
        if (diagnostic && z.uuid().safeParse(diagnostic).success) trace = diagnostic;
        denied = response.status === 401 || response.status === 403 || response.status === 404;
        if (!response.ok) throw new Error('Catalogue read unavailable');
        const page = contractCataloguePage.parse(await response.json());
        if (page.kind !== query.kind || inspectionActorKey(page.actor) !== actorKey)
          throw new Error('Catalogue context changed');
        if (
          query.parent &&
          page.items.some((item) =>
            'logicalContractId' in item
              ? item.logicalContractId !== query.parent!.id
              : 'runtimeBindingId' in item
                ? item.runtimeBindingId !== query.parent!.id
                : true,
          )
        )
          throw new Error('Catalogue parent changed');
        if (current()) setRead({ key, status: 'loaded', page });
      } catch {
        if (current()) setRead({ key, status: 'unavailable', trace, denied });
      }
    })();
    return () => controller.abort();
  }, [key, actorKey, changing, query]);

  const page = visible?.page;
  const loading = visible?.status === 'loading';
  function navigate(kind: ContractCatalogueKind, parent?: Query['parent']) {
    pending.current?.abort();
    setRead(undefined);
    setDraftSearch('');
    setQuery({ kind, parent, search: '', cursors: [undefined] });
  }
  function renderRecordDetails(item: ContractCataloguePage['items'][number]) {
    return (
      <dl className="registry-record-details">
        {'logicalName' in item ? (
          <div>
            <dt className="text-[color:var(--muted)]">Logical name</dt>
            <dd className="break-all">{item.logicalName}</dd>
          </div>
        ) : null}
        {'chainId' in item ? (
          <>
            <div>
              <dt className="text-[color:var(--muted)]">Network / chain ID</dt>
              <dd className="break-all">
                {item.networkId} / {item.chainId}
              </dd>
            </div>
            <div>
              <dt className="text-[color:var(--muted)]">Binding state</dt>
              <dd>
                {item.state.charAt(0) + item.state.slice(1).toLowerCase().replaceAll('_', ' ')}
              </dd>
            </div>
          </>
        ) : null}
        {'selector' in item ? (
          <>
            <div>
              <dt className="text-[color:var(--muted)]">Action</dt>
              <dd>
                {item.effect === 'READ' ? 'Read data' : 'Change data'} ·{' '}
                {item.state === 'ACTIVE' ? 'registered' : item.state.toLowerCase()}
              </dd>
            </div>
            <div>
              <dt className="text-[color:var(--muted)]">Approval</dt>
              <dd>
                {
                  {
                    NONE: 'No approval required',
                    SINGLE: 'One approval required',
                    MAKER_CHECKER: 'Independent approval required',
                  }[item.approvalRequirement]
                }
              </dd>
            </div>
            <div>
              <dt className="text-[color:var(--muted)]">Authentication</dt>
              <dd>
                {item.mfaRequirement === 'WEBAUTHN'
                  ? 'Security key verification'
                  : 'No additional verification'}
              </dd>
            </div>
          </>
        ) : null}
        {'functions' in item ? (
          <>
            <div>
              <dt className="text-[color:var(--muted)]">Callable methods</dt>
              <dd>{item.functions}</dd>
            </div>
            <div>
              <dt className="text-[color:var(--muted)]">Source</dt>
              <dd>{abiSourceLabels[item.source] ?? item.source}</dd>
            </div>
            <div>
              <dt className="text-[color:var(--muted)]">Fingerprint</dt>
              <dd className="font-mono text-xs">{item.abiDigest.slice(7, 19)}…</dd>
            </div>
          </>
        ) : null}
      </dl>
    );
  }
  function renderRecordActions(
    item: ContractCataloguePage['items'][number],
    kind: ContractCatalogueKind,
  ) {
    return (
      <>
        <SecondaryPanel
          title={`Technical details for ${item.label}`}
          triggerLabel="Technical details"
        >
          <dl className="mt-2 grid min-w-0 gap-2">
            <div>
              <dt>Resource reference</dt>
              <dd className="break-all font-mono text-xs">{item.id}</dd>
            </div>
            <div>
              <dt>Revision</dt>
              <dd>{item.revision}</dd>
            </div>
            {'selector' in item ? (
              <div>
                <dt>Selector</dt>
                <dd className="font-mono">{item.selector}</dd>
              </div>
            ) : null}
            {'abiDigest' in item ? (
              <div>
                <dt>ABI digest</dt>
                <dd className="break-all font-mono text-xs">{item.abiDigest}</dd>
              </div>
            ) : null}
          </dl>
        </SecondaryPanel>
        {onSelectResource && selectionKinds.includes(kind) ? (
          <button
            type="button"
            className="catalogue-button mt-3"
            disabled={
              selectionDisabled || changing || ('chainId' in item && item.state !== 'BOUND')
            }
            onClick={() => {
              if (
                activeKey.current === key &&
                !isSessionTransitionPending() &&
                !selectionDisabled &&
                !('chainId' in item && item.state !== 'BOUND')
              )
                onSelectResource({
                  kind: kind,
                  item,
                } as ContractCatalogueSelection);
            }}
          >
            Use {item.label}
          </button>
        ) : null}
        {'logicalName' in item ? (
          <button
            type="button"
            className="catalogue-button mt-3"
            aria-label={`View bindings for ${item.label}`}
            onClick={() => navigate('bindings', { id: item.id })}
          >
            View bindings
          </button>
        ) : null}
        {'chainId' in item ? (
          <button
            type="button"
            className="catalogue-button mt-3"
            aria-label={`View methods for ${item.contractAddress}`}
            onClick={() =>
              navigate('methods', {
                id: item.id,
              })
            }
          >
            View methods
          </button>
        ) : null}
        {'selector' in item && onSelectMethod ? (
          <button
            type="button"
            className="catalogue-button mt-3"
            aria-label={`Select ${item.label}`}
            disabled={selectionDisabled || changing}
            onClick={() => {
              if (activeKey.current === key && !isSessionTransitionPending() && !selectionDisabled)
                onSelectMethod(item);
            }}
          >
            Use method
          </button>
        ) : null}
      </>
    );
  }
  return (
    <section
      aria-label="Contract catalogue"
      className="contract-catalogue min-w-0 rounded-xl border border-[color:var(--border)] bg-[color:var(--surface)] p-4 lg:col-span-2"
      aria-busy={loading}
    >
      <header className="registry-header">
        <div>
          <LibraryHeading className="text-lg font-semibold">Contract library</LibraryHeading>
          <p className="text-sm text-[color:var(--muted)]">
            Contract definitions, ABIs and network deployments.
          </p>
        </div>
        {onCreate ? (
          <div className="registry-actions">
            <button
              type="button"
              className="catalogue-button workflow-primary"
              disabled={!actor || changing || creationDisabled}
              onClick={() => onCreate('contract-asset')}
            >
              New contract
            </button>
            <button
              type="button"
              className="catalogue-button"
              disabled={!actor || changing || creationDisabled}
              onClick={() => onCreate('contract-abi')}
            >
              Import ABI
            </button>
            <button
              type="button"
              className="catalogue-button"
              disabled={!actor || changing || creationDisabled}
              onClick={() => onCreate('contract-binding')}
            >
              Bind contract
            </button>
            <button
              type="button"
              className="catalogue-button"
              disabled={!actor || changing || creationDisabled}
              onClick={() => onCreate('contract-method')}
            >
              Define method
            </button>
          </div>
        ) : null}
      </header>
      <p className="mt-1 text-sm text-[color:var(--muted)]">
        Select a category to inspect records available in your workspace.
      </p>
      <nav className="registry-categories" aria-label="Catalogue categories">
        {(Object.keys(titles) as ContractCatalogueKind[]).map((kind) => (
          <button
            type="button"
            key={kind}
            aria-pressed={query.kind === kind}
            className="catalogue-button"
            onClick={() => navigate(kind)}
          >
            {titles[kind]}
          </button>
        ))}
      </nav>
      {query.kind === 'methods' && (
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[color:var(--border)] p-3">
          <p className="text-sm text-[color:var(--muted)]">
            Activate an access policy and assign application access to use registered methods.
          </p>
          <Link className="catalogue-button" href="/configure/policies">
            Manage access policies
          </Link>
        </div>
      )}
      {query.parent ? (
        <div className="mt-4 min-w-0">
          <p className="text-sm">
            {query.kind === 'bindings'
              ? 'Bindings for the selected contract'
              : 'Methods for the selected binding'}
          </p>
          <button
            type="button"
            className="catalogue-button mt-2"
            onClick={() => navigate(query.kind)}
          >
            Show all {titles[query.kind].toLowerCase()}
          </button>
        </div>
      ) : (
        <div className="catalogue-search mt-4 flex min-w-0 flex-wrap items-end gap-2">
          <div className="grid min-w-0 flex-1 gap-1">
            <label className="text-sm font-medium" htmlFor={searchId}>
              {searchLabels[query.kind]} prefix
            </label>
            <input
              id={searchId}
              className="min-w-0 rounded-lg border border-[color:var(--border)] bg-[color:var(--canvas)] px-3 py-2"
              maxLength={160}
              value={draftSearch}
              onChange={(event) => setDraftSearch(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault();
                  setQuery((value) => ({
                    ...value,
                    search: draftSearch.trim(),
                    cursors: [undefined],
                  }));
                }
              }}
            />
            <p className="text-xs text-[color:var(--muted)]">
              Matches the beginning exactly, including letter case.
            </p>
          </div>
          <button
            type="button"
            className="catalogue-button"
            disabled={!actor || changing}
            onClick={() =>
              setQuery((value) => ({ ...value, search: draftSearch.trim(), cursors: [undefined] }))
            }
          >
            Search catalogue
          </button>
        </div>
      )}
      <div role="status" aria-live="polite" className="mt-4 text-sm">
        {!actor || changing ? (
          'Reload the authenticated Participant context to browse the catalogue.'
        ) : loading ? (
          'Loading catalogue…'
        ) : visible?.status === 'unavailable' ? (
          <WorkspaceStatus
            state={visible.denied ? 'DENIED' : 'UNAVAILABLE'}
            headingLevel={headingLevel === 2 ? 3 : 4}
            title={visible.denied ? 'Catalogue access unavailable' : 'Contract library unavailable'}
            detail={
              visible.denied
                ? 'Check your account and workspace access. A method you are permitted to use can still be inspected by its reference.'
                : 'Refresh the catalogue to try again. If the problem continues, contact your administrator.'
            }
          />
        ) : page ? (
          page.authorizedEmpty ? (
            page.total === '0' ? (
              'No matching resources in this authorized catalogue.'
            ) : (
              'This page has no remaining matching resources. Refresh to start again.'
            )
          ) : (
            `${page.items.length} ${page.items.length === 1 ? 'resource' : 'resources'} on this page · ${page.total} matching ${page.total === '1' ? 'result' : 'results'} when last refreshed.`
          )
        ) : (
          'Preparing catalogue read…'
        )}
      </div>
      {visible?.trace ? (
        <SecondaryPanel title="Request reference" className="mt-2">
          <p>Share this reference and the time of the issue with your administrator.</p>
          <dl className="mt-3 grid gap-1 text-sm">
            <dt>Request reference</dt>
            <dd className="break-all">{visible.trace}</dd>
          </dl>
        </SecondaryPanel>
      ) : null}
      {page ? (
        <ul
          className="catalogue-record-list"
          aria-label={`${titles[page.kind]} in the current workspace`}
        >
          {page.items.map((item) => (
            <li className="catalogue-record-card" key={item.id}>
              <header>
                <RecordHeading
                  className={`catalogue-record-title${page.kind === 'methods' ? ' font-mono' : ''}`}
                >
                  {item.label}
                </RecordHeading>
                <p className="registry-revision">Revision {item.revision}</p>
              </header>
              {renderRecordDetails(item)}
              <div className="catalogue-record-actions">{renderRecordActions(item, page.kind)}</div>
            </li>
          ))}
        </ul>
      ) : null}
      <div className="mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          className="catalogue-button"
          disabled={!actor || changing || loading}
          onClick={() => {
            pending.current?.abort();
            setRead(undefined);
            setQuery((value) => ({ ...value, cursors: [undefined] }));
            setRevision((value) => value + 1);
          }}
        >
          Refresh catalogue
        </button>
        <button
          type="button"
          className="catalogue-button"
          disabled={!page || loading || query.cursors.length < 2}
          onClick={() => setQuery((value) => ({ ...value, cursors: value.cursors.slice(0, -1) }))}
        >
          Previous page
        </button>
        <button
          type="button"
          className="catalogue-button"
          disabled={!page?.nextCursor || loading}
          onClick={() => {
            if (page?.nextCursor)
              setQuery((value) => ({ ...value, cursors: [...value.cursors, page.nextCursor!] }));
          }}
        >
          Next page
        </button>
      </div>
    </section>
  );
}
