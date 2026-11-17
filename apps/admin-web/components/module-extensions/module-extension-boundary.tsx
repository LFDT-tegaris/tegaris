'use client';

import { useQueryClient } from '@tanstack/react-query';
import {
  createContext,
  useCallback,
  useContext,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import {
  moduleExtensionEndpoint,
  moduleExtensionEvent,
  moduleExtensionEventName,
  moduleExtensionObservationOf,
  sameModuleExtensionObservation,
  moduleExtensionOriginalOperation,
  moduleExtensionQueryString,
  moduleExtensionSnapshot,
  sameModuleExtensionQuery,
  type ModuleExtensionSnapshot,
  type ModuleExtensionOriginalOperation,
} from '../../lib/module-extensions';

export interface ModuleExtensionRequest {
  readonly signal: AbortSignal;
  /** Check immediately before applying a response to component/cache state. */
  current(): boolean;
  cancel(): void;
  finish(): void;
  /** Retain original identity even if its response arrives after teardown.
   * This neither retries nor reports business cancellation/success. */
  retainOperation(value: ModuleExtensionOriginalOperation): void;
}
export interface ModuleExtensionLifetime {
  readonly snapshot: ModuleExtensionSnapshot;
  readonly queryKey: readonly string[];
  beginRequest(): ModuleExtensionRequest;
  registerCleanup(cleanup: () => void): () => void;
  reportCleanupFailure(): void;
  originalOperations(): readonly ModuleExtensionOriginalOperation[];
}
const Context = createContext<ModuleExtensionLifetime | undefined>(undefined);
export function useModuleExtensionLifetime(): ModuleExtensionLifetime {
  const value = useContext(Context);
  if (!value) throw new Error('Module extension is outside its current protected lifetime');
  return value;
}

interface Live {
  readonly sequence: number;
  readonly snapshot: ModuleExtensionSnapshot;
  readonly controllers: Set<AbortController>;
  readonly cleanups: Set<() => void>;
  valid: boolean;
}
/** Mount around extension-owned content, never around sealed safety/session UI.
 * Canonical context/session transitions must change contextKey synchronously.
 * Observations are invalidation signals, never authorization or a disable ACK. */
export function ModuleExtensionBoundary({
  routeId,
  objectRef,
  contextKey,
  safety,
  children,
}: {
  readonly routeId: string;
  readonly objectRef?: string;
  readonly contextKey: string;
  readonly safety?: ReactNode;
  readonly children: ReactNode;
}) {
  const client = useQueryClient();
  const sequence = useRef(0);
  const live = useRef<Live | undefined>(undefined);
  const pending = useRef<AbortController | undefined>(undefined);
  const source = useRef<EventSource | undefined>(undefined);
  const heartbeat = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const cleanupFailed = useRef(false);
  // Minimal correlation only; protected drafts/results remain inside the keyed subtree.
  // Durable operation recovery still belongs to the original API/Workbench owner.
  const originals = useRef(new Map<string, Map<string, ModuleExtensionOriginalOperation>>());
  const [ready, setReady] = useState<{ identity: string; lifetime: ModuleExtensionLifetime }>();
  const [status, setStatus] = useState('Loading module contributions.');
  const [refresh, setRefresh] = useState(0);
  const identity = JSON.stringify([contextKey, routeId, objectRef ?? null]);

  const clear = useCallback((): void => {
    sequence.current += 1;
    pending.current?.abort();
    pending.current = undefined;
    source.current?.close();
    source.current = undefined;
    if (heartbeat.current) clearTimeout(heartbeat.current);
    heartbeat.current = undefined;
    const previous = live.current;
    live.current = undefined;
    if (previous) {
      previous.valid = false;
      for (const controller of previous.controllers) controller.abort();
      previous.controllers.clear();
      for (const cleanup of previous.cleanups) {
        try {
          cleanup();
        } catch {
          cleanupFailed.current = true;
        }
      }
      previous.cleanups.clear();
      const queryKey = [
        'module-extensions',
        previous.snapshot.binding.actorKey,
        previous.snapshot.binding.observationKey,
      ];
      void client.cancelQueries({ queryKey }).catch(() => {
        cleanupFailed.current = true;
        clear();
        setStatus('Module cleanup could not be confirmed. Reload the Workbench.');
      });
      try {
        client.removeQueries({ queryKey });
      } catch {
        cleanupFailed.current = true;
      }
    }
    setReady(undefined);
  }, [client]);

  useLayoutEffect(() => {
    clear();
    if (cleanupFailed.current) {
      setStatus('Module cleanup could not be confirmed. Reload the Workbench.');
      return;
    }
    const turn = sequence.current;
    const query = { routeId, ...(objectRef ? { objectRef } : {}) };
    const controller = new AbortController();
    pending.current = controller;
    let disposed = false;
    const fail = () => {
      if (disposed || turn !== sequence.current) return;
      clear();
      setStatus(
        cleanupFailed.current
          ? 'Module cleanup could not be confirmed. Reload the Workbench.'
          : 'Module contributions are unavailable. Refresh to reauthorize.',
      );
    };
    setStatus('Loading module contributions.');
    void (async () => {
      const parameters = moduleExtensionQueryString(query);
      const response = await fetch(`${moduleExtensionEndpoint}?${parameters}`, {
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15_000)]),
      });
      if (
        !response.ok ||
        response.headers.get('cache-control') !== 'no-store' ||
        response.headers.get('content-type')?.split(';')[0] !== 'application/json'
      )
        throw new Error('Unavailable');
      const snapshot = moduleExtensionSnapshot.parse(await response.json());
      if (!sameModuleExtensionQuery(snapshot.query, query)) throw new Error('Wrong query');
      if (disposed || controller.signal.aborted || turn !== sequence.current) return;
      pending.current = undefined;
      const current: Live = {
        sequence: turn,
        snapshot,
        controllers: new Set(),
        cleanups: new Set(),
        valid: true,
      };
      live.current = current;
      const isCurrent = () =>
        !disposed && current.valid && live.current === current && sequence.current === turn;
      const lifetime: ModuleExtensionLifetime = {
        snapshot,
        queryKey: ['module-extensions', snapshot.binding.actorKey, snapshot.binding.observationKey],
        beginRequest() {
          if (!isCurrent()) throw new Error('Module contribution is stale');
          const abort = new AbortController();
          current.controllers.add(abort);
          return {
            signal: abort.signal,
            current: () => isCurrent() && !abort.signal.aborted,
            cancel: () => {
              abort.abort();
              current.controllers.delete(abort);
            },
            finish: () => {
              current.controllers.delete(abort);
            },
            retainOperation(value) {
              const operation = moduleExtensionOriginalOperation.parse(value);
              const key = snapshot.binding.actorKey;
              const retained =
                originals.current.get(key) ?? new Map<string, ModuleExtensionOriginalOperation>();
              const old = retained.get(operation.requestId);
              if (
                old?.operationId &&
                operation.operationId &&
                old.operationId !== operation.operationId
              )
                throw new Error('Original module operation identity changed');
              retained.set(operation.requestId, { ...old, ...operation });
              originals.current.set(key, retained);
            },
          };
        },
        registerCleanup(cleanup) {
          if (!isCurrent()) {
            try {
              cleanup();
            } catch {
              lifetime.reportCleanupFailure();
            }
            return () => {};
          }
          current.cleanups.add(cleanup);
          return () => {
            current.cleanups.delete(cleanup);
          };
        },
        reportCleanupFailure() {
          cleanupFailed.current = true;
          clear();
          setStatus('Module cleanup could not be confirmed. Reload the Workbench.');
        },
        originalOperations: () =>
          isCurrent()
            ? [...(originals.current.get(snapshot.binding.actorKey)?.values() ?? [])]
            : [],
      };
      const armDeadline = () => {
        if (heartbeat.current) clearTimeout(heartbeat.current);
        heartbeat.current = setTimeout(fail, 10_000);
      };
      // Do not display protected content until the separate live observation
      // agrees with the fetched snapshot. Named events are handled explicitly.
      const connect = (): void => {
        if (!isCurrent()) return;
        const stream = new EventSource(`${moduleExtensionEndpoint}/events?${parameters}`, {
          withCredentials: true,
        });
        source.current = stream;
        armDeadline();
        stream.addEventListener(moduleExtensionEventName, (event) => {
          if (!isCurrent() || source.current !== stream) return;
          try {
            const message = moduleExtensionEvent.parse(
              JSON.parse((event as MessageEvent<string>).data),
            );
            if (
              message.type === 'INVALIDATED' ||
              !sameModuleExtensionObservation(message, moduleExtensionObservationOf(snapshot))
            )
              return fail();
            if (message.type === 'REOBSERVE') {
              // Expected transport rotation only; each new stream independently
              // reauthenticates and reads the owner. Never replay a business write.
              stream.close();
              source.current = undefined;
              connect();
              return;
            }
            armDeadline();
            setReady({ identity, lifetime });
            setStatus('');
          } catch {
            fail();
          }
        });
        stream.onerror = () => {
          if (source.current === stream) fail();
        };
      };
      connect();
    })().catch(fail);
    return () => {
      disposed = true;
      clear();
    };
  }, [clear, contextKey, identity, objectRef, refresh, routeId]);

  const display = ready?.identity === identity ? ready : undefined;
  return (
    <>
      {safety}
      {display ? (
        <Context.Provider
          key={`${identity}:${display.lifetime.snapshot.binding.observationKey}`}
          value={display.lifetime}
        >
          {children}
        </Context.Provider>
      ) : (
        <div role="status">
          <p>{status || 'Module contributions require reauthorization.'}</p>
          <button
            type="button"
            disabled={cleanupFailed.current}
            onClick={() => {
              clear();
              setRefresh((value) => value + 1);
            }}
          >
            Refresh module contributions
          </button>
        </div>
      )}
    </>
  );
}

/** Per-contribution lifetime ensures a render failure unmounts/cancels only its
 * own work, while the outer boundary still tears down the entire old context.
 * Start asynchronous contribution work in passive effects or event handlers. */
export function ModuleContributionBoundary({
  contributionId,
  children,
}: {
  readonly contributionId: string;
  readonly children: ReactNode;
}) {
  const parent = useModuleExtensionLifetime();
  const client = useQueryClient();
  const tasks = useRef(new Set<ModuleExtensionRequest>());
  const cleanups = useRef(new Set<() => void>());
  const active = useRef(false);
  const value = useMemo<ModuleExtensionLifetime>(
    () => ({
      snapshot: parent.snapshot,
      queryKey: [...parent.queryKey, contributionId],
      beginRequest() {
        if (!active.current) throw new Error('Module contribution is stale');
        const task = parent.beginRequest();
        tasks.current.add(task);
        return {
          ...task,
          current: () => active.current && task.current(),
          finish: () => {
            tasks.current.delete(task);
            task.finish();
          },
          cancel: () => {
            tasks.current.delete(task);
            task.cancel();
          },
        };
      },
      registerCleanup(cleanup) {
        if (!active.current) {
          try {
            cleanup();
          } catch {
            parent.reportCleanupFailure();
          }
          return () => {};
        }
        cleanups.current.add(cleanup);
        return () => {
          cleanups.current.delete(cleanup);
        };
      },
      reportCleanupFailure: () => parent.reportCleanupFailure(),
      originalOperations: () => (active.current ? parent.originalOperations() : []),
    }),
    [contributionId, parent],
  );
  useLayoutEffect(() => {
    active.current = true;
    const clear = () => {
      active.current = false;
      for (const task of tasks.current) task.cancel();
      tasks.current.clear();
      let failed = false;
      for (const cleanup of cleanups.current) {
        try {
          cleanup();
        } catch {
          failed = true;
        }
      }
      cleanups.current.clear();
      void client
        .cancelQueries({ queryKey: value.queryKey })
        .catch(() => parent.reportCleanupFailure());
      try {
        client.removeQueries({ queryKey: value.queryKey });
      } catch {
        failed = true;
      }
      if (failed) parent.reportCleanupFailure();
    };
    const remove = parent.registerCleanup(clear);
    return () => {
      remove();
      clear();
    };
  }, [client, parent, value]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}
