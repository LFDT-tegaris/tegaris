'use client';

import { QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type PropsWithChildren,
} from 'react';

import type { UiEvent } from './contracts';

interface UiRuntime {
  readonly handleEvent: (event: UiEvent) => void;
  readonly resetProtectedState: () => void;
}

const UiRuntimeContext = createContext<UiRuntime | undefined>(undefined);

function createClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchOnWindowFocus: false, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

function RuntimeOwner({
  children,
  processEventsEnabled,
}: PropsWithChildren<{ processEventsEnabled: boolean }>) {
  const queryClient = useQueryClient();
  const resetProtectedState = () => queryClient.clear();
  const handleEvent = (event: UiEvent) => {
    if (event.type === 'context-changed' || event.type === 'module-removed') {
      resetProtectedState();
      return;
    }
    void queryClient.invalidateQueries({ queryKey: ['ui-process', event.routeId] });
  };

  useEffect(() => {
    if (!processEventsEnabled) return;
    const source = new EventSource('/api/v1/ui/events', { withCredentials: true });
    source.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as UiEvent;
        if (
          event.type === 'snapshot-invalidated' ||
          event.type === 'context-changed' ||
          event.type === 'module-removed'
        ) {
          handleEvent(event);
        }
      } catch {
        // Unrecognized events are deliberately ignored; they cannot grant state or authority.
      }
    };
    return () => source.close();
  }, [queryClient, processEventsEnabled]);

  const runtime = useMemo<UiRuntime>(() => ({ handleEvent, resetProtectedState }), [queryClient]);
  return <UiRuntimeContext.Provider value={runtime}>{children}</UiRuntimeContext.Provider>;
}

export function UiRuntimeProvider({
  children,
  processEventsEnabled = true,
}: PropsWithChildren<{ processEventsEnabled?: boolean }>) {
  const [queryClient] = useState(createClient);
  return (
    <QueryClientProvider client={queryClient}>
      <RuntimeOwner processEventsEnabled={processEventsEnabled}>{children}</RuntimeOwner>
    </QueryClientProvider>
  );
}

export function useUiRuntime(): UiRuntime {
  const runtime = useContext(UiRuntimeContext);
  if (!runtime) {
    throw new Error('useUiRuntime must be used inside UiRuntimeProvider.');
  }
  return runtime;
}
