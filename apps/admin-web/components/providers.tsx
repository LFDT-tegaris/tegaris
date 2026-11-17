'use client';

import { routes, UiRuntimeProvider } from '@openpc/ui-shell';
import { usePathname, useSearchParams } from 'next/navigation';
import { WorkspaceSessionBoundary } from './workspace-session-boundary';

export function Providers({
  children,
  processEventsEnabled,
}: Readonly<{ children: React.ReactNode; processEventsEnabled: boolean }>) {
  const pathname = usePathname();
  const parameters = useSearchParams();
  const query = parameters.toString();
  const returnPath = `${pathname}${query ? `?${query}` : ''}`;
  const protectedRoute =
    routes.some((route) => route.path === pathname) &&
    !(
      pathname === '/govern/memberships' &&
      parameters.getAll('view').length === 1 &&
      parameters.get('view') === 'invitation-acceptance'
    );
  return (
    <UiRuntimeProvider processEventsEnabled={processEventsEnabled}>
      {protectedRoute ? (
        <WorkspaceSessionBoundary returnPath={returnPath}>{children}</WorkspaceSessionBoundary>
      ) : (
        children
      )}
    </UiRuntimeProvider>
  );
}
