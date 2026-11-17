import { notFound, redirect } from 'next/navigation';
import { cookies } from 'next/headers';

import { redirects, routes } from '@openpc/ui-shell';

import { Workbench } from '../../components/workbench';
import { InvitationAcceptanceWorkflow } from '../../components/invitation-acceptance';
import { signInHref } from '../../lib/workspace-navigation';
import { readWorkspaceSession } from '../api/v1/ui/workspace-session';

interface RoutePageProps {
  readonly params: Promise<{ path: string[] }>;
  readonly searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function RoutePage({ params, searchParams }: RoutePageProps) {
  const pathname = `/${(await params).path.join('/')}`;
  const target = redirects[pathname];
  if (target) {
    redirect(target);
  }
  const route = routes.find((candidate) => candidate.path === pathname);
  if (!route) {
    notFound();
  }
  const query = await searchParams;
  if (pathname === '/govern/memberships' && query.view === 'invitation-acceptance') {
    return (
      <main className="invitation-entry">
        <header>
          <strong>Tegaris</strong>
          <h1>Accept your invitation</h1>
        </header>
        <InvitationAcceptanceWorkflow />
      </main>
    );
  }
  const parameters = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    for (const item of Array.isArray(value) ? value : value === undefined ? [] : [value])
      parameters.append(key, item);
  }
  const returnPath = `${pathname}${parameters.size ? `?${parameters}` : ''}`;
  const session = await readWorkspaceSession(
    (await cookies()).get('openpc_local_runtime_session')?.value,
    (await cookies()).get('openpc_functional_actor')?.value,
    (await cookies()).get('openpc_functional_context')?.value,
  );
  if (!session) redirect(signInHref(returnPath));
  return <Workbench route={route} evaluationUi={process.env.OPENPC_EVALUATION_UI === '1'} />;
}
