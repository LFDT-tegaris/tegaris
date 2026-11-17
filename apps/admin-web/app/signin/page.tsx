import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { SignIn } from '../../components/sign-in';
import { signInParticipant, workspaceReturnPath } from '../../lib/workspace-navigation';
import { readWorkspaceSession } from '../api/v1/ui/workspace-session';

export default async function SignInPage({
  searchParams,
}: {
  readonly searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const query = await searchParams;
  const returnPath = workspaceReturnPath(query.returnTo);
  const participantId = signInParticipant(query.participantId);
  const session = await readWorkspaceSession(
    (await cookies()).get('openpc_local_runtime_session')?.value,
    (await cookies()).get('openpc_functional_actor')?.value,
    (await cookies()).get('openpc_functional_context')?.value,
  );
  if (
    session &&
    participantId !== null &&
    (participantId === undefined || session.participantId === participantId)
  )
    redirect(returnPath);
  return (
    <SignIn
      key={participantId === null ? 'invalid-organization' : (participantId ?? 'unselected')}
      returnPath={returnPath}
      participantId={participantId ?? undefined}
      organizationContextInvalid={participantId === null}
      authenticationFailed={query.oidcError === 'authentication_failed'}
      sessionEnded={query.reason === 'session-ended'}
    />
  );
}
