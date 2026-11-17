'use client';

import { useQuery } from '@tanstack/react-query';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import { localSessionStatusSchema } from '../lib/local-session-status';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';

export function EvaluationContext({ routeKey }: { readonly routeKey: string }) {
  const [generation, setGeneration] = useState(0);
  const [changingScope, setChangingScope] = useState<string>();
  const changing = changingScope === routeKey || isSessionTransitionPending();
  useEffect(
    () =>
      observeSessionTransitions(
        () => {
          setChangingScope(routeKey);
          setGeneration((value) => value + 1);
        },
        (pending) => {
          setChangingScope(pending ? routeKey : undefined);
          setGeneration((value) => value + 1);
        },
      ),
    [routeKey],
  );
  const query = useQuery({
    queryKey: ['evaluation-session-context', routeKey, generation],
    queryFn: async ({ signal }) => {
      const response = await fetch('/api/v1/ui/local-session', { cache: 'no-store', signal });
      if (!response.ok) throw new Error('Session context unavailable');
      return localSessionStatusSchema.parse(await response.json());
    },
    enabled: !changing,
    retry: false,
  });
  const checking = changing || query.isFetching;
  const session = !checking && !query.error ? query.data : undefined;
  const authenticated = session?.enabled && 'authenticated' in session && session.authenticated;
  return (
    <div className="evaluation-context" role="region" aria-label="Session context">
      <div aria-live="polite">
        {checking ? (
          'Checking session…'
        ) : authenticated ? (
          <details>
            <summary>
              {session.contextMode === 'PARTICIPANT'
                ? 'Participant workspace'
                : 'Platform workspace'}
            </summary>
            <dl>
              <div>
                <dt>Principal</dt>
                <dd>{session.principalId}</dd>
              </div>
              <div>
                <dt>Participant</dt>
                <dd>{session.participantId}</dd>
              </div>
              {session.privacyDomainId && (
                <div>
                  <dt>Privacy domain</dt>
                  <dd>{session.privacyDomainId}</dd>
                </div>
              )}
            </dl>
          </details>
        ) : session?.enabled ? (
          'Signed out'
        ) : (
          'Context unavailable'
        )}
      </div>
      <Link href="/home/session">{authenticated ? 'Account & security' : 'Sign in'}</Link>
    </div>
  );
}
