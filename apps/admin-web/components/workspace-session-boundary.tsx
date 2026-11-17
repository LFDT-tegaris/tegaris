'use client';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useRouter } from 'next/navigation';
import { localSessionStatusSchema } from '../lib/local-session-status';
import { signInHref } from '../lib/workspace-navigation';
import { CentralSessionContext } from './central-session-context';
import { clearTransactionWorkflowStorage } from './policy-workflow-storage';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';

export function WorkspaceSessionBoundary({
  returnPath,
  children,
}: {
  readonly returnPath: string;
  readonly children: ReactNode;
}) {
  const router = useRouter();
  const [state, setState] = useState<'checking' | 'updating' | 'ready' | 'unavailable' | 'ended'>(
    'checking',
  );
  const retry = useRef(() => {});
  const recheckRoute = useRef(() => {});
  const currentPath = useRef(returnPath);
  const checkedPath = useRef(returnPath);
  currentPath.current = returnPath;
  const previousBinding = useRef<string | undefined>(undefined);
  const previousFunctionalContext = useRef<'PARTICIPANT' | 'PLATFORM' | undefined>(undefined);
  useEffect(() => {
    let generation = 0,
      live = true,
      pending = isSessionTransitionPending();
    let navigatingTo: string | undefined;
    let controller: AbortController | undefined;
    let deadline: number | undefined;
    const conceal = () => {
      generation++;
      controller?.abort();
      window.clearTimeout(deadline);
      setState(pending ? 'updating' : 'checking');
    };
    const read = (foreground = true) => {
      if (navigatingTo && currentPath.current !== navigatingTo) return;
      navigatingTo = undefined;
      if (foreground) conceal();
      else {
        generation++;
        controller?.abort();
        window.clearTimeout(deadline);
      }
      if (pending) return;
      const selected = generation;
      controller = new AbortController();
      const signal = controller.signal;
      deadline = window.setTimeout(() => {
        if (live && generation === selected) {
          controller?.abort();
          setState('unavailable');
        }
      }, 10_000);
      void fetch('/api/v1/ui/local-session', { cache: 'no-store', signal })
        .then(async (response) => {
          if (!response.ok) throw new Error();
          return localSessionStatusSchema.parse(await response.json());
        })
        .then((session) => {
          if (!live || signal.aborted || generation !== selected || pending) return;
          window.clearTimeout(deadline);
          if (!session.enabled) throw new Error();
          if (!session.authenticated) {
            clearTransactionWorkflowStorage();
            setState('ended');
            router.replace(signInHref(currentPath.current, true));
            return;
          }
          const binding = JSON.stringify([
            session.sessionId,
            session.principalId,
            session.participantId,
            session.contextMode,
            session.privacyDomainId,
            session.contextEpoch,
          ]);
          if (previousBinding.current && previousBinding.current !== binding) {
            setState('checking');
            if (
              session.functionalTest &&
              previousFunctionalContext.current &&
              previousFunctionalContext.current !== session.contextMode
            ) {
              const destination =
                session.contextMode === 'PLATFORM'
                  ? '/govern/participants?view=rpc-access'
                  : '/develop/modules';
              if (currentPath.current === destination) window.location.reload();
              else {
                navigatingTo = destination;
                previousBinding.current = binding;
                previousFunctionalContext.current = session.contextMode;
                router.replace(destination);
              }
            } else window.location.reload();
            return;
          }
          previousBinding.current = binding;
          previousFunctionalContext.current = session.functionalTest
            ? session.contextMode
            : undefined;
          setState('ready');
        })
        .catch(() => {
          if (live && !signal.aborted && generation === selected) {
            window.clearTimeout(deadline);
            setState('unavailable');
          }
        });
    };
    retry.current = read;
    recheckRoute.current = () => {
      navigatingTo = undefined;
      read(false);
    };
    read();
    const stop = observeSessionTransitions(
      () => {
        pending = true;
        conceal();
      },
      (changing) => {
        pending = changing;
        read();
      },
    );
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') read(false);
    }, 30_000);
    const restored = () => read();
    window.addEventListener('pageshow', restored);
    return () => {
      live = false;
      generation++;
      controller?.abort();
      stop();
      window.clearInterval(timer);
      window.clearTimeout(deadline);
      window.removeEventListener('pageshow', restored);
    };
  }, [router]);

  useEffect(() => {
    if (checkedPath.current === returnPath) return;
    checkedPath.current = returnPath;
    recheckRoute.current();
  }, [returnPath]);

  return (
    <CentralSessionContext.Provider value={true}>
      {state !== 'ready' && (
        <main className="workspace-session-message" aria-live="polite">
          <strong>Tegaris</strong>
          <p>
            {state === 'unavailable'
              ? 'Your session could not be verified.'
              : state === 'ended'
                ? 'Returning to sign-in…'
                : state === 'updating'
                  ? 'Updating your session…'
                  : 'Checking your session…'}
          </p>
          {state === 'updating' && (
            <p>
              If your browser is showing a sign-in or authenticator prompt, complete it to continue.
            </p>
          )}
          {state === 'unavailable' && (
            <button type="button" onClick={() => retry.current()}>
              Retry session check
            </button>
          )}
        </main>
      )}
      <div hidden={state !== 'ready'} inert={state !== 'ready'}>
        {state !== 'ended' && children}
      </div>
    </CentralSessionContext.Provider>
  );
}
