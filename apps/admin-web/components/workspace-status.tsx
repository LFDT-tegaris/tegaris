'use client';

import { useId, type ReactNode } from 'react';
import { AlertCircle, CheckCircle2, LoaderCircle, ShieldAlert } from 'lucide-react';
import type { TruthState } from '@openpc/ui-shell';
import { CopyReference } from './copy-reference';

const statusLabels: Record<TruthState, string> = {
  SUCCESS: 'Available',
  AUTHORIZED_EMPTY: 'No records to show',
  DENIED: 'Access denied',
  LOADING: 'Loading workspace',
  UNKNOWN: 'Status not confirmed',
  UNAVAILABLE: 'Workspace unavailable',
  STALE: 'Information needs refreshing',
  REORG: 'Chain reorganization detected',
  PARTIAL: 'Some information is unavailable',
  CONFLICTING: 'Conflicting information',
  DEGRADED: 'Service degraded',
  FAILED: 'Request failed',
  RETRY_ELIGIBLE: 'Retry available',
  FAILOVER_ELIGIBLE: 'Alternative provider available',
  WRITE_AMBIGUITY: 'Outcome not confirmed',
  RECOVERY: 'Recovery',
  ROLLBACK: 'Rollback',
  RETIREMENT: 'Retirement',
  UNINSTALL: 'Uninstall',
  DECOMMISSION: 'Decommission',
};

export interface WorkspaceStatusProps {
  state: TruthState;
  detail: string;
  title?: string;
  headingLevel?: 2 | 3 | 4;
  support?: { code: string; traceId: string };
  onRetry?: () => void;
  retrying?: boolean;
  children?: ReactNode;
}

export function WorkspaceStatus({
  state,
  detail,
  title,
  headingLevel = 2,
  support,
  onRetry,
  retrying = false,
  children,
}: WorkspaceStatusProps) {
  const titleId = useId();
  const Heading = ({ 2: 'h2', 3: 'h3', 4: 'h4' } as const)[headingLevel];
  const Icon =
    state === 'LOADING'
      ? LoaderCircle
      : state === 'SUCCESS' || state === 'AUTHORIZED_EMPTY'
        ? CheckCircle2
        : state === 'DENIED'
          ? ShieldAlert
          : AlertCircle;
  return (
    <section className="workspace-status" data-state={state} aria-labelledby={titleId}>
      <span className="workspace-status-icon">
        <Icon
          aria-hidden
          size={23}
          className={state === 'LOADING' ? 'animate-spin motion-reduce:animate-none' : undefined}
        />
      </span>
      <div className="workspace-status-content">
        <Heading id={titleId}>{title ?? statusLabels[state]}</Heading>
        <p>{detail}</p>
        {(onRetry || children) && (
          <div className="workspace-status-actions">
            {onRetry && (
              <button
                type="button"
                className="workflow-primary"
                disabled={retrying}
                onClick={onRetry}
              >
                {retrying ? 'Refreshing…' : 'Try again'}
              </button>
            )}
            {children}
          </div>
        )}
        {support && (
          <details className="workspace-status-support">
            <summary>Support reference</summary>
            <p>Share these references with your administrator when reporting this issue.</p>
            <dl>
              <div>
                <dt>Code</dt>
                <dd>{support.code}</dd>
              </div>
              <div>
                <dt>Request reference</dt>
                <dd>
                  <CopyReference
                    key={`${state}:${support.code}:${support.traceId}`}
                    label="request reference"
                    value={support.traceId}
                  />
                </dd>
              </div>
            </dl>
          </details>
        )}
      </div>
    </section>
  );
}
