import type { ReactNode } from 'react';
import { SecondaryPanel } from './secondary-panel';
import { CopyReference } from './copy-reference';
import type { PolicyWorkflowActorBinding } from './policy-workflow-storage';

export function GovernanceContextSummary({
  title,
  description,
  actor,
  children,
  includePrincipal = false,
}: {
  title: string;
  description: string;
  actor: PolicyWorkflowActorBinding & { role: string };
  children?: ReactNode;
  includePrincipal?: boolean;
}) {
  const contextKey = [
    actor.sessionId,
    actor.principalId,
    actor.participantId,
    actor.privacyDomainId,
    actor.contextEpoch,
    actor.role,
  ].join(':');
  return (
    <section className="governance-context" aria-label="Current context">
      <div className="governance-context-heading">
        <div>
          <h2>{title}</h2>
          <p>{description}</p>
        </div>
        <span className="governance-role">
          <span>Your role</span>
          <strong>
            {actor.role === 'operator'
              ? 'Maker'
              : actor.role === 'viewer'
                ? 'Checker'
                : 'Current access'}
          </strong>
        </span>
      </div>
      <div className="governance-context-actions">
        {children}
        <SecondaryPanel title="Workspace details" closeOnChange={contextKey}>
          <p className="text-sm text-[color:var(--muted)]">
            These identifiers describe the workspace used for this page. Each change still requires
            current permission, any required verification and independent approval.
          </p>
          <dl className="governance-context-details">
            {includePrincipal && (
              <div>
                <dt>Principal</dt>
                <dd>
                  <CopyReference
                    key={contextKey}
                    label="principal reference"
                    value={actor.principalId}
                  />
                </dd>
              </div>
            )}
            <div>
              <dt>Participant</dt>
              <dd>
                <CopyReference
                  key={contextKey}
                  label="participant reference"
                  value={actor.participantId}
                />
              </dd>
            </div>
            <div>
              <dt>Privacy domain</dt>
              <dd>
                <CopyReference
                  key={contextKey}
                  label="privacy domain reference"
                  value={actor.privacyDomainId}
                />
              </dd>
            </div>
            <div>
              <dt>Context generation</dt>
              <dd>{actor.contextEpoch}</dd>
            </div>
          </dl>
        </SecondaryPanel>
      </div>
    </section>
  );
}
