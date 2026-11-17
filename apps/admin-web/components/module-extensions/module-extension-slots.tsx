'use client';

import { Component, type ReactNode, type ComponentType } from 'react';
import {
  orderModuleContributions,
  type ExtensionSlot,
  type ModuleSlotAnchors,
} from '@openpc/ui-extensions';
import type { ModuleExtensionEntry } from '../../lib/module-extensions';
import {
  ModuleContributionBoundary,
  useModuleExtensionLifetime,
} from './module-extension-boundary';

export interface BundledModulePresentation {
  readonly moduleId: string;
  readonly moduleVersion: string;
  readonly moduleDigest: string;
  readonly uiManifestDigest: string;
  readonly contributionId: string;
  readonly slotId: ExtensionSlot;
  readonly viewOrFormId: string | null;
  readonly label: string;
  /** Statically imported, reviewed shell component. Never a manifest URL/script. */
  readonly component: ComponentType<{ readonly entry: ModuleExtensionEntry }>;
}
class IsolatedContribution extends Component<
  {
    readonly label: string;
    readonly contributionId: string;
    readonly observationKey: string;
    readonly children: ReactNode;
  },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <p role="status">This module contribution is unavailable.</p>
    ) : (
      <section
        aria-label={this.props.label}
        data-module-contribution={this.props.contributionId}
        data-module-observation={this.props.observationKey}
      >
        {this.props.children}
      </section>
    );
  }
}

/** Six registered positions share one ordered, isolated renderer. The shell
 * owns anchors and compile-time component bindings. The real binding producer
 * is still a canonical release prerequisite; no production entries are supplied
 * here. Matching these identities is not signature/trust verification or proof
 * of budget/accessibility qualification. Nothing here authorizes a
 * data query, action, route or field, or makes a contribution runtime-admitted. */
export function ModuleExtensionSlot({
  slot,
  anchor,
  anchors,
  presentations,
}: {
  readonly slot: ExtensionSlot;
  readonly anchor: string;
  readonly anchors: ModuleSlotAnchors;
  readonly presentations: readonly BundledModulePresentation[];
}) {
  const lifetime = useModuleExtensionLifetime();
  let entries: readonly ModuleExtensionEntry[];
  try {
    entries = orderModuleContributions(lifetime.snapshot.entries, anchors);
  } catch {
    return <p role="status">Module contribution ordering is unavailable.</p>;
  }
  return (
    <>
      {entries
        .filter(
          (entry) => entry.contribution.slotId === slot && entry.contribution.anchor === anchor,
        )
        .map((entry) => {
          const matches = presentations.filter(
            (presentation) =>
              presentation.moduleId === entry.moduleId &&
              presentation.moduleVersion === entry.moduleVersion &&
              presentation.moduleDigest === entry.moduleDigest &&
              presentation.uiManifestDigest === entry.uiManifestDigest &&
              presentation.contributionId === entry.contribution.contributionId &&
              presentation.slotId === entry.contribution.slotId &&
              presentation.viewOrFormId === entry.contribution.viewOrFormId,
          );
          const presentation = matches.length === 1 ? matches[0] : undefined;
          if (!presentation || !presentation.label.trim())
            return (
              <p key={entry.contribution.contributionId} role="status">
                A registered module contribution could not be loaded.
              </p>
            );
          const Content = presentation.component;
          return (
            <IsolatedContribution
              key={`${entry.contribution.contributionId}:${entry.uiManifestDigest}:${entry.moduleRevision}`}
              label={presentation.label}
              contributionId={entry.contribution.contributionId}
              observationKey={lifetime.snapshot.binding.observationKey}
            >
              <ModuleContributionBoundary contributionId={entry.contribution.contributionId}>
                <Content entry={entry} />
              </ModuleContributionBoundary>
            </IsolatedContribution>
          );
        })}
    </>
  );
}
