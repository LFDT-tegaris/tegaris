import type { ReactNode } from 'react';
import { SecondaryPanel } from './secondary-panel';

/** Selected tasks are inline; secondary tools open a separate, focused surface. */
export function WorkflowDetails({
  enabled,
  summary,
  expanded = false,
  preserveChildren = false,
  children,
}: Readonly<{
  enabled: boolean;
  summary: string;
  expanded?: boolean;
  preserveChildren?: boolean;
  children: ReactNode;
}>) {
  if (!preserveChildren && (!enabled || expanded)) return <>{children}</>;
  return (
    <SecondaryPanel title={summary} inline={!enabled || expanded}>
      {children}
    </SecondaryPanel>
  );
}
