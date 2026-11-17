'use client';

import { useContext, type ReactNode } from 'react';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { CentralSessionContext } from './central-session-context';

export function WorkspaceEntry({
  children,
  disabled = false,
}: {
  children: ReactNode;
  disabled?: boolean;
}) {
  const centralized = useContext(CentralSessionContext);
  if (!centralized) return <>{children}</>;
  const label = (
    <>
      <span>Choose workspace</span>
      <ArrowRight aria-hidden size={16} />
    </>
  );
  return disabled ? (
    <span role="link" aria-disabled="true" className="workspace-entry-link">
      {label}
    </span>
  ) : (
    <Link href="/home/session" className="workspace-entry-link">
      {label}
    </Link>
  );
}
