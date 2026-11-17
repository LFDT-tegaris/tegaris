'use client';

import { useEffect, useLayoutEffect, useRef, type ReactNode } from 'react';
import { ChevronDown, UserRound } from 'lucide-react';

export function AccountMenu({
  children,
  hidden = false,
}: {
  children: ReactNode;
  hidden?: boolean;
}) {
  const menu = useRef<HTMLDetailsElement>(null);
  useLayoutEffect(() => {
    if (hidden && menu.current) menu.current.open = false;
  }, [hidden]);
  useEffect(() => {
    const closeOutside = (event: PointerEvent) => {
      const element = menu.current;
      if (element?.open && event.target instanceof Node && !element.contains(event.target)) {
        element.open = false;
      }
    };
    document.addEventListener('pointerdown', closeOutside);
    return () => document.removeEventListener('pointerdown', closeOutside);
  }, []);
  return (
    <details
      ref={menu}
      className="workspace-account-menu"
      hidden={hidden}
      onClick={(event) => {
        if (event.target instanceof Element && event.target.closest('a[href]')) {
          event.currentTarget.open = false;
        }
      }}
      onKeyDown={(event) => {
        if (event.key !== 'Escape' || !event.currentTarget.open) return;
        event.preventDefault();
        event.currentTarget.open = false;
        event.currentTarget.querySelector('summary')?.focus();
      }}
      onBlur={(event) => {
        if (
          !(event.relatedTarget instanceof Node) ||
          !event.currentTarget.contains(event.relatedTarget)
        ) {
          event.currentTarget.open = false;
        }
      }}
    >
      <summary>
        <UserRound aria-hidden size={17} />
        Account
        <ChevronDown aria-hidden size={15} />
      </summary>
      {children}
    </details>
  );
}
