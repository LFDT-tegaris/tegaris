'use client';

import {
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
  type SyntheticEvent,
} from 'react';
import { ArrowUpRight, X } from 'lucide-react';

const invalidFieldEvent = 'openpc:reveal-first-invalid-field';

function containModalTab(event: KeyboardEvent<HTMLDialogElement>) {
  if (
    event.key !== 'Tab' ||
    event.defaultPrevented ||
    event.nativeEvent.isComposing ||
    event.altKey ||
    event.ctrlKey ||
    event.metaKey
  )
    return;
  const panel = event.currentTarget;
  if (
    !panel.open ||
    panel.closest('[hidden], [inert]') ||
    !(event.target instanceof Element) ||
    event.target.closest('dialog') !== panel
  )
    return;
  const controls = Array.from(
    panel.querySelectorAll<HTMLElement>(
      'a[href], area[href], button, input:not([type="hidden"]), select, textarea, summary, [tabindex]',
    ),
  ).filter(
    (element) =>
      element.tabIndex >= 0 &&
      !element.matches(':disabled') &&
      !element.closest('[hidden], [inert]') &&
      element.closest('dialog') === panel &&
      !['hidden', 'collapse'].includes(getComputedStyle(element).visibility) &&
      element.getClientRects().length > 0,
  );
  const order = (element: HTMLElement) =>
    element.tabIndex > 0 ? element.tabIndex : Number.MAX_SAFE_INTEGER;
  controls.sort((a, b) => order(a) - order(b));
  const first = controls[0];
  const last = controls.at(-1);
  if (!first || !last) {
    event.preventDefault();
    panel.focus();
  } else if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

/** Native form order owns validation; later failures cannot steal the first field's focus. */
export function focusFirstInvalidField(event: SyntheticEvent<HTMLElement>) {
  if (event.defaultPrevented) return;
  const control = event.target;
  if (!(
    control instanceof HTMLInputElement ||
    control instanceof HTMLSelectElement ||
    control instanceof HTMLTextAreaElement
  ))
    return;
  const first = Array.from(control.form?.elements ?? []).find(
    (element) =>
      (element instanceof HTMLInputElement ||
        element instanceof HTMLSelectElement ||
        element instanceof HTMLTextAreaElement) &&
      element.willValidate &&
      !element.validity.valid,
  );
  if (first !== control) {
    event.preventDefault();
    return;
  }
  const panel = control.closest<HTMLDialogElement>('dialog.secondary-panel-dialog');
  if (panel && !panel.open) {
    event.preventDefault();
    panel.dispatchEvent(new CustomEvent(invalidFieldEvent, { detail: control }));
  }
}

/** A separate inspection surface; opening it never submits a business action. */
export function SecondaryPanel({
  title,
  triggerLabel,
  children,
  className = '',
  inline = false,
  closeOnChange,
  onOpenChange,
}: {
  title: string;
  triggerLabel?: string;
  children: ReactNode;
  className?: string;
  inline?: boolean;
  closeOnChange?: string;
  onOpenChange?: (open: boolean) => void;
}) {
  const id = useId();
  const dialog = useRef<HTMLDialogElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false);
  const previousInline = useRef(inline);
  const previousCloseKey = useRef(closeOnChange);
  useLayoutEffect(() => {
    const element = dialog.current;
    if (!element) return;
    const changed = previousInline.current !== inline || previousCloseKey.current !== closeOnChange;
    previousCloseKey.current = closeOnChange;
    previousInline.current = inline;
    if (changed) {
      if (element.open) element.close();
      setOpen(false);
    }
    if (inline) element.open = true;
    else if (open && !changed && !element.open) element.showModal();
    else if ((!open || changed) && element.open) element.close();
    onOpenChange?.(element.open);
  }, [open, inline, closeOnChange, onOpenChange]);
  useLayoutEffect(() => {
    const element = dialog.current;
    if (!element) return;
    const reveal = (event: Event) => {
      const control = (event as CustomEvent<HTMLInputElement>).detail;
      if (!control || control.closest('dialog') !== element) return;
      if (!element.open) element.showModal();
      setOpen(true);
      control.focus();
    };
    element.addEventListener(invalidFieldEvent, reveal);
    return () => element.removeEventListener(invalidFieldEvent, reveal);
  }, []);
  return (
    <div className={`secondary-panel ${className}`} onInvalidCapture={focusFirstInvalidField}>
      <button
        hidden={inline}
        ref={trigger}
        type="button"
        className="secondary-panel-trigger"
        aria-label={title}
        aria-haspopup="dialog"
        aria-controls={`${id}-dialog`}
        aria-expanded={open}
        onClick={() => setOpen(true)}
      >
        {triggerLabel ?? title}
        <ArrowUpRight aria-hidden size={15} />
      </button>
      <dialog
        ref={dialog}
        id={`${id}-dialog`}
        aria-labelledby={id}
        className={`secondary-panel-dialog ${inline ? 'secondary-panel-inline' : ''}`}
        onKeyDown={inline ? undefined : containModalTab}
        onCancel={(event) => {
          if (event.target === event.currentTarget) setOpen(false);
        }}
        onClose={(event) => {
          if (event.target !== event.currentTarget) return;
          if (!previousInline.current) {
            setOpen(false);
            if (trigger.current?.isConnected && !trigger.current.closest('[hidden]'))
              trigger.current.focus();
          }
        }}
      >
        <header hidden={inline}>
          <h2 id={id}>{title}</h2>
          <button type="button" aria-label={`Close ${title}`} onClick={() => setOpen(false)}>
            <X size={20} aria-hidden="true" />
          </button>
        </header>
        <div className={inline ? 'secondary-panel-inline-body' : 'secondary-panel-body'}>
          {children}
        </div>
      </dialog>
    </div>
  );
}
