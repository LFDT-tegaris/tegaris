import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { FormEvent } from 'react';
import { SecondaryPanel } from './secondary-panel';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function withLayout(...elements: HTMLElement[]) {
  // jsdom has no layout; rendered browser checks verify the actual geometry.
  for (const element of elements)
    vi.spyOn(element, 'getClientRects').mockReturnValue([
      new DOMRect(0, 0, 10, 10),
    ] as unknown as DOMRectList);
}

it('wraps modal Tab at active controls without submitting or changing the draft', () => {
  const submit = vi.fn((event: FormEvent) => event.preventDefault());
  render(
    <form onSubmit={submit}>
      <SecondaryPanel title="Read original request">
        <input aria-label="Original request" defaultValue="retained-original" />
        <textarea aria-label="Read-only reference" readOnly value="original-reference" />
        <fieldset disabled>
          <input aria-label="Unavailable control" />
        </fieldset>
        <div hidden>
          <input aria-label="Hidden control" />
        </div>
        <div inert>
          <input aria-label="Inert control" />
        </div>
        <button tabIndex={-1} type="button">
          Pointer only
        </button>
        <button style={{ display: 'none' }} type="button">
          Not displayed
        </button>
      </SecondaryPanel>
    </form>,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Read original request' }));
  const close = screen.getByRole('button', { name: 'Close Read original request' });
  const firstInput = screen.getByLabelText('Original request');
  const last = screen.getByLabelText('Read-only reference');
  withLayout(
    close,
    firstInput,
    last,
    screen.getByLabelText('Unavailable control'),
    screen.getByLabelText('Hidden control'),
    screen.getByLabelText('Inert control'),
    screen.getByRole('button', { name: 'Pointer only' }),
  );
  last.focus();
  expect(fireEvent.keyDown(last, { key: 'Tab' })).toBe(false);
  expect(close).toHaveFocus();
  expect(fireEvent.keyDown(close, { key: 'Tab', shiftKey: true })).toBe(false);
  expect(last).toHaveFocus();
  firstInput.focus();
  expect(fireEvent.keyDown(firstInput, { key: 'Tab' })).toBe(true);
  expect(fireEvent.keyDown(last, { key: 'Tab', ctrlKey: true })).toBe(true);
  expect(fireEvent.keyDown(last, { key: 'Tab', metaKey: true })).toBe(true);
  expect(fireEvent.keyDown(last, { key: 'Tab', isComposing: true })).toBe(true);
  expect(firstInput).toHaveValue('retained-original');
  expect(submit).not.toHaveBeenCalled();
});

it('wraps within the nested modal while leaving an inline workflow in normal page order', () => {
  render(
    <SecondaryPanel title="Inline workflow" inline>
      <input aria-label="Inline draft" />
      <SecondaryPanel title="Inspect nested request">
        <input aria-label="Nested draft" />
      </SecondaryPanel>
    </SecondaryPanel>,
  );
  const inline = screen.getByLabelText('Inline draft');
  const trigger = screen.getByRole('button', { name: 'Inspect nested request' });
  withLayout(inline, trigger);
  trigger.focus();
  expect(fireEvent.keyDown(trigger, { key: 'Tab' })).toBe(true);
  fireEvent.click(trigger);
  const close = screen.getByRole('button', { name: 'Close Inspect nested request' });
  const draft = screen.getByLabelText('Nested draft');
  withLayout(close, draft);
  draft.focus();
  expect(fireEvent.keyDown(draft, { key: 'Tab' })).toBe(false);
  expect(close).toHaveFocus();
  expect(fireEvent.keyDown(close, { key: 'Tab', shiftKey: true })).toBe(false);
  expect(draft).toHaveFocus();
  expect(screen.getByRole('dialog', { name: 'Inline workflow' })).toBeVisible();
});

it('respects explicit tab order at the modal boundary', () => {
  render(
    <SecondaryPanel title="Ordered fields">
      <input aria-label="Second field" tabIndex={2} />
      <input aria-label="First field" tabIndex={1} />
      <textarea aria-label="Last field" />
    </SecondaryPanel>,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Ordered fields' }));
  const close = screen.getByRole('button', { name: 'Close Ordered fields' });
  const first = screen.getByLabelText('First field');
  const last = screen.getByLabelText('Last field');
  withLayout(close, first, last, screen.getByLabelText('Second field'));
  last.focus();
  expect(fireEvent.keyDown(last, { key: 'Tab' })).toBe(false);
  expect(first).toHaveFocus();
  expect(fireEvent.keyDown(first, { key: 'Tab', shiftKey: true })).toBe(false);
  expect(last).toHaveFocus();
});

it.each(['hidden', 'inert'])('does not move focus into a %s workspace', (attribute) => {
  render(
    <div data-testid="workspace">
      <SecondaryPanel title="Inspect current context">
        <input aria-label="Context reference" />
      </SecondaryPanel>
    </div>,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Inspect current context' }));
  const close = screen.getByRole('button', { name: 'Close Inspect current context' });
  const reference = screen.getByLabelText('Context reference');
  withLayout(close, reference);
  reference.focus();
  screen.getByTestId('workspace').setAttribute(attribute, '');
  const focus = vi.spyOn(close, 'focus');
  expect(fireEvent.keyDown(reference, { key: 'Tab' })).toBe(true);
  expect(focus).not.toHaveBeenCalled();
});
it('opens a named inspection dialog and returns focus without losing the draft', () => {
  render(
    <SecondaryPanel title="Inspect request">
      <input aria-label="Original intent" defaultValue="Saved business input" />
    </SecondaryPanel>,
  );
  const action = screen.getByRole('button', { name: 'Inspect request' });
  const draft = screen.getByLabelText('Original intent');
  expect(draft).not.toBeVisible();
  expect(action).toHaveAttribute('aria-expanded', 'false');
  fireEvent.click(action);
  const inspection = screen.getByRole('dialog', { name: 'Inspect request' });
  expect(inspection).toBeVisible();
  expect(action).toHaveAttribute('aria-expanded', 'true');
  expect(action).toHaveAttribute('aria-controls', inspection.id);
  fireEvent.change(draft, { target: { value: 'Unchanged recovered intent' } });
  fireEvent.click(screen.getByRole('button', { name: 'Close Inspect request' }));
  expect(draft).not.toBeVisible();
  expect(action).toHaveFocus();
  expect(action).toHaveAttribute('aria-expanded', 'false');
  fireEvent.click(action);
  expect(screen.getByLabelText('Original intent')).toBe(draft);
  expect(draft).toHaveValue('Unchanged recovered intent');
  fireEvent(
    screen.getByRole('dialog', { name: 'Inspect request' }),
    new Event('cancel', { cancelable: true }),
  );
  expect(draft).not.toBeVisible();
});

it('reveals only the first invalid field across sibling inspection panels', () => {
  const modal = vi.spyOn(HTMLDialogElement.prototype, 'showModal');
  render(
    <form aria-label="Method definition">
      <SecondaryPanel title="Method signature">
        <input aria-label="Signature" required />
      </SecondaryPanel>
      <SecondaryPanel title="Required roles">
        <input aria-label="Roles" required />
      </SecondaryPanel>
      <button type="submit">Review method</button>
    </form>,
  );
  const form = screen.getByRole('form', { name: 'Method definition' }) as HTMLFormElement;
  act(() => {
    expect(form.reportValidity()).toBe(false);
  });
  expect(modal).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('dialog', { name: 'Method signature' })).toBeVisible();
  expect(screen.getByLabelText('Signature')).toHaveFocus();
  expect(screen.getByLabelText('Roles')).not.toBeVisible();
  modal.mockRestore();
});

it.each(['close', 'cancel'] as const)(
  'keeps the outer workflow open when a nested dialog receives %s',
  (event) => {
    render(
      <SecondaryPanel title="Provider workflow">
        <input aria-label="Provider draft" defaultValue="Original provider" />
        <SecondaryPanel title="Recover original request">
          <input aria-label="Request reference" defaultValue="Saved request" />
        </SecondaryPanel>
      </SecondaryPanel>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Provider workflow' }));
    fireEvent.click(screen.getByRole('button', { name: 'Recover original request' }));
    const child = screen.getByRole('dialog', { name: 'Recover original request' });
    fireEvent(child, new Event(event, { cancelable: event === 'cancel' }));
    expect(child).not.toBeVisible();
    expect(screen.getByRole('dialog', { name: 'Provider workflow' })).toBeVisible();
    expect(screen.getByLabelText('Provider draft')).toHaveValue('Original provider');
    expect(screen.getByRole('button', { name: 'Recover original request' })).toHaveFocus();
    fireEvent.click(screen.getByRole('button', { name: 'Close Provider workflow' }));
    expect(screen.getByLabelText('Provider draft')).not.toBeVisible();
    expect(screen.getByRole('button', { name: 'Provider workflow' })).toHaveFocus();
  },
);

it('reports actual panel visibility through open, scope change and close without submitting', () => {
  const change = vi.fn();
  const submit = vi.fn((event: FormEvent) => event.preventDefault());
  const view = render(
    <SecondaryPanel title="Create a record" closeOnChange="first-scope" onOpenChange={change}>
      <form onSubmit={submit}>
        <input aria-label="Draft name" defaultValue="Unsent draft" />
      </form>
    </SecondaryPanel>,
  );
  expect(change).toHaveBeenLastCalledWith(false);
  fireEvent.click(screen.getByRole('button', { name: /^Create a record$/u }));
  expect(change).toHaveBeenLastCalledWith(true);
  view.rerender(
    <SecondaryPanel title="Create a record" closeOnChange="second-scope" onOpenChange={change}>
      <form onSubmit={submit}>
        <input aria-label="Draft name" defaultValue="Unsent draft" />
      </form>
    </SecondaryPanel>,
  );
  expect(change).toHaveBeenLastCalledWith(false);
  expect(screen.queryByRole('dialog')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: /^Create a record$/u }));
  fireEvent.click(screen.getByRole('button', { name: 'Close Create a record' }));
  expect(change).toHaveBeenLastCalledWith(false);
  expect(screen.getByLabelText('Draft name')).toHaveValue('Unsent draft');
  expect(submit).not.toHaveBeenCalled();
});
