import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { AccountMenu } from './account-menu';

afterEach(cleanup);

it('dismisses with Escape and returns focus without invoking an account action', async () => {
  const action = vi.fn();
  const user = userEvent.setup();
  render(
    <AccountMenu>
      <div>
        <a href="/home/session">Account & security</a>
        <button onClick={action}>Sign out</button>
      </div>
    </AccountMenu>,
  );
  const toggle = screen.getByText('Account', { exact: true });
  await user.click(toggle);
  const link = screen.getByRole('link', { name: 'Account & security' });
  link.focus();
  await user.keyboard('{Escape}');
  expect(link).not.toBeVisible();
  expect(toggle).toHaveFocus();
  expect(action).not.toHaveBeenCalled();
});

it('closes on an outside pointer without discarding mounted child state', async () => {
  const user = userEvent.setup();
  render(
    <>
      <AccountMenu>
        <div>
          <input aria-label="Retained menu input" defaultValue="Original input" />
        </div>
      </AccountMenu>
      <button>Outside control</button>
    </>,
  );
  const toggle = screen.getByText('Account', { exact: true });
  await user.click(toggle);
  const input = screen.getByRole('textbox', { name: 'Retained menu input' });
  fireEvent.change(input, { target: { value: 'Retained input' } });
  await user.click(screen.getByRole('button', { name: 'Outside control' }));
  expect(input).not.toBeVisible();
  expect(screen.getByRole('button', { name: 'Outside control' })).toHaveFocus();
  await user.click(toggle);
  expect(screen.getByRole('textbox', { name: 'Retained menu input' })).toBe(input);
  expect(input).toHaveValue('Retained input');
});

it('closes when keyboard focus leaves the disclosure', async () => {
  const user = userEvent.setup();
  render(
    <>
      <AccountMenu>
        <div>
          <button>Menu action</button>
        </div>
      </AccountMenu>
      <button>Next control</button>
    </>,
  );
  await user.click(screen.getByText('Account', { exact: true }));
  const action = screen.getByRole('button', { name: 'Menu action' });
  action.focus();
  await user.tab();
  expect(screen.getByRole('button', { name: 'Next control' })).toHaveFocus();
  expect(action).not.toBeVisible();
});

it('resets the open disclosure when its session controls are concealed', async () => {
  const user = userEvent.setup();
  const view = (hidden = false) => (
    <AccountMenu hidden={hidden}>
      <div>
        <button>Menu action</button>
      </div>
    </AccountMenu>
  );
  const rendered = render(view());
  await user.click(screen.getByText('Account', { exact: true }));
  const toggle = screen.getByText('Account', { exact: true });
  expect(toggle.closest('details')).toHaveProperty('open', true);
  rendered.rerender(view(true));
  expect(toggle.closest('details')).toHaveProperty('open', false);
  rendered.rerender(view());
  expect(screen.getByText('Menu action', { exact: true })).not.toBeVisible();
  expect(toggle.closest('details')).toHaveProperty('open', false);
});

it('closes after activating a navigation link without suppressing its handler', async () => {
  const navigate = vi.fn();
  const user = userEvent.setup();
  render(
    <AccountMenu>
      <div>
        <a
          href="/home/session"
          onClick={(event) => {
            event.preventDefault();
            navigate();
          }}
        >
          Account & security
        </a>
      </div>
    </AccountMenu>,
  );
  await user.click(screen.getByText('Account', { exact: true }));
  const link = screen.getByRole('link', { name: 'Account & security' });
  await user.click(link);
  expect(navigate).toHaveBeenCalledTimes(1);
  expect(link).not.toBeVisible();
});
