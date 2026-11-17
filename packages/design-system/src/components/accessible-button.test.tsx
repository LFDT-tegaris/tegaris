import { render, screen } from '@testing-library/react';
import { userEvent } from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';

import { AccessibleButton } from './accessible-button.js';

it('provides a keyboard-operable generic button', async () => {
  const onPress = vi.fn();
  render(<AccessibleButton onPress={onPress}>Continue</AccessibleButton>);

  const button = screen.getByRole('button', { name: 'Continue' });
  const user = userEvent.setup();
  await user.tab();
  await user.keyboard('{Enter}');

  expect(button).toHaveFocus();
  expect(onPress).toHaveBeenCalledTimes(1);
});
