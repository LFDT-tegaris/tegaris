import axeCore from 'axe-core';
import { render } from '@testing-library/react';
import { expect, it } from 'vitest';

import { AccessibleButton } from '../../../packages/design-system/src/index.js';

it('has no detectable accessibility violations for a generic button primitive', async () => {
  const { container } = render(<AccessibleButton>Continue</AccessibleButton>);
  const result = await axeCore.run(container);

  expect(result.violations).toEqual([]);
});
