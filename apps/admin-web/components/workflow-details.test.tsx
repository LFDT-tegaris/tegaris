import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, expect, it } from 'vitest';
import { WorkflowDetails } from './workflow-details';

afterEach(cleanup);
function Draft() {
  const [value, setValue] = useState('');
  return (
    <input
      aria-label="Request draft"
      value={value}
      onChange={(event) => setValue(event.target.value)}
    />
  );
}

it('preserves the exact child and draft when the current task becomes primary or secondary', () => {
  const { rerender } = render(
    <WorkflowDetails enabled preserveChildren summary="Request tools">
      <Draft />
    </WorkflowDetails>,
  );
  const draft = screen.getByLabelText('Request draft');
  expect(draft).not.toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Request tools', hidden: true }));
  fireEvent.change(draft, { target: { value: 'Original request intent' } });
  rerender(
    <WorkflowDetails enabled={false} preserveChildren summary="Request tools">
      <Draft />
    </WorkflowDetails>,
  );
  expect(screen.getByLabelText('Request draft')).toBe(draft);
  expect(draft).toBeVisible();
  expect(draft).toHaveValue('Original request intent');
  expect(screen.getByText('Request tools', { selector: 'button' })).not.toBeVisible();
  rerender(
    <WorkflowDetails enabled preserveChildren summary="Request tools">
      <Draft />
    </WorkflowDetails>,
  );
  expect(screen.getByLabelText('Request draft')).toBe(draft);
  expect(draft).not.toBeVisible();
  expect(draft).toHaveValue('Original request intent');
  rerender(
    <WorkflowDetails enabled expanded preserveChildren summary="Request tools">
      <Draft />
    </WorkflowDetails>,
  );
  expect(screen.getByLabelText('Request draft')).toBe(draft);
  expect(draft).toBeVisible();
  expect(draft).toHaveValue('Original request intent');
});

it('retains the existing primary rendering when child preservation is not selected', () => {
  const { container, rerender } = render(
    <WorkflowDetails enabled={false} summary="Request tools">
      <Draft />
    </WorkflowDetails>,
  );
  expect(container.querySelector('details')).toBeNull();
  expect(screen.getByLabelText('Request draft')).toBeVisible();
  rerender(
    <WorkflowDetails enabled expanded summary="Request tools">
      <Draft />
    </WorkflowDetails>,
  );
  expect(container.querySelector('details')).toBeNull();
  expect(screen.getByLabelText('Request draft')).toBeVisible();
});
