import { useState } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { InteractionAnalysisFields } from './interaction-analysis-fields';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const definition = {
  targetRuntimeId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000004001',
  expectedGenerationDigest: `sha256:${'1'.repeat(64)}`,
  runtimeBindingId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000004002',
  contractMethodPolicyId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000004003',
  expectedRuntimeBindingRevision: '3',
  expectedMethodRevision: '2',
  workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000004004',
  transactionHash: `0x${'2'.repeat(64)}`,
  expiresInSeconds: 300,
};

function Draft({ initial = '', changed = vi.fn() }) {
  const [value, setValue] = useState(initial);
  return (
    <form>
      <InteractionAnalysisFields
        value={value}
        onChange={(next) => {
          changed(next);
          setValue(next);
        }}
      />
    </form>
  );
}

it('builds the existing definition from labeled inputs without issuing a request', () => {
  const changed = vi.fn();
  const request = vi.spyOn(globalThis, 'fetch');
  render(<Draft changed={changed} />);
  for (const [label, value] of [
    ['Runtime target reference', definition.targetRuntimeId],
    ['Installed generation digest', definition.expectedGenerationDigest],
    ['Runtime binding reference', definition.runtimeBindingId],
    ['Method policy reference', definition.contractMethodPolicyId],
    ['Runtime binding revision', definition.expectedRuntimeBindingRevision],
    ['Method policy revision', definition.expectedMethodRevision],
    ['Workload reference', definition.workloadId],
    ['Transaction hash', definition.transactionHash],
    ['Analysis lifetime (seconds)', '300'],
  ] as const)
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  expect(JSON.parse(changed.mock.lastCall![0])).toEqual(definition);
  expect(screen.getByLabelText('Analysis definition')).not.toBeVisible();
  expect(screen.getByRole('group', { name: 'Contract and method' })).toBeVisible();
  expect(request).not.toHaveBeenCalled();
});

it('preserves large revision strings and every other binding when one field changes', () => {
  const changed = vi.fn();
  const original = { ...definition, expectedMethodRevision: '99999999999999999999' };
  render(<Draft initial={JSON.stringify(original)} changed={changed} />);
  fireEvent.change(screen.getByLabelText('Transaction hash'), {
    target: { value: `0x${'3'.repeat(64)}` },
  });
  expect(JSON.parse(changed.mock.lastCall![0])).toEqual({
    ...original,
    transactionHash: `0x${'3'.repeat(64)}`,
  });
});

it('keeps the lifetime numeric, enforces its browser bounds and never substitutes a default', () => {
  const changed = vi.fn();
  render(<Draft initial={JSON.stringify(definition)} changed={changed} />);
  const lifetime = screen.getByLabelText('Analysis lifetime (seconds)');
  for (const value of ['29', '901', '30.5']) {
    fireEvent.change(lifetime, { target: { value } });
    expect(lifetime).toBeInvalid();
  }
  for (const value of ['30', '900']) {
    fireEvent.change(lifetime, { target: { value } });
    expect(lifetime).toBeValid();
    expect(JSON.parse(changed.mock.lastCall![0]).expiresInSeconds).toBe(Number(value));
  }
  fireEvent.change(lifetime, { target: { value: '' } });
  expect(lifetime).toBeInvalid();
  expect(JSON.parse(changed.mock.lastCall![0])).not.toHaveProperty('expiresInSeconds');
});

it.each(['{invalid', '[]', '{"extra":"retain-me"}', '{"expiresInSeconds":"300"}'])(
  'preserves a definition needing JSON editing byte for byte: %s',
  (value) => {
    const changed = vi.fn();
    render(<InteractionAnalysisFields value={value} onChange={changed} />);
    expect(screen.getByRole('alert')).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: 'Edit analysis JSON' }));
    expect(screen.getByLabelText('Analysis definition')).toBeVisible();
    expect(screen.getByLabelText('Analysis definition')).toHaveValue(value);
    expect(screen.queryByLabelText('Transaction hash')).toBeNull();
    expect(changed).not.toHaveBeenCalled();
  },
);

it('synchronizes JSON edits with the form and keeps the draft when the editor closes', () => {
  render(<Draft initial={JSON.stringify(definition)} />);
  const trigger = screen.getByRole('button', { name: 'Edit analysis JSON' });
  fireEvent.click(trigger);
  const editor = screen.getByLabelText('Analysis definition');
  expect(editor).toBeVisible();
  fireEvent.change(editor, { target: { value: '{' } });
  expect(screen.getByRole('dialog', { name: 'Edit analysis JSON' })).toBeVisible();
  expect(editor).toBeVisible();
  fireEvent.change(editor, {
    target: { value: JSON.stringify({ ...definition, expectedMethodRevision: '9' }) },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Close Edit analysis JSON' }));
  expect(trigger).toHaveFocus();
  expect(screen.getByLabelText('Method policy revision')).toHaveValue('9');
  fireEvent.click(trigger);
  expect(JSON.parse((editor as HTMLTextAreaElement).value).expectedMethodRevision).toBe('9');
});

it('shows only the current controlled draft after its owner replaces or clears it', () => {
  const changed = vi.fn();
  const { rerender } = render(
    <InteractionAnalysisFields value={JSON.stringify(definition)} onChange={changed} />,
  );
  rerender(
    <InteractionAnalysisFields
      value={JSON.stringify({ transactionHash: 'replacement' })}
      onChange={changed}
    />,
  );
  expect(screen.getByLabelText('Transaction hash')).toHaveValue('replacement');
  expect(screen.getByLabelText('Runtime target reference')).toHaveValue('');
  rerender(<InteractionAnalysisFields value="" onChange={changed} />);
  expect(screen.getByLabelText('Transaction hash')).toHaveValue('');
  expect(screen.getByLabelText('Analysis definition')).toHaveValue('');
  expect(changed).not.toHaveBeenCalled();
});

it('inherits the workflow lock for the guided inputs and JSON editor', () => {
  const changed = vi.fn();
  render(
    <fieldset disabled>
      <InteractionAnalysisFields value={JSON.stringify(definition)} onChange={changed} />
    </fieldset>,
  );
  expect(screen.getByLabelText('Transaction hash')).toBeDisabled();
  expect(screen.getByLabelText('Analysis definition')).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Edit analysis JSON' })).toBeDisabled();
  expect(changed).not.toHaveBeenCalled();
});
