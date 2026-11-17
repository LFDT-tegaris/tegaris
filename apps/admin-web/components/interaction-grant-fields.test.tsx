import { useState } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ciglGrantDefinitionSchema } from '../../../services/control-api/src/configuration/cigl/grant-contract.js';
import { InteractionGrantFields } from './interaction-grant-fields';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const identifier = '018f0000-0000-7000-8000-000000004002';
const definition = {
  runtimeBindingId: `urn:openpc:resource:${identifier}`,
  selector: '0x70a08231',
  subject: { kind: 'ROLE', id: `urn:openpc:role:${identifier}` },
  surface: 'ETH_CALL',
  effect: 'DENY',
};

function Draft({ initial = '', changed = vi.fn() }) {
  const [value, setValue] = useState(initial);
  return (
    <form aria-label="Method grant draft">
      <InteractionGrantFields
        value={value}
        onChange={(next) => {
          changed(next);
          setValue(next);
        }}
      />
    </form>
  );
}

it('builds the owning grant definition from labeled controls without a request', () => {
  const changed = vi.fn();
  const request = vi.spyOn(globalThis, 'fetch');
  render(<Draft changed={changed} />);
  fireEvent.change(screen.getByLabelText('Runtime binding reference'), {
    target: { value: definition.runtimeBindingId },
  });
  fireEvent.change(screen.getByLabelText('Method selector'), {
    target: { value: definition.selector },
  });
  fireEvent.change(screen.getByLabelText('Recipient type'), { target: { value: 'ROLE' } });
  fireEvent.change(screen.getByLabelText('Role reference'), {
    target: { value: definition.subject.id },
  });
  fireEvent.change(screen.getByLabelText('Interface'), { target: { value: 'ETH_CALL' } });
  fireEvent.change(screen.getByLabelText('Decision'), { target: { value: 'DENY' } });
  const result = JSON.parse(changed.mock.lastCall![0]);
  expect(result).toEqual(definition);
  expect(ciglGrantDefinitionSchema.parse(result)).toEqual(definition);
  expect(screen.getByLabelText('Grant definition')).not.toBeVisible();
  expect(request).not.toHaveBeenCalled();
});

it.each([
  ['ROLE', 'Role reference', `urn:openpc:role:${identifier}`],
  ['USER', 'User identifier', identifier],
  ['GROUP', 'Group identifier', identifier],
  ['WORKLOAD', 'Workload reference', `urn:openpc:workload:${identifier}`],
  ['PARTICIPANT', 'Participant identifier', identifier],
  ['ANY_AUTHENTICATED', '', ''],
] as const)('preserves the owning %s subject representation', (kind, label, reference) => {
  const changed = vi.fn();
  render(<Draft initial={JSON.stringify(definition)} changed={changed} />);
  fireEvent.change(screen.getByLabelText('Recipient type'), { target: { value: kind } });
  if (reference) fireEvent.change(screen.getByLabelText(label), { target: { value: reference } });
  const subject = kind === 'ANY_AUTHENTICATED' ? { kind } : { kind, id: reference };
  const result = JSON.parse(changed.mock.lastCall![0]);
  expect(result).toEqual({ ...definition, subject });
  expect(ciglGrantDefinitionSchema.parse(result)).toEqual(result);
  if (kind === 'ANY_AUTHENTICATED') {
    expect(screen.queryByLabelText('Recipient reference')).toBeNull();
    expect(screen.getByText(/This rule concerns any authenticated subject/)).toBeVisible();
    expect(result.subject).not.toHaveProperty('id');
  }
});

it.each([
  'ETH_CALL',
  'ETH_ESTIMATE_GAS',
  'PREPARE_WRITE',
  'RAW_SUBMISSION',
  'DEPLOYMENT_CONSTRUCTOR',
  'RUNTIME_WRITE_TRACE',
])('keeps the exact %s interface value', (surface) => {
  const changed = vi.fn();
  render(<Draft initial={JSON.stringify(definition)} changed={changed} />);
  fireEvent.change(screen.getByLabelText('Interface'), { target: { value: surface } });
  expect(ciglGrantDefinitionSchema.parse(JSON.parse(changed.mock.lastCall![0]))).toEqual({
    ...definition,
    surface,
  });
});

it('clears a recipient reference only when its type is explicitly changed', () => {
  const changed = vi.fn();
  render(<Draft initial={JSON.stringify(definition)} changed={changed} />);
  fireEvent.change(screen.getByLabelText('Recipient type'), { target: { value: 'WORKLOAD' } });
  expect(JSON.parse(changed.mock.lastCall![0])).toEqual({
    ...definition,
    subject: { kind: 'WORKLOAD' },
  });
  expect(screen.getByLabelText('Workload reference')).toHaveValue('');
  expect(screen.getByLabelText('Workload reference')).toBeInvalid();
});

it('requires explicit choices and preserves the selector representation', () => {
  const changed = vi.fn();
  render(<Draft changed={changed} />);
  for (const label of ['Recipient type', 'Interface', 'Decision']) {
    expect(screen.getByLabelText(label)).toHaveValue('');
    expect(screen.getByLabelText(label)).toBeInvalid();
  }
  expect(changed).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Method selector'), { target: { value: '0xABCDEF12' } });
  expect(screen.getByLabelText('Method selector')).toHaveValue('0xABCDEF12');
  expect(screen.getByLabelText('Method selector')).toBeInvalid();
  expect(JSON.parse(changed.mock.lastCall![0])).toEqual({ selector: '0xABCDEF12' });
  fireEvent.change(screen.getByLabelText('Method selector'), { target: { value: '0x00000000' } });
  expect(screen.getByLabelText('Method selector')).toBeValid();
});

it.each([
  '{invalid',
  '[]',
  'null',
  '{"unexpected":"keep"}',
  '{"selector":123}',
  '{"subject":{"kind":"UNKNOWN"}}',
  '{"subject":{"kind":"ROLE","privateField":"keep"}}',
  '{"subject":{"kind":"ANY_AUTHENTICATED","id":"keep"}}',
  '{"subject":{"kind":"ROLE","id":123}}',
  '{"surface":"UNKNOWN"}',
  '{"effect":"UNKNOWN"}',
])('retains an incompatible draft byte for byte: %s', (value) => {
  const changed = vi.fn();
  render(<InteractionGrantFields value={value} onChange={changed} />);
  expect(screen.getByRole('alert')).toBeVisible();
  expect(screen.queryByLabelText('Method selector')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Edit grant JSON' }));
  expect(screen.getByLabelText('Grant definition')).toBeVisible();
  expect(screen.getByLabelText('Grant definition')).toHaveValue(value);
  expect(changed).not.toHaveBeenCalled();
});

it('keeps JSON editing open through partial edits and returns focus without discarding changes', () => {
  render(<Draft initial={JSON.stringify(definition)} />);
  const trigger = screen.getByRole('button', { name: 'Edit grant JSON' });
  fireEvent.click(trigger);
  const editor = screen.getByLabelText('Grant definition');
  fireEvent.change(editor, { target: { value: '{' } });
  expect(screen.getByRole('dialog', { name: 'Edit grant JSON' })).toBeVisible();
  fireEvent.change(editor, {
    target: { value: JSON.stringify({ ...definition, effect: 'ALLOW' }) },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Close Edit grant JSON' }));
  expect(trigger).toHaveFocus();
  expect(screen.getByLabelText('Decision')).toHaveValue('ALLOW');
});

it('shows only the current controlled definition after replacement or clearing', () => {
  const changed = vi.fn();
  const { rerender } = render(
    <InteractionGrantFields value={JSON.stringify(definition)} onChange={changed} />,
  );
  rerender(
    <InteractionGrantFields value={JSON.stringify({ effect: 'ALLOW' })} onChange={changed} />,
  );
  expect(screen.getByLabelText('Decision')).toHaveValue('ALLOW');
  expect(screen.getByLabelText('Runtime binding reference')).toHaveValue('');
  expect(screen.getByLabelText('Recipient type')).toHaveValue('');
  rerender(<InteractionGrantFields value="" onChange={changed} />);
  expect(screen.getByLabelText('Decision')).toHaveValue('');
  expect(screen.getByLabelText('Grant definition')).toHaveValue('');
  expect(changed).not.toHaveBeenCalled();
});

it('inherits the existing workflow lock for every input and the JSON editor', () => {
  render(
    <fieldset disabled>
      <InteractionGrantFields value={JSON.stringify(definition)} onChange={vi.fn()} />
    </fieldset>,
  );
  for (const label of [
    'Runtime binding reference',
    'Method selector',
    'Recipient type',
    'Role reference',
    'Interface',
    'Decision',
    'Grant definition',
  ])
    expect(screen.getByLabelText(label)).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Edit grant JSON' })).toBeDisabled();
});
