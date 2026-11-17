import { useState } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { PolicyDocumentInput } from './policy-document-input';
import {
  clearPolicyWorkflowStorage,
  transactionWorkflowPrivacyEvent,
} from './policy-workflow-storage';
import { notifySessionTransition } from './session-transition';
const actor = {
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  contextEpoch: '2',
};
const document = {
  schemaVersion: '1.0.0',
  participantId: actor.participantId,
  privacyDomainId: actor.privacyDomainId,
  moduleBindings: [],
  rpcPolicies: [],
  contractPolicies: [],
  requiredFacts: [],
};
const disclosureDocument = {
  ...document,
  visibilityPolicies: [
    {
      policyId: '018f0000-0000-7000-8000-000000000901',
      selector: {
        kind: 'TRANSACTION',
        runtimeBindingId: '018f0000-0000-7000-8000-000000000902',
        bindingRevision: '1',
      },
      mode: 'STATIC',
      effect: 'ALLOW',
      subject: { kind: 'PRINCIPAL', principalId: actor.principalId },
      purpose: 'AUDIT',
      requiredRoles: ['reader'],
      dimensions: ['EXISTENCE', 'METADATA', 'PAYLOAD'],
      fields: ['from', 'to', 'value'],
      conditions: [],
    },
  ],
};

it('starts a blank policy file form when the authenticated workspace arrives', async () => {
  const onChange = vi.fn(),
    view = render(<PolicyDocumentInput value="" onChange={onChange} />);
  expect(screen.getByLabelText('Policy file')).toBeDisabled();
  expect(screen.getByRole('status')).toHaveTextContent('Load the current workspace');
  view.rerender(<PolicyDocumentInput actor={actor} value="" onChange={onChange} />);
  await waitFor(() => expect(screen.getByLabelText('Policy file')).toBeEnabled());
  expect(screen.getByRole('status')).toHaveTextContent('Choose a policy file to begin.');
  expect(onChange).not.toHaveBeenCalled();
});
it('does not attach an existing unbound draft to a newly loaded workspace', () => {
  const onChange = vi.fn(),
    value = JSON.stringify(disclosureDocument),
    view = render(<PolicyDocumentInput value={value} onChange={onChange} />);
  view.rerender(<PolicyDocumentInput actor={actor} value={value} onChange={onChange} />);
  expect(screen.getByRole('status')).toHaveTextContent('Reload the current workspace');
  expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue('');
  expect(screen.queryByRole('region', { name: 'Disclosure permissions' })).not.toBeInTheDocument();
  expect(onChange).not.toHaveBeenCalled();
});
it('keeps an invalidated blank draft fenced after the session is revalidated', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ authenticated: true, contextMode: 'PARTICIPANT', ...actor })),
  );
  const onChange = vi.fn();
  render(<PolicyDocumentInput actor={actor} value="" onChange={onChange} />);
  expect(screen.getByRole('status')).toHaveTextContent('Choose a policy file to begin.');
  act(() => {
    clearPolicyWorkflowStorage();
    window.dispatchEvent(new Event(transactionWorkflowPrivacyEvent));
  });
  await waitFor(() => expect(screen.getByLabelText('Policy file')).toBeEnabled());
  expect(screen.getByRole('status')).toHaveTextContent('Reload the current workspace');
  expect(onChange).not.toHaveBeenCalled();
});

it('edits disclosure with controls, restores deselected choices and preserves rule prerequisites', async () => {
  const onChange = vi.fn();
  render(<Host initial={JSON.stringify(disclosureDocument)} onChange={onChange} />);
  const region = screen.getByRole('region', { name: 'Disclosure permissions' });
  expect(region).toBeVisible();
  expect(screen.getByLabelText('Typed policy document (JSON)')).not.toBeVisible();
  await userEvent.click(screen.getByLabelText('from'));
  let parsed = JSON.parse(onChange.mock.lastCall![0]);
  expect(parsed).toEqual({
    ...disclosureDocument,
    visibilityPolicies: [{ ...disclosureDocument.visibilityPolicies[0], fields: ['to', 'value'] }],
  });
  expect(screen.getByLabelText('from')).not.toBeChecked();
  await userEvent.click(screen.getByText('Edit policy JSON'));
  const editor = screen.getByRole('textbox', { name: 'Typed policy document (JSON)' });
  expect(editor).toHaveAccessibleName('Typed policy document (JSON)');
  expect(editor).toHaveValue(onChange.mock.lastCall![0]);
  await userEvent.click(screen.getByText('Edit policy JSON'));
  await userEvent.click(screen.getByLabelText('from'));
  expect(screen.getByLabelText('from')).toBeChecked();
  await userEvent.selectOptions(screen.getByLabelText('Response permission'), 'DENY');
  expect(screen.getByLabelText('Payload')).toBeDisabled();
  expect(screen.getByLabelText('from')).toBeDisabled();
  await userEvent.selectOptions(screen.getByLabelText('Response permission'), 'ALLOW');
  expect(screen.getByLabelText('Payload')).toBeEnabled();
  parsed = JSON.parse(onChange.mock.lastCall![0]);
  expect(parsed.visibilityPolicies[0].requiredRoles).toEqual(['reader']);
  expect(parsed.visibilityPolicies[0].subject).toEqual(
    disclosureDocument.visibilityPolicies[0]!.subject,
  );
  expect(parsed.visibilityPolicies[0].selector).toEqual(
    disclosureDocument.visibilityPolicies[0]!.selector,
  );
  expect(parsed.visibilityPolicies[0].conditions).toEqual([]);
});
it('keeps the current draft when the last payload field is deselected', async () => {
  const initial = {
      ...disclosureDocument,
      visibilityPolicies: [{ ...disclosureDocument.visibilityPolicies[0], fields: ['value'] }],
    },
    onChange = vi.fn();
  render(<Host initial={JSON.stringify(initial)} onChange={onChange} />);
  await userEvent.click(screen.getByLabelText('value'));
  expect(screen.getByRole('alert')).toHaveTextContent('Payload also requires a selected field');
  expect(screen.getByLabelText('value')).toBeChecked();
  expect(onChange).not.toHaveBeenCalled();
});
it.each(['actor', 'blur', 'privacy', 'transition'] as const)(
  'conceals guided rule subjects and controls on %s invalidation',
  async (kind) => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json({ authenticated: true, contextMode: 'PARTICIPANT', ...actor }),
      ),
    );
    const onChange = vi.fn(),
      value = JSON.stringify(disclosureDocument),
      view = render(<PolicyDocumentInput actor={actor} value={value} onChange={onChange} />);
    await userEvent.click(screen.getByText('Subject and rule references'));
    expect(screen.getByText('reader')).toBeVisible();
    let nonce: string | undefined;
    act(() => {
      if (kind === 'actor')
        view.rerender(
          <PolicyDocumentInput
            actor={{ ...actor, contextEpoch: '3' }}
            value={value}
            onChange={onChange}
          />,
        );
      else if (kind === 'privacy') {
        clearPolicyWorkflowStorage();
        window.dispatchEvent(new Event(transactionWorkflowPrivacyEvent));
      } else if (kind === 'transition') nonce = notifySessionTransition('changing');
      else window.dispatchEvent(new Event('blur'));
    });
    expect(
      screen.queryByRole('region', { name: 'Disclosure permissions' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText('reader')).not.toBeInTheDocument();
    expect(onChange).not.toHaveBeenCalled();
    if (nonce) {
      act(() => {
        notifySessionTransition('settled', nonce);
      });
      await waitFor(() => expect(screen.getByLabelText('Policy file')).toBeEnabled());
    }
    if (kind === 'privacy') {
      await waitFor(() => expect(screen.getByLabelText('Policy file')).toBeEnabled());
      expect(
        screen.queryByRole('region', { name: 'Disclosure permissions' }),
      ).not.toBeInTheDocument();
    }
  },
);
it('keeps guided choices after a foreign import and replaces their baseline only with explicit new input', async () => {
  render(<Host initial={JSON.stringify(disclosureDocument)} />);
  await userEvent.click(screen.getByLabelText('from'));
  await userEvent.upload(
    screen.getByLabelText('Policy file'),
    new File(
      [JSON.stringify({ ...disclosureDocument, privacyDomainId: 'foreign' })],
      'foreign.json',
      { type: 'application/json' },
    ),
  );
  expect(await screen.findByRole('alert')).toHaveTextContent('The existing draft has been kept.');
  expect(screen.getByLabelText('from')).not.toBeChecked();
  await userEvent.click(screen.getByLabelText('from'));
  expect(screen.getByLabelText('from')).toBeChecked();
  const next = {
    ...disclosureDocument,
    visibilityPolicies: [{ ...disclosureDocument.visibilityPolicies[0], fields: ['value'] }],
  };
  await userEvent.upload(
    screen.getByLabelText('Policy file'),
    new File([JSON.stringify(next)], 'next.json', { type: 'application/json' }),
  );
  await waitFor(() => expect(screen.queryByLabelText('from')).not.toBeInTheDocument());
  expect(screen.getByLabelText('value')).toBeChecked();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function Host({
  initial = '',
  onChange = () => {},
}: {
  initial?: string;
  onChange?: (value: string) => void;
}) {
  const [value, setValue] = useState(initial);
  return (
    <PolicyDocumentInput
      actor={actor}
      value={value}
      onChange={(v) => {
        setValue(v);
        onChange(v);
      }}
    />
  );
}
it('imports a real local file, shows draft review, and keeps raw JSON secondary', async () => {
  const onChange = vi.fn();
  render(<Host onChange={onChange} />);
  expect(screen.getByLabelText('Typed policy document (JSON)')).not.toBeVisible();
  const text = JSON.stringify(document, null, 2);
  await userEvent.upload(
    screen.getByLabelText('Policy file'),
    new File([text], 'rules.json', { type: 'application/json' }),
  );
  await screen.findByRole('region', { name: 'Policy draft review' });
  expect(onChange).toHaveBeenCalledExactlyOnceWith(text);
  expect(screen.getByText('rules.json')).toBeVisible();
  expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue(text);
  expect(screen.getByText(/still require validation when you create the version/)).toBeVisible();
});
it.each(['actor', 'blur', 'privacy'] as const)(
  'conceals an imported filename after %s invalidation',
  async (change) => {
    function BoundHost({ binding = actor }: { binding?: typeof actor }) {
      const [value, setValue] = useState('');
      return (
        <PolicyDocumentInput actor={binding} value={value} onChange={(next) => setValue(next)} />
      );
    }
    const filename = 'treasury-policy-private-review.json';
    const view = render(<BoundHost />);
    await userEvent.upload(
      screen.getByLabelText('Policy file'),
      new File([JSON.stringify(document)], filename, { type: 'application/json' }),
    );
    expect(await screen.findByText(filename)).toBeVisible();
    if (change === 'actor')
      view.rerender(
        <BoundHost binding={{ ...actor, principalId: '018f0000-0000-7000-8000-000000000199' }} />,
      );
    else fireEvent(window, new Event(change === 'blur' ? 'blur' : transactionWorkflowPrivacyEvent));
    expect(screen.queryByText(filename)).toBeNull();
    expect(screen.queryByRole('region', { name: 'Policy draft review' })).toBeNull();
  },
);
it('rejects a foreign file and preserves the existing draft', async () => {
  const initial = JSON.stringify(document),
    onChange = vi.fn();
  render(<Host initial={initial} onChange={onChange} />);
  await userEvent.upload(
    screen.getByLabelText('Policy file'),
    new File([JSON.stringify({ ...document, privacyDomainId: 'foreign' })], 'rules.json', {
      type: 'application/json',
    }),
  );
  await screen.findByRole('alert');
  expect(screen.getByRole('alert')).toHaveTextContent('different workspace');
  expect(screen.queryByText('rules.json')).toBeNull();
  expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue(initial);
  expect(onChange).not.toHaveBeenCalled();
});
it('rejects oversize files before reading bytes', async () => {
  const read = vi.spyOn(FileReader.prototype, 'readAsArrayBuffer');
  render(<Host />);
  await userEvent.upload(
    screen.getByLabelText('Policy file'),
    new File(['x'.repeat(1_048_577)], 'rules.json', { type: 'application/json' }),
  );
  await screen.findByRole('alert');
  expect(read).not.toHaveBeenCalled();
});
it.each(['actor', 'blur', 'privacy'] as const)(
  'discards late file bytes after %s invalidation',
  async (change) => {
    const readers: FileReader[] = [];
    vi.spyOn(FileReader.prototype, 'readAsArrayBuffer').mockImplementation(function (
      this: FileReader,
    ) {
      readers.push(this);
    });
    const onChange = vi.fn(),
      view = render(<PolicyDocumentInput actor={actor} value="" onChange={onChange} />);
    await userEvent.upload(
      screen.getByLabelText('Policy file'),
      new File([JSON.stringify(document)], 'rules.json', { type: 'application/json' }),
    );
    await waitFor(() => expect(readers).toHaveLength(1));
    const pending = readers[0]!;
    if (change === 'actor')
      view.rerender(
        <PolicyDocumentInput
          actor={{ ...actor, principalId: '018f0000-0000-7000-8000-000000000199' }}
          value=""
          onChange={onChange}
        />,
      );
    else fireEvent(window, new Event(change === 'blur' ? 'blur' : transactionWorkflowPrivacyEvent));
    Object.defineProperty(pending!, 'result', {
      value: new TextEncoder().encode(JSON.stringify(document)).buffer,
      configurable: true,
    });
    await act(async () => pending.dispatchEvent(new ProgressEvent('load')));
    await waitFor(() =>
      expect(screen.getByRole('region', { name: 'Policy document' })).toHaveAttribute(
        'aria-busy',
        'false',
      ),
    );
    expect(onChange).not.toHaveBeenCalled();
    expect(screen.queryByRole('region', { name: 'Policy draft review' })).not.toBeInTheDocument();
  },
);
it.each([
  { sessionId: '018f0000-0000-7000-8000-000000000199' },
  { principalId: '018f0000-0000-7000-8000-000000000199' },
  { participantId: '018f0000-0000-7000-8000-000000000199' },
  { privacyDomainId: '018f0000-0000-7000-8000-000000000199' },
  { contextEpoch: '3' },
])(
  'withholds an unchanged old draft from both review and editor after actor change %j',
  (change) => {
    const value = JSON.stringify(document),
      onChange = vi.fn(),
      view = render(<PolicyDocumentInput actor={actor} value={value} onChange={onChange} />);
    expect(screen.getByRole('region', { name: 'Policy draft review' })).toBeVisible();
    expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue(value);
    view.rerender(
      <PolicyDocumentInput actor={{ ...actor, ...change }} value={value} onChange={onChange} />,
    );
    expect(screen.queryByRole('region', { name: 'Policy draft review' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue('');
    expect(onChange).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Policy file')).toBeEnabled();
  },
);
it('keeps loaded content concealed until native actor revalidation and rejects a different account', async () => {
  let complete!: (response: Response) => void;
  const fetch = vi.fn(
    () =>
      new Promise<Response>((resolve) => {
        complete = resolve;
      }),
  );
  vi.stubGlobal('fetch', fetch);
  render(<Host initial={JSON.stringify(document)} />);
  await userEvent.click(screen.getByText('Edit policy JSON'));
  expect(screen.getByLabelText('Typed policy document (JSON)')).toBeVisible();
  let nonce: string | undefined;
  act(() => {
    nonce = notifySessionTransition('changing');
  });
  act(() => {
    notifySessionTransition('settled', nonce);
  });
  expect(fetch).toHaveBeenCalledExactlyOnceWith(
    '/api/v1/ui/local-session',
    expect.objectContaining({
      cache: 'no-store',
      credentials: 'same-origin',
      signal: expect.any(AbortSignal),
    }),
  );
  expect(screen.queryByRole('region', { name: 'Policy draft review' })).not.toBeInTheDocument();
  expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue('');
  expect(screen.getByLabelText('Policy file')).toBeDisabled();
  await act(async () => {
    complete(
      Response.json({
        authenticated: true,
        contextMode: 'PARTICIPANT',
        ...actor,
        principalId: '018f0000-0000-7000-8000-000000000199',
      }),
    );
  });
  expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue('');
  expect(screen.getByLabelText('Policy file')).toBeDisabled();
});
it('invalidates an expanded loaded draft on privacy cleanup and requires explicit fresh input', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json({ authenticated: true, contextMode: 'PARTICIPANT', ...actor })),
  );
  const onChange = vi.fn();
  render(<Host initial={JSON.stringify(document)} onChange={onChange} />);
  await userEvent.click(screen.getByText('Edit policy JSON'));
  act(() => {
    clearPolicyWorkflowStorage();
    window.dispatchEvent(new Event(transactionWorkflowPrivacyEvent));
  });
  await waitFor(() => expect(screen.getByLabelText('Policy file')).toBeEnabled());
  expect(screen.queryByRole('region', { name: 'Policy draft review' })).not.toBeInTheDocument();
  expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue('');
  expect(onChange).not.toHaveBeenCalled();
  await userEvent.upload(
    screen.getByLabelText('Policy file'),
    new File([JSON.stringify(document)], 'rules.json', { type: 'application/json' }),
  );
  await screen.findByRole('region', { name: 'Policy draft review' });
  expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue(
    JSON.stringify(document),
  );
  expect(onChange).toHaveBeenCalledExactlyOnceWith(JSON.stringify(document));
});
it('discards a late session read after privacy cleanup instead of restoring the old projection', async () => {
  const reads: { complete(response: Response): void; signal: AbortSignal }[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(
      (_url: string, init: RequestInit) =>
        new Promise<Response>((resolve) =>
          reads.push({ complete: resolve, signal: init.signal as AbortSignal }),
        ),
    ),
  );
  render(<Host initial={JSON.stringify(document)} />);
  let nonce: string | undefined;
  act(() => {
    nonce = notifySessionTransition('changing');
    notifySessionTransition('settled', nonce);
  });
  act(() => {
    clearPolicyWorkflowStorage();
    window.dispatchEvent(new Event(transactionWorkflowPrivacyEvent));
  });
  expect(reads).toHaveLength(2);
  expect(reads[0]!.signal.aborted).toBe(true);
  await act(async () => {
    reads[0]!.complete(
      Response.json({ authenticated: true, contextMode: 'PARTICIPANT', ...actor }),
    );
  });
  expect(screen.getByLabelText('Policy file')).toBeDisabled();
  await act(async () => {
    reads[1]!.complete(
      Response.json({ authenticated: true, contextMode: 'PARTICIPANT', ...actor }),
    );
  });
  expect(screen.getByLabelText('Policy file')).toBeEnabled();
  expect(screen.getByLabelText('Typed policy document (JSON)')).toHaveValue('');
  expect(screen.queryByRole('region', { name: 'Policy draft review' })).not.toBeInTheDocument();
});
it('does not become stuck busy when a file-selection event arrives during native focus revalidation', async () => {
  let complete!: (response: Response) => void;
  vi.stubGlobal(
    'fetch',
    vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          complete = resolve;
        }),
    ),
  );
  const read = vi.spyOn(FileReader.prototype, 'readAsArrayBuffer');
  render(<Host />);
  fireEvent(window, new Event('blur'));
  fireEvent(window, new Event('focus'));
  const selected = new File([JSON.stringify(document)], 'rules.json', { type: 'application/json' });
  fireEvent.change(screen.getByLabelText('Policy file'), {
    target: {
      files: { 0: selected, length: 1, item: (index: number) => (index === 0 ? selected : null) },
    },
  });
  expect(read).not.toHaveBeenCalled();
  expect(screen.getByRole('region', { name: 'Policy document' })).toHaveAttribute(
    'aria-busy',
    'false',
  );
  await act(async () => {
    complete(Response.json({ authenticated: true, contextMode: 'PARTICIPANT', ...actor }));
  });
  expect(screen.getByLabelText('Policy file')).toBeEnabled();
  expect(screen.getByRole('region', { name: 'Policy document' })).toHaveAttribute(
    'aria-busy',
    'false',
  );
  await userEvent.upload(
    screen.getByLabelText('Policy file'),
    new File([JSON.stringify(document)], 'rules.json', { type: 'application/json' }),
  );
  await screen.findByRole('region', { name: 'Policy draft review' });
});
