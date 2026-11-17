import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { PolicyVersionPicker } from './policy-version-picker';
const id = (n: number) => `018f0000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const actor = {
  sessionId: id(117),
  principalId: id(111),
  participantId: id(101),
  privacyDomainId: id(201),
  contextEpoch: '2',
};
const version = {
  policyVersionId: `urn:openpc:policy-version:${id(921)}`,
  policySetId: `urn:openpc:policy-set:${id(920)}`,
  semanticVersion: '1.2.0',
  normalizedPolicyDigest: `sha256:${'a1'.repeat(32)}`,
  dependencyClosureDigest: `sha256:${'b2'.repeat(32)}`,
  state: 'DRAFT',
  revision: '1',
  createdAt: '2026-09-22T15:01:01.123456Z',
  updatedAt: '2026-09-22T15:01:01.123456Z',
};
const page = {
  actor,
  policySetId: version.policySetId,
  items: [version],
  nextCursor: null,
  total: '1',
  completeness: 'COMPLETE',
  authorizedEmpty: false,
  snapshotRevision: '1',
};
const props = {
  actor,
  policySetId: version.policySetId,
  enabled: true,
  selected: '',
  onVerified: vi.fn(),
  onInvalidated: vi.fn(),
};

it('keeps six readable rows per local page and only requests the native cursor after exhausting them', async () => {
  const rows = Array.from({ length: 7 }, (_, index) => ({
    ...version,
    policyVersionId: `urn:openpc:policy-version:${id(921 + index)}`,
    semanticVersion: `1.2.${index}`,
  }));
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(
      Response.json({ ...page, items: rows, total: '8', nextCursor: 'native-next' }),
    );
  render(<PolicyVersionPicker {...props} />);
  await screen.findByRole('button', { name: /Review version 1[.]2[.]0/ });
  expect(screen.getAllByRole('button', { name: /Review version/ })).toHaveLength(6);
  await userEvent.click(screen.getByRole('button', { name: 'Next versions' }));
  await screen.findByRole('button', { name: /Review version 1[.]2[.]6/ });
  expect(fetch).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole('button', { name: 'Next versions' }));
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  expect(String(fetch.mock.calls[1]![0])).toContain('cursor=native-next');
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  props.onVerified.mockClear();
  props.onInvalidated.mockClear();
});
it('lets a keyboard user choose a version and verifies exact owner metadata before marking it selected', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (url) =>
      Response.json(String(url).includes('policyVersionId=') ? { actor, version } : page),
    );
  render(<PolicyVersionPicker {...props} />);
  const choice = await screen.findByRole('button', { name: /Review version 1[.]2[.]0/ });
  const user = userEvent.setup();
  choice.focus();
  await user.keyboard('{Enter}');
  await screen.findByText('Version 1.2.0 selected');
  expect(props.onVerified).toHaveBeenCalledWith({ actor, version });
  expect(choice).toHaveAttribute('aria-pressed', 'true');
  expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
  expect(
    fetch.mock.calls.every(([, options]) => !options?.method || options.method === 'GET'),
  ).toBe(true);
  expect(screen.getByText(version.normalizedPolicyDigest).closest('details')).not.toHaveAttribute(
    'open',
  );
});
it.each(['principalId', 'sessionId', 'contextEpoch'] as const)(
  'rejects a collection belonging to another %s',
  async (field) => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      Response.json({
        ...page,
        actor: { ...actor, [field]: field === 'contextEpoch' ? '99' : id(999) },
      }),
    );
    render(<PolicyVersionPicker {...props} />);
    await screen.findByText('Policy versions could not be confirmed. Refresh to try again.');
    expect(screen.queryByText('Version 1.2.0')).not.toBeInTheDocument();
    expect(props.onVerified).not.toHaveBeenCalled();
  },
);
it('withholds a selected version if exact readback differs from the listed digest', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    Response.json(
      String(url).includes('policyVersionId=')
        ? { actor, version: { ...version, normalizedPolicyDigest: `sha256:${'c3'.repeat(32)}` } }
        : page,
    ),
  );
  render(<PolicyVersionPicker {...props} />);
  await userEvent.click(await screen.findByRole('button', { name: /Review version 1[.]2[.]0/ }));
  await screen.findByText('Policy versions could not be confirmed. Refresh to try again.');
  expect(props.onVerified).not.toHaveBeenCalled();
});
it('discards a late owner read after the policy set changes', async () => {
  let finish!: (value: Response) => void;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    String(url).includes('policyVersionId=')
      ? new Promise<Response>((resolve) => {
          finish = resolve;
        })
      : Response.json(page),
  );
  const { rerender } = render(<PolicyVersionPicker {...props} />);
  await userEvent.click(await screen.findByRole('button', { name: /Review version 1[.]2[.]0/ }));
  rerender(<PolicyVersionPicker {...props} policySetId={`urn:openpc:policy-set:${id(999)}`} />);
  await act(async () => finish(Response.json({ actor, version })));
  expect(props.onVerified).not.toHaveBeenCalled();
  expect(screen.queryByText('Version 1.2.0 selected')).not.toBeInTheDocument();
});
it('clears selection and protected metadata on blur without issuing a command', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    Response.json(String(url).includes('policyVersionId=') ? { actor, version } : page),
  );
  render(<PolicyVersionPicker {...props} />);
  await userEvent.click(await screen.findByRole('button', { name: /Review version 1[.]2[.]0/ }));
  await screen.findByText('Version 1.2.0 selected');
  fireEvent(window, new Event('blur'));
  await waitFor(() => expect(screen.queryByText('Version 1.2.0 selected')).not.toBeInTheDocument());
  expect(screen.queryByText(version.normalizedPolicyDigest)).not.toBeInTheDocument();
  expect(props.onInvalidated).toHaveBeenCalled();
});
it('distinguishes genuine authorized empty data from a denied list', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({ ...page, items: [], total: '0', authorizedEmpty: true }),
  );
  render(<PolicyVersionPicker {...props} />);
  await screen.findByText('No versions are available in this policy set for your current access.');
  expect(props.onVerified).not.toHaveBeenCalled();
});

it('removes a verified version when the actor changes within the same policy set', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    Response.json(String(url).includes('policyVersionId=') ? { actor, version } : page),
  );
  const { rerender } = render(<PolicyVersionPicker {...props} />);
  await userEvent.click(await screen.findByRole('button', { name: /Review version 1[.]2[.]0/ }));
  await screen.findByText('Version 1.2.0 selected');
  rerender(<PolicyVersionPicker {...props} actor={{ ...actor, principalId: id(999) }} />);
  expect(screen.queryByText('Version 1.2.0 selected')).not.toBeInTheDocument();
  expect(screen.queryByText(version.normalizedPolicyDigest)).not.toBeInTheDocument();
});
