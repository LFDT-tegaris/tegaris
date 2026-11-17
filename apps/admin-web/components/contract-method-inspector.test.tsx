import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { ContractMethodInspector } from './contract-method-inspector';
import type { ContractMethodInspection } from '../lib/contract-method-inspection';

const id = (suffix: string) => `018f0000-0000-7000-8000-${suffix.padStart(12, '0')}`;
const ref = (suffix: string) => `urn:openpc:resource:${id(suffix)}`;
const actor = {
  sessionId: id('1'),
  principalId: id('2'),
  participantId: id('3'),
  privacyDomainId: id('4'),
  contextEpoch: '1',
};
const huge = '115792089237316195423570985008687907853269984665640564039457584007913129639935';
const fixture: ContractMethodInspection = {
  actor,
  method: {
    contractMethodPolicyId: ref('10'),
    runtimeBindingId: ref('11'),
    abiArtifactId: ref('12'),
    canonicalSignature: 'transfer(address,uint256)',
    selector: '0xa9059cbb',
    effect: 'WRITE',
    requiredRoles: ['treasury-writer'],
    approvalRequirement: 'MAKER_CHECKER',
    mfaRequirement: 'WEBAUTHN',
    environments: ['LOCAL'],
    argumentRuleVersionId: ref('13'),
    state: 'ACTIVE',
    revision: '9007199254740993',
  },
  binding: {
    runtimeBindingId: ref('11'),
    logicalContractId: ref('14'),
    abiArtifactId: ref('12'),
    contractAddress: `0x${'11'.repeat(20)}`,
    chainId: '31337',
    networkId: 'local',
    state: 'BOUND',
    revision: '1',
  },
  contract: {
    logicalContractId: ref('14'),
    displayName: 'Local token',
    logicalName: 'token',
    revision: '1',
  },
  argumentRules: {
    argumentRuleVersionId: ref('13'),
    runtimeBindingId: ref('11'),
    abiArtifactId: ref('12'),
    canonicalSignature: 'transfer(address,uint256)',
    version: '1.0.0',
    state: 'ACTIVE',
    revision: '1',
    rules: [
      { parameterPath: 'inputs[1]', operandType: 'INTEGER', operator: 'LTE', values: [huge] },
    ],
  },
};
const props = { actor, methodPolicyId: id('10'), authorityContextKey: 'context-one' };
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it.each(['loading', 'loaded'] as const)(
  'allows a fresh read after leaving and returning to a %s selection',
  async (status) => {
    let finish: (response: Response) => void = () => {};
    const pending = new Promise<Response>((resolve) => {
      finish = resolve;
    });
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(Response.json(fixture))
      .mockImplementationOnce(() =>
        status === 'loading' ? pending : Promise.resolve(Response.json(fixture)),
      );
    const user = userEvent.setup();
    const { rerender } = render(<ContractMethodInspector {...props} />);
    await user.click(screen.getByRole('button'));
    if (status === 'loaded') expect(await screen.findByText(huge)).toBeVisible();
    rerender(<ContractMethodInspector {...props} methodPolicyId="invalid" />);
    rerender(<ContractMethodInspector {...props} />);
    expect(screen.getByRole('button')).toBeEnabled();
    expect(screen.queryByText(huge)).not.toBeInTheDocument();
    await act(async () => {
      finish(Response.json(fixture));
    });
    expect(screen.queryByText(huge)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button'));
    expect(await screen.findByText(huge)).toBeVisible();
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);

it('loads configured requirements with a GET and preserves large values exactly', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(fixture));
  const user = userEvent.setup();
  render(<ContractMethodInspector {...props} />);
  expect(fetch).not.toHaveBeenCalled();
  await user.click(screen.getByRole('button', { name: 'Inspect configured method' }));
  expect(await screen.findByText(huge)).toBeVisible();
  expect(screen.getByText('transfer(address,uint256)')).toBeVisible();
  expect(screen.getByText('0xa9059cbb')).toBeVisible();
  expect(screen.getByText('WRITE')).toBeVisible();
  expect(screen.getByText('treasury-writer')).toBeVisible();
  expect(screen.getByText('MAKER_CHECKER')).toBeVisible();
  expect(screen.getByText('WEBAUTHN')).toBeVisible();
  expect(screen.getByText('ACTIVE · revision 9007199254740993')).toBeVisible();
  expect(screen.getByText(/does not grant permission/)).toBeVisible();
  const [url, init] = fetch.mock.calls[0]!;
  expect(String(url)).toContain(encodeURIComponent(ref('10')));
  expect(init).toMatchObject({ credentials: 'same-origin', cache: 'no-store' });
  expect(init?.method).toBeUndefined();
  expect(init?.body).toBeUndefined();
});

it('shows a READ policy with no attached argument rules without implying access', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      ...fixture,
      method: { ...fixture.method, effect: 'READ', argumentRuleVersionId: null },
      argumentRules: null,
    }),
  );
  render(<ContractMethodInspector {...props} />);
  await userEvent.click(screen.getByRole('button', { name: 'Inspect configured method' }));
  expect(await screen.findByText('READ')).toBeVisible();
  expect(screen.getByText(/No argument-rule version is attached/)).toBeVisible();
});

it('renders both normalized BOOLEAN operands while preserving the exact integer operand', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      ...fixture,
      argumentRules: {
        ...fixture.argumentRules,
        rules: [
          ...fixture.argumentRules!.rules,
          {
            parameterPath: 'inputs[0]',
            operandType: 'BOOLEAN',
            operator: 'IN',
            values: ['true', 'false'],
          },
        ],
      },
    }),
  );
  render(<ContractMethodInspector {...props} />);
  await userEvent.click(screen.getByRole('button', { name: 'Inspect configured method' }));
  expect(await screen.findByText('true')).toBeVisible();
  expect(screen.getByText('false')).toBeVisible();
  expect(screen.getByText(huge)).toBeVisible();
});

it('clears the old method immediately and ignores a late previous response', async () => {
  let finish: (response: Response) => void = () => undefined;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  const { rerender } = render(<ContractMethodInspector {...props} />);
  await userEvent.click(screen.getByRole('button', { name: 'Inspect configured method' }));
  expect(screen.getByRole('status')).toHaveTextContent('Loading');
  rerender(<ContractMethodInspector {...props} methodPolicyId={id('20')} />);
  expect(screen.getByRole('status')).not.toHaveTextContent('Loading');
  await act(async () => {
    finish(Response.json(fixture));
  });
  expect(screen.queryByText('transfer(address,uint256)')).toBeNull();
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('removes loaded details on Participant change and logout', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(fixture));
  const { rerender } = render(<ContractMethodInspector {...props} />);
  await userEvent.click(screen.getByRole('button', { name: 'Inspect configured method' }));
  await screen.findByText(huge);
  rerender(
    <ContractMethodInspector
      {...props}
      actor={{ ...actor, participantId: id('30'), contextEpoch: '2' }}
    />,
  );
  expect(screen.queryByText(huge)).toBeNull();
  rerender(<ContractMethodInspector {...props} actor={undefined} />);
  expect(screen.getByRole('button')).toBeDisabled();
  expect(screen.getByRole('status')).toHaveTextContent('Reload the authenticated Participant');
});

it('clears details on ordinary owner errors and displays only the diagnostic request', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(fixture))
    .mockResolvedValueOnce(
      Response.json(
        { private: 'must not render' },
        { status: 503, headers: { 'x-request-id': id('99') } },
      ),
    );
  render(<ContractMethodInspector {...props} />);
  await userEvent.click(screen.getByRole('button'));
  await screen.findByText(huge);
  await userEvent.click(screen.getByRole('button'));
  await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('unavailable'));
  expect(screen.queryByText(huge)).toBeNull();
  expect(screen.getByText(`Diagnostic request: ${id('99')}`)).toBeVisible();
  expect(screen.queryByText('must not render')).toBeNull();
});

it('does not fetch an empty or malformed selection', () => {
  const fetch = vi.spyOn(globalThis, 'fetch');
  const { rerender } = render(<ContractMethodInspector {...props} methodPolicyId="" />);
  expect(screen.getByRole('button')).toBeDisabled();
  rerender(<ContractMethodInspector {...props} methodPolicyId="not-a-reference" />);
  expect(screen.getByRole('button')).toBeDisabled();
  expect(fetch).not.toHaveBeenCalled();
});
