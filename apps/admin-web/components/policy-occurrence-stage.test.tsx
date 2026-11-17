import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { PolicyOccurrenceStage } from './policy-occurrence-stage';

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.restoreAllMocks();
});
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = `sha256:${'a'.repeat(64)}`;
const token = 'original-sealed-stage-'.padEnd(100, 'x');
const privateMarker = 'PRIVATE_OCCURRENCE_OWNER_TRANSPORT_OR_VALIDATOR_DETAIL';
const responseFailure =
  'The policy staging response could not be confirmed. Read back the original operation before retrying.';
const stageFailure =
  'The staging result could not be confirmed. Read back the original operation before retrying.';
const preview = {
  releaseBundleId: `urn:openpc:resource:${id(1)}`,
  releaseRevision: '3',
  policyVersionId: id(2),
  targetGenerationDigest: digest,
  dependencyClosureDigest: digest,
  simulationId: id(3),
  simulationInputDigest: digest,
  simulationResultDigest: digest,
  factGenerationDigest: digest,
  matchedTargetCount: '1',
  totalTargetCount: '1',
  activationPreviewDigest: digest,
  targets: [
    {
      targetId: id(4),
      expectedRevision: '42',
      expectedPredecessorDigest: digest,
      configurationDigest: digest,
      providerProfileId: id(5),
      projectionPlanId: id(6),
      configuredMatch: true,
    },
  ],
};
const review = { stageReviewToken: token, preview };
const operation = {
  operationId: id(7),
  actionIntentId: 'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1',
  intentDigest: 'sha256:ab25e0e1acc4faa65753906943f99e359ef60e4f90cd70f8cfb72bfd4e9c0dfd',
  idempotencyKey: 'original-policy-stage-idempotency',
  resourceRef: `urn:openpc:resource:${id(9)}`,
  revision: '1',
  state: 'ACCEPTED',
  truthState: 'SUCCESS',
  createdAt: '2026-10-04T00:00:00.000000Z',
  updatedAt: '2026-10-04T00:00:01.000000Z',
};
async function fillPreview() {
  const user = userEvent.setup();
  for (const [label, value] of [
    ['Published release ID', id(1)],
    ['Release revision', '3'],
    ['Activation reservation operation ID', id(8)],
    ['Staging reason', 'Governed fresh intent preserving immutable policy semantics.'],
  ])
    await user.type(screen.getByLabelText(label!), value!);
  await user.click(screen.getByRole('button', { name: 'Review current activation targets' }));
  return user;
}
function expectNoStageSuccess() {
  expect(screen.queryByText(/Occurrence:|activation still requires fresh approval/u)).toBeNull();
  expect(screen.queryByText(new RegExp(privateMarker, 'u'))).toBeNull();
}
function requestBodies(fetch: { mock: { calls: readonly (readonly unknown[])[] } }) {
  return fetch.mock.calls.map(([, init]) => JSON.parse(String((init as RequestInit)?.body)));
}
it('reviews authoritative revisions and stages only the sealed preview, retaining it after response loss', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(review, { status: 201 }))
    .mockRejectedValueOnce(new TypeError('response lost'))
    .mockResolvedValueOnce(Response.json(operation, { status: 202 }));
  render(<PolicyOccurrenceStage />);
  const user = await fillPreview();
  await screen.findByText(/revision 42; predecessor sha256:/u);
  await user.click(screen.getByRole('button', { name: 'Stage reviewed activation' }));
  await screen.findByText(stageFailure);
  expect(screen.queryByText('response lost')).toBeNull();
  expect(fetchMock).toHaveBeenCalledTimes(2);
  expectNoStageSuccess();
  await user.click(screen.getByRole('button', { name: 'Stage reviewed activation' }));
  await screen.findByText(/activation still requires fresh approval/u);
  const first = JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body));
  expect(first).toEqual({ command: 'STAGE_OCCURRENCE', stageReviewToken: token });
  expect(JSON.parse(String(fetchMock.mock.calls[2]?.[1]?.body))).toEqual(first);
});

const httpFailures = [
  {
    status: 400,
    message: 'The policy staging request was invalid. Review the inputs before retrying.',
  },
  {
    status: 422,
    message: 'The policy staging request was invalid. Review the inputs before retrying.',
  },
  ...[401, 403, 404].map((status) => ({
    status,
    message:
      'Policy staging was not authorized. Refresh the authenticated context before continuing.',
  })),
  ...[409, 412, 428].map((status) => ({
    status,
    message:
      'The policy staging context changed. Read back the original operation before retrying.',
  })),
  ...[500, 503].map((status) => ({
    status,
    message:
      'The policy staging owner is unavailable. Read back the original operation before retrying.',
  })),
];
it.each(['preview', 'stage'] as const)(
  '%s HTTP failures redact private payloads and forbid automatic continuation',
  async (phase) => {
    for (const { status, message } of httpFailures) {
      const fetch = vi.spyOn(globalThis, 'fetch');
      if (phase === 'stage') fetch.mockResolvedValueOnce(Response.json(review, { status: 201 }));
      fetch.mockResolvedValueOnce(
        Response.json(
          { title: privateMarker, code: privateMarker, detail: privateMarker },
          { status },
        ),
      );
      const view = render(<PolicyOccurrenceStage />);
      const user = await fillPreview();
      if (phase === 'stage')
        await user.click(await screen.findByRole('button', { name: 'Stage reviewed activation' }));
      await screen.findByText(message);
      expectNoStageSuccess();
      expect(fetch).toHaveBeenCalledTimes(phase === 'stage' ? 2 : 1);
      if (phase === 'preview')
        expect(screen.queryByRole('button', { name: 'Stage reviewed activation' })).toBeNull();
      else {
        expect(screen.getByRole('button', { name: 'Stage reviewed activation' })).toBeEnabled();
        expect(requestBodies(fetch)[1]).toEqual({
          command: 'STAGE_OCCURRENCE',
          stageReviewToken: token,
        });
      }
      view.unmount();
      vi.restoreAllMocks();
    }
  },
);
const responseFailures = [
  'non-JSON failure',
  'invalid JSON',
  'empty success',
  'null success',
  'problem-shaped success',
  'transport Error',
  'transport object',
] as const;
it.each(
  (['preview', 'stage'] as const).flatMap((phase) =>
    responseFailures.map((failure) => ({ phase, failure })),
  ),
)(
  'keeps $phase safe after $failure without losing the original stage intent',
  async ({ phase, failure }) => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    if (phase === 'stage') fetch.mockResolvedValueOnce(Response.json(review, { status: 201 }));
    if (failure === 'transport Error') fetch.mockRejectedValueOnce(new TypeError(privateMarker));
    else if (failure === 'transport object')
      fetch.mockRejectedValueOnce({ message: privateMarker, code: privateMarker });
    else
      fetch.mockResolvedValueOnce(
        failure === 'non-JSON failure'
          ? new Response(privateMarker, { status: 503 })
          : failure === 'invalid JSON'
            ? new Response(privateMarker, {
                status: phase === 'preview' ? 201 : 202,
                headers: { 'Content-Type': 'application/json' },
              })
            : failure === 'empty success'
              ? new Response(null, { status: 204 })
              : Response.json(
                  failure === 'null success'
                    ? null
                    : { title: privateMarker, code: 'PC-AUTH-0005' },
                  { status: phase === 'preview' ? 201 : 202 },
                ),
      );
    localStorage.setItem('openpc:policy-release-workflow:v2', 'original-parent-custody');
    render(<PolicyOccurrenceStage />);
    const user = await fillPreview();
    if (phase === 'stage')
      await user.click(await screen.findByRole('button', { name: 'Stage reviewed activation' }));
    await screen.findByRole('status');
    expectNoStageSuccess();
    expect(fetch).toHaveBeenCalledTimes(phase === 'stage' ? 2 : 1);
    expect(localStorage.getItem('openpc:policy-release-workflow:v2')).toBe(
      'original-parent-custody',
    );
    if (phase === 'preview')
      expect(screen.queryByRole('button', { name: 'Stage reviewed activation' })).toBeNull();
    else {
      const button = screen.getByRole('button', { name: 'Stage reviewed activation' });
      expect(button).toBeEnabled();
      fetch.mockResolvedValueOnce(Response.json(operation, { status: 202 }));
      await user.click(button);
      await screen.findByText(/activation still requires fresh approval/u);
      expect(requestBodies(fetch)[2]).toEqual(requestBodies(fetch)[1]);
      expect(requestBodies(fetch)[2]).toEqual({
        command: 'STAGE_OCCURRENCE',
        stageReviewToken: token,
      });
      expect(fetch).toHaveBeenCalledTimes(3);
    }
  },
);
it.each([
  {
    name: 'unknown canonical preview field',
    value: { ...review, preview: { ...preview, privateDetail: privateMarker } },
  },
  {
    name: 'unknown canonical target field',
    value: {
      ...review,
      preview: { ...preview, targets: [{ ...preview.targets[0], privateDetail: privateMarker }] },
    },
  },
  {
    name: 'matched null predecessor',
    value: {
      ...review,
      preview: {
        ...preview,
        targets: [{ ...preview.targets[0], expectedPredecessorDigest: null }],
      },
    },
  },
  {
    name: 'foreign release',
    value: { ...review, preview: { ...preview, releaseBundleId: `urn:openpc:resource:${id(9)}` } },
  },
  { name: 'foreign revision', value: { ...review, preview: { ...preview, releaseRevision: '4' } } },
  {
    name: 'contradictory total',
    value: { ...review, preview: { ...preview, totalTargetCount: '2' } },
  },
  {
    name: 'contradictory matches',
    value: { ...review, preview: { ...preview, matchedTargetCount: '0' } },
  },
  { name: 'missing sealed token', value: { preview } },
  { name: 'short sealed token', value: { ...review, stageReviewToken: 'short' } },
  { name: 'invalid cohort', value: { ...review, preview: { ...preview, targets: {} } } },
  {
    name: 'private malformed target',
    value: {
      ...review,
      preview: { ...preview, targets: [{ ...preview.targets[0], targetId: privateMarker }] },
    },
  },
  {
    name: 'invalid digest',
    value: { ...review, preview: { ...preview, activationPreviewDigest: privateMarker } },
  },
])('rejects $name preview before offering staging', async ({ value }) => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(value, { status: 201 }));
  render(<PolicyOccurrenceStage />);
  await fillPreview();
  await screen.findByText(responseFailure);
  expectNoStageSuccess();
  expect(screen.queryByRole('button', { name: 'Stage reviewed activation' })).toBeNull();
  expect(fetch).toHaveBeenCalledTimes(1);
});
it.each([
  { name: 'wrong action digest', override: { intentDigest: digest } },
  { name: 'wrong creation revision', override: { revision: '2' } },
  { name: 'missing operation ID', override: { operationId: undefined } },
  { name: 'private resource reference', override: { resourceRef: privateMarker } },
  { name: 'wrong action', override: { actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1' } },
  { name: 'missing truth', override: { truthState: undefined } },
  { name: 'non-success truth', override: { truthState: 'WRITE_AMBIGUITY' } },
  { name: 'invalid operation state', override: { state: 'FAILED' } },
  { name: 'invalid revision', override: { revision: '01' } },
])(
  'retains the sealed review after $name instead of reporting successful staging',
  async ({ override }) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(review, { status: 201 }))
      .mockResolvedValueOnce(Response.json({ ...operation, ...override }, { status: 202 }))
      .mockResolvedValueOnce(Response.json(operation, { status: 202 }));
    render(<PolicyOccurrenceStage />);
    const user = await fillPreview();
    const button = await screen.findByRole('button', { name: 'Stage reviewed activation' });
    await user.click(button);
    await screen.findByText(responseFailure);
    expectNoStageSuccess();
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(screen.getByRole('button', { name: 'Stage reviewed activation' })).toBe(button);
    await user.click(button);
    await screen.findByText(/activation still requires fresh approval/u);
    expect(requestBodies(fetch)[2]).toEqual(requestBodies(fetch)[1]);
    expect(fetch).toHaveBeenCalledTimes(3);
  },
);
it('preserves exact requests and accepts harmless DTO extras without changing staging into activation', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ ...review, hint: privateMarker }, { status: 201 }))
    .mockResolvedValueOnce(Response.json({ ...operation, hint: privateMarker }, { status: 202 }));
  render(<PolicyOccurrenceStage />);
  const user = await fillPreview();
  await user.click(await screen.findByRole('button', { name: 'Stage reviewed activation' }));
  await screen.findByText(
    `Occurrence: ${operation.resourceRef}. SUCCESS; activation still requires fresh approval.`,
  );
  expect(screen.queryByText(new RegExp(privateMarker, 'u'))).toBeNull();
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(operation.resourceRef).not.toBe(`urn:openpc:resource:${id(8)}`);
  expect(requestBodies(fetch)).toEqual([
    {
      command: 'PREVIEW_OCCURRENCE',
      releaseId: id(1),
      expectedRevision: '3',
      reason: 'Governed fresh intent preserving immutable policy semantics.',
      resourceReservationId: id(8),
    },
    { command: 'STAGE_OCCURRENCE', stageReviewToken: token },
  ]);
  for (const [url, init] of fetch.mock.calls) {
    expect(url).toBe('/api/v1/ui/policy-release-workbench');
    expect(init).toEqual({
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: (init as RequestInit)?.body,
    });
  }
});

it.each([
  { phase: 'preview', status: 200, contentType: 'application/json' },
  { phase: 'preview', status: 202, contentType: 'application/json' },
  { phase: 'preview', status: 201, contentType: 'text/html' },
  { phase: 'stage', status: 200, contentType: 'application/json' },
  { phase: 'stage', status: 201, contentType: 'application/json' },
  { phase: 'stage', status: 202, contentType: 'text/html' },
])(
  'rejects valid $phase JSON at wrong status/MIME $status $contentType',
  async ({ phase, status, contentType }) => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    if (phase === 'stage') fetch.mockResolvedValueOnce(Response.json(review, { status: 201 }));
    fetch.mockResolvedValueOnce(
      new Response(JSON.stringify(phase === 'preview' ? review : operation), {
        status,
        headers: { 'Content-Type': contentType },
      }),
    );
    render(<PolicyOccurrenceStage />);
    const user = await fillPreview();
    if (phase === 'stage')
      await user.click(await screen.findByRole('button', { name: 'Stage reviewed activation' }));
    await screen.findByText(responseFailure);
    expectNoStageSuccess();
    expect(fetch).toHaveBeenCalledTimes(phase === 'stage' ? 2 : 1);
    if (phase === 'preview')
      expect(screen.queryByRole('button', { name: 'Stage reviewed activation' })).toBeNull();
    else expect(screen.getByRole('button', { name: 'Stage reviewed activation' })).toBeEnabled();
  },
);

it.each(['success', 'failure'])(
  'blocks pending draft edits and ignores an obsolete preview %s',
  async (outcome) => {
    let resolve!: (value: Response) => void;
    let reject!: (reason: unknown) => void;
    const pending = new Promise<Response>((yes, no) => {
      resolve = yes;
      reject = no;
    });
    const fetch = vi.spyOn(globalThis, 'fetch').mockReturnValueOnce(pending);
    render(<PolicyOccurrenceStage />);
    await fillPreview();
    for (const label of [
      'Published release ID',
      'Release revision',
      'Activation reservation operation ID',
      'Staging reason',
    ])
      expect(screen.getByLabelText(label)).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Published release ID'), { target: { value: id(77) } });
    await act(async () =>
      outcome === 'success'
        ? resolve(Response.json(review, { status: 201 }))
        : reject(new Error(privateMarker)),
    );
    expectNoStageSuccess();
    expect(screen.queryByRole('button', { name: 'Stage reviewed activation' })).toBeNull();
    expect(screen.queryByRole('status')).toBeNull();
    expect(screen.getByLabelText('Published release ID')).toBeEnabled();
    expect(fetch).toHaveBeenCalledTimes(1);
  },
);
it('retains the original draft and review while staging is uncertain without an automatic replay', async () => {
  let reject!: (reason: unknown) => void;
  const pending = new Promise<Response>((_, no) => {
    reject = no;
  });
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(review, { status: 201 }))
    .mockReturnValueOnce(pending);
  render(<PolicyOccurrenceStage />);
  const user = await fillPreview();
  const button = await screen.findByRole('button', { name: 'Stage reviewed activation' });
  await user.click(button);
  expect(button).toBeDisabled();
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  await act(async () => reject(new TypeError(privateMarker)));
  await screen.findByText(stageFailure);
  expect(button).toBeEnabled();
  expect(screen.getByLabelText('Published release ID')).toHaveValue(id(1));
  expect(screen.getByLabelText('Activation reservation operation ID')).toHaveValue(id(8));
  expectNoStageSuccess();
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('accepts zero matches, null predecessors and shared profiles when staging without a reservation', async () => {
  const source = {
    ...preview,
    matchedTargetCount: '0',
    totalTargetCount: '2',
    targets: [
      { ...preview.targets[0], configuredMatch: false, expectedPredecessorDigest: null },
      {
        ...preview.targets[0],
        targetId: id(20),
        configuredMatch: false,
        expectedPredecessorDigest: digest,
      },
    ],
  };
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ ...review, preview: source }, { status: 201 }))
    .mockResolvedValueOnce(
      Response.json(
        { ...operation, resourceRef: `urn:openpc:resource:${id(21)}` },
        { status: 202 },
      ),
    );
  render(<PolicyOccurrenceStage />);
  const user = userEvent.setup();
  for (const [label, value] of [
    ['Published release ID', id(1)],
    ['Release revision', '3'],
    ['Staging reason', 'Current zero-match cohort still needs governed activation.'],
  ])
    await user.type(screen.getByLabelText(label!), value!);
  await user.click(screen.getByRole('button', { name: 'Review current activation targets' }));
  await screen.findByText(/configuration matches 0\/2/u);
  await user.click(screen.getByRole('button', { name: 'Stage reviewed activation' }));
  await screen.findByText(/activation still requires fresh approval/u);
  expect(requestBodies(fetch)[0]).not.toHaveProperty('resourceReservationId');
  expect(requestBodies(fetch)[1]).toEqual({ command: 'STAGE_OCCURRENCE', stageReviewToken: token });
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('fails closed on the oversized valid 256-target preview until the shared staging owner supports it', async () => {
  const source = {
    ...preview,
    matchedTargetCount: '256',
    totalTargetCount: '256',
    targets: Array.from({ length: 256 }, (_, index) => ({
      ...preview.targets[0],
      targetId: id(100 + index),
    })),
  };
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(
      Response.json({ stageReviewToken: 't'.repeat(119394), preview: source }, { status: 201 }),
    );
  render(<PolicyOccurrenceStage />);
  await fillPreview();
  await screen.findByText(
    'This preview exceeds the supported staging limit. Staging is unavailable.',
  );
  expectNoStageSuccess();
  expect(screen.queryByRole('button', { name: 'Stage reviewed activation' })).toBeNull();
  expect(fetch).toHaveBeenCalledTimes(1);
});
