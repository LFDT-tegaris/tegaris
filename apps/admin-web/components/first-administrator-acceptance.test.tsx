import { act, cleanup, render, screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { StrictMode } from 'react';
import { FirstAdministratorAcceptance } from './first-administrator-acceptance';
const passiveEffects = vi.hoisted(() => ({ held: false, pending: [] as Array<() => void> }));
// Pass through normally; boundary regressions hold passive cleanup and setup while commit hooks run.
vi.mock('react', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react')>();
  return {
    ...actual,
    useEffect(effect: () => void | (() => void), dependencies?: readonly unknown[]) {
      actual.useEffect(() => {
        let active = true;
        let dispose: (() => void) | undefined;
        const setup = () => {
          if (!active) return;
          const cleanup = effect();
          if (typeof cleanup === 'function') dispose = cleanup;
        };
        if (passiveEffects.held) passiveEffects.pending.push(setup);
        else setup();
        return () => {
          active = false;
          const cleanup = () => dispose?.();
          if (passiveEffects.held) passiveEffects.pending.push(cleanup);
          else cleanup();
        };
      }, dependencies);
    },
  };
});
vi.mock('./local-session', () => ({
  LocalSessionSurface: ({ participantId }: { participantId: string }) => (
    <div aria-label="Accepted Participant sign-in">Participant {participantId}</div>
  ),
}));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const pending = {
  state: 'CLAIM_PENDING',
  participantId: id(1),
  invitationId: id(2),
  mandateId: id(3),
  displayName: 'Administrator',
  enrollmentRequired: true,
  intentDigest: `sha256:${'aa'.repeat(32)}`,
  expiresAt: '2026-09-16T12:00:00.000Z',
  roleId: id(4),
  actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
};
afterEach(() => {
  cleanup();
  passiveEffects.held = false;
  passiveEffects.pending.splice(0).forEach((work) => work());
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
const privateAdministratorFailure =
  'PRIVATE_ADMINISTRATOR_ERROR token=original-secret cookie=private sql=SELECT';
const administratorUnavailable =
  'First-administrator acceptance is unavailable. Retry to check its current state.';
const ceremonyUnavailable =
  'The ceremony could not finish. Refresh to check for a committed result.';
const administratorFailures = [
  'denial',
  'conflict',
  'server',
  'transport',
  'parse',
  'unknown',
] as const;
async function failedAdministratorResponse(failure: string): Promise<Response> {
  if (failure === 'transport') throw new Error(privateAdministratorFailure);
  if (failure === 'unknown')
    return Promise.reject({
      name: 'FirstAdministratorFailure',
      message: privateAdministratorFailure,
    });
  if (failure === 'parse')
    return new Response(privateAdministratorFailure, {
      headers: { 'Content-Type': 'application/json' },
    });
  return Response.json(
    {
      title: privateAdministratorFailure,
      code: privateAdministratorFailure,
      detail: privateAdministratorFailure,
    },
    {
      status: failure === 'denial' ? 403 : failure === 'conflict' ? 409 : 503,
    },
  );
}
function administratorFailureMessage(failure: string, reading: boolean) {
  return failure === 'denial'
    ? 'Administrator acceptance is not authorized in the current context. Refresh to check its current state.'
    : failure === 'conflict'
      ? 'Administrator acceptance has changed. Refresh to check for a committed result.'
      : failure === 'parse'
        ? 'The administrator acceptance response is invalid. Refresh to check its current state.'
        : failure === 'server' || reading
          ? administratorUnavailable
          : ceremonyUnavailable;
}
const assertionOptions = {
  challenge: 'A'.repeat(43),
  intentDigest: pending.intentDigest,
  rpId: 'localhost',
  credentialIds: ['AQ'],
  userVerification: 'required',
};
const enrollmentOptions = {
  enrollmentId: id(8),
  publicKey: {
    challenge: 'A'.repeat(43),
    rp: { id: 'localhost', name: 'OpenPC' },
    user: { id: 'AQ', name: 'provider-subject', displayName: 'Administrator' },
    pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
  },
};
const enrollmentComplete = { credentialId: id(9), state: 'ENROLLED', authorityGranted: false };
const accepted = {
  state: 'ACCEPTED',
  participantId: id(1),
  invitationId: id(2),
  mandateId: id(3),
  membershipId: id(5),
  assignmentId: id(6),
  roleId: id(4),
  participantEpoch: '1',
  membershipState: 'ACTIVE',
  platformBootstrapAuthority: 'CLOSED',
  operationId: id(7),
  acceptedAt: '2026-09-15T12:00:00.000Z',
};
function authenticator() {
  const enrollment = { id: 'AQ', response: { attestationObject: 'original-enrollment' } };
  const parseCreation = vi.fn((value: unknown) => value);
  class Credential {
    static parseCreationOptionsFromJSON = parseCreation;
    id = 'AQ';
    response = {
      authenticatorData: new Uint8Array([1]).buffer,
      clientDataJSON: new Uint8Array([2]).buffer,
      signature: new Uint8Array([3]).buffer,
    };
    toJSON() {
      return enrollment;
    }
  }
  vi.stubGlobal('PublicKeyCredential', Credential);
  const credential = new Credential();
  const create = vi.fn().mockResolvedValue(credential);
  const get = vi.fn().mockResolvedValue(credential);
  vi.stubGlobal('navigator', { credentials: { create, get } });
  return { create, get, credential, enrollment, parseCreation };
}
const commandBodies = (fetcher: {
  mock: { calls: readonly (readonly [unknown, RequestInit?])[] };
}) => fetcher.mock.calls.map(([, init]) => JSON.parse(String(init?.body)));
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (cause: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
it.each(
  ['enroll', 'accept'].flatMap((action) =>
    ['options', 'body', 'credential'].flatMap((phase) =>
      ['context', 'unmount'].flatMap((transition) =>
        ['success', 'failure'].map((outcome) => [action, phase, transition, outcome]),
      ),
    ),
  ),
)(
  'invalidates %s %s ownership at committed %s before passive effects on %s',
  async (action, phase, transition, outcome) => {
    const auth = authenticator();
    const pendingResponse = deferred<Response>();
    const pendingBody = deferred<unknown>();
    const pendingCredential = deferred<typeof auth.credential>();
    const enrolling = action === 'enroll';
    const optionsCommand = enrolling ? 'ENROLL_OPTIONS' : 'ACCEPT_OPTIONS';
    const options = enrolling ? enrollmentOptions : assertionOptions;
    const delayedBody = Response.json(options);
    const json = vi.spyOn(delayedBody, 'json').mockReturnValue(pendingBody.promise);
    if (phase === 'credential')
      (enrolling ? auth.create : auth.get).mockReturnValueOnce(pendingCredential.promise);
    let switched = false;
    const next = {
      ...pending,
      participantId: id(10),
      invitationId: id(20),
      displayName: 'Current administrator',
      enrollmentRequired: enrolling,
    };
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const { command } = JSON.parse(String(init?.body));
      if (command === 'READ')
        return Response.json(switched ? next : { ...pending, enrollmentRequired: enrolling });
      if (command === optionsCommand)
        return phase === 'options'
          ? pendingResponse.promise
          : phase === 'body'
            ? delayedBody
            : Response.json(options);
      return Response.json(command === 'ENROLL_COMPLETE' ? enrollmentComplete : accepted);
    });
    const view = render(
      <FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />,
    );
    fireEvent.click(
      await screen.findByRole('button', {
        name: enrolling
          ? 'Register administrator authenticator'
          : 'Accept Participant administration',
      }),
    );
    if (phase === 'body') await waitFor(() => expect(json).toHaveBeenCalledTimes(1));
    else if (phase === 'credential')
      await waitFor(() => expect(enrolling ? auth.create : auth.get).toHaveBeenCalledTimes(1));
    else await waitFor(() => expect(commandBodies(fetcher)).toHaveLength(2));
    const originalCommands = commandBodies(fetcher);
    switched = true;
    // Hold passive cleanup AND setup so the old owner cannot rely on either to stop its continuation.
    passiveEffects.held = true;
    if (transition === 'unmount') view.unmount();
    else
      view.rerender(<FirstAdministratorAcceptance participantId={id(10)} invitationId={id(20)} />);
    expect(passiveEffects.pending.length).toBeGreaterThan(0);
    expect(commandBodies(fetcher)).toEqual(originalCommands);
    expect(screen.queryByText('Administrator: Administrator')).not.toBeInTheDocument();
    await act(async () => {
      if (phase === 'credential') {
        if (outcome === 'failure') pendingCredential.reject(new Error(privateAdministratorFailure));
        else pendingCredential.resolve(auth.credential);
      } else if (phase === 'body') {
        if (outcome === 'failure') pendingBody.reject(new Error(privateAdministratorFailure));
        else pendingBody.resolve(options);
      } else {
        if (outcome === 'failure') pendingResponse.reject(new Error(privateAdministratorFailure));
        else pendingResponse.resolve(Response.json(options));
      }
    });
    expect(commandBodies(fetcher)).toEqual(originalCommands);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Working…' })).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(privateAdministratorFailure);
    expect(auth.create).toHaveBeenCalledTimes(enrolling && phase === 'credential' ? 1 : 0);
    expect(auth.get).toHaveBeenCalledTimes(!enrolling && phase === 'credential' ? 1 : 0);
    await act(async () => {
      passiveEffects.held = false;
      passiveEffects.pending.splice(0).forEach((work) => work());
    });
    if (transition === 'context') {
      await screen.findByText('Administrator: Current administrator');
      expect(commandBodies(fetcher)).toEqual([...originalCommands, { command: 'READ' }]);
      expect(
        screen.getByRole('button', {
          name: enrolling
            ? 'Register administrator authenticator'
            : 'Accept Participant administration',
        }),
      ).toBeEnabled();
    } else expect(commandBodies(fetcher)).toEqual(originalCommands);
  },
);
it('keeps one current ceremony after StrictMode cleanup and replacement setup', async () => {
  const auth = authenticator();
  let completed = false;
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
    const { command } = JSON.parse(String(init?.body));
    if (command === 'ACCEPT_OPTIONS') return Response.json(assertionOptions);
    if (command === 'ACCEPT') {
      completed = true;
      return Response.json(accepted);
    }
    return Response.json(completed ? accepted : { ...pending, enrollmentRequired: false });
  });
  render(
    <StrictMode>
      <FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />
    </StrictMode>,
  );
  fireEvent.click(await screen.findByRole('button', { name: 'Accept Participant administration' }));
  expect(
    await screen.findByRole('heading', { name: 'Participant administration accepted' }),
  ).toBeVisible();
  expect(
    commandBodies(fetcher)
      .filter((body) => body.command !== 'READ')
      .map((body) => body.command),
  ).toEqual(['ACCEPT_OPTIONS', 'ACCEPT']);
  expect(commandBodies(fetcher).at(-1)).toEqual({ command: 'READ' });
  expect(auth.get).toHaveBeenCalledTimes(1);
  expect(auth.create).not.toHaveBeenCalled();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
it.each(
  ['enroll', 'accept'].flatMap((action) =>
    ['options', 'credential', 'completion', 'body'].flatMap((phase) =>
      ['context', 'unmount'].flatMap((transition) =>
        ['success', 'failure'].map((outcome) => [action, phase, transition, outcome]),
      ),
    ),
  ),
)(
  'fences obsolete %s %s after %s on %s before any next command or projection',
  async (action, phase, transition, outcome) => {
    const auth = authenticator();
    const response = deferred<Response>();
    const credential = deferred<typeof auth.credential>();
    const body = deferred<unknown>();
    const enrolling = action === 'enroll';
    const optionCommand = enrolling ? 'ENROLL_OPTIONS' : 'ACCEPT_OPTIONS';
    const completeCommand = enrolling ? 'ENROLL_COMPLETE' : 'ACCEPT';
    const optionValue = enrolling ? enrollmentOptions : assertionOptions;
    const decoded = Response.json(optionValue);
    const json = vi.spyOn(decoded, 'json').mockReturnValue(body.promise);
    if (phase === 'credential')
      (enrolling ? auth.create : auth.get).mockReturnValueOnce(credential.promise);
    let switched = false;
    const next = {
      ...pending,
      participantId: id(10),
      invitationId: id(20),
      displayName: 'Current administrator',
      enrollmentRequired: enrolling,
    };
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const { command } = JSON.parse(String(init?.body));
      if (command === 'READ')
        return Response.json(switched ? next : { ...pending, enrollmentRequired: enrolling });
      if (command === optionCommand)
        return phase === 'options'
          ? response.promise
          : phase === 'body'
            ? decoded
            : Response.json(optionValue);
      if (command === completeCommand) return response.promise;
      throw new Error('Unexpected command in the isolated ceremony');
    });
    const view = render(
      <FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />,
    );
    fireEvent.click(
      await screen.findByRole('button', {
        name: enrolling
          ? 'Register administrator authenticator'
          : 'Accept Participant administration',
      }),
    );
    await waitFor(() =>
      expect(commandBodies(fetcher).map((value) => value.command)).toContain(optionCommand),
    );
    if (phase === 'body') await waitFor(() => expect(json).toHaveBeenCalledTimes(1));
    if (phase === 'credential')
      await waitFor(() => expect(enrolling ? auth.create : auth.get).toHaveBeenCalledTimes(1));
    if (phase === 'completion')
      await waitFor(() =>
        expect(commandBodies(fetcher).map((value) => value.command)).toContain(completeCommand),
      );
    const oldCommands = commandBodies(fetcher);
    switched = true;
    if (transition === 'unmount') view.unmount();
    else {
      view.rerender(<FirstAdministratorAcceptance participantId={id(10)} invitationId={id(20)} />);
      expect(screen.queryByText('Administrator: Administrator')).not.toBeInTheDocument();
      expect(screen.queryByText(`Participant: ${id(1)}`)).not.toBeInTheDocument();
      await screen.findByText('Administrator: Current administrator');
    }
    await act(async () => {
      if (phase === 'credential') {
        if (outcome === 'failure') credential.reject(new Error(privateAdministratorFailure));
        else credential.resolve(auth.credential);
      } else if (phase === 'body') {
        if (outcome === 'failure') body.reject(new Error(privateAdministratorFailure));
        else body.resolve(optionValue);
      } else {
        if (outcome === 'failure') response.reject(new Error(privateAdministratorFailure));
        else
          response.resolve(
            Response.json(
              phase === 'options' ? optionValue : enrolling ? enrollmentComplete : accepted,
            ),
          );
      }
    });
    expect(commandBodies(fetcher)).toEqual([
      ...oldCommands,
      ...(transition === 'context' ? [{ command: 'READ' }] : []),
    ]);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('heading', { name: 'Participant administration accepted' }),
    ).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(privateAdministratorFailure);
    if (transition === 'context') {
      expect(screen.getByText('Administrator: Current administrator')).toBeVisible();
      expect(
        screen.getByRole('button', {
          name: enrolling
            ? 'Register administrator authenticator'
            : 'Accept Participant administration',
        }),
      ).toBeEnabled();
    }
    if (phase === 'options' || phase === 'body') {
      expect(auth.create).not.toHaveBeenCalled();
      expect(auth.get).not.toHaveBeenCalled();
    }
  },
);
it.each(['success', 'failure'] as const)(
  'ignores an obsolete initial READ %s after a newer explicit READ',
  async (outcome) => {
    const initial = deferred<Response>();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockReturnValueOnce(initial.promise)
      .mockResolvedValue(Response.json({ ...pending, displayName: 'Current administrator' }));
    render(<FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh administrator acceptance' }));
    await screen.findByText('Administrator: Current administrator');
    await act(async () => {
      if (outcome === 'success') initial.resolve(Response.json(pending));
      else initial.reject(new Error(privateAdministratorFailure));
    });
    expect(screen.getByText('Administrator: Current administrator')).toBeVisible();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(commandBodies(fetcher)).toEqual([{ command: 'READ' }, { command: 'READ' }]);
  },
);
it('keeps a newer context READ busy after the old ceremony fails, then adopts only the newer readback', async () => {
  const auth = authenticator();
  const oldCredential = deferred<typeof auth.credential>();
  const newRead = deferred<Response>();
  auth.get.mockReturnValueOnce(oldCredential.promise);
  let switched = false;
  let newReads = 0;
  const next = {
    ...pending,
    participantId: id(10),
    invitationId: id(20),
    displayName: 'Current administrator',
    enrollmentRequired: false,
  };
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
    const { command } = JSON.parse(String(init?.body));
    if (command === 'ACCEPT_OPTIONS') return Response.json(assertionOptions);
    if (switched && ++newReads === 2) return newRead.promise;
    return Response.json(switched ? next : { ...pending, enrollmentRequired: false });
  });
  const view = render(<FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Accept Participant administration' }));
  await waitFor(() => expect(auth.get).toHaveBeenCalledTimes(1));
  switched = true;
  view.rerender(<FirstAdministratorAcceptance participantId={id(10)} invitationId={id(20)} />);
  await screen.findByText('Administrator: Current administrator');
  fireEvent.click(screen.getByRole('button', { name: 'Refresh administrator acceptance' }));
  await waitFor(() => expect(newReads).toBe(2));
  await act(async () => oldCredential.reject(new Error(privateAdministratorFailure)));
  expect(screen.getByRole('button', { name: 'Working…' })).toBeDisabled();
  expect(screen.getByRole('button', { name: 'Refresh administrator acceptance' })).toBeDisabled();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  await act(async () => newRead.resolve(Response.json(next)));
  expect(screen.getByRole('button', { name: 'Accept Participant administration' })).toBeEnabled();
  expect(commandBodies(fetcher).map((value) => value.command)).toEqual([
    'READ',
    'ACCEPT_OPTIONS',
    'READ',
    'READ',
  ]);
});
it.each(['denial', 'malformed', 'foreign', 'transport'])(
  'removes previous personal metadata and action controls after a current READ %s',
  async (failure) => {
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(pending))
      .mockImplementation(() =>
        failure === 'malformed'
          ? Promise.resolve(
              Response.json({
                ...pending,
                displayName: privateAdministratorFailure,
                state: 'UNKNOWN',
              }),
            )
          : failure === 'foreign'
            ? Promise.resolve(
                Response.json({
                  ...pending,
                  invitationId: id(99),
                  displayName: privateAdministratorFailure,
                }),
              )
            : failedAdministratorResponse(failure),
      );
    render(<FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />);
    await screen.findByText('Administrator: Administrator');
    fireEvent.click(screen.getByRole('button', { name: 'Refresh administrator acceptance' }));
    await screen.findByRole('alert');
    expect(screen.queryByText('Administrator: Administrator')).not.toBeInTheDocument();
    expect(screen.queryByText(`Participant: ${id(1)}`)).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Register administrator authenticator' }),
    ).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(privateAdministratorFailure);
    expect(commandBodies(fetcher)).toEqual([{ command: 'READ' }, { command: 'READ' }]);
  },
);
it.each(['transport', 'parse'] as const)(
  'reconciles an ambiguous ACCEPT %s through explicit READ without another ceremony or consuming command',
  async (failure) => {
    const auth = authenticator();
    let consumingAttempt = false;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const { command } = JSON.parse(String(init?.body));
      if (command === 'ACCEPT_OPTIONS') return Response.json(assertionOptions);
      if (command === 'ACCEPT') {
        consumingAttempt = true;
        return failedAdministratorResponse(failure);
      }
      return Response.json(consumingAttempt ? accepted : { ...pending, enrollmentRequired: false });
    });
    render(<FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />);
    fireEvent.click(
      await screen.findByRole('button', { name: 'Accept Participant administration' }),
    );
    await screen.findByRole('alert');
    expect(
      screen.queryByRole('button', { name: 'Accept Participant administration' }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText('Administrator: Administrator')).not.toBeInTheDocument();
    expect(commandBodies(fetcher).map((value) => value.command)).toEqual([
      'READ',
      'ACCEPT_OPTIONS',
      'ACCEPT',
    ]);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh administrator acceptance' }));
    expect(
      await screen.findByRole('heading', { name: 'Participant administration accepted' }),
    ).toBeVisible();
    expect(commandBodies(fetcher).map((value) => value.command)).toEqual([
      'READ',
      'ACCEPT_OPTIONS',
      'ACCEPT',
      'READ',
    ]);
    expect(auth.get).toHaveBeenCalledTimes(1);
    expect(auth.create).not.toHaveBeenCalled();
  },
);
it.each([...administratorFailures, 'schema'])(
  'redacts an initial administrator READ %s and retries only durable READ',
  async (failure) => {
    const auth = authenticator();
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementationOnce(() =>
        failure === 'schema'
          ? Promise.resolve(Response.json({ ...pending, state: privateAdministratorFailure }))
          : failedAdministratorResponse(failure),
      )
      .mockResolvedValue(Response.json(pending));
    render(<FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />);
    expect(await screen.findByRole('alert')).toHaveTextContent(
      administratorFailureMessage(failure, true),
    );
    expect(document.body).not.toHaveTextContent(privateAdministratorFailure);
    expect(
      screen.queryByRole('button', { name: 'Register administrator authenticator' }),
    ).not.toBeInTheDocument();
    expect(commandBodies(fetcher)).toEqual([{ command: 'READ' }]);
    fireEvent.click(screen.getByRole('button', { name: 'Refresh administrator acceptance' }));
    expect(
      await screen.findByRole('button', { name: 'Register administrator authenticator' }),
    ).toBeEnabled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(commandBodies(fetcher)).toEqual([{ command: 'READ' }, { command: 'READ' }]);
    expect(auth.create).not.toHaveBeenCalled();
    expect(auth.get).not.toHaveBeenCalled();
  },
);
it.each(
  ['ENROLL_OPTIONS', 'ENROLL_COMPLETE', 'ACCEPT_OPTIONS', 'ACCEPT'].flatMap((command) =>
    administratorFailures.map((failure) => [command, failure]),
  ),
)(
  'redacts %s %s while preserving exact ceremony requests and READ-only recovery',
  async (failedCommand, failure) => {
    const auth = authenticator();
    const enrolling = failedCommand.startsWith('ENROLL');
    let recovered = false;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const body = JSON.parse(String(init?.body));
      if (body.command === failedCommand && !recovered) return failedAdministratorResponse(failure);
      if (body.command === 'ENROLL_OPTIONS') return Response.json(enrollmentOptions);
      if (body.command === 'ACCEPT_OPTIONS') return Response.json(assertionOptions);
      return Response.json({ ...pending, enrollmentRequired: enrolling });
    });
    render(<FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />);
    fireEvent.click(
      await screen.findByRole('button', {
        name: enrolling
          ? 'Register administrator authenticator'
          : 'Accept Participant administration',
      }),
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(
      administratorFailureMessage(failure, false),
    );
    expect(document.body).not.toHaveTextContent(privateAdministratorFailure);
    expect(
      screen.queryByRole('heading', { name: 'Participant administration accepted' }),
    ).not.toBeInTheDocument();
    const expected = [
      { command: 'READ' },
      { command: enrolling ? 'ENROLL_OPTIONS' : 'ACCEPT_OPTIONS' },
    ];
    const bodies = commandBodies(fetcher);
    if (failedCommand.endsWith('OPTIONS')) expect(bodies).toEqual(expected);
    else {
      expect(bodies.slice(0, 2)).toEqual(expected);
      expect(bodies[2]).toEqual(
        enrolling
          ? {
              command: 'ENROLL_COMPLETE',
              enrollmentId: enrollmentOptions.enrollmentId,
              response: auth.enrollment,
            }
          : {
              command: 'ACCEPT',
              intentDigest: assertionOptions.intentDigest,
              challenge: assertionOptions.challenge,
              assertion: JSON.stringify({
                credentialId: 'AQ',
                authenticatorData: 'AQ',
                clientDataJson: 'Ag',
                signature: 'Aw',
              }),
            },
      );
      expect(bodies).toHaveLength(3);
    }
    expect(auth.create).toHaveBeenCalledTimes(failedCommand === 'ENROLL_COMPLETE' ? 1 : 0);
    expect(auth.get).toHaveBeenCalledTimes(failedCommand === 'ACCEPT' ? 1 : 0);
    const priorCalls = fetcher.mock.calls.length;
    recovered = true;
    fireEvent.click(screen.getByRole('button', { name: 'Refresh administrator acceptance' }));
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(priorCalls + 1));
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
    expect(commandBodies(fetcher).slice(priorCalls)).toEqual([{ command: 'READ' }]);
    expect(
      fetcher.mock.calls.every(
        ([url, init]) =>
          url === '/api/v1/ui/invitation-proof/first-administrator' &&
          init?.method === 'POST' &&
          init.cache === 'no-store' &&
          JSON.stringify(init.headers) === JSON.stringify({ 'Content-Type': 'application/json' }),
      ),
    ).toBe(true);
  },
);
it.each(['enroll', 'accept'] as const)(
  'redacts a private authenticator %s exception before submitting an assertion or enrollment',
  async (action) => {
    const auth = authenticator();
    (action === 'enroll' ? auth.create : auth.get).mockRejectedValueOnce(
      new Error(privateAdministratorFailure),
    );
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const { command } = JSON.parse(String(init?.body));
      return Response.json(
        command === 'ENROLL_OPTIONS'
          ? enrollmentOptions
          : command === 'ACCEPT_OPTIONS'
            ? assertionOptions
            : { ...pending, enrollmentRequired: action === 'enroll' },
      );
    });
    render(<FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />);
    fireEvent.click(
      await screen.findByRole('button', {
        name:
          action === 'enroll'
            ? 'Register administrator authenticator'
            : 'Accept Participant administration',
      }),
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(ceremonyUnavailable);
    expect(document.body).not.toHaveTextContent(privateAdministratorFailure);
    expect(commandBodies(fetcher)).toEqual([
      { command: 'READ' },
      { command: action === 'enroll' ? 'ENROLL_OPTIONS' : 'ACCEPT_OPTIONS' },
    ]);
  },
);
it.each(['cancelled enrollment', 'cancelled acceptance', 'changed digest', 'invalid options'])(
  'keeps trusted local %s validation without an unauthorized complete command',
  async (failure) => {
    const auth = authenticator();
    const enrolling = failure === 'cancelled enrollment';
    if (enrolling) auth.create.mockResolvedValueOnce(null);
    else if (failure === 'cancelled acceptance') auth.get.mockResolvedValueOnce(null);
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const { command } = JSON.parse(String(init?.body));
      return Response.json(
        command === 'ENROLL_OPTIONS'
          ? enrollmentOptions
          : command === 'ACCEPT_OPTIONS'
            ? {
                ...assertionOptions,
                intentDigest:
                  failure === 'changed digest'
                    ? `sha256:${'bb'.repeat(32)}`
                    : failure === 'invalid options'
                      ? privateAdministratorFailure
                      : assertionOptions.intentDigest,
              }
            : { ...pending, enrollmentRequired: enrolling },
      );
    });
    render(<FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />);
    fireEvent.click(
      await screen.findByRole('button', {
        name: enrolling
          ? 'Register administrator authenticator'
          : 'Accept Participant administration',
      }),
    );
    expect(await screen.findByRole('alert')).toHaveTextContent(
      failure === 'cancelled enrollment'
        ? 'Authenticator registration was cancelled.'
        : failure === 'cancelled acceptance'
          ? 'Administrator acceptance was cancelled.'
          : failure === 'changed digest'
            ? 'The reviewed invitation changed. Refresh it before accepting.'
            : ceremonyUnavailable,
    );
    expect(document.body).not.toHaveTextContent(privateAdministratorFailure);
    expect(commandBodies(fetcher)).toEqual([
      { command: 'READ' },
      { command: enrolling ? 'ENROLL_OPTIONS' : 'ACCEPT_OPTIONS' },
    ]);
    if (failure === 'changed digest' || failure === 'invalid options')
      expect(auth.get).not.toHaveBeenCalled();
  },
);
it.each(['enroll', 'accept'] as const)(
  'preserves successful %s custody and authoritative READ after completion',
  async (action) => {
    const auth = authenticator();
    let completed = false;
    const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_url, init) => {
      const { command } = JSON.parse(String(init?.body));
      if (command === 'ENROLL_OPTIONS') return Response.json(enrollmentOptions);
      if (command === 'ACCEPT_OPTIONS') return Response.json(assertionOptions);
      if (command === 'ENROLL_COMPLETE') {
        completed = true;
        return Response.json(enrollmentComplete);
      }
      if (command === 'ACCEPT') {
        completed = true;
        return Response.json(accepted);
      }
      return Response.json(
        completed && action === 'accept'
          ? accepted
          : { ...pending, enrollmentRequired: action === 'enroll' && !completed },
      );
    });
    render(<FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />);
    fireEvent.click(
      await screen.findByRole('button', {
        name:
          action === 'enroll'
            ? 'Register administrator authenticator'
            : 'Accept Participant administration',
      }),
    );
    if (action === 'enroll') {
      expect(
        await screen.findByRole('button', { name: 'Accept Participant administration' }),
      ).toBeEnabled();
      expect(auth.parseCreation).toHaveBeenCalledExactlyOnceWith(enrollmentOptions.publicKey);
      expect(auth.create).toHaveBeenCalledExactlyOnceWith({
        publicKey: enrollmentOptions.publicKey,
      });
    } else {
      expect(
        await screen.findByRole('heading', { name: 'Participant administration accepted' }),
      ).toBeVisible();
      expect(screen.getByLabelText('Accepted Participant sign-in')).toHaveTextContent(id(1));
      expect(auth.get).toHaveBeenCalledExactlyOnceWith({
        publicKey: {
          challenge: Uint8Array.from(atob(assertionOptions.challenge), (c) => c.charCodeAt(0)),
          rpId: assertionOptions.rpId,
          allowCredentials: [{ type: 'public-key', id: new Uint8Array([1]) }],
          userVerification: 'required',
        },
      });
    }
    expect(commandBodies(fetcher).map((body) => body.command)).toEqual([
      'READ',
      action === 'enroll' ? 'ENROLL_OPTIONS' : 'ACCEPT_OPTIONS',
      action === 'enroll' ? 'ENROLL_COMPLETE' : 'ACCEPT',
      'READ',
    ]);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  },
);
it('reconciles a lost response from durable readback without repeating acceptance', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({ enabled: false }))
    .mockResolvedValueOnce(Response.json({ title: 'Connection lost' }, { status: 503 }));
  render(<FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />);
  expect(await screen.findByRole('alert')).toHaveTextContent(administratorUnavailable);
  expect(document.body).not.toHaveTextContent('Connection lost');
  fetcher.mockResolvedValueOnce(
    Response.json({
      state: 'ACCEPTED',
      participantId: id(1),
      invitationId: id(2),
      mandateId: id(3),
      membershipId: id(5),
      assignmentId: id(6),
      roleId: id(4),
      participantEpoch: '1',
      membershipState: 'ACTIVE',
      platformBootstrapAuthority: 'CLOSED',
      operationId: id(7),
      acceptedAt: '2026-09-15T12:00:00.000Z',
    }),
  );
  fireEvent.click(screen.getByRole('button', { name: 'Refresh administrator acceptance' }));
  expect(
    await screen.findByRole('heading', { name: 'Participant administration accepted' }),
  ).toBeVisible();
  expect(
    fetcher.mock.calls
      .filter(([url]) => String(url).endsWith('/first-administrator'))
      .map(([, init]) => JSON.parse(String(init?.body))),
  ).toEqual([{ command: 'READ' }, { command: 'READ' }]);
});
it('rejects readback from a different invitation before exposing any acceptance control', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({ ...pending, invitationId: id(99) }),
  );
  render(<FirstAdministratorAcceptance participantId={id(1)} invitationId={id(2)} />);
  expect(await screen.findByRole('alert')).toHaveTextContent('acceptance context changed');
  expect(
    screen.queryByRole('button', { name: 'Register administrator authenticator' }),
  ).not.toBeInTheDocument();
});
