import { beforeEach, expect, it, vi } from 'vitest';
const owner = vi.hoisted(() => ({
  config: vi.fn(),
  decode: vi.fn(),
  validate: vi.fn(),
  functional: vi.fn(),
}));
vi.mock('./local-runtime', () => ({
  localRuntimeConfig: owner.config,
  decodeBffSession: owner.decode,
  validateIdentitySessionToken: owner.validate,
  functionalIdentitySession: owner.functional,
}));
import { readWorkspaceSession } from './workspace-session';
const native = {
  role: 'viewer',
  sessionId: '018f0000-0000-7000-8000-000000000701',
  principalId: '018f0000-0000-7000-8000-000000000112',
  participantId: '018f0000-0000-7000-8000-000000000101',
  contextMode: 'PLATFORM',
  contextEpoch: '2',
  availableContexts: [],
};
beforeEach(() => {
  vi.resetAllMocks();
  owner.config.mockResolvedValue({ cookieKey: Buffer.alloc(32) });
  owner.decode.mockReturnValue({ sessionToken: 'sealed-native-token', role: 'viewer' });
  owner.validate.mockResolvedValue(native);
});
it('does not query an identity owner without a browser cookie', async () => {
  expect(await readWorkspaceSession(undefined)).toBeUndefined();
  expect(owner.validate).not.toHaveBeenCalled();
});
it('requires a decoded cookie and native validation before admitting a page', async () => {
  expect(await readWorkspaceSession('sealed-cookie')).toMatchObject({
    authenticated: true,
    principalId: native.principalId,
  });
  expect(owner.validate).toHaveBeenCalledWith(expect.any(Object), 'sealed-native-token');
  owner.decode.mockReturnValue(undefined);
  expect(await readWorkspaceSession('forged-cookie')).toBeUndefined();
});
it.each([
  undefined,
  { ...native, role: 'operator' },
  { ...native, contextMode: 'PARTICIPANT' },
  { ...native, principalId: 'malformed' },
])('denies revoked, mismatched or malformed native sessions', async (result) => {
  owner.validate.mockResolvedValue(result);
  expect(await readWorkspaceSession('cookie')).toBeUndefined();
});
it('fails closed when identity configuration is unavailable', async () => {
  owner.config.mockRejectedValue(new Error('private diagnostic'));
  expect(await readWorkspaceSession('cookie')).toBeUndefined();
});
it('admits the selected live Platform session without falling back to an expired Participant session', async () => {
  owner.config.mockResolvedValue({ functionalTest: {} });
  owner.functional.mockImplementation(async (_runtime, role, context) =>
    role === 'viewer' && context === 'PLATFORM' ? native : undefined,
  );
  expect(await readWorkspaceSession(undefined, 'viewer', 'PLATFORM')).toEqual(native);
  expect(owner.functional).toHaveBeenCalledWith(expect.anything(), 'viewer', 'PLATFORM');
  expect(owner.validate).not.toHaveBeenCalled();
  expect(owner.decode).not.toHaveBeenCalled();
});
it('denies an invalid Platform selection even when the Participant session is live', async () => {
  owner.config.mockResolvedValue({ functionalTest: {} });
  owner.functional.mockImplementation(async (_runtime, _role, context) =>
    context === undefined || context === 'PARTICIPANT'
      ? { ...native, contextMode: 'PARTICIPANT' }
      : undefined,
  );
  expect(await readWorkspaceSession('unrelated-cookie', 'viewer', 'PLATFORM')).toBeUndefined();
  expect(owner.functional).toHaveBeenCalledWith(expect.anything(), 'viewer', 'PLATFORM');
  expect(owner.validate).not.toHaveBeenCalled();
  expect(owner.decode).not.toHaveBeenCalled();
});
