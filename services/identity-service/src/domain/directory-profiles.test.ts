import { describe, expect, it, vi } from 'vitest';
import {
  DirectoryProfileRegistry,
  createRegisteredDirectoryProfiles,
  directoryProfileDefinitionsSchema,
  type RegisteredDirectoryProfile,
} from './directory-profiles.js';

const participantId = '01990000-0000-7000-8000-000000000001';
const profileId = '01990000-0000-7000-8000-000000000002';
const definition = {
  participantId,
  profileId,
  baseUrl: 'https://directory.example.invalid/scim/v2',
  oidcIssuer: 'https://idp.example.invalid',
  oidcClientId: 'openpc',
  subjectMapping: 'SCIM_ID' as const,
  certificateRef: 'secret://local/directory_cert#1',
  privateKeyRef: 'secret://local/directory_key#1',
  trustCaRef: 'secret://local/directory_ca#1',
};
function profile(overrides: Partial<RegisteredDirectoryProfile> = {}): RegisteredDirectoryProfile {
  return {
    participantId,
    oidcIssuer: definition.oidcIssuer,
    oidcClientId: definition.oidcClientId,
    subjectMapping: 'SCIM_ID',
    source: {
      profileId,
      baseUrl: definition.baseUrl,
      enumerate: vi.fn(),
      read: vi.fn(),
      close: vi.fn(),
    },
    ...overrides,
  };
}
describe('registered directory provenance', () => {
  it('isolates profile discovery and lookup by Participant and binds the provider namespace', () => {
    const selected = profile(),
      registry = new DirectoryProfileRegistry([selected]);
    expect(registry.list(participantId)).toEqual([
      { profileId, label: 'idp.example.invalid · openpc' },
    ]);
    expect(registry.list(profileId)).toEqual([]);
    expect(() => registry.get(profileId, profileId)).toThrow('PC-AUTH-0002');
    const bound = registry.get(participantId, profileId);
    for (const changed of [
      profile({ oidcClientId: 'different' }),
      profile({ oidcIssuer: 'https://other.example.invalid' }),
      profile({ source: { ...selected.source, baseUrl: 'https://other.example.invalid/scim/v2' } }),
    ]) {
      expect(() =>
        new DirectoryProfileRegistry([changed]).get(participantId, profileId, bound.digest),
      ).toThrow('PC-AUTH-0002');
    }
    registry.close();
    expect(selected.source.close).toHaveBeenCalledOnce();
  });
  it('requires HTTPS, unique registrations and an exact explicit local OIDC exception', () => {
    expect(() => new DirectoryProfileRegistry([profile(), profile()])).toThrow();
    for (const oidcIssuer of [
      'http://idp.example.invalid',
      'https://user:pass@idp.example.invalid',
      'https://idp.example.invalid?tenant=x',
      'https://idp.example.invalid#x',
    ])
      expect(() => new DirectoryProfileRegistry([profile({ oidcIssuer })])).toThrow();
    const local = profile({ oidcIssuer: 'http://oidc-emulator:3006' });
    expect(
      () => new DirectoryProfileRegistry([local], { localOidcIssuer: local.oidcIssuer }),
    ).not.toThrow();
    expect(
      () => new DirectoryProfileRegistry([local], { localOidcIssuer: 'http://other:3006' }),
    ).toThrow();
  });
  it('rejects aliases and raw material before resolving any registered secret', async () => {
    for (const privateKeyRef of [
      'secret://local/key#latest',
      'secret://local/key#CURRENT',
      'secret://local/key',
      'raw-private-key',
    ]) {
      expect(
        directoryProfileDefinitionsSchema.safeParse([{ ...definition, privateKeyRef }]).success,
      ).toBe(false);
    }
    const resolve = vi.fn(async () => Buffer.alloc(65537));
    await expect(createRegisteredDirectoryProfiles([definition], resolve)).rejects.toThrow(
      'Registered directory configuration unavailable',
    );
    expect(resolve).toHaveBeenCalledTimes(1);
    await expect(
      createRegisteredDirectoryProfiles([definition], async () => {
        throw new Error('secret-provider-private-details');
      }),
    ).rejects.toThrow(/^Registered directory configuration unavailable$/u);
  });
});
