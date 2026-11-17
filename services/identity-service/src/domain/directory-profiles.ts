import { z } from 'zod';
import { isExactSigningSecretReference } from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { IdentityKernelError } from './identity-errors.js';
import type { ScimDirectorySource } from './scim-directory-source.js';
import { createHttpScimDirectorySource } from './http-scim-directory-source.js';

export interface RegisteredDirectoryProfile {
  readonly participantId: string;
  readonly source: ScimDirectorySource;
  readonly oidcIssuer: string;
  readonly oidcClientId: string;
  /** An explicit provider contract; never guess OIDC subject equality from labels or emails. */
  readonly subjectMapping: 'SCIM_ID';
}
const registrationSchema = z.strictObject({
  participantId: z.uuid(),
  profileId: z.uuid(),
  baseUrl: z.url(),
  oidcIssuer: z.url(),
  oidcClientId: z.string().min(1).max(512),
  subjectMapping: z.literal('SCIM_ID'),
});

/** Trusted composition input. Public requests may select only their Participant's registered profile. */
export class DirectoryProfileRegistry {
  private readonly profiles = new Map<
    string,
    RegisteredDirectoryProfile & { readonly digest: string }
  >();
  constructor(
    profiles: readonly RegisteredDirectoryProfile[] = [],
    options: { readonly localOidcIssuer?: string } = {},
  ) {
    for (const profile of profiles) {
      const identity = registrationSchema.parse({
        participantId: profile.participantId,
        profileId: profile.source.profileId,
        baseUrl: profile.source.baseUrl,
        oidcIssuer: profile.oidcIssuer,
        oidcClientId: profile.oidcClientId,
        subjectMapping: profile.subjectMapping,
      });
      const issuer = new URL(identity.oidcIssuer);
      if (
        new URL(identity.baseUrl).protocol !== 'https:' ||
        this.profiles.has(identity.profileId) ||
        issuer.username ||
        issuer.password ||
        issuer.search ||
        issuer.hash ||
        (issuer.protocol !== 'https:' &&
          !(issuer.protocol === 'http:' && identity.oidcIssuer === options.localOidcIssuer))
      )
        throw new Error('Invalid or duplicate directory profile registration');
      this.profiles.set(
        identity.profileId,
        Object.freeze({ ...profile, digest: canonicalAuthorizationDigest(identity) }),
      );
    }
  }
  list(participantId: string) {
    return [...this.profiles.entries()]
      .filter(([, profile]) => profile.participantId === participantId)
      .map(([profileId, profile]) => ({
        profileId,
        label: `${new URL(profile.oidcIssuer).host} · ${profile.oidcClientId}`,
      }));
  }
  close() {
    for (const profile of this.profiles.values()) profile.source.close();
  }
  get(participantId: string, profileId: string, expectedDigest?: string) {
    const profile = this.profiles.get(profileId);
    if (
      !profile ||
      profile.participantId !== participantId ||
      (expectedDigest !== undefined && profile.digest !== expectedDigest)
    )
      throw new IdentityKernelError('PC-AUTH-0002');
    return profile;
  }
}

const secretRef = z
  .string()
  .refine((value) => isExactSigningSecretReference(value, value.split('#')[1]));
export const directoryProfileDefinitionsSchema = z
  .array(
    registrationSchema.extend({
      certificateRef: secretRef,
      privateKeyRef: secretRef,
      trustCaRef: secretRef,
    }),
  )
  .max(16);
export type DirectoryProfileDefinitions = z.infer<typeof directoryProfileDefinitionsSchema>;

/** Resolve exact-version references through the registered runtime provider; no secret enters a public candidate. */
export async function createRegisteredDirectoryProfiles(
  definitions: DirectoryProfileDefinitions,
  resolveSecret: (reference: string) => Promise<Buffer>,
  options: { readonly localOidcIssuer?: string } = {},
) {
  const parsed = directoryProfileDefinitionsSchema.parse(definitions),
    profiles: RegisteredDirectoryProfile[] = [];
  try {
    for (const value of parsed) {
      const secret = async (reference: string) => {
        const bytes = await resolveSecret(reference);
        if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 65536)
          throw new Error('Invalid registered directory secret');
        return bytes;
      };
      const certificate = await secret(value.certificateRef),
        privateKey = await secret(value.privateKeyRef),
        trustCa = await secret(value.trustCaRef);
      profiles.push({
        participantId: value.participantId,
        oidcIssuer: value.oidcIssuer,
        oidcClientId: value.oidcClientId,
        subjectMapping: value.subjectMapping,
        source: createHttpScimDirectorySource({
          profileId: value.profileId,
          baseUrl: value.baseUrl,
          certificate,
          privateKey,
          trustCa,
        }),
      });
    }
    return new DirectoryProfileRegistry(profiles, options);
  } catch {
    for (const profile of profiles) profile.source.close();
    throw new Error('Registered directory configuration unavailable');
  }
}
