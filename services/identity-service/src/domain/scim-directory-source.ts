import { z } from 'zod';

export const scimUserSchemaUrn = 'urn:ietf:params:scim:schemas:core:2.0:User';
export const scimGroupSchemaUrn = 'urn:ietf:params:scim:schemas:core:2.0:Group';
export const scimListSchemaUrn = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';

// Provider-assigned IDs are case-exact and scoped to the registered connector. Neither
// userName nor the client's optional externalId is a durable identity binding.
export const scimResourceIdSchema = z
  .string()
  .min(1)
  .max(512)
  .refine(
    (value) =>
      value !== '.' &&
      value !== '..' &&
      Array.from(value).every((character) => {
        const code = character.codePointAt(0)!;
        return code > 31 && code !== 127;
      }),
  );
export const scimVersionSchema = z
  .string()
  .max(1024)
  .regex(/^(?:W\/)?"[\x21\x23-\x7e]+"$/u);
const meta = z.object({
  resourceType: z.enum(['User', 'Group']),
  version: scimVersionSchema,
  lastModified: z.iso.datetime({ offset: true }),
});
const schemas = z.array(z.string().max(256)).min(1).max(32);
const user = z.object({
  schemas: schemas.refine((value) => value.includes(scimUserSchemaUrn)),
  id: scimResourceIdSchema,
  userName: z.string().min(1).max(512),
  displayName: z.string().min(1).max(512).optional(),
  // An omitted active attribute cannot authorize provisioning or reactivation.
  active: z.boolean(),
  meta: meta.extend({ resourceType: z.literal('User') }),
});
const member = z.object({
  value: scimResourceIdSchema,
  type: z.enum(['User', 'Group']).optional(),
});
const group = z.object({
  schemas: schemas.refine((value) => value.includes(scimGroupSchemaUrn)),
  id: scimResourceIdSchema,
  displayName: z.string().min(1).max(512),
  members: z.array(member).max(10_000).optional(),
  meta: meta.extend({ resourceType: z.literal('Group') }),
});

export interface ScimUserObservation {
  readonly resourceType: 'User';
  readonly id: string;
  readonly version: string;
  readonly lastModified: string;
  readonly userName: string;
  readonly displayName: string;
  readonly active: boolean;
}
export const scimGroupObservationSchema = z.strictObject({
  resourceType: z.literal('Group'),
  id: scimResourceIdSchema,
  version: scimVersionSchema,
  lastModified: z.iso.datetime({ offset: true }),
  displayName: z.string().min(1).max(512),
  members: z
    .array(z.strictObject({ id: scimResourceIdSchema, type: z.enum(['User', 'Group']).nullable() }))
    .max(10_000)
    .nullable(),
});
export type ScimGroupObservation = z.infer<typeof scimGroupObservationSchema>;
export type ScimResourceObservation = ScimUserObservation | ScimGroupObservation;

/** Retain only the fields owned by reconciliation, never credentials or arbitrary extensions. */
export function parseScimResource(
  kind: 'Users' | 'Groups',
  input: unknown,
): ScimResourceObservation {
  if (kind === 'Users') {
    const value = user.parse(input);
    return {
      resourceType: 'User',
      id: value.id,
      version: value.meta.version,
      lastModified: value.meta.lastModified,
      userName: value.userName,
      displayName: value.displayName ?? value.userName,
      active: value.active,
    };
  }
  const value = group.parse(input);
  const ids = new Set<string>();
  for (const item of value.members ?? []) {
    if (ids.has(item.value)) throw new Error('Duplicate SCIM group member');
    ids.add(item.value);
  }
  return {
    resourceType: 'Group',
    id: value.id,
    version: value.meta.version,
    lastModified: value.meta.lastModified,
    displayName: value.displayName,
    // An omitted member list is unknown, not an empty group. Missing types and nested
    // groups also remain unresolved; they cannot silently become local human memberships.
    members: value.members?.map((item) => ({ id: item.value, type: item.type ?? null })) ?? null,
  };
}

export const scimListSchema = z.object({
  schemas: schemas.refine((value) => value.includes(scimListSchemaUrn)),
  totalResults: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  startIndex: z.number().int().positive().optional(),
  itemsPerPage: z.number().int().nonnegative().optional(),
  Resources: z.array(z.unknown()).optional(),
});

/** A finished enumeration is not an atomic snapshot and never establishes deletion. */
export interface ScimEnumeration {
  readonly profileId: string;
  readonly kind: 'Users' | 'Groups';
  readonly observedAt: string;
  readonly resources: readonly ScimResourceObservation[];
  readonly omissionMeaning: 'NONE';
}
export interface ScimDirectorySource {
  readonly profileId: string;
  readonly baseUrl: string;
  enumerate(kind: 'Users' | 'Groups'): Promise<ScimEnumeration>;
  read(kind: 'Users' | 'Groups', id: string): Promise<ScimResourceObservation>;
  close(): void;
}

/** Registered external failure; messages never expose provider bodies, identifiers or secrets. */
export class ScimDirectoryUnavailable extends Error {
  readonly code = 'PC-AUTH-0002';
  constructor() {
    super('PC-AUTH-0002');
  }
}
