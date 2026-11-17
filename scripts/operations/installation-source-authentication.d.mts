export type OperationsSourceProfile = 'local' | 'development' | 'test' | 'staging' | 'production';
export interface LegacyOperationsSourceCustody {
  readonly version: 1;
  readonly receiptId: string;
  readonly archiveDigest: string;
  readonly manifestHex: string;
  readonly schemaHex: string;
  readonly profileHex: string;
}
export interface LegacyOperationsSourceIdentity {
  readonly receiptId: string;
  readonly archiveDigest: string;
  readonly manifestDigest: string;
  readonly profile: OperationsSourceProfile;
  readonly configurationSchemaDigest: string;
  readonly namedProfileDigest: string;
}
export const operationsSourceAnchor: Readonly<{
  receiptId: string;
  packageId: string;
  archiveDigest: string;
  archiveBytes: number;
  manifestDigest: string;
  manifestBytes: number;
  schemaPath: string;
  schemaDigest: string;
  schemaBytes: number;
}>;
export const operationsSourceProfiles: Readonly<
  Record<
    OperationsSourceProfile,
    Readonly<{
      path: string;
      digest: string;
      bytes: number;
      canonicalDigest: string;
    }>
  >
>;
/** custody is PRIVATE installation data; never return it from status/readback. */
export function authenticateOperationsSources(input: {
  receiptBytes: Uint8Array;
  manifestBytes: Uint8Array;
  schemaBytes: Uint8Array;
  profileBytes: Uint8Array;
  profile: OperationsSourceProfile;
}): Readonly<{ identity: LegacyOperationsSourceIdentity; custody: LegacyOperationsSourceCustody }>;

export interface PublicOperationsSourceCustody {
  readonly version: 2;
  readonly sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1';
  readonly inventoryHex: string;
  readonly schemaHex: string;
  readonly profileHex: string;
}
export interface PublicOperationsSourceIdentity {
  readonly sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1';
  readonly inventoryDigest: string;
  readonly profile: OperationsSourceProfile;
  readonly configurationSchemaDigest: string;
  readonly namedProfileDigest: string;
}
export type OperationsSourceCustody = LegacyOperationsSourceCustody | PublicOperationsSourceCustody;
export type OperationsSourceIdentity =
  LegacyOperationsSourceIdentity | PublicOperationsSourceIdentity;
export const publicOperationsSourceAnchor: Readonly<{
  sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1';
  inventoryDigest: string;
  inventoryBytes: number;
  schemaPath: string;
  schemaDigest: string;
  schemaBytes: number;
}>;
export const publicOperationsSourceProfiles: typeof operationsSourceProfiles;
export function authenticateOperationsSources(input: {
  sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1';
  inventoryBytes: Uint8Array;
  schemaBytes: Uint8Array;
  profileBytes: Uint8Array;
  profile: OperationsSourceProfile;
}): Readonly<{ identity: PublicOperationsSourceIdentity; custody: PublicOperationsSourceCustody }>;
