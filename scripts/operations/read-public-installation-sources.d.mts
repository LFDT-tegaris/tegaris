import type {
  OperationsSourceProfile,
  PublicOperationsSourceIdentity,
  PublicOperationsSourceCustody,
} from './installation-source-authentication.mjs';
export function readPublicOperationsSources(input: {
  readonly sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1';
  readonly profile: OperationsSourceProfile;
  readonly root?: string;
}): Promise<
  Readonly<{ identity: PublicOperationsSourceIdentity; custody: PublicOperationsSourceCustody }>
>;
