import type { PoolClient } from 'pg';
import type { MutationAuthorization } from '../domain/control-mutation-authorization.js';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import { SigningRotationError } from '../domain/signing-rotation.js';
import type { SigningRotationScope } from './signing-rotation-store.js';
import {
  verifyRuntimeMutationAuthorization,
  RuntimeMutationAuthorizationError,
} from './runtime-mutation-authorization.js';

export interface SigningCommandAuthorization {
  readonly authorization: Extract<
    MutationAuthorization,
    { readonly evidenceKind: 'IDENTITY_RUNTIME' }
  >;
  readonly sessionToken: string;
}
export function signingCommandVerifier(
  scope: SigningRotationScope,
  rotationId: string,
  candidate: { actionIntentId: string; actionIntentDigest: string; expectedRevision: string },
  inputDigest: Buffer,
  requestAuthorization: SigningCommandAuthorization,
  verifier: IdentityRuntimeVerifier,
  catalogOperationId: string,
) {
  const proof = requestAuthorization.authorization;
  const expectedAuthority = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    principalId: scope.authority.principalId,
    sessionId: scope.authority.sessionId,
    sessionEpoch: scope.authority.sessionEpoch,
    participantEpoch: scope.authority.participantEpoch,
    principalEpoch: scope.authority.principalEpoch,
    assignmentId: scope.authority.assignmentId,
    assignmentEpoch: scope.authority.assignmentRowVersion,
    authorityEnvelopeId: scope.authority.authorityEnvelopeId,
    authorityEpoch: scope.authority.authorityEpoch,
    delegationEpoch: scope.authority.delegationEpoch,
  };
  if (
    Object.entries(expectedAuthority).some(
      ([key, value]) => proof[key as keyof typeof expectedAuthority] !== value,
    )
  )
    throw new SigningRotationError('DENIED');
  return async (client: PoolClient) => {
    try {
      await verifyRuntimeMutationAuthorization(
        client,
        {
          ...requestAuthorization,
          ...candidate,
          catalogOperationId,
          resourceId: rotationId,
        },
        inputDigest,
        verifier,
      );
    } catch (error) {
      if (error instanceof RuntimeMutationAuthorizationError)
        throw new SigningRotationError('DENIED');
      throw error;
    }
  };
}
