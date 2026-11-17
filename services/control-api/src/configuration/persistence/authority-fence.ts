import type { PoolClient } from 'pg';

import { approvalAuthorityDependencies } from '../../../../identity-service/src/db/approval-authority-fence.js';
import {
  AuthorityFenceError,
  fenceBoundAuthorities,
  type AuthorityFence,
  type BoundAuthority,
} from '../../../../identity-service/src/db/authority-fence.js';
import { ConfigurationRepositoryError, type MutationContext } from './types.js';

export async function fenceConfigurationMutation(
  client: PoolClient,
  context: MutationContext,
  makerCheckerRequired: boolean,
  additional: AuthorityFence = {},
  dependencies: AuthorityFence = {},
): Promise<{ readonly authorities: readonly BoundAuthority[]; readonly fence: AuthorityFence }> {
  const proof = context.authorization;
  if (proof.sessionEpoch === undefined) throw new ConfigurationRepositoryError('PC-AUTH-0005');
  try {
    const approval = makerCheckerRequired
      ? await approvalAuthorityDependencies(client, proof, proof.approvalRequestId ?? '', true)
      : undefined;
    const authorities: BoundAuthority[] = [
      {
        principalId: proof.principalId,
        sessionId: proof.sessionId,
        sessionEpoch: proof.sessionEpoch,
        participantEpoch: proof.participantEpoch,
        principalEpoch: proof.principalEpoch,
        assignmentId: proof.assignmentId,
        assignmentRowVersion: proof.assignmentEpoch,
        authorityEnvelopeId: proof.authorityEnvelopeId,
        authorityEpoch: proof.authorityEpoch,
        delegationEpoch: proof.delegationEpoch,
        privacyDomainId: proof.privacyDomainId,
        actionIntentId: context.actionIntentId,
        resourceId: context.resourceId,
      },
      ...(approval?.authorities ?? []),
    ];
    const combined: AuthorityFence = Object.fromEntries(
      [...new Set([...Object.keys(additional), ...Object.keys(dependencies)])].map((table) => {
        const key = table as keyof AuthorityFence;
        return [key, [...(additional[key] ?? []), ...(dependencies[key] ?? [])]];
      }),
    );
    const fence = await fenceBoundAuthorities(client, proof.participantId, authorities, {
      ...combined,
      credential: [
        ...(combined.credential ?? []),
        ...(proof.evidenceKind === 'USER_WEBAUTHN' ? [{ id: proof.signerCredentialId }] : []),
        ...(proof.webauthnSignerCredentialId === undefined
          ? []
          : [{ id: proof.webauthnSignerCredentialId }]),
        ...(approval?.rows.credential ?? []),
      ],
    });
    // Credential state/epoch and request expiry are checked again after the fence.
    if (makerCheckerRequired) {
      await approvalAuthorityDependencies(client, proof, proof.approvalRequestId ?? '', true);
    }
    return { authorities, fence };
  } catch (error) {
    if (error instanceof AuthorityFenceError)
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    throw error;
  }
}
