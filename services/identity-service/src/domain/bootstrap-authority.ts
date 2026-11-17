import type { PoolClient } from 'pg';
import {
  captureDurableAuthorities,
  fenceBoundAuthorities,
  fenceDurableAuthorities,
  type BoundAuthority,
  type DurableAuthority,
  type MutationAuthorityContext,
} from '../db/authority-fence.js';
import { IdentityKernelError } from './identity-errors.js';
import type { FirstAdministratorProposal } from '../../../participant-service/src/contracts/first-administrator.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  fenceEnvelopePlatformContext,
  type EnvelopePlatformContext,
} from '../db/platform-context.js';
import { isDeepStrictEqual } from 'node:util';

export interface BootstrapIssuanceAuthority {
  readonly version: 1;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly operationId: string;
  readonly approvalRequestId: string;
  readonly candidateDigest: string;
  readonly authorities: readonly DurableAuthority[];
  readonly platformContext?: EnvelopePlatformContext;
  readonly signers: readonly {
    readonly principalId: string;
    readonly credentialId: string;
    readonly credentialEpoch: string;
  }[];
}

const deny = () => new IdentityKernelError('PC-AUTH-0002');

/** Kind, context and direct live grants all matter. Neither the context label nor kind supplies a grant. */
export async function assertPlatformBootstrapActor(
  client: PoolClient,
  participantId: string,
  principalId: string,
  sessionId: string,
) {
  const selected = await client.query(
    `select 1 from control.principal principal
    join control.participant participant on participant.participant_id=principal.participant_id and participant.state='ACTIVE'
    join control.session session on session.participant_id=principal.participant_id and session.principal_id=principal.principal_id
    where principal.participant_id=$1 and principal.principal_id=$2 and principal.kind='PLATFORM_OPERATOR' and principal.state='ACTIVE'
      and session.session_id=$3 and session.state='ACTIVE' and session.context_mode='PLATFORM' and session.privacy_domain_id is null
      and session.participant_epoch=participant.authority_epoch and session.authority_epoch=principal.authority_epoch
      and session.idle_expires_at>clock_timestamp() and session.absolute_expires_at>clock_timestamp()`,
    [participantId, principalId, sessionId],
  );
  if (selected.rowCount !== 1) throw deny();
}

/** Called under the ordinary candidate/approval fence, before entering the new Participant's scope. */
export async function captureBootstrapAuthority(
  client: PoolClient,
  participantId: string,
  input: MutationAuthorityContext & {
    readonly operationId: string;
    readonly approvalRequestId: string;
    readonly candidateDigest: string;
    readonly adminActions: readonly string[];
  },
): Promise<BootstrapIssuanceAuthority> {
  const maker = input.makerAuthority;
  const checker = input.approvalAuthorities[1];
  if (
    input.approvalAuthorities.length !== 2 ||
    !checker ||
    checker.principalId === maker.principalId ||
    input.approvalAuthorities[0]?.principalId !== maker.principalId ||
    input.adminActions.length === 0
  )
    throw deny();
  await assertPlatformBootstrapActor(client, participantId, maker.principalId, maker.sessionId);
  await assertPlatformBootstrapActor(client, participantId, checker.principalId, checker.sessionId);
  // The first administrative grant is bounded by both custodians' actual capability envelopes.
  // These are direct paths: bootstrap custody cannot be obtained by delegation.
  const authorities: BoundAuthority[] = [maker, ...input.approvalAuthorities];
  for (const actor of [maker, checker]) {
    const direct = await client.query(
      `select 1 from control.assignment where participant_id=$1 and assignment_id=$2 and principal_id=$3`,
      [participantId, actor.assignmentId, actor.principalId],
    );
    if (direct.rowCount !== 1) throw deny();
    for (const actionIntentId of input.adminActions)
      authorities.push({
        ...actor,
        catalogOperationId: undefined,
        actionIntentId,
        resourceId: maker.resourceId,
      });
  }
  await fenceBoundAuthorities(client, participantId, authorities);
  const makerPlatform = await fenceEnvelopePlatformContext(
    client,
    participantId,
    maker.authorityEnvelopeId,
  );
  const checkerPlatform = await fenceEnvelopePlatformContext(
    client,
    participantId,
    checker.authorityEnvelopeId,
  );
  if (!isDeepStrictEqual(makerPlatform, checkerPlatform)) throw deny();
  const signers = [];
  for (const [actor, credentialId] of [
    [maker, input.makerSignerCredentialId],
    [checker, input.checkerSignerCredentialId],
  ] as const) {
    if (!credentialId) throw deny();
    const selected = await client.query<{ credential_epoch: string }>(
      `select credential_epoch::text from control.credential
      where participant_id=$1 and principal_id=$2 and credential_id=$3 and kind='WEBAUTHN' and state='ACTIVE'
        and valid_from<=clock_timestamp() and (valid_until is null or valid_until>clock_timestamp())`,
      [participantId, actor.principalId, credentialId],
    );
    if (selected.rowCount !== 1) throw deny();
    signers.push({
      principalId: actor.principalId,
      credentialId,
      credentialEpoch: selected.rows[0]!.credential_epoch,
    });
  }
  return {
    version: 1,
    participantId,
    privacyDomainId: maker.privacyDomainId,
    operationId: input.operationId,
    approvalRequestId: input.approvalRequestId,
    candidateDigest: input.candidateDigest,
    authorities: await captureDurableAuthorities(client, participantId, authorities),
    ...(makerPlatform === null ? {} : { platformContext: makerPlatform }),
    signers,
  };
}

/** The committed proposal outlives browser/approval expiry, but never custodian revocation. */
export async function fenceBootstrapAuthority(
  client: PoolClient,
  value: BootstrapIssuanceAuthority,
  targetParticipantId: string,
  candidate: FirstAdministratorProposal,
) {
  if (
    value.version !== 1 ||
    value.authorities.length < 5 ||
    value.signers.length !== 2 ||
    value.signers[0]!.principalId === value.signers[1]!.principalId ||
    value.authorities.some((entry) => entry.grant.privacyDomainId !== value.privacyDomainId)
  )
    throw deny();
  await fenceDurableAuthorities(client, value.participantId, value.authorities, {
    participant: [{ id: value.participantId }],
    credential: value.signers.map((entry) => ({ id: entry.credentialId })),
  });
  for (const envelopeId of new Set(
    value.authorities.map((entry) => entry.grant.authorityEnvelopeId),
  )) {
    const current = await fenceEnvelopePlatformContext(client, value.participantId, envelopeId);
    if (!isDeepStrictEqual(current, value.platformContext ?? null)) throw deny();
  }
  for (const signer of value.signers) {
    const live = await client.query(
      `select 1 from control.principal principal join control.credential credential
      on credential.participant_id=principal.participant_id and credential.principal_id=principal.principal_id
      where principal.participant_id=$1 and principal.principal_id=$2 and principal.kind='PLATFORM_OPERATOR' and principal.state='ACTIVE'
        and credential.credential_id=$3 and credential.credential_epoch=$4 and credential.kind='WEBAUTHN' and credential.state='ACTIVE'
        and credential.valid_from<=clock_timestamp() and (credential.valid_until is null or credential.valid_until>clock_timestamp())`,
      [value.participantId, signer.principalId, signer.credentialId, signer.credentialEpoch],
    );
    if (live.rowCount !== 1) throw deny();
  }
  const receipt = await client.query(
    `select 1 from control.mutation_candidate candidate
    join control.mutation_evidence evidence on evidence.participant_id=candidate.participant_id and evidence.privacy_domain_id=candidate.privacy_domain_id
      and evidence.operation_id=candidate.consumed_operation_id and evidence.candidate_digest=candidate.candidate_digest
    join control.idempotency_record receipt on receipt.participant_id=candidate.participant_id and receipt.operation_id=candidate.consumed_operation_id
      and receipt.terminal_state='COMMITTED' and receipt.result_payload#>>'{result,bootstrap,issuanceAuthorityDigest}'=$10
    where candidate.participant_id=$1 and candidate.privacy_domain_id=$2 and candidate.state='CONSUMED'
      and candidate.catalog_operation_id='ID-OP-PARTICIPANT-CREATE' and candidate.consumed_operation_id=$3
      and candidate.candidate_digest=$4 and evidence.approval_request_id=$5
      and candidate.resource_id=$6 and candidate.candidate_document->>'participantId'=$6::text
      and candidate.candidate_document->'firstAdministrator'=$7::jsonb
      and evidence.principal_id=$8 and evidence.checker_principal_id=$9`,
    [
      value.participantId,
      value.privacyDomainId,
      value.operationId,
      Buffer.from(value.candidateDigest.slice(7), 'hex'),
      value.approvalRequestId,
      targetParticipantId,
      candidate,
      value.signers[0]!.principalId,
      value.signers[1]!.principalId,
      canonicalAuthorizationDigest(value),
    ],
  );
  if (receipt.rowCount !== 1) throw deny();
}
