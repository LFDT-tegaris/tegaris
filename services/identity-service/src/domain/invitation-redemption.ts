import { createHash, timingSafeEqual } from 'node:crypto';
import type { PoolClient } from 'pg';
import { lockAuthorityFence } from '../db/authority-fence.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { fenceInvitationAuthority, type InvitationAuthority } from './invitation-authority.js';
import { IdentityKernelError } from './identity-errors.js';
import { localOperationId } from './local-operation-id.js';
import {
  fenceBootstrapInvitation,
  readBootstrapCustody,
  startBootstrapAcceptanceSession,
} from './bootstrap-invitation.js';
import {
  persistOidcAuthorization,
  matchesOidcCustody,
  oidcExchangeFromRow,
  type OidcClientConfiguration,
  type OidcRow,
  type OidcTransactionCustody,
} from './oidc-authorization.js';
import type { VerifiedOidcIdentity } from './trust-adapter.js';
import type { IdentityRuntimeEvidenceSigner } from './identity-kernel.js';
import {
  createInvitationProofAssertion,
  verifyInvitationProofAssertion,
  type InvitationProofEvidence,
} from './invitation-acceptance-evidence.js';

export interface InvitationScope {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly invitationId: string;
}
export interface InvitationProofRequest extends InvitationScope {
  readonly transactionId: string;
  readonly state: string;
  readonly authorizationCode: string;
}
export interface InvitationAcceptance {
  readonly invitationId: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly state: 'ACCEPTED';
  readonly tokenVersion: string;
  readonly membershipId: string;
  readonly membershipStateAtAcceptance: 'PROVISIONED' | 'ACTIVE';
  readonly roleIntent: { readonly roleId: string; readonly authorityGranted: false };
  readonly acceptedAt: string;
  readonly operationId: string;
  readonly bootstrap?: {
    readonly mandateId: string;
    readonly sessionToken: string;
    readonly state: 'CLAIM_PENDING';
  };
}
interface InvitationToken {
  invitation_id: string;
  participant_id: string;
  privacy_domain_id: string;
  state: string;
  token_version: string;
  token_digest: Buffer;
  operation_id: string;
  expires_at: Date;
  row_version: string;
  display_name: string;
  intended_role_id: string;
  recipient_issuer: string;
  recipient_subject: string;
  recipient_audience: string;
  issuance_authority: InvitationAuthority | null;
}
const sha = (value: string) => createHash('sha256').update(value).digest();
const digestText = (value: Buffer) => `sha256:${value.toString('hex')}`;
const equal = (left: Buffer, right: Buffer) =>
  left.length === right.length && timingSafeEqual(left, right);
const denied = () => new IdentityKernelError('PC-AUTH-0002');

async function currentInvitation(
  client: PoolClient,
  scope: InvitationScope,
  lock = false,
): Promise<InvitationToken> {
  const selected = await client.query<InvitationToken>(
    `select invitation.*,invitation.token_version::text,invitation.row_version::text,token.token_digest,token.operation_id,token.issuance_authority
      from control.participant_invitation invitation join control.participant_invitation_token token
        on token.participant_id=invitation.participant_id and token.privacy_domain_id=invitation.privacy_domain_id
         and token.invitation_id=invitation.invitation_id and token.token_version=invitation.token_version
      where invitation.participant_id=$1 and invitation.privacy_domain_id=$2 and invitation.invitation_id=$3 ${lock ? 'for update of invitation' : ''}`,
    [scope.participantId, scope.privacyDomainId, scope.invitationId],
  );
  if (selected.rowCount !== 1) throw denied();
  return selected.rows[0]!;
}

async function fencePendingInvitation(
  client: PoolClient,
  scope: InvitationScope,
  version: string,
  tokenDigest: Buffer,
): Promise<InvitationToken> {
  const observed = await currentInvitation(client, scope);
  if (
    observed.state !== 'PENDING' ||
    observed.token_version !== version ||
    !equal(observed.token_digest, tokenDigest)
  )
    throw denied();
  const bootstrap = await fenceBootstrapInvitation(
    client,
    scope.participantId,
    scope.privacyDomainId,
    scope.invitationId,
  );
  if (!bootstrap)
    await fenceInvitationAuthority(
      client,
      scope.participantId,
      scope.privacyDomainId,
      observed.operation_id,
      observed.issuance_authority,
    );
  const current = await currentInvitation(client, scope, true);
  if (
    current.state !== 'PENDING' ||
    current.token_version !== version ||
    current.operation_id !== observed.operation_id ||
    !equal(current.token_digest, tokenDigest)
  )
    throw denied();
  const valid = await client.query(
    `select 1 from control.authority_role where participant_id=$1 and authority_role_id=$2 and state='ACTIVE'
    and $3::timestamptz>clock_timestamp() for share`,
    [scope.participantId, current.intended_role_id, current.expires_at],
  );
  if (valid.rowCount !== 1) throw denied();
  return current;
}

export async function beginInvitationProof(
  client: PoolClient,
  scope: InvitationScope & { readonly tokenVersion: string; readonly token: string },
  configuration: OidcClientConfiguration,
  now: Date,
) {
  const tokenDigest = sha(scope.token);
  const invitation = await fencePendingInvitation(client, scope, scope.tokenVersion, tokenDigest);
  if (
    invitation.recipient_issuer !== configuration.issuer ||
    invitation.recipient_audience !== configuration.clientId
  )
    throw denied();
  const started = await persistOidcAuthorization(
    client,
    configuration,
    now,
    'INVITATION',
    scope.participantId,
  );
  await client.query(
    `insert into control.participant_invitation_proof(transaction_id,participant_id,privacy_domain_id,invitation_id,token_version,token_digest)
    values($1,$2,$3,$4,$5,$6)`,
    [
      started.authorization.transactionId,
      scope.participantId,
      scope.privacyDomainId,
      scope.invitationId,
      scope.tokenVersion,
      tokenDigest,
    ],
  );
  return started;
}

interface ProofRow extends OidcRow {
  token_version: string;
  token_digest: Buffer;
  unexpired: boolean;
}
async function proofRow(
  client: PoolClient,
  request: InvitationProofRequest,
  custody: OidcTransactionCustody,
  lock = false,
): Promise<ProofRow> {
  const selected = await client.query<ProofRow>(
    `select oidc.*,oidc.expires_at>clock_timestamp() unexpired,proof.token_version::text,proof.token_digest from control.participant_invitation_proof proof
      join control.oidc_transaction oidc on oidc.transaction_id=proof.transaction_id
      where proof.participant_id=$1 and proof.privacy_domain_id=$2 and proof.invitation_id=$3 and proof.transaction_id=$4
        and oidc.purpose='INVITATION' and oidc.selected_participant_id=proof.participant_id
      ${lock ? 'for update of oidc' : ''}`,
    [request.participantId, request.privacyDomainId, request.invitationId, request.transactionId],
  );
  const row = selected.rows[0];
  if (!row || !matchesOidcCustody(row, custody) || !equal(row.state_digest, sha(request.state)))
    throw denied();
  return row;
}

async function committedAcceptance(
  client: PoolClient,
  request: InvitationProofRequest,
): Promise<InvitationAcceptance | undefined> {
  const selected = await client.query<{
    authorization_code_digest: Buffer;
    result: InvitationAcceptance;
  }>(
    `select authorization_code_digest,result from control.participant_invitation_acceptance
      where participant_id=$1 and privacy_domain_id=$2 and invitation_id=$3 and proof_transaction_id=$4`,
    [request.participantId, request.privacyDomainId, request.invitationId, request.transactionId],
  );
  const row = selected.rows[0];
  if (row && !equal(row.authorization_code_digest, sha(request.authorizationCode))) throw denied();
  return row?.result;
}

/** Return an exact committed retry before contacting the one-use provider code endpoint. */
export async function invitationProofContext(
  client: PoolClient,
  request: InvitationProofRequest,
  custody: OidcTransactionCustody,
  configuration: OidcClientConfiguration,
) {
  if (await readBootstrapCustody(client, request.participantId, request.invitationId)) {
    await proofRow(client, request, custody);
    const receipt = await committedAcceptance(client, request);
    if (receipt) return { receipt };
    await fenceBootstrapInvitation(
      client,
      request.participantId,
      request.privacyDomainId,
      request.invitationId,
    );
  }
  await lockAuthorityFence(client, request.participantId, {
    participant: [{ id: request.participantId, write: true }],
  });
  const row = await proofRow(client, request, custody);
  const receipt = await committedAcceptance(client, request);
  if (receipt) return { receipt };
  if (
    !row.unexpired ||
    row.consumed_at ||
    row.issuer !== configuration.issuer ||
    row.client_id !== configuration.clientId ||
    row.redirect_uri !== configuration.redirectUri
  )
    throw denied();
  await fencePendingInvitation(client, request, row.token_version, row.token_digest);
  return { exchange: oidcExchangeFromRow(row, custody) };
}

export async function completeInvitationProof(
  client: PoolClient,
  operationId: string,
  request: InvitationProofRequest,
  custody: OidcTransactionCustody,
  identity: VerifiedOidcIdentity,
  signer: IdentityRuntimeEvidenceSigner,
) {
  // Serialize at the authority root before reading receipts or locking child aggregates.
  // A concurrent committed callback is then observed as an exact retry.
  const bootstrap = await readBootstrapCustody(client, request.participantId, request.invitationId);
  if (bootstrap) {
    await proofRow(client, request, custody);
    const prior = await committedAcceptance(client, request);
    if (prior) return { result: prior };
    await fenceBootstrapInvitation(
      client,
      request.participantId,
      request.privacyDomainId,
      request.invitationId,
    );
  }
  await lockAuthorityFence(client, request.participantId, {
    participant: [{ id: request.participantId, write: true }],
  });
  const observed = await proofRow(client, request, custody);
  const prior = await committedAcceptance(client, request);
  if (prior) return { result: prior };
  const invitation = await fencePendingInvitation(
    client,
    request,
    observed.token_version,
    observed.token_digest,
  );
  const oidc = await proofRow(client, request, custody, true);
  const proof = identity.proofEvidence;
  const now = (await client.query<{ now: Date }>('select clock_timestamp() now')).rows[0]!.now;
  if (
    !oidc.unexpired ||
    oidc.consumed_at ||
    !proof ||
    identity.issuer !== oidc.issuer ||
    identity.audience !== oidc.client_id ||
    identity.issuer !== invitation.recipient_issuer ||
    identity.subject !== invitation.recipient_subject ||
    identity.audience !== invitation.recipient_audience ||
    identity.authorizedParty !== identity.audience ||
    !equal(oidc.nonce_digest, sha(identity.nonce)) ||
    identity.issuedAt > now ||
    identity.expiresAt <= now ||
    proof.verifiedAt > now ||
    proof.verifiedAt.getTime() < now.getTime() - 60_000 ||
    ![proof.idTokenDigest, proof.signingKeyDigest, proof.claimsDigest].every((value) =>
      /^sha256:[0-9a-f]{64}$/u.test(value),
    )
  )
    throw denied();
  await client.query('set local role openpc_identity_binding_resolver');
  const subjectId = (
    await client.query<{ subject_id: string }>(
      'select openpc.resolve_proved_oidc_identity($1,$2,$3) subject_id',
      [identity.issuer, identity.subject, identity.audience],
    )
  ).rows[0]!.subject_id;
  await client.query('reset role');
  const existing = await client.query<{
    principal_id: string;
    state: string;
    authority_epoch: string;
  }>(
    `select principal.principal_id,principal.state,principal.authority_epoch::text from control.participant_membership membership
      join control.principal principal on principal.participant_id=membership.participant_id and principal.principal_id=membership.membership_id
      where membership.participant_id=$1 and membership.identity_subject_id=$2 for update of principal`,
    [request.participantId, subjectId],
  );
  let member = existing.rows[0];
  if (!member) {
    const membershipId = localOperationId();
    member = (
      await client.query<{ principal_id: string; state: string; authority_epoch: string }>(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
        values($1,$2,'USER',$3,'PROVISIONED',0) returning principal_id,state,authority_epoch::text`,
        [membershipId, request.participantId, invitation.display_name],
      )
    ).rows[0]!;
    await client.query(
      'insert into control.participant_membership(membership_id,participant_id,identity_subject_id) values($1,$2,$3)',
      [membershipId, request.participantId, subjectId],
    );
  }
  if (member.state !== 'PROVISIONED' && member.state !== 'ACTIVE') throw denied();
  const credentials = await client.query<{ principal_id: string; valid: boolean }>(
    `select principal_id,state='ACTIVE' and credential_epoch>0 and valid_from<=clock_timestamp()
      and (valid_until is null or valid_until>clock_timestamp()) valid from control.credential
      where participant_id=$1 and kind='OIDC_SUBJECT' and issuer=$2 and subject=$3 and audience=$4 for share`,
    [request.participantId, identity.issuer, identity.subject, identity.audience],
  );
  if (credentials.rowCount === 0)
    await client.query(
      `insert into control.credential(participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,valid_from)
      values($1,$2,'OIDC_SUBJECT',$3,$4,$5,'ACTIVE',1,clock_timestamp())`,
      [
        request.participantId,
        member.principal_id,
        identity.issuer,
        identity.subject,
        identity.audience,
      ],
    );
  else if (
    credentials.rowCount !== 1 ||
    credentials.rows[0]!.principal_id !== member.principal_id ||
    !credentials.rows[0]!.valid
  )
    throw denied();
  const participantEpoch = (
    await client.query<{ authority_epoch: string }>(
      "select authority_epoch::text from control.participant where participant_id=$1 and (state='ACTIVE' or ($2 and state='PROVISIONING'))",
      [request.participantId, bootstrap !== undefined],
    )
  ).rows[0]?.authority_epoch;
  if (!participantEpoch) throw denied();
  const result: InvitationAcceptance = {
    invitationId: request.invitationId,
    participantId: request.participantId,
    privacyDomainId: request.privacyDomainId,
    state: 'ACCEPTED',
    tokenVersion: oidc.token_version,
    membershipId: member.principal_id,
    membershipStateAtAcceptance: member.state,
    roleIntent: { roleId: invitation.intended_role_id, authorityGranted: false },
    acceptedAt: now.toISOString(),
    operationId,
    ...(bootstrap
      ? {
          bootstrap: await startBootstrapAcceptanceSession(
            client,
            bootstrap,
            member.principal_id,
            member.authority_epoch,
          ),
        }
      : {}),
  };
  const inputs: InvitationProofEvidence = {
    operationId,
    participantId: request.participantId,
    privacyDomainId: request.privacyDomainId,
    membershipId: member.principal_id,
    participantEpoch,
    invitationId: request.invitationId,
    tokenVersion: oidc.token_version,
    tokenDigest: digestText(oidc.token_digest),
    issuanceAuthorityDigest: canonicalAuthorizationDigest(
      bootstrap?.issuance_authority ?? invitation.issuance_authority,
    ),
    recipientDigest: canonicalAuthorizationDigest([
      identity.issuer,
      identity.subject,
      identity.audience,
    ]),
    oidcConfigurationDigest: canonicalAuthorizationDigest([
      oidc.issuer,
      oidc.client_id,
      oidc.redirect_uri,
    ]),
    transactionId: oidc.transaction_id,
    stateDigest: digestText(oidc.state_digest),
    nonceDigest: digestText(oidc.nonce_digest),
    codeVerifierDigest: digestText(oidc.code_verifier_digest),
    browserSessionDigest: digestText(oidc.browser_session_digest),
    codeChallenge: oidc.code_challenge,
    authorizationCodeDigest: digestText(sha(request.authorizationCode)),
    idTokenDigest: proof.idTokenDigest,
    signingKeyDigest: proof.signingKeyDigest,
    claimsDigest: proof.claimsDigest,
    resultDigest: canonicalAuthorizationDigest(result),
    verifiedAt: proof.verifiedAt,
    validUntil: new Date(
      Math.min(
        oidc.expires_at.getTime(),
        identity.expiresAt.getTime(),
        invitation.expires_at.getTime(),
      ),
    ),
  };
  const signed = await signer.signCanonicalAssertion(createInvitationProofAssertion(inputs));
  if (
    !(await verifyInvitationProofAssertion(inputs, signed.evidenceCbor, signed.coseSign1, signer))
  )
    throw denied();
  await client.query(
    'update control.oidc_transaction set consumed_at=clock_timestamp() where transaction_id=$1 and consumed_at is null',
    [oidc.transaction_id],
  );
  if (!bootstrap)
    await client.query(
      `update control.participant_invitation set state='ACCEPTED',row_version=row_version+1,updated_at=clock_timestamp(),last_mutation_operation_id=$4
    where participant_id=$1 and privacy_domain_id=$2 and invitation_id=$3`,
      [request.participantId, request.privacyDomainId, request.invitationId, operationId],
    );
  await client.query(
    `insert into control.participant_invitation_acceptance(invitation_id,participant_id,privacy_domain_id,token_version,proof_transaction_id,identity_subject_id,membership_id,operation_id,authorization_code_digest,result,evidence_cbor,evidence_digest,cose_sign1,accepted_at)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      request.invitationId,
      request.participantId,
      request.privacyDomainId,
      oidc.token_version,
      oidc.transaction_id,
      subjectId,
      member.principal_id,
      operationId,
      sha(request.authorizationCode),
      result,
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      now,
    ],
  );
  await client.query(
    `insert into control.mutation_evidence(participant_id,privacy_domain_id,operation_id,principal_id,action_intent_id,catalog_operation_id,aggregate_type,aggregate_id,aggregate_version,candidate_digest,bound_participant_epoch,bound_principal_epoch,evidence_role,evidence_format,evidence_cbor,evidence_digest,cose_sign1)
    values($1,$2,$3,$4,'ACT-PARTICIPANT_CREATE_MEMBER-V1','ID-OP-INVITATION-ACCEPT','invitation-redemption',$5,$6,$7,$8,$9,'IDENTITY_PROOF_INPUT','IDENTITY_RUNTIME_ASSERTION_3002_2_13',$10,$11,$12)`,
    [
      request.participantId,
      request.privacyDomainId,
      operationId,
      member.principal_id,
      request.invitationId,
      invitation.row_version,
      Buffer.from(inputs.resultDigest.slice(7), 'hex'),
      participantEpoch,
      member.authority_epoch,
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
    ],
  );
  return { result, signed };
}
