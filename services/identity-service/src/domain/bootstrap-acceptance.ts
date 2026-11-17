import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { encodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
} from '../contracts/authorization.js';
import { IdentityKernelError } from './identity-errors.js';
import {
  fenceBootstrapInvitation,
  readBootstrapCustody,
  type BootstrapCustodyRow,
} from './bootstrap-invitation.js';
import { localOperationId } from './local-operation-id.js';
import { verifyLocalWebAuthnAssertion } from './local-webauthn-trust-adapter.js';
import { verifiedWebAuthnAssertionDigest } from './trust-adapter.js';
import type { IdentityRuntimeEvidenceSigner } from './identity-kernel.js';
import type { WebAuthnRegistrationAdapter } from './webauthn-registration.js';
import { identityActorKeyDigest } from './identity-runtime-authorization.js';
import { assertGrantAdmission } from '../../../participant-service/src/domain/grant-admission.js';
import type { Assignment } from '../../../participant-service/src/domain/authority-kernel.js';

export const bootstrapCommand = z.discriminatedUnion('command', [
  z.strictObject({ command: z.literal('READ') }),
  z.strictObject({ command: z.literal('ENROLL_OPTIONS') }),
  z.strictObject({
    command: z.literal('ENROLL_COMPLETE'),
    enrollmentId: z.uuidv7(),
    response: z.unknown(),
  }),
  z.strictObject({ command: z.literal('ACCEPT_OPTIONS') }),
  z.strictObject({
    command: z.literal('ACCEPT'),
    intentDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    challenge: z.string().min(32).max(256),
    assertion: z.string().min(1).max(32768),
  }),
]);
export type BootstrapCommand = z.infer<typeof bootstrapCommand>;
export interface BootstrapSessionScope {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly invitationId: string;
  readonly sessionToken: string;
}
const denied = () => new IdentityKernelError('PC-AUTH-0002');
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();
const digestText = (value: Buffer) => `sha256:${value.toString('hex')}`;
const bytes = (value: string) => Buffer.from(value.slice(7), 'hex');
const acceptanceAction = 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1';

function intent(custody: BootstrapCustodyRow) {
  return canonicalAuthorizationDigest({
    mandateId: custody.mandate_id,
    participantId: custody.participant_id,
    participantEpoch: custody.participant_epoch,
    custodyGeneration: custody.custody_generation,
    invitationId: custody.invitation_id,
    membershipId: custody.candidate_membership_id,
    candidateDigest: digestText(custody.candidate_digest),
    operation: 'FIRST_ADMIN_ACCEPTANCE',
  });
}

/** Only this owner accepts the proof-bound ceremony session. Ordinary session authentication remains unchanged. */
export async function runBootstrapCommand(
  client: PoolClient,
  operationId: string,
  scope: BootstrapSessionScope,
  command: BootstrapCommand,
  origin: string,
  registration: WebAuthnRegistrationAdapter,
  signer: IdentityRuntimeEvidenceSigner,
) {
  const observed = await readBootstrapCustody(client, scope.participantId, scope.invitationId);
  if (
    !observed ||
    observed.candidate.privacyDomainId !== scope.privacyDomainId ||
    !observed.candidate_session_id ||
    !observed.candidate_membership_id ||
    scope.sessionToken !== `${scope.participantId}.${observed.candidate_session_id}`
  )
    throw denied();
  const session = (
    await client.query<{ opaque_token_digest: Buffer; valid: boolean; receipt_valid: boolean }>(
      `select opaque_token_digest,
    state='ACTIVE' and context_mode='PLATFORM' and privacy_domain_id is null and absolute_expires_at>clock_timestamp() valid,
    state='REVOKED' and revoked_reason='first-administrator-handoff' and context_mode='PLATFORM' and privacy_domain_id is null
      and absolute_expires_at>clock_timestamp() receipt_valid
    from control.session where participant_id=$1 and principal_id=$2 and session_id=$3`,
      [scope.participantId, observed.candidate_membership_id, observed.candidate_session_id],
    )
  ).rows[0];
  if (
    !session ||
    session.opaque_token_digest.length !== 32 ||
    !timingSafeEqual(session.opaque_token_digest, hash(scope.sessionToken))
  )
    throw denied();
  if (observed.state === 'ACCEPTED') {
    if (!session.receipt_valid) throw denied();
    if (
      command.command !== 'READ' &&
      !(
        command.command === 'ACCEPT' &&
        observed.accepted_intent_digest?.equals(bytes(command.intentDigest))
      )
    )
      throw denied();
    return observed.acceptance_result;
  }
  if (!session.valid) throw denied();
  const custody = await fenceBootstrapInvitation(
    client,
    scope.participantId,
    scope.privacyDomainId,
    scope.invitationId,
  );
  if (
    !custody ||
    custody.state !== 'CLAIM_PENDING' ||
    custody.candidate_session_id !== observed.candidate_session_id
  )
    throw denied();
  const currentToken = await client.query(
    `select 1 from control.participant_invitation invitation
    join control.participant_invitation_acceptance proof on proof.participant_id=invitation.participant_id and proof.invitation_id=invitation.invitation_id
      and proof.token_version=invitation.token_version and proof.membership_id=$3
    where invitation.participant_id=$1 and invitation.invitation_id=$2 and invitation.state='PENDING' and invitation.expires_at>clock_timestamp()`,
    [scope.participantId, scope.invitationId, custody.candidate_membership_id],
  );
  if (currentToken.rowCount !== 1) throw denied();
  const member = (
    await client.query<{ display_label: string; authority_epoch: string }>(
      `select display_label,authority_epoch::text from control.principal where participant_id=$1 and principal_id=$2 and state='PROVISIONED' and kind='USER' for update`,
      [scope.participantId, custody.candidate_membership_id],
    )
  ).rows[0];
  if (!member) throw denied();
  const intentDigest = intent(custody);
  const credentials = await client.query<{
    credential_epoch: string;
    credential_id: string;
    subject: string;
    public_key_digest: Buffer;
    public_key_spki_der: Buffer;
    authenticator_sign_count: string;
  }>(
    `select credential_id,credential_epoch::text,subject,public_key_digest,public_key_spki_der,authenticator_sign_count::text from control.credential
    where participant_id=$1 and principal_id=$2 and kind='WEBAUTHN' and state='ACTIVE' and valid_from<=clock_timestamp()
      and (valid_until is null or valid_until>clock_timestamp()) for update`,
    [scope.participantId, custody.candidate_membership_id],
  );
  if (command.command === 'READ')
    return {
      state: 'CLAIM_PENDING',
      mandateId: custody.mandate_id,
      participantId: scope.participantId,
      invitationId: scope.invitationId,
      displayName: member.display_label,
      enrollmentRequired: credentials.rowCount === 0,
      intentDigest,
      expiresAt: custody.expires_at.toISOString(),
      roleId: custody.candidate.roleId,
      actionIntentIds: custody.candidate.actionIntentIds,
    };
  if (command.command === 'ENROLL_OPTIONS') {
    if (credentials.rowCount !== 0) throw denied();
    const enrollmentId = localOperationId(),
      challenge = randomBytes(32).toString('base64url'),
      rpId = new URL(origin).hostname;
    await client.query(
      `update control.webauthn_enrollment set expires_at=clock_timestamp(),row_version=row_version+1 where participant_id=$1 and session_id=$2 and consumed_at is null and expires_at>clock_timestamp()`,
      [scope.participantId, custody.candidate_session_id],
    );
    await client.query(
      `insert into control.webauthn_enrollment(enrollment_id,participant_id,principal_id,session_id,challenge_digest,rp_id,origin,expires_at)
      values($1,$2,$3,$4,$5,$6,$7,least($8,clock_timestamp()+interval '5 minutes'))`,
      [
        enrollmentId,
        scope.participantId,
        custody.candidate_membership_id,
        custody.candidate_session_id,
        hash(challenge),
        rpId,
        origin,
        custody.expires_at,
      ],
    );
    return {
      enrollmentId,
      publicKey: await registration.options({
        challenge,
        rpId,
        principalId: custody.candidate_membership_id!,
        displayLabel: member.display_label,
        excludedCredentialIds: [],
      }),
    };
  }
  if (command.command === 'ENROLL_COMPLETE') {
    if (credentials.rowCount !== 0) throw denied();
    const row = (
      await client.query<{ challenge_digest: Buffer; origin: string; rp_id: string }>(
        `select challenge_digest,origin,rp_id from control.webauthn_enrollment
      where participant_id=$1 and session_id=$2 and principal_id=$3 and enrollment_id=$4 and consumed_at is null and expires_at>clock_timestamp() for update`,
        [
          scope.participantId,
          custody.candidate_session_id,
          custody.candidate_membership_id,
          command.enrollmentId,
        ],
      )
    ).rows[0];
    if (!row || row.origin !== origin || row.rp_id !== new URL(origin).hostname) throw denied();
    const verified = await registration.verify({
      response: command.response,
      expectedChallengeDigest: row.challenge_digest,
      expectedOrigin: origin,
      expectedRpId: row.rp_id,
    });
    if (!verified || !hash(verified.publicKeySpkiDer).equals(verified.publicKeyDigest))
      throw denied();
    const credentialId = localOperationId();
    await client.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,authenticator_sign_count,state,credential_epoch,valid_from)
      values($1,$2,$3,'WEBAUTHN',$4,$5,$6,$7,$8,$9,'ACTIVE',1,clock_timestamp())`,
      [
        credentialId,
        scope.participantId,
        custody.candidate_membership_id,
        `webauthn://${row.rp_id}`,
        verified.externalCredentialId,
        origin,
        verified.publicKeyDigest,
        verified.publicKeySpkiDer,
        verified.signCount,
      ],
    );
    await client.query(
      `update control.webauthn_enrollment set consumed_at=clock_timestamp(),credential_id=$3,attestation_digest=$4,row_version=row_version+1 where participant_id=$1 and enrollment_id=$2`,
      [scope.participantId, command.enrollmentId, credentialId, verified.attestationDigest],
    );
    return { credentialId, state: 'ENROLLED', authorityGranted: false };
  }
  if (credentials.rowCount !== 1) throw denied();
  const credential = credentials.rows[0]!;
  const rpIdHash = digestText(hash(new URL(origin).hostname));
  if (command.command === 'ACCEPT_OPTIONS') {
    await client.query(
      `update control.mfa_challenge set expires_at=clock_timestamp(),row_version=row_version+1 where participant_id=$1 and session_id=$2 and action_intent_id=$3 and consumed_at is null and used_at is null and expires_at>clock_timestamp()`,
      [scope.participantId, custody.candidate_session_id, acceptanceAction],
    );
    const challenge = randomBytes(32).toString('base64url');
    await client.query(
      `insert into control.mfa_challenge(participant_id,session_id,principal_id,action_intent_id,resource_digest,challenge_digest,rp_id_hash,expires_at)
      values($1,$2,$3,$4,$5,$6,$7,least($8,clock_timestamp()+interval '5 minutes'))`,
      [
        scope.participantId,
        custody.candidate_session_id,
        custody.candidate_membership_id,
        acceptanceAction,
        bytes(intentDigest),
        hash(challenge),
        bytes(rpIdHash),
        custody.expires_at,
      ],
    );
    return {
      challenge,
      intentDigest,
      rpId: new URL(origin).hostname,
      credentialIds: [credential.subject],
      userVerification: 'required',
    };
  }
  if (command.intentDigest !== intentDigest) throw denied();
  const challenge = (
    await client.query<{ mfa_challenge_id: string }>(
      `select mfa_challenge_id from control.mfa_challenge where participant_id=$1 and principal_id=$2 and session_id=$3 and action_intent_id=$4 and resource_digest=$5 and challenge_digest=$6 and rp_id_hash=$7 and consumed_at is null and used_at is null and expires_at>clock_timestamp() for update`,
      [
        scope.participantId,
        custody.candidate_membership_id,
        custody.candidate_session_id,
        acceptanceAction,
        bytes(intentDigest),
        hash(command.challenge),
        bytes(rpIdHash),
      ],
    )
  ).rows[0];
  if (!challenge) throw denied();
  const proof = verifyLocalWebAuthnAssertion(
    {
      credentialId: credential.credential_id,
      externalCredentialId: credential.subject,
      publicKeyDigest: credential.public_key_digest,
      publicKeySpkiDer: credential.public_key_spki_der,
    },
    {
      principalId: custody.candidate_membership_id!,
      sessionId: custody.candidate_session_id!,
      actionIntentId: acceptanceAction,
      resourceDigest: intentDigest,
      challenge: command.challenge,
      rpIdHash,
      allowedOrigin: origin,
      assertion: command.assertion,
    },
  );
  if (
    !proof ||
    (BigInt(credential.authenticator_sign_count) > 0n &&
      BigInt(proof.signCount) <= BigInt(credential.authenticator_sign_count))
  )
    throw denied();
  const now = (await client.query<{ now: Date }>('select clock_timestamp() now')).rows[0]!.now;
  const result = {
    state: 'ACCEPTED',
    participantId: scope.participantId,
    invitationId: scope.invitationId,
    mandateId: custody.mandate_id,
    membershipId: custody.candidate_membership_id,
    membershipState: 'ACTIVE',
    roleId: custody.candidate.roleId,
    assignmentId: custody.candidate.assignmentId,
    participantEpoch: String(BigInt(custody.participant_epoch) + 1n),
    platformBootstrapAuthority: 'CLOSED',
    operationId,
    acceptedAt: now.toISOString(),
  };
  const commit = (purpose: string, value: unknown) =>
    canonicalAuthorizationDigestBytes({ purpose: `pc.identity.first-admin.${purpose}.v1`, value });
  const proofDigest = digestText(verifiedWebAuthnAssertionDigest(proof));
  const evidenceCbor = encodeIdentityAuthContextAssertionPayload({
    assertionId: operationId,
    actorKind: 0,
    actorKeyDigest: identityActorKeyDigest(scope.participantId, custody.candidate_membership_id!),
    participantContextDigest: commit('context', [
      scope.participantId,
      custody.participant_epoch,
      custody.custody_generation,
    ]),
    audienceDigest: commit('acceptance', [intentDigest, result]),
    senderBindingKind: 1,
    senderCredentialBindingDigest: commit('credential', [
      credential.credential_id,
      digestText(credential.public_key_digest),
      proofDigest,
    ]),
    assuranceProfileDigest: commit('assurance', [
      'exact-oidc-recipient',
      'webauthn-user-verification',
      'distinct-maker-checker-candidate',
      'atomic-custody-handoff',
    ]),
    authorityVectorDigest: commit('custody', [
      custody.mandate_id,
      custody.issuance_authority,
      custody.candidate_digest.toString('hex'),
    ]),
    authenticationEvidenceDigest: commit('proof', proofDigest),
    issuedAtNs: BigInt(now.getTime()) * 1_000_000n,
    expiresAtNs: BigInt(Math.min(now.getTime() + 60000, custody.expires_at.getTime())) * 1_000_000n,
  });
  const signed = await signer.signCanonicalAssertion(evidenceCbor);
  if (
    !signed.evidenceCbor.equals(evidenceCbor) ||
    !hash(evidenceCbor).equals(signed.evidenceDigest) ||
    !(await signer.verifyCanonicalAssertion(evidenceCbor, signed.coseSign1))
  )
    throw denied();
  await activateFirstAdministrator(client, custody, result, signed, member.authority_epoch, now, {
    challengeId: challenge.mfa_challenge_id,
    credentialId: credential.credential_id,
    proofDigest,
  });
  await client.query(
    `update control.mfa_challenge set consumed_at=clock_timestamp(),used_at=clock_timestamp(),used_operation_id=$3,
      signer_credential_id=$4,signer_credential_epoch=$5,row_version=row_version+1
      where participant_id=$1 and mfa_challenge_id=$2 and used_at is null`,
    [
      scope.participantId,
      challenge.mfa_challenge_id,
      operationId,
      credential.credential_id,
      credential.credential_epoch,
    ],
  );
  await client.query(
    `update control.credential set authenticator_sign_count=$3,row_version=row_version+1 where participant_id=$1 and credential_id=$2`,
    [scope.participantId, credential.credential_id, proof.signCount],
  );
  await client.query(
    `update control.participant_bootstrap_custody set state='ACCEPTED',accepted_membership_id=candidate_membership_id,accepted_operation_id=$3,accepted_intent_digest=$4,acceptance_result=$5,closed_at=clock_timestamp(),row_version=row_version+1 where participant_id=$1 and mandate_id=$2 and state='CLAIM_PENDING'`,
    [scope.participantId, custody.mandate_id, operationId, bytes(intentDigest), result],
  );
  await client.query(
    `update control.participant_invitation set state='ACCEPTED',last_mutation_operation_id=$3,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and invitation_id=$2`,
    [scope.participantId, scope.invitationId, operationId],
  );
  await client.query(
    `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='first-administrator-handoff',row_version=row_version+1 where participant_id=$1 and session_id=$2`,
    [scope.participantId, custody.candidate_session_id],
  );
  return result;
}

/** The sole governed first-administrator grant writes the existing Participant, principal, envelope and assignment models. */
async function activateFirstAdministrator(
  client: PoolClient,
  custody: BootstrapCustodyRow,
  result: { operationId: string; participantEpoch: string },
  signed: { evidenceCbor: Buffer; evidenceDigest: Buffer; coseSign1: Buffer },
  principalEpoch: string,
  now: Date,
  proof: { challengeId: string; credentialId: string; proofDigest: string },
) {
  const value = custody.candidate;
  const role = await client.query(
    `select 1 from control.authority_role where participant_id=$1 and authority_role_id=$2 and bootstrap_mandate_id=$3 and state='ACTIVE' and action_intent_ids=$4::text[] for share`,
    [custody.participant_id, value.roleId, custody.mandate_id, value.actionIntentIds],
  );
  if (role.rowCount !== 1) throw denied();
  const principal = await client.query(
    `update control.principal set state='ACTIVE',authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and principal_id=$2 and state='PROVISIONED' and authority_epoch=$3`,
    [custody.participant_id, custody.candidate_membership_id, principalEpoch],
  );
  if (principal.rowCount !== 1) throw denied();
  const participant = await client.query(
    `update control.participant set state='ACTIVE',authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and state='PROVISIONING' and authority_epoch=$2`,
    [custody.participant_id, custody.participant_epoch],
  );
  if (participant.rowCount !== 1) throw denied();
  const privacy = await client.query(
    `update control.privacy_domain set state='ACTIVE',row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and privacy_domain_id=$2 and state='PROVISIONING'`,
    [custody.participant_id, value.privacyDomainId],
  );
  if (privacy.rowCount !== 1) throw denied();
  await client.query(
    `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
    bootstrap_mandate_id,bootstrap_platform_participant_id,authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,
    privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,last_mutation_operation_id,
    platform_context_id,platform_authority_epoch)
    values($1,$2,$3,$4,$5,$6,$7,$8,0,'ACTIVE',$9,$10,$11,$12,$13,$14,ARRAY['*'],ARRAY['LOW','STANDARD','HIGH'],true,true,0,$15,$16,$17)`,
    [
      value.authorityEnvelopeId,
      custody.participant_id,
      custody.candidate_membership_id,
      custody.maker_principal_id,
      custody.checker_principal_id,
      custody.mandate_id,
      custody.platform_participant_id,
      result.participantEpoch,
      now,
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      [value.privacyDomainId],
      value.actionIntentIds,
      result.operationId,
      custody.issuance_authority.platformContext?.platformContextId ?? null,
      custody.issuance_authority.platformContext?.platformAuthorityEpoch ?? null,
    ],
  );
  const assignment: Assignment = {
    id: value.assignmentId,
    participantId: custody.participant_id,
    principalId: custody.candidate_membership_id!,
    authorityEnvelopeId: value.authorityEnvelopeId,
    roleId: `urn:openpc:role:${value.roleId}`,
    state: 'ACTIVE',
    delegationEpoch: '0',
    scopeDigest: canonicalAuthorizationDigest(value),
    privacyDomainIds: [value.privacyDomainId],
    actionIntentIds: value.actionIntentIds,
    resourceIds: ['*'],
    riskClasses: ['LOW', 'STANDARD', 'HIGH'],
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
    validFrom: now,
    validUntil: null,
  };
  await assertGrantAdmission(client, assignment);
  await client.query(
    `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,role_id,delegation_epoch,scope_digest,valid_during,state,created_by_principal_id,
    bootstrap_mandate_id,bootstrap_platform_participant_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,last_mutation_operation_id)
    values($1,$2,$3,$4,$5,0,$6,tstzrange($7,null,'[)'),'ACTIVE',$8,$9,$10,$11,$12,ARRAY['*'],ARRAY['LOW','STANDARD','HIGH'],true,true,0,$13)`,
    [
      value.assignmentId,
      custody.participant_id,
      custody.candidate_membership_id,
      value.authorityEnvelopeId,
      assignment.roleId,
      bytes(assignment.scopeDigest),
      now,
      custody.maker_principal_id,
      custody.mandate_id,
      custody.platform_participant_id,
      [value.privacyDomainId],
      value.actionIntentIds,
      result.operationId,
    ],
  );
  await client.query(
    `insert into control.mutation_evidence(participant_id,privacy_domain_id,operation_id,principal_id,action_intent_id,catalog_operation_id,aggregate_type,aggregate_id,aggregate_version,candidate_digest,bound_participant_epoch,bound_principal_epoch,evidence_role,evidence_format,evidence_cbor,evidence_digest,cose_sign1,mfa_challenge_id,signer_credential_id,webauthn_assertion_binding_digest)
    values($1,$2,$3,$4,$5,'ID-OP-PARTICIPANT-FIRST-ADMIN-ACCEPT','participant',$1,$6,$7,$6,$8,'AUTHORIZATION_INPUT','IDENTITY_RUNTIME_ASSERTION_3002_2_13',$9,$10,$11,$12,$13,$14)`,
    [
      custody.participant_id,
      value.privacyDomainId,
      result.operationId,
      custody.candidate_membership_id,
      acceptanceAction,
      custody.participant_epoch,
      bytes(intent(custody)),
      principalEpoch,
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      proof.challengeId,
      proof.credentialId,
      bytes(proof.proofDigest),
    ],
  );
  const sequence = (
    await client.query<{ last_sequence: string }>(
      `insert into control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence)
    values($1,'participant',$1,1) on conflict(participant_id,aggregate_type,aggregate_id) do update set last_sequence=control.outbox_aggregate_head.last_sequence+1 returning last_sequence::text`,
      [custody.participant_id],
    )
  ).rows[0]!.last_sequence;
  await client.query(
    `insert into control.outbox_event(participant_id,privacy_domain_id,aggregate_type,aggregate_id,aggregate_sequence,event_id,event_type,payload_cbor,payload_digest,cose_sign1,occurred_at)
    values($1,$2,'participant',$1,$3,$7,'openpc.identity.first-administrator.accepted.v1',$4,$5,$6,clock_timestamp())`,
    [
      custody.participant_id,
      value.privacyDomainId,
      sequence,
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      localOperationId(),
    ],
  );
}
