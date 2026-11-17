import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { encodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
} from '../contracts/authorization.js';
import { identityActorKeyDigest } from '../domain/identity-runtime-authorization.js';
import type { IdentityRuntimeEvidenceSigner } from '../domain/identity-kernel.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import {
  assertPlatformRecoveryCeremony,
  type PlatformRecoveryProof,
} from '../domain/platform-recovery-ceremony.js';
import { discoveryCertificateRecoveryPermissions } from '../domain/discovery-certificate-recovery.js';
import { platformRecoveryLeasePermissions } from '../domain/platform-recovery-lease.js';
import { localOperationId } from '../domain/local-operation-id.js';
import type { PlatformRecoveryCeremonyContext } from './platform-recovery-proof.js';

const hash = (value: Buffer) => createHash('sha256').update(value).digest();
const deny = () => new PlatformRecoveryError();

/** Called only after the fresh executor activation proof, under the declared Participant write fence and fixed source/case locks.
 * All epoch rotation, signed lease rows, case state and outbox writes share the caller's transaction. */
export async function activatePlatformRecoveryLease(
  client: PoolClient,
  context: PlatformRecoveryCeremonyContext,
  activationProof: PlatformRecoveryProof,
  operationId: string,
  signer: IdentityRuntimeEvidenceSigner,
) {
  // The transport purpose has its own activation owner. Never interpret its
  // custody proofs as authorization to prepare or commit a Root replacement.
  if (
    context.enrollment.schema !== 'pc.identity.platform-recovery-enrollment' ||
    context.intent.schema !== 'pc.identity.platform-recovery-intent'
  )
    throw deny();
  return activateRecoveryLease(client, context, activationProof, operationId, signer);
}

/** The same independent custody owner issues only the separately installed certificate purpose. */
export async function activateDiscoveryCertificateRecoveryLease(
  client: PoolClient,
  context: PlatformRecoveryCeremonyContext,
  activationProof: PlatformRecoveryProof,
  operationId: string,
  signer: IdentityRuntimeEvidenceSigner,
) {
  if (
    context.enrollment.schema !== 'pc.identity.discovery-certificate-recovery-enrollment' ||
    context.intent.schema !== 'pc.identity.discovery-certificate-recovery-intent'
  )
    throw deny();
  return activateRecoveryLease(client, context, activationProof, operationId, signer);
}

async function activateRecoveryLease(
  client: PoolClient,
  context: PlatformRecoveryCeremonyContext,
  activationProof: PlatformRecoveryProof,
  operationId: string,
  signer: IdentityRuntimeEvidenceSigner,
) {
  const { enrollment, intent, now } = context;
  // Signer repair has its own epoch fence and exact rotation lease owner.
  if (
    enrollment.schema === 'pc.identity.identity-envelope-recovery-enrollment' ||
    intent.schema === 'pc.identity.identity-envelope-recovery-intent' ||
    intent.schema === 'pc.identity.local-root-expiry-recovery-intent'
  )
    throw deny();
  assertPlatformRecoveryCeremony(
    enrollment,
    intent,
    context.state,
    context.proofs,
    'ACTIVATE',
    enrollment.recoveryPrincipal.principalId,
    now,
  );
  if (
    activationProof.phase !== 'ACTIVATE' ||
    activationProof.principalId !== enrollment.recoveryPrincipal.principalId ||
    activationProof.intentDigest !== canonicalAuthorizationDigest(intent)
  )
    throw deny();
  const proof = await client.query<{ digest: Buffer }>(
    `select proof.assertion_digest as digest from control.platform_recovery_proof proof
     join control.platform_recovery_challenge h on h.participant_id=proof.participant_id and h.privacy_domain_id=proof.privacy_domain_id
       and h.recovery_id=proof.recovery_id and h.challenge_id=proof.challenge_id and h.proof_id=proof.proof_id
     where proof.participant_id=$1 and proof.privacy_domain_id=$2
     and proof.recovery_id=$3 and proof.proof_id=$4 and proof.phase='ACTIVATE' and proof.principal_id=$5 and proof.credential_id=$6
     and proof.principal_epoch=$7 and proof.credential_epoch=$8 and proof.session_id=$9 and proof.session_epoch=$10 and proof.intent_digest=$11
     and proof.verified_at<=clock_timestamp()
     and proof.verified_at>clock_timestamp()-make_interval(secs=>h.verified_proof_max_age_ms/1000.0)
     and (h.verified_proof_max_age_ms=300000 or (h.verified_proof_max_age_ms=3000000
       and h.duration_profile='LOCAL_QA_10X' and h.expires_at>clock_timestamp()))`,
    [
      enrollment.participantId,
      enrollment.privacyDomainId,
      intent.recoveryId,
      activationProof.proofId,
      activationProof.principalId,
      activationProof.credentialId,
      activationProof.principalEpoch,
      activationProof.credentialEpoch,
      activationProof.sessionId,
      activationProof.sessionEpoch,
      Buffer.from(activationProof.intentDigest.slice(7), 'hex'),
    ],
  );
  if (proof.rowCount !== 1) throw deny();
  const commit = (purpose: string, value: unknown) =>
    canonicalAuthorizationDigestBytes({
      domain: `pc.identity.platform-recovery.${purpose}.v1`,
      value,
    });
  async function signEvidence(assertionId: string, purpose: string, value: unknown) {
    const evidenceCbor = encodeIdentityAuthContextAssertionPayload({
      assertionId,
      actorKind: 0,
      actorKeyDigest: identityActorKeyDigest(
        enrollment.participantId,
        enrollment.recoveryPrincipal.principalId,
      ),
      participantContextDigest: commit('context', [
        enrollment.participantId,
        enrollment.privacyDomainId,
        enrollment.platformContextId,
        enrollment.rootEpoch,
        enrollment.rootDigest,
      ]),
      audienceDigest: commit(purpose, value),
      senderBindingKind: 1,
      senderCredentialBindingDigest: commit('executor', [
        enrollment.recoveryPrincipal,
        activationProof.proofId,
        proof.rows[0]!.digest.toString('hex'),
      ]),
      assuranceProfileDigest: commit('assurance', [
        enrollment.assurance,
        'independent-two-custodian-webauthn-uv',
        'fixed-recovery-purpose',
        'no-runtime-capability',
      ]),
      authorityVectorDigest: commit('source', [
        intent,
        context.proofs.map((v) => v.proofId),
        activationProof.proofId,
      ]),
      authenticationEvidenceDigest: commit(
        'proofs',
        [...context.proofs, activationProof].map(({ verifiedProofMaxAgeMs: _age, ...value }) => ({
          ...value,
          verifiedAt: value.verifiedAt.toISOString(),
        })),
      ),
      issuedAtNs: BigInt(now.getTime()) * 1000000n,
      expiresAtNs: BigInt(Date.parse(intent.validUntil)) * 1000000n,
    });
    const signed = await signer.signCanonicalAssertion(evidenceCbor);
    if (
      !signed.evidenceCbor.equals(evidenceCbor) ||
      !hash(evidenceCbor).equals(signed.evidenceDigest) ||
      !(await signer.verifyCanonicalAssertion(evidenceCbor, signed.coseSign1))
    )
      throw deny();
    return signed;
  }
  const administrators =
    intent.schema === 'pc.identity.discovery-certificate-recovery-intent'
      ? intent.administrators.map((v) => ({ ...v, expectedRoleRevision: v.roleRevision }))
      : intent.preparation.administrators;
  const epochs =
    intent.schema === 'pc.identity.discovery-certificate-recovery-intent'
      ? intent.administrators
      : intent.administratorEpochs;
  const bindings = [];
  for (const administrator of administrators) {
    const original = epochs.find((v) => v.principalId === administrator.principalId);
    if (!original) throw deny();
    const permissions =
      intent.schema === 'pc.identity.discovery-certificate-recovery-intent'
        ? {
            ...discoveryCertificateRecoveryPermissions(
              intent.certificateRecovery,
              enrollment.privacyDomainId,
              administrator.principalId,
              intent.schemaVersion,
            ),
            riskClasses: intent.administrators.find(
              (v) => v.principalId === administrator.principalId,
            )!.riskClasses,
            validFrom: now.toISOString(),
            validUntil: intent.validUntil,
          }
        : enrollment.schema === 'pc.identity.platform-recovery-enrollment'
          ? platformRecoveryLeasePermissions(enrollment, intent, administrator.principalId, now)
          : (() => {
              throw deny();
            })();
    const selected = await client.query<{
      role: { roleId: string; version: string; actions: string[] };
    }>(
      `select jsonb_build_object('roleId',r.role_id,'version',r.row_version::text,'actions',r.action_intent_ids,
        'origin',r.origin,'createdByPrincipalId',r.created_by_principal_id::text,'creatorParticipantId',r.creator_participant_id::text,
        'bootstrapMandateId',r.bootstrap_mandate_id::text,'bootstrapPlatformParticipantId',r.bootstrap_platform_participant_id::text) as role
       from control.authority_role r where r.participant_id=$1 and r.authority_role_id=$2 and r.state='ACTIVE' for share`,
      [enrollment.participantId, administrator.roleId],
    );
    const role = selected.rows[0]?.role;
    if (
      selected.rowCount !== 1 ||
      !role ||
      role.version !== administrator.expectedRoleRevision ||
      canonicalAuthorizationDigest({
        domain: 'pc.identity.envelope-role-binding.v1',
        participantId: enrollment.participantId,
        role,
      }) !== administrator.roleDigest ||
      permissions.actionIntentIds.some((v) => !role.actions.includes(v))
    )
      throw deny();
    const binding = {
      principalId: administrator.principalId,
      principalEpoch: (BigInt(original.principalEpoch) + 1n).toString(),
      envelopeId: localOperationId(),
      assignmentId: localOperationId(),
      permissions: { ...permissions, roleId: role.roleId },
    };
    const signed = await signEvidence(binding.envelopeId, 'lease-envelope', binding);
    bindings.push({
      ...binding,
      evidenceCbor: signed.evidenceCbor.toString('hex'),
      evidenceDigest: signed.evidenceDigest.toString('hex'),
      coseSign1: signed.coseSign1.toString('hex'),
    });
  }
  const result = {
    recoveryId: intent.recoveryId,
    enrollmentId: enrollment.enrollmentId,
    operationId,
    state: 'ACTIVE' as const,
    authority:
      intent.schema === 'pc.identity.discovery-certificate-recovery-intent'
        ? ('DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY' as const)
        : ('FIXED_PLATFORM_HANDOFF_ONLY' as const),
    assurance: enrollment.assurance,
    activatedAt: now.toISOString(),
    expiresAt: intent.validUntil,
    intentDigest: canonicalAuthorizationDigest(intent),
    bindings: bindings.map((v) => ({
      principalId: v.principalId,
      principalEpoch: v.principalEpoch,
      envelopeId: v.envelopeId,
      assignmentId: v.assignmentId,
    })),
  };
  const signed = await signEvidence(operationId, 'activation', { result, bindings });
  // No original grant, credential bytes or signed lifetime is changed. Rotate only affected session families and identity epochs.
  for (const original of [...epochs].sort((a, b) => a.principalId.localeCompare(b.principalId))) {
    const updated = await client.query(
      `update control.principal set authority_epoch=authority_epoch+1,row_version=row_version+1,updated_at=clock_timestamp()
      where participant_id=$1 and principal_id=$2 and state='ACTIVE' and authority_epoch=$3`,
      [enrollment.participantId, original.principalId, original.principalEpoch],
    );
    if (updated.rowCount !== 1) throw deny();
    await client.query(
      `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason=$3,
      row_version=row_version+1,updated_at=clock_timestamp() where participant_id=$1 and principal_id=$2 and state in ('ACTIVE','STEP_UP_REQUIRED')`,
      [
        enrollment.participantId,
        original.principalId,
        intent.schema === 'pc.identity.discovery-certificate-recovery-intent'
          ? 'discovery-certificate-recovery'
          : 'platform-administration-recovery',
      ],
    );
  }
  const activated = await client.query(
    `update control.platform_recovery_case set state='ACTIVE',row_version=row_version+1,updated_at=clock_timestamp(),
    activated_at=$4,activation_operation_id=$5,activation_evidence_cbor=$6,activation_evidence_digest=$7,activation_cose=$8,lease_bindings=$9
    where participant_id=$1 and privacy_domain_id=$2 and recovery_id=$3 and state='REQUESTED' and valid_until>clock_timestamp()`,
    [
      enrollment.participantId,
      enrollment.privacyDomainId,
      intent.recoveryId,
      now,
      operationId,
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      JSON.stringify(bindings),
    ],
  );
  if (activated.rowCount !== 1) throw deny();
  for (const binding of bindings) {
    const p = binding.permissions;
    await client.query(
      `insert into control.authority_envelope(authority_envelope_id,participant_id,representation,recovery_case_id,principal_id,
      maker_principal_id,checker_principal_id,platform_context_id,platform_authority_epoch,authority_epoch,delegation_epoch,state,valid_from,valid_until,
      semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,runtime_capability_ids,resource_ids,risk_classes,
      maker_checker_required,step_up_required,onward_delegation_depth,last_mutation_operation_id)
      values($1,$2,'RECOVERY_V1',$3,$4,$5,$6,$7,$8,1,0,'ACTIVE',$9,$10,$11,$12,$13,$14,$15,ARRAY[]::text[],$16,$17,true,true,0,$18)`,
      [
        binding.envelopeId,
        enrollment.participantId,
        intent.recoveryId,
        binding.principalId,
        enrollment.recoveryPrincipal.principalId,
        enrollment.custodians[0].principalId,
        enrollment.platformContextId,
        enrollment.rootEpoch,
        p.validFrom,
        p.validUntil,
        Buffer.from(binding.evidenceCbor, 'hex'),
        Buffer.from(binding.evidenceDigest, 'hex'),
        Buffer.from(binding.coseSign1, 'hex'),
        p.privacyDomainIds,
        p.actionIntentIds,
        p.resourceIds,
        p.riskClasses,
        operationId,
      ],
    );
    await client.query(
      `insert into control.assignment(assignment_id,participant_id,principal_id,role_id,authority_envelope_id,delegation_epoch,scope_digest,
      privacy_domain_ids,action_intent_ids,runtime_capability_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,
      valid_during,state,created_by_principal_id,last_mutation_operation_id)
      values($1,$2,$3,$4,$5,0,$6,$7,$8,ARRAY[]::text[],$9,$10,true,true,0,tstzrange($11,$12,'[)'),'ACTIVE',$13,$14)`,
      [
        binding.assignmentId,
        enrollment.participantId,
        binding.principalId,
        p.roleId,
        binding.envelopeId,
        canonicalAuthorizationDigestBytes(p),
        p.privacyDomainIds,
        p.actionIntentIds,
        p.resourceIds,
        p.riskClasses,
        p.validFrom,
        p.validUntil,
        enrollment.recoveryPrincipal.principalId,
        operationId,
      ],
    );
  }
  await client.query(
    `insert into control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence)
    values($1,'platform-recovery',$2,1)`,
    [enrollment.participantId, intent.recoveryId],
  );
  await client.query(
    `insert into control.outbox_event(participant_id,privacy_domain_id,aggregate_type,aggregate_id,aggregate_sequence,event_id,event_type,
    payload_cbor,payload_digest,cose_sign1,occurred_at) values($1,$2,'platform-recovery',$3,1,$4,'openpc.identity.platform-recovery.activated.v1',$5,$6,$7,$8)`,
    [
      enrollment.participantId,
      enrollment.privacyDomainId,
      intent.recoveryId,
      localOperationId(),
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      now,
    ],
  );
  return result;
}
