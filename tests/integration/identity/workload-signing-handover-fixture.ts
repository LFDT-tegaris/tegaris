import { writeFile } from 'node:fs/promises';
import { createHash, generateKeyPairSync } from 'node:crypto';
import type { Pool } from 'pg';
import {
  businessSigningTrustPreimage,
  businessSigningTrustDigest,
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningProfileJson,
  identityEnvelopeSigningTrustPreimage,
  identityEnvelopeSigningTrustDigest,
  type BusinessSigningTrust,
  type IdentityEnvelopeSigningTrust,
} from '../../../packages/security-kernel/src/index.js';
import { businessTransitionProfiles } from '../../../packages/security-kernel/src/business-transition/profiles.generated.js';
import { businessSigningPurpose } from '../../../services/identity-service/src/domain/business-signing-provider.js';
import type { WorkloadSigningReplacement } from '../../../services/identity-service/src/contracts/workload-signing-handover.js';

/** Validate the full fixture grant set before allocating a database. */
export function workloadHandoverSigningFamilies() {
  const definitions = [
    {
      name: 'notification',
      role: 'BUSINESS_EFFECT',
      prefixes: ['pc.control.notification.'],
      count: 2,
    },
    {
      name: 'configuration',
      role: 'BUSINESS_EFFECT',
      prefixes: ['pc.control.indexer-profile.', 'pc.control.module.'],
      count: 8,
    },
    { name: 'hold', role: 'BUSINESS_EFFECT', prefixes: ['pc.control.evidence-hold.'], count: 2 },
    {
      name: 'participant-hold',
      role: 'BUSINESS_EFFECT',
      prefixes: ['pc.control.evidence-participant-hold.'],
      count: 2,
    },
    {
      name: 'retention',
      role: 'BUSINESS_EFFECT',
      prefixes: ['pc.control.retention-policy.'],
      count: 2,
    },
    {
      name: 'lifecycle',
      role: 'LIFECYCLE_EVIDENCE',
      prefixes: ['pc.control.signing-rotation.'],
      count: 2,
    },
    { name: 'envelope', role: 'IDENTITY_ENVELOPE', prefixes: [], count: 0 },
  ] as const;
  return definitions.map((family) => {
    const profiles = businessTransitionProfiles
      .filter((p) => family.prefixes.some((prefix) => p.profileId.startsWith(prefix)))
      .sort(
        (a, b) =>
          Buffer.compare(Buffer.from(a.profileId), Buffer.from(b.profileId)) ||
          a.profileVersion - b.profileVersion,
      );
    if (profiles.length !== family.count)
      throw new Error('Exact handover fixture grant set required');
    return { ...family, profiles };
  });
}

/** Initial public trust for an independent expired-workload rehearsal. No
 * successor grants, business intermediates, approvals or provider outcomes.
 * Private signing material is never stored in the control database. */
export async function workloadSigningHandoverFixture(
  admin: Pool,
  scope: {
    participantId: string;
    privacyDomainId: string;
    predecessorCredentialId: string;
    validUntilNs: bigint;
  },
) {
  const environmentId = 'workload-handover-postgres';
  const now = BigInt(Date.now()) * 1000000n;
  const hash = (value: Buffer | string) => createHash('sha256').update(value).digest();
  const replacements: WorkloadSigningReplacement[] = [];
  const privateKeys: Buffer[] = [];
  const client = await admin.connect();
  try {
    await client.query('begin');
    const identity = await client.query<{ participant_epoch: string; principal_epoch: string }>(
      `select participant.authority_epoch::text participant_epoch,principal.authority_epoch::text principal_epoch
       from control.credential credential join control.principal principal using(participant_id,principal_id)
       join control.participant participant using(participant_id)
       where credential.participant_id=$1 and credential.credential_id=$2 and credential.kind='WORKLOAD_MTLS' and credential.credential_epoch=1`,
      [scope.participantId, scope.predecessorCredentialId],
    );
    if (identity.rowCount !== 1) throw new Error('Exact initial workload required');
    const families = workloadHandoverSigningFamilies();
    for (const family of families) {
      const role = family.role;
      const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      privateKeys.push(key.privateKey.export({ type: 'pkcs8', format: 'der' }));
      const publicKeySpkiDer = key.publicKey.export({ type: 'spki', format: 'der' });
      const common = {
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        environmentId,
        signerId: evidenceKeyId(publicKeySpkiDer),
        publicKeySpkiDer,
        workloadCredentialId: scope.predecessorCredentialId,
        workloadCredentialEpoch: 1n,
        keyEpoch: 1n,
        validFromNs: now - 86400000000000n,
        validUntilNs: scope.validUntilNs,
        admissionKind: 'BOOTSTRAP' as const,
        admissionReference: 'Independent initial handover trust',
        admissionDigest: hash(publicKeySpkiDer),
        secretClass: 'SECRET-SIGNING-KEY' as const,
        secretReference: `secret://local/handover-${family.name}#1`,
        secretVersion: '1',
      };
      let trustPreimage: Buffer, trustDigest: Buffer;
      const profiles = family.profiles;
      if (role === 'IDENTITY_ENVELOPE') {
        const trust: IdentityEnvelopeSigningTrust = {
          ...common,
          workloadParticipantEpoch: BigInt(identity.rows[0]!.participant_epoch),
          workloadPrincipalEpoch: BigInt(identity.rows[0]!.principal_epoch),
          purpose: identityEnvelopeContext.purpose,
          profileId: identityEnvelopeSigningProfile.profileId,
          profileVersion: 1,
          profileDigest: identityEnvelopeSigningProfileDigest,
        };
        trustPreimage = identityEnvelopeSigningTrustPreimage(trust);
        trustDigest = Buffer.from(identityEnvelopeSigningTrustDigest(trust).slice(7), 'hex');
        await client.query(
          `insert into control.identity_envelope_signing_profile(profile_id,profile_version,profile_digest,schema_definition_digest,definition_canonical_json,signing_purpose_code)
          values($1,1,$2,$3,$4,371) on conflict do nothing`,
          [
            trust.profileId,
            Buffer.from(trust.profileDigest.slice(7), 'hex'),
            Buffer.from(identityEnvelopeContext.definitionDigest.slice(7), 'hex'),
            Buffer.from(identityEnvelopeSigningProfileJson),
          ],
        );
      } else {
        if (profiles.length !== family.count) throw new Error('Exact role profiles required');
        for (const p of profiles)
          await client.query(
            `insert into control.business_transition_profile(profile_id,profile_version,profile_digest,schema_definition_digest,definition_canonical_json,action_intent_id,catalog_operation_id,resource_type,aggregate_type,sequence_namespace,transition_kind)
          values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) on conflict do nothing`,
            [
              p.profileId,
              p.profileVersion,
              Buffer.from(p.profileDigest.slice(7), 'hex'),
              Buffer.from(p.schemaDefinitionDigest.slice(7), 'hex'),
              Buffer.from(p.definitionCanonicalJson),
              p.actionIntentId,
              p.catalogOperationId,
              p.resourceType,
              p.aggregateType,
              p.sequenceNamespace,
              p.transitionKind,
            ],
          );
        const trust: BusinessSigningTrust = {
          ...common,
          grants: profiles.map((p) => ({
            profileId: p.profileId,
            profileVersion: p.profileVersion,
            profileDigest: Buffer.from(p.profileDigest.slice(7), 'hex'),
            actionIntentId: p.actionIntentId,
            catalogOperationId: p.catalogOperationId,
          })),
        };
        trustPreimage = businessSigningTrustPreimage(trust);
        trustDigest = businessSigningTrustDigest(trust);
      }
      await client.query(
        `insert into control.business_signing_key(participant_id,privacy_domain_id,signer_id,environment_id,public_key_spki_der,workload_credential_id,workload_credential_epoch,key_epoch,valid_from_ns,valid_until_ns,admission_kind,admission_reference,admission_digest,secret_class,secret_reference,secret_version,trust_preimage,trust_digest,signing_purpose_code,envelope_workload_participant_epoch,envelope_workload_principal_epoch)
        values($1,$2,$3,$4,$5,$6,1,1,$7,$8,'BOOTSTRAP',$9,$10,$11,$12,'1',$13,$14,$15,$16,$17)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          common.signerId,
          environmentId,
          publicKeySpkiDer,
          scope.predecessorCredentialId,
          common.validFromNs.toString(),
          common.validUntilNs.toString(),
          common.admissionReference,
          common.admissionDigest,
          common.secretClass,
          common.secretReference,
          trustPreimage,
          trustDigest,
          role === 'IDENTITY_ENVELOPE' ? 371 : 338,
          role === 'IDENTITY_ENVELOPE' ? identity.rows[0]!.participant_epoch : null,
          role === 'IDENTITY_ENVELOPE' ? identity.rows[0]!.principal_epoch : null,
        ],
      );
      await client.query(
        `insert into control.business_signing_key_state(participant_id,privacy_domain_id,signer_id,state,changed_at_ns,change_reference,change_digest) values($1,$2,$3,'ADMITTED',$4,$5,$6)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          common.signerId,
          now.toString(),
          common.admissionReference,
          common.admissionDigest,
        ],
      );
      await client.query(
        `update control.business_signing_key_state set state='ACTIVE',row_version=row_version+1,changed_at_ns=$4,change_digest=$5 where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3`,
        [
          scope.participantId,
          scope.privacyDomainId,
          common.signerId,
          (now + 1000n).toString(),
          hash('Initial handover selection'),
        ],
      );
      if (role === 'IDENTITY_ENVELOPE') {
        const profile = Buffer.from(identityEnvelopeSigningProfileDigest.slice(7), 'hex');
        await client.query(
          `insert into control.identity_envelope_signing_grant(participant_id,privacy_domain_id,signer_id,profile_digest) values($1,$2,$3,$4)`,
          [scope.participantId, scope.privacyDomainId, common.signerId, profile],
        );
        await client.query(
          `insert into control.identity_envelope_signing_selection(participant_id,privacy_domain_id,environment_id,profile_digest,signer_id) values($1,$2,$3,$4,$5)`,
          [scope.participantId, scope.privacyDomainId, environmentId, profile, common.signerId],
        );
      } else
        for (const p of profiles) {
          const profile = Buffer.from(p.profileDigest.slice(7), 'hex');
          await client.query(
            `insert into control.business_signing_grant(participant_id,privacy_domain_id,signer_id,profile_digest) values($1,$2,$3,$4)`,
            [scope.participantId, scope.privacyDomainId, common.signerId, profile],
          );
          await client.query(
            `insert into control.business_signing_selection(participant_id,privacy_domain_id,environment_id,profile_digest,signer_id,changed_at_ns,change_reference,change_digest) values($1,$2,$3,$4,$5,$6,$7,$8)`,
            [
              scope.participantId,
              scope.privacyDomainId,
              environmentId,
              profile,
              common.signerId,
              now.toString(),
              common.admissionReference,
              hash('Initial handover selection'),
            ],
          );
        }
      const base = {
        oldFingerprint: common.signerId,
        oldTrustDigest: `sha256:${trustDigest.toString('hex')}`,
        expectedKeyEpoch: '1',
        oldReference: common.secretReference,
        newReference: `secret://local/handover-${family.name}#2`,
      };
      replacements.push(
        role === 'IDENTITY_ENVELOPE'
          ? { ...base, signerRole: role, purpose: identityEnvelopeContext.purpose }
          : { ...base, signerRole: role, purpose: businessSigningPurpose },
      );
    }
    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    for (const key of privateKeys) key.fill(0);
    throw error;
  } finally {
    client.release();
  }
  return {
    environmentId,
    replacements: replacements.sort((a, b) => a.oldFingerprint.localeCompare(b.oldFingerprint)),
    async savePrivateState(file: string) {
      await writeFile(
        file,
        JSON.stringify({
          privateKeysPkcs8Base64: privateKeys.map((key) => key.toString('base64')),
        }),
        { mode: 0o600, flag: 'wx' },
      );
    },
    close() {
      for (const key of privateKeys) key.fill(0);
    },
  };
}
