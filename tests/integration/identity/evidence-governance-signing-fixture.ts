import { createHash, generateKeyPairSync } from 'node:crypto';
import type { Pool } from 'pg';
import {
  businessSigningTrustPreimage,
  businessSigningTrustDigest,
  evidenceKeyId,
  signReceiptCose,
  type BusinessSigningTrust,
} from '../../../packages/security-kernel/src/index.js';
import { businessTransitionProfiles } from '../../../packages/security-kernel/src/business-transition/profiles.generated.js';
import type { ConfigurationBusinessEvidence } from '../../../services/control-api/src/configuration/persistence/business-receipt-writer.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

/** Pure authoritative-input check, shared with pre-allocation acceptance. */
export function evidenceGovernanceProfiles(
  aggregateType: NonNullable<Parameters<typeof evidenceGovernanceSigningFixture>[3]>,
) {
  const profiles = businessTransitionProfiles
    .filter((p) => p.aggregateType === aggregateType)
    .sort(
      (left, right) =>
        Buffer.compare(Buffer.from(left.profileId), Buffer.from(right.profileId)) ||
        left.profileVersion - right.profileVersion,
    );
  const expectedCount =
    aggregateType === 'evidence-deletion'
      ? 8
      : aggregateType === 'notification-endpoint'
        ? 3
        : ['retention-policy', 'notification'].includes(aggregateType)
          ? 2
          : 4;
  if (profiles.length !== expectedCount)
    throw new Error('Exact admitted evidence governance profiles required');
  if (aggregateType === 'notification-endpoint') {
    const operations = profiles.map((p) => p.catalogOperationId).sort();
    const expected = ['CREATE', 'UPDATE', 'VERIFY']
      .map((command) => `CFG-OP-${command}-NOTIFICATION-ENDPOINT`)
      .sort();
    if (
      operations.some((operation, index) => operation !== expected[index]) ||
      profiles.some((p) => p.profileVersion !== 1)
    )
      throw new Error('Exact three notification endpoint signing grants required');
  }
  return profiles;
}

/** Initial public trust plus a genuinely external signing substitute. No business rows or approvals. */
export async function evidenceGovernanceSigningFixture(
  admin: Pool,
  participantId: string,
  privacyDomainId: string,
  aggregateType:
    | 'evidence-hold'
    | 'retention-policy'
    | 'evidence-deletion'
    | 'work-item'
    | 'notification'
    | 'notification-endpoint' = 'evidence-hold',
) {
  const profiles = evidenceGovernanceProfiles(aggregateType);
  const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privateKey = key.privateKey.export({ type: 'pkcs8', format: 'der' });
  const publicKey = key.publicKey.export({ type: 'spki', format: 'der' });
  const workload = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
    type: 'spki',
    format: 'der',
  });
  const workloadCredentialId = id(),
    principalId = id();
  const now = BigInt(Date.now()) * 1000000n;
  const hash = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest();
  const trust: BusinessSigningTrust = {
    participantId,
    privacyDomainId,
    environmentId: `${aggregateType}-postgres`,
    signerId: evidenceKeyId(publicKey),
    publicKeySpkiDer: publicKey,
    workloadCredentialId,
    workloadCredentialEpoch: 1n,
    keyEpoch: 1n,
    validFromNs: now - 1000000000n,
    validUntilNs: now + 3600000000000n,
    admissionKind: 'BOOTSTRAP',
    admissionReference: 'Initial PostgreSQL hold signing trust',
    admissionDigest: hash(publicKey),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: `secret://local/${aggregateType}-postgres#1`,
    secretVersion: '1',
    grants: profiles.map((p) => ({
      profileId: p.profileId,
      profileVersion: p.profileVersion,
      profileDigest: Buffer.from(p.profileDigest.slice(7), 'hex'),
      actionIntentId: p.actionIntentId,
      catalogOperationId: p.catalogOperationId,
    })),
  };
  const client = await admin.connect();
  try {
    await client.query('begin');
    await client.query(
      `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD',$3,'ACTIVE',1)`,
      [principalId, participantId, `${aggregateType} signing fixture`],
    );
    await client.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
      public_key_digest,public_key_spki_der,state,credential_epoch,valid_from,valid_until,secret_fingerprint)
      values($1::uuid,$2,$3,'WORKLOAD_MTLS','urn:openpc:hold-test-ca',$1::uuid::text,'hold-test',$4,$5,'ACTIVE',1,
      clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour',$4)`,
      [workloadCredentialId, participantId, principalId, hash(workload), workload],
    );
    for (const profile of profiles)
      await client.query(
        `insert into control.business_transition_profile(profile_id,profile_version,profile_digest,schema_definition_digest,
      definition_canonical_json,action_intent_id,catalog_operation_id,resource_type,aggregate_type,sequence_namespace,transition_kind)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) on conflict do nothing`,
        [
          profile.profileId,
          profile.profileVersion,
          Buffer.from(profile.profileDigest.slice(7), 'hex'),
          Buffer.from(profile.schemaDefinitionDigest.slice(7), 'hex'),
          Buffer.from(profile.definitionCanonicalJson),
          profile.actionIntentId,
          profile.catalogOperationId,
          profile.resourceType,
          profile.aggregateType,
          profile.sequenceNamespace,
          profile.transitionKind,
        ],
      );
    await client.query(
      `insert into control.business_signing_key(participant_id,privacy_domain_id,signer_id,environment_id,public_key_spki_der,
      workload_credential_id,workload_credential_epoch,key_epoch,valid_from_ns,valid_until_ns,admission_kind,admission_reference,admission_digest,
      secret_class,secret_reference,secret_version,trust_preimage,trust_digest)
      values($1,$2,$3,$4,$5,$6,1,1,$7,$8,'BOOTSTRAP',$9,$10,$11,$12,$13,$14,$15)`,
      [
        participantId,
        privacyDomainId,
        trust.signerId,
        trust.environmentId,
        publicKey,
        workloadCredentialId,
        trust.validFromNs.toString(),
        trust.validUntilNs.toString(),
        trust.admissionReference,
        trust.admissionDigest,
        trust.secretClass,
        trust.secretReference,
        trust.secretVersion,
        businessSigningTrustPreimage(trust),
        businessSigningTrustDigest(trust),
      ],
    );
    for (const grant of trust.grants)
      await client.query(
        `insert into control.business_signing_grant(participant_id,privacy_domain_id,signer_id,profile_digest) values($1,$2,$3,$4)`,
        [participantId, privacyDomainId, trust.signerId, grant.profileDigest],
      );
    await client.query(
      `insert into control.business_signing_key_state(participant_id,privacy_domain_id,signer_id,state,changed_at_ns,change_reference,change_digest)
      values($1,$2,$3,'ADMITTED',$4,$5,$6)`,
      [
        participantId,
        privacyDomainId,
        trust.signerId,
        now.toString(),
        trust.admissionReference,
        trust.admissionDigest,
      ],
    );
    await client.query(
      `update control.business_signing_key_state set state='ACTIVE',row_version=row_version+1,change_digest=$4 where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3`,
      [participantId, privacyDomainId, trust.signerId, hash('initial hold selection')],
    );
    for (const grant of trust.grants)
      await client.query(
        `insert into control.business_signing_selection(participant_id,privacy_domain_id,environment_id,profile_digest,signer_id,changed_at_ns,change_reference,change_digest) values($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          participantId,
          privacyDomainId,
          trust.environmentId,
          grant.profileDigest,
          trust.signerId,
          now.toString(),
          trust.admissionReference,
          hash('initial hold selection'),
        ],
      );
    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    throw error;
  } finally {
    client.release();
  }
  const faults: { mode: 'UNAVAILABLE' | 'CORRUPT' | undefined; calls: number } = {
    mode: undefined,
    calls: 0,
  };
  const evidence: ConfigurationBusinessEvidence = {
    environmentId: trust.environmentId,
    signer: {
      async sign({ payload, trust: actual }) {
        faults.calls++;
        if (faults.mode === 'UNAVAILABLE') throw new Error('External hold signer unavailable');
        if (!businessSigningTrustDigest(actual).equals(businessSigningTrustDigest(trust)))
          throw new Error('Unexpected hold signing trust');
        const result = signReceiptCose(privateKey, publicKey, payload);
        if (faults.mode === 'CORRUPT') result[result.length - 1] = result[result.length - 1]! ^ 1;
        return result;
      },
    },
  };
  return {
    evidence,
    publicKey,
    trust,
    faults,
    close() {
      privateKey.fill(0);
    },
  };
}
