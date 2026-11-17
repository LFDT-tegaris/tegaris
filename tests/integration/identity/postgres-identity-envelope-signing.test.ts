import { execFile } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { promisify } from 'node:util';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { fenceIdentityEnvelopeSigningTrust } from '../../../services/identity-service/src/db/identity-envelope-signing-store.js';
import { assertReceiptRotationPurpose } from '../../../services/identity-service/src/db/signing-rotation-store.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';
import { identityEnvelopeFixture } from '../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  assertIdentityEnvelopeSigningTrust,
  businessSigningTrustDigest,
  encodeIdentityAuthorityEnvelope,
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningProfileJson,
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
  signIdentityAuthorityEnvelopeCose,
  verifyIdentityAuthorityEnvelopeCose,
  type IdentityEnvelopeSigningTrust,
} from '../../../packages/security-kernel/src/index.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const container = process.env.OPENPC_IDENTITY_ENVELOPE_UPGRADE_CONTAINER;
const integration = adminUrl && runtimeUrl && container ? it : it.skip;
const execute = promisify(execFile);
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest();

integration(
  'preserves populated338 trust and admits isolated371 only through the scoped key owner',
  async () => {
    expect(container).toMatch(/^openpc-participant-readback-[0-9]+$/u);
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const url = new URL(runtimeUrl!);
    url.username = 'openpc_participant_runtime';
    const runtime = new Pool({ connectionString: url.href, max: 2 });
    const participantId = id(),
      privacyDomainId = id();
    const scope = { participantId, privacyDomainId, environmentId: 'identity-envelope-postgres' };
    let legacy: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>> | undefined;
    const principalId = id(),
      credentialId = id();
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'der' });
    const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' });
    async function governor<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
      const client = await admin.connect();
      try {
        await client.query('begin');
        await client.query('set local role openpc_control_key_governor');
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',true),openpc.assert_request_context(true)`,
          [participantId, privacyDomainId, id()],
        );
        const role = await client.query(
          `select current_user as name,rolsuper,rolbypassrls from pg_roles where rolname=current_user`,
        );
        expect(role.rows).toEqual([
          { name: 'openpc_control_key_governor', rolsuper: false, rolbypassrls: false },
        ]);
        const value = await operation(client);
        await client.query('commit');
        return value;
      } catch (error) {
        await client.query('rollback');
        throw error;
      } finally {
        client.release();
      }
    }
    const read = (selected = scope) =>
      runScopedTransaction(
        runtime,
        {
          participantId: selected.participantId,
          privacyDomainId: selected.privacyDomainId,
          actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
        },
        id,
        (client) => fenceIdentityEnvelopeSigningTrust(client, selected),
      );
    try {
      // Initial identities and public key trust only; no envelope, approval,
      // activation, assignment, signing attempt or business result is seeded.
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Independent envelope trust','ACTIVE',1)`,
        [participantId],
      );
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Envelope trust','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [privacyDomainId, participantId],
      );
      await admin.query(
        `update control.participant set root_privacy_domain_id=$2 where participant_id=$1`,
        [participantId, privacyDomainId],
      );
      expect(
        (
          await admin.query(
            `select 1 from information_schema.columns where table_schema='control' and table_name='business_signing_key' and column_name='signing_purpose_code'`,
          )
        ).rowCount,
      ).toBe(0);
      legacy = await evidenceGovernanceSigningFixture(admin, participantId, privacyDomainId);
      const before = await admin.query(
        `select signer_id,encode(trust_preimage,'hex') bytes,encode(trust_digest,'hex') digest from control.business_signing_key where participant_id=$1`,
        [participantId],
      );
      expect(before.rowCount).toBe(1);
      expect(before.rows[0].digest).toBe(businessSigningTrustDigest(legacy.trust).toString('hex'));
      await execute(
        'docker',
        [
          'exec',
          '-e',
          'PGHOST=127.0.0.1',
          '-e',
          'PGUSER=postgres',
          '-e',
          'PGDATABASE=openpc_control',
          container!,
          'sh',
          '/local/migrate.sh',
          'control',
        ],
        { timeout: 120000, maxBuffer: 1024 * 1024 },
      );
      const after = await admin.query(
        `select signer_id,encode(trust_preimage,'hex') bytes,encode(trust_digest,'hex') digest from control.business_signing_key where participant_id=$1`,
        [participantId],
      );
      expect(after.rows).toEqual(before.rows);
      expect(
        (
          await admin.query(
            `select signing_purpose_code,envelope_workload_participant_epoch,envelope_workload_principal_epoch from control.business_signing_key where participant_id=$1`,
            [participantId],
          )
        ).rows,
      ).toEqual([
        {
          signing_purpose_code: 338,
          envelope_workload_participant_epoch: null,
          envelope_workload_principal_epoch: null,
        },
      ]);
      await expect(read()).rejects.toThrow('unavailable');

      const workload = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
        type: 'spki',
        format: 'der',
      });
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Independent envelope signer','ACTIVE',1)`,
        [principalId, participantId],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,state,credential_epoch,valid_from,valid_until,secret_fingerprint)
      values($1::uuid,$2,$3,'WORKLOAD_MTLS','urn:openpc:envelope-test-ca',$1::uuid::text,'envelope-test',$4,$5,'ACTIVE',1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour',$4)`,
        [credentialId, participantId, principalId, hash(workload), workload],
      );
      const now = BigInt(Date.now()) * 1000000n;
      const trust: IdentityEnvelopeSigningTrust = {
        ...scope,
        signerId: evidenceKeyId(publicKey),
        publicKeySpkiDer: publicKey,
        workloadCredentialId: credentialId,
        workloadCredentialEpoch: 1n,
        workloadParticipantEpoch: 1n,
        workloadPrincipalEpoch: 1n,
        keyEpoch: 1n,
        validFromNs: now - 1000000000n,
        validUntilNs: now + 3600000000000n,
        admissionKind: 'BOOTSTRAP',
        admissionReference: 'independent-envelope-installation',
        admissionDigest: hash('initial-envelope-key'),
        secretClass: 'SECRET-SIGNING-KEY',
        secretReference: 'secret://local/identity-envelope-postgres#1',
        secretVersion: '1',
        purpose: 'pc.cose.identity-authority-envelope.v1',
        profileId: 'pc.identity.authority-envelope.v1',
        profileVersion: 1,
        profileDigest: identityEnvelopeSigningProfileDigest,
      };
      const profileDigest = Buffer.from(identityEnvelopeSigningProfileDigest.slice(7), 'hex');
      await governor(async (client) => {
        await client.query(
          `insert into control.identity_envelope_signing_profile(profile_id,profile_version,profile_digest,schema_definition_digest,definition_canonical_json,signing_purpose_code) values($1,1,$2,$3,$4,371)`,
          [
            trust.profileId,
            profileDigest,
            Buffer.from(identityEnvelopeContext.definitionDigest.slice(7), 'hex'),
            Buffer.from(identityEnvelopeSigningProfileJson),
          ],
        );
        await client.query(
          `insert into control.business_signing_key(participant_id,privacy_domain_id,signer_id,signing_purpose_code,envelope_workload_participant_epoch,envelope_workload_principal_epoch,environment_id,public_key_spki_der,workload_credential_id,workload_credential_epoch,key_epoch,valid_from_ns,valid_until_ns,admission_kind,admission_reference,admission_digest,secret_class,secret_reference,secret_version,trust_preimage,trust_digest)
        values($1,$2,$3,371,1,1,$4,$5,$6,1,1,$7,$8,'BOOTSTRAP',$9,$10,$11,$12,$13,$14,$15)`,
          [
            participantId,
            privacyDomainId,
            trust.signerId,
            trust.environmentId,
            publicKey,
            credentialId,
            trust.validFromNs.toString(),
            trust.validUntilNs.toString(),
            trust.admissionReference,
            trust.admissionDigest,
            trust.secretClass,
            trust.secretReference,
            trust.secretVersion,
            identityEnvelopeSigningTrustPreimage(trust),
            Buffer.from(identityEnvelopeSigningTrustDigest(trust).slice(7), 'hex'),
          ],
        );
        await client.query(
          `insert into control.identity_envelope_signing_grant(participant_id,privacy_domain_id,signer_id,profile_digest) values($1,$2,$3,$4)`,
          [participantId, privacyDomainId, trust.signerId, profileDigest],
        );
        await client.query(
          `insert into control.business_signing_key_state(participant_id,privacy_domain_id,signer_id,state,changed_at_ns,change_reference,change_digest) values($1,$2,$3,'ADMITTED',$4,$5,$6)`,
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
          [participantId, privacyDomainId, trust.signerId, hash('envelope-key-active')],
        );
        await client.query(
          `insert into control.identity_envelope_signing_selection(participant_id,privacy_domain_id,environment_id,profile_digest,signer_id) values($1,$2,$3,$4,$5)`,
          [participantId, privacyDomainId, trust.environmentId, profileDigest, trust.signerId],
        );
      });
      const admitted = await read();
      expect(admitted.trust).toEqual(trust);
      const receiptRotationPurpose = (signerId: string) =>
        runScopedTransaction(
          runtime,
          {
            participantId,
            privacyDomainId,
            actionIntentId: 'ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1',
          },
          id,
          (client) => assertReceiptRotationPurpose(client, scope, signerId),
        );
      await receiptRotationPurpose(legacy.trust.signerId);
      await expect(receiptRotationPurpose(trust.signerId)).rejects.toThrow('DENIED');
      const artifact = identityEnvelopeFixture(trust.signerId);
      // Codec boundary fixture only, not a seed or claim of a governed envelope.
      const { decodeEnvelopeProposal, encodeEnvelopeProposal, authorityEnvelopeDigest } =
        await import('../../../packages/security-kernel/src/index.js');
      const proposal = decodeEnvelopeProposal(artifact.proposalBytes);
      proposal.participantId = participantId;
      artifact.proposalBytes = encodeEnvelopeProposal(proposal);
      artifact.proposalDigest = authorityEnvelopeDigest(artifact.proposalBytes);
      artifact.signer = {
        environmentId: trust.environmentId,
        participantId,
        privacyDomainId,
        profileId: identityEnvelopeSigningProfile.profileId,
        profileVersion: '1',
        profileDigest: trust.profileDigest,
        keyId: trust.signerId,
        keyVersion: trust.secretVersion,
        workloadCredentialId: credentialId,
        workloadCredentialEpoch: '1',
        trustContextDigest: identityEnvelopeSigningTrustDigest(trust),
      };
      artifact.issuedAtNs = admitted.recordedAtNs.toString();
      const payload = encodeIdentityAuthorityEnvelope(artifact);
      assertIdentityEnvelopeSigningTrust(payload, trust, admitted.recordedAtNs);
      expect(
        verifyIdentityAuthorityEnvelopeCose(
          publicKey,
          payload,
          signIdentityAuthorityEnvelopeCose(privateKey, publicKey, payload),
        ),
      ).toBe(true);
      await expect(read({ ...scope, environmentId: 'wrong' })).rejects.toThrow('unavailable');
      await expect(read({ ...scope, participantId: id(), privacyDomainId: id() })).rejects.toThrow(
        'unavailable',
      );
      await expect(
        governor((client) =>
          client.query(
            `update control.business_signing_key set signing_purpose_code=338 where signer_id=$1`,
            [trust.signerId],
          ),
        ),
      ).rejects.toThrow();
      await expect(
        governor((client) =>
          client.query(
            `insert into control.identity_envelope_signing_grant(participant_id,privacy_domain_id,signer_id,profile_digest) values($1,$2,$3,$4)`,
            [participantId, privacyDomainId, legacy!.trust.signerId, profileDigest],
          ),
        ),
      ).rejects.toThrow();
      await expect(
        governor((client) =>
          client.query(
            `insert into control.business_signing_grant(participant_id,privacy_domain_id,signer_id,profile_digest) values($1,$2,$3,$4)`,
            [
              participantId,
              privacyDomainId,
              trust.signerId,
              legacy!.trust.grants[0]!.profileDigest,
            ],
          ),
        ),
      ).rejects.toThrow('MIXED-SIGNING-PURPOSE');
      await expect(
        runScopedTransaction(
          runtime,
          { participantId, privacyDomainId, actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' },
          id,
          (client) =>
            client.query(
              `insert into control.identity_envelope_signing_selection select * from control.identity_envelope_signing_selection`,
            ),
        ),
      ).rejects.toThrow('permission denied');
      expect((await read()).trust).toEqual(trust);
      // Change each initial-trust identity epoch within the actual runtime
      // transaction, assert the current fence, then roll that negative case back.
      // No business authority, envelope or approval is manufactured.
      for (const [table, column, epoch, identity] of [
        ['credential', 'credential_id', 'credential_epoch', credentialId],
        ['principal', 'principal_id', 'authority_epoch', principalId],
        ['participant', 'participant_id', 'authority_epoch', participantId],
      ] as const) {
        await expect(
          runScopedTransaction(
            runtime,
            {
              participantId,
              privacyDomainId,
              actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
            },
            id,
            async (client) => {
              const changed = await client.query(
                `update control.${table} set ${epoch}=${epoch}+1,row_version=row_version+1 where participant_id=$1 and ${column}=$2 returning ${epoch}`,
                [participantId, identity],
              );
              expect(changed.rowCount).toBe(1);
              expect(String(changed.rows[0][epoch])).toBe('2');
              await fenceIdentityEnvelopeSigningTrust(client, scope);
            },
          ),
        ).rejects.toThrow('unavailable');
        expect((await read()).trust).toEqual(trust);
      }
      for (const state of ['RETIRED', 'REVOKED', 'COMPROMISED']) {
        await governor((client) =>
          client.query(
            `update control.business_signing_key_state set state=$4,row_version=row_version+1,changed_at_ns=greatest(changed_at_ns,floor(extract(epoch from clock_timestamp())*1000000)*1000),change_digest=$5 where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3`,
            [participantId, privacyDomainId, trust.signerId, state, hash(state)],
          ),
        );
        await expect(read()).rejects.toThrow('unavailable');
      }
      expect(
        (
          await admin.query(
            `select count(*)::int count from control.authority_envelope where participant_id=$1`,
            [participantId],
          )
        ).rows[0].count,
      ).toBe(0);
      expect(
        (
          await admin.query(
            `select signer_id,encode(trust_preimage,'hex') bytes,encode(trust_digest,'hex') digest from control.business_signing_key where participant_id=$1 and signing_purpose_code=338`,
            [participantId],
          )
        ).rows,
      ).toEqual(before.rows);
    } finally {
      privateKey.fill(0);
      legacy?.close();
      await runtime.end();
      await admin.end();
    }
  },
  180000,
);
