import { generateKeyPairSync } from 'node:crypto';
import { readWorkloadRenewalParticipantSecurityEpoch } from '../../../services/identity-service/src/db/workload-renewal-participant-security.js';
import { renewalSigningTrustFixture } from '../../../packages/security-kernel/src/workload-renewal/fixture.js';
import {
  workloadRenewalSigningTrustPreimage,
  workloadRenewalSigningProfileCanonicalJson,
  workloadRenewalSigningProfileDigest,
} from '../../../packages/security-kernel/src/workload-renewal/signing-trust.js';
import { Pool, type PoolClient } from 'pg';
import { readFile } from 'node:fs/promises';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { identityOidcBindingUpgradeSql } from '../../../services/identity-service/src/db/identity-oidc-binding-guards.mjs';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const issuer = 'https://identity-binding.openpc.example';
const audience = 'private-binding-fixture';

// Private persistence/security component. Calls below stand in for the verified proof
// consumer; they do not establish public invitation acceptance or issuer verification.
integration(
  'keeps scoped claims private and unverified until proof, with conflict tombstones and atomic global resolution',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    const runtime = new Pool({ connectionString: runtimeUrl });
    const participants = [id(), id()];
    const privacy = [id(), id()];
    let assumeResolver = false;
    const resolve = (
      subject: string,
      index = 0,
      actionIntentId = 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
    ) =>
      runScopedTransaction(
        runtime,
        { participantId: participants[index]!, privacyDomainId: privacy[index]!, actionIntentId },
        id,
        async (connection) => {
          if (assumeResolver)
            await connection.query('set local role openpc_identity_binding_resolver');
          const result = (
            await connection.query<{ subject: string }>(
              'select openpc.resolve_proved_oidc_identity($1,$2,$3) subject',
              [issuer, subject, audience],
            )
          ).rows[0]!.subject;
          if (assumeResolver) await connection.query('reset role');
          return result;
        },
      );
    const claim = async (
      subject: string,
      index = 0,
      membership = true,
      canonicalSubject?: string,
      state = 'ACTIVE',
    ) => {
      const connection = await admin.connect();
      const principal = id();
      try {
        await connection.query('begin');
        await connection.query(
          `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'USER',$3,'ACTIVE',1)`,
          [principal, participants[index], principal],
        );
        if (membership) {
          if (!canonicalSubject)
            await connection.query(
              `insert into control.identity_subject(identity_subject_id) values($1)`,
              [principal],
            );
          await connection.query(
            `insert into control.participant_membership(membership_id,participant_id,identity_subject_id) values($1,$2,$3)`,
            [principal, participants[index], canonicalSubject ?? principal],
          );
        }
        const credential = (
          await connection.query<{ credential_id: string }>(
            `insert into control.credential(participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,valid_from) values($1,$2,'OIDC_SUBJECT',$3,$4,$5,$6,1,clock_timestamp()-interval '1 minute') returning credential_id`,
            [participants[index], principal, issuer, subject, audience, state],
          )
        ).rows[0]!.credential_id;
        await connection.query('commit');
        return { principal, credential };
      } catch (error) {
        await connection.query('rollback');
        throw error;
      } finally {
        connection.release();
      }
    };
    const reservation = async (subject: string, connection: Pool | PoolClient = admin) =>
      (
        await connection.query(
          `select state,identity_subject_id from control.identity_oidc_binding where issuer=$1 and subject=$2 and audience=$3`,
          [issuer, subject, audience],
        )
      ).rows[0];
    try {
      for (const [index, participant] of participants.entries()) {
        await admin.query(
          `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Private binding initial trust','ACTIVE',1)`,
          [participant],
        );
        await admin.query(
          `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Root','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
          [privacy[index], participant],
        );
      }
      const local = await claim('unique-claim');
      expect(await reservation('unique-claim')).toEqual({
        state: 'UNVERIFIED_LEGACY',
        identity_subject_id: local.principal,
      });
      await expect(resolve('unique-claim')).rejects.toThrow('permission denied');
      expect((await runtime.query('select * from control.identity_oidc_binding')).rows).toEqual([]);
      await expect(runtime.query('set role openpc_identity_binding_owner')).rejects.toThrow(
        'permission denied',
      );
      // The deployed capability is non-inherited. Only the explicit proof-consumer
      // role transition can execute; ordinary runtime calls above must remain denied.
      assumeResolver = true;
      await expect(resolve('unique-claim', 0, 'ACT-PARTICIPANTS_READ_RESOURCE-V1')).rejects.toThrow(
        'PC-AUTH-0002',
      );
      expect(await resolve('unique-claim')).toBe(local.principal);
      expect(await reservation('unique-claim')).toEqual({
        state: 'BOUND',
        identity_subject_id: local.principal,
      });
      await expect(claim('unique-claim', 1)).rejects.toThrow(
        'PC-IDENTITY-1002-OIDC-IDENTITY-CONFLICT',
      );
      await admin.query(
        `update control.credential set state='REVOKED',credential_epoch=credential_epoch+1 where credential_id=$1`,
        [local.credential],
      );
      expect(await resolve('unique-claim', 1)).toBe(local.principal);
      const secondMembership = await claim('unique-claim', 1, true, local.principal);
      expect(secondMembership.principal).not.toBe(local.principal);
      await claim('ambiguous', 0);
      await claim('ambiguous', 1);
      await claim('missing-membership', 0, false);
      await claim('revoked-history', 0, true, undefined, 'REVOKED');
      for (const subject of ['ambiguous', 'missing-membership', 'revoked-history']) {
        expect(await reservation(subject)).toEqual({
          state: 'AMBIGUOUS_LEGACY',
          identity_subject_id: null,
        });
        await expect(resolve(subject)).rejects.toThrow('PC-AUTH-0002');
      }
      const before = Number(
        (await admin.query('select count(*) count from control.identity_subject')).rows[0].count,
      );
      const raced = await Promise.all([
        resolve('new-proved-identity'),
        resolve('new-proved-identity', 1),
      ]);
      expect(raced[0]).toBe(raced[1]);
      expect(
        Number(
          (await admin.query('select count(*) count from control.identity_subject')).rows[0].count,
        ),
      ).toBe(before + 1);
      expect((await runtime.query('select * from control.identity_oidc_binding')).rows).toEqual([]);
      await expect(
        runtime.query(
          `insert into control.identity_oidc_binding(issuer,subject,audience,state) values($1,'injected',$2,'AMBIGUOUS_LEGACY')`,
          [issuer, audience],
        ),
      ).rejects.toThrow('row-level security');
      const upgradeUnique = await claim('upgrade-unique');
      const migration = await readFile(
        new URL('../../../migrations/postgres/identity/0047_grey_venom.sql', import.meta.url),
        'utf8',
      );
      expect(migration.split(identityOidcBindingUpgradeSql.trim())).toHaveLength(2);
      const populated = await admin.connect();
      try {
        // Reconstruct the pre-reservation data state in a rolled-back, exclusive fixture.
        // Execute the actual generated upgrade owner against existing credential/membership history.
        await populated.query('begin');
        await populated.query('truncate control.identity_oidc_binding');
        await populated.query(identityOidcBindingUpgradeSql);
        expect(await reservation('upgrade-unique', populated)).toEqual({
          state: 'UNVERIFIED_LEGACY',
          identity_subject_id: upgradeUnique.principal,
        });
        for (const subject of ['ambiguous', 'missing-membership', 'revoked-history'])
          expect(await reservation(subject, populated)).toEqual({
            state: 'AMBIGUOUS_LEGACY',
            identity_subject_id: null,
          });
      } finally {
        await populated.query('rollback');
        populated.release();
      }
    } finally {
      await Promise.all([admin.end(), runtime.end()]);
    }
  },
);

/** Minimum installed SQL/profile qualification, not policy/instance admission
 * or a complete renewal. No business outcome or active family is manufactured. */
integration(
  'qualifies exact376 trust bytes and complete Participant security history under real runtime roles',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 }),
      runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
    const participantId = id(),
      privacyDomainId = id(),
      foreignPrivacy = id();
    try {
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Renewal trust SQL qualification','ACTIVE',1)`,
        [participantId],
      );
      for (const domain of [privacyDomainId, foreignPrivacy])
        await admin.query(
          `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
   values($1,$2,$3,'PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
          [domain, participantId, `Renewal trust SQL qualification ${domain}`],
        );
      const scope = { participantId, privacyDomainId };
      const read = () =>
        runScopedTransaction(
          runtime,
          { ...scope, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
          id,
          async (client) => {
            const role = await client.query(
              `select current_user as name,rolsuper,rolbypassrls,pg_has_role(current_user,'openpc_control_runtime','USAGE') as inherited_runtime from pg_roles where rolname=current_user`,
            );
            expect(role.rows).toEqual([
              {
                name: 'openpc_identity_runtime',
                rolsuper: false,
                rolbypassrls: false,
                inherited_runtime: true,
              },
            ]);
            return readWorkloadRenewalParticipantSecurityEpoch(client, scope);
          },
        );
      expect(await read()).toBe(0n);
      await expect(
        runScopedTransaction(
          runtime,
          { ...scope, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
          id,
          (client) =>
            readWorkloadRenewalParticipantSecurityEpoch(client, {
              ...scope,
              privacyDomainId: foreignPrivacy,
            }),
        ),
      ).rejects.toThrow('HISTORY-VISIBILITY');
      await expect(
        runScopedTransaction(
          runtime,
          {
            participantId: id(),
            privacyDomainId: id(),
            actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
          },
          id,
          (client) => readWorkloadRenewalParticipantSecurityEpoch(client, scope),
        ),
      ).rejects.toThrow('HISTORY-VISIBILITY');
      // Each isolated adversarial metadata change rolls back. No lifecycle result,
      // authority, receipt, candidate, or hidden-history zero is synthesized.
      for (const sql of [
        `GRANT openpc_control_owner TO openpc_control_runtime`,
        `GRANT openpc_control_key_governor TO openpc_control_runtime`,
        `GRANT openpc_control_maintenance TO openpc_control_runtime`,
        `CREATE POLICY renewal_hidden_history_test ON control.participant_lifecycle_transition AS RESTRICTIVE FOR SELECT TO openpc_control_runtime USING(false)`,
        `REVOKE SELECT ON control.participant_lifecycle_transition FROM openpc_control_runtime`,
        `ALTER TABLE control.participant_lifecycle_transition NO FORCE ROW LEVEL SECURITY`,
      ]) {
        const client = await admin.connect();
        try {
          await client.query('begin');
          await client.query(sql);
          await client.query('set local role openpc_control_runtime');
          await client.query(
            `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)`,
            [participantId, privacyDomainId, id()],
          );
          await expect(readWorkloadRenewalParticipantSecurityEpoch(client, scope)).rejects.toThrow(
            'HISTORY-VISIBILITY',
          );
        } finally {
          await client.query('rollback');
          client.release();
        }
        expect(await read()).toBe(0n);
      }
      const publicKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
        type: 'spki',
        format: 'der',
      });
      const t = { ...renewalSigningTrustFixture(publicKey), participantId, privacyDomainId };
      // Execute the owning SQL preimage expression itself with public typed input,
      // without inserting a signer/family or treating vectors as current admission.
      const ownerPath =
        '../../../services/identity-service/src/db/workload-renewal-signing-guards.mjs';
      const owner: Record<string, unknown> = await import(ownerPath);
      const branch = owner.workloadRenewalSigningTrustBranchSql;
      if (typeof branch !== 'string') throw new Error('Missing owning376 trust projection');
      const expression = /expected:=([\s\S]*?);\s*$/u.exec(branch)?.[1];
      if (!expression) throw new Error('Missing exact376 trust projection');
      const key = {
        participant_id: participantId,
        privacy_domain_id: privacyDomainId,
        environment_id: t.environmentId,
        signer_id: t.signerId,
        public_key_spki_der: `\\x${publicKey.toString('hex')}`,
        key_epoch: '2',
        valid_from_ns: t.validFromNs.toString(),
        valid_until_ns: t.validUntilNs.toString(),
        admission_kind: t.admissionKind,
        admission_reference: t.admissionReference,
        admission_digest: `\\x${t.admissionDigest.slice(7)}`,
        secret_class: t.secretClass,
        secret_reference: t.secretReference,
        secret_version: t.secretVersion,
      };
      const grant = {
        principal_id: t.principalId,
        workload_id: t.workloadId,
        family_id: t.familyId,
        family_security_epoch: '2',
        participant_security_invalidation_epoch: '0',
        key_security_generation: '2',
        provider_qualification_digest: `\\x${t.providerQualificationDigest.slice(7)}`,
      };
      const bytes = workloadRenewalSigningTrustPreimage(t);
      const canonical = await runScopedTransaction(
        runtime,
        { ...scope, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
        id,
        (client) =>
          client.query<{ valid: boolean }>(
            `with key_row as(select * from jsonb_populate_record(null::control.business_signing_key,$2::jsonb)),
    input as(select $3::jsonb as renewal_grant) select openpc.business_cbor($1) is not distinct from (${expression}) as valid from key_row cross join input`,
            [bytes, JSON.stringify(key), JSON.stringify(grant)],
          ),
      );
      expect(canonical.rows).toEqual([{ valid: true }]);
      await expect(
        runScopedTransaction(
          runtime,
          { ...scope, actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' },
          id,
          (client) =>
            client.query(
              `insert into control.workload_renewal_signing_profile(profile_id,profile_version,profile_digest,schema_definition_digest,definition_canonical_json,signing_purpose_code)
    values('pc.identity.workload-renewal.policy-authorization.v1',2,$1,$2,$3,376)`,
              [
                Buffer.from(workloadRenewalSigningProfileDigest.slice(7), 'hex'),
                Buffer.from(
                  '0d9bb7686dc932fc17b4ccfb8700f600b9a46e765cef61e93d68b8e1d7efc10d',
                  'hex',
                ),
                Buffer.from(workloadRenewalSigningProfileCanonicalJson),
              ],
            ),
        ),
      ).rejects.toMatchObject({ code: '42501' });
      const tables =
        await admin.query(`select c.relname,c.relrowsecurity,c.relforcerowsecurity,r.rolname as owner
   from pg_class c join pg_namespace n on n.oid=c.relnamespace join pg_roles r on r.oid=c.relowner
   where n.nspname='control' and c.relname in ('workload_renewal_signing_grant','workload_renewal_signing_selection') order by c.relname`);
      expect(tables.rows).toEqual(
        ['workload_renewal_signing_grant', 'workload_renewal_signing_selection'].map((relname) => ({
          relname,
          relrowsecurity: true,
          relforcerowsecurity: true,
          owner: 'openpc_control_owner',
        })),
      );
    } finally {
      await runtime.end();
      await admin.end();
    }
  },
  120000,
);
