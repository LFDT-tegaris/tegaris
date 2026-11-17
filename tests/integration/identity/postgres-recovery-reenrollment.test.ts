import { createHash, generateKeyPairSync } from 'node:crypto';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { PostgresIdentityRepository } from '../../../services/identity-service/src/domain/identity-kernel.js';
import { createLocalIdentityRuntimeCryptoAdapter } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import { localWebAuthnRegistrationAdapter } from '../../../services/identity-service/src/domain/webauthn-registration.js';
import { createUnattestedTestRegistration } from './hardware-authenticator.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const hash = (value: Buffer | string) => createHash('sha256').update(value).digest();

integration(
  'requires fresh IdP authentication and admits one real replacement enrollment after a retained completed recovery',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    const runtime = new Pool({ connectionString: runtimeUrl });
    const signingKey = generateKeyPairSync('ed25519');
    const publicKey = signingKey.publicKey.export({ format: 'der', type: 'spki' });
    const signer = createLocalIdentityRuntimeCryptoAdapter({
      activePrivateKeyPkcs8Der: signingKey.privateKey.export({ format: 'der', type: 'pkcs8' }),
      activePublicKeySpkiDer: publicKey,
      trustedPublicKeysSpkiDer: [publicKey],
    });
    const repository = new PostgresIdentityRepository(runtime, undefined, signer);
    const participantId = id(),
      privacyDomainId = id(),
      subjectId = id(),
      executorId = id(),
      firstId = id(),
      secondId = id(),
      recoveryId = id(),
      envelopeId = id();
    const issuer = 'https://recovery-idp.example',
      clientId = 'recovery-reenrollment',
      origin = 'https://recovery.example';
    const consumedAt = new Date(Date.now() - 3000);
    try {
      // This is downstream component evidence. The completed recovery row is a fixture;
      // the public/browser journey must create it through both custodians and executor.
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch,root_privacy_domain_id) values ($1,'Recovery enrollment fixture','ACTIVE',1,$2)`,
        [participantId, privacyDomainId],
      );
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values ($1,$2,'Recovery fixture','PARTICIPANT_LOCAL','LOCAL_TEST','ACTIVE')`,
        [privacyDomainId, participantId],
      );
      for (const principalId of [subjectId, executorId, firstId, secondId])
        await admin.query(
          `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values ($1,$2,'USER',$4,'ACTIVE',$3)`,
          [
            principalId,
            participantId,
            principalId === subjectId ? 2 : 1,
            `Recovery fixture ${principalId}`,
          ],
        );
      await admin.query(
        `insert into control.credential(participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,valid_from) values ($1,$2,'OIDC_SUBJECT',$3,'recovered-subject',$4,'ACTIVE',2,clock_timestamp()-interval '1 hour')`,
        [participantId, subjectId, issuer, clientId],
      );
      const retiredKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
        format: 'der',
        type: 'spki',
      });
      await admin.query(
        `insert into control.credential(participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,public_key_spki_der,public_key_digest,valid_from) values ($1,$2,'WEBAUTHN','webauthn://recovery.example','retired-key',$3,'REVOKED',2,$4,$5,clock_timestamp()-interval '1 hour')`,
        [participantId, subjectId, origin, retiredKey, hash(retiredKey)],
      );
      await admin.query(
        `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
      values ($1,$2,$3,$3,$4,1,0,'ACTIVE',clock_timestamp()-interval '1 hour',$5,$6,$7,$8,array['ACT-IDENTITY_UPDATE_STEP_UP-V1'],array['*'],array['LOW','HIGH'],true,true,0)`,
        [
          envelopeId,
          participantId,
          subjectId,
          firstId,
          Buffer.from('initial-trust'),
          hash(envelopeId),
          Buffer.alloc(0),
          [privacyDomainId],
        ],
      );
      await admin.query(
        `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,valid_during,state,created_by_principal_id)
      values ($1,$2,$3,$4,0,$5,$6,array['ACT-IDENTITY_UPDATE_STEP_UP-V1'],array['*'],array['LOW','HIGH'],true,true,0,tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour','[)'),'ACTIVE',$7)`,
        [
          id(),
          participantId,
          subjectId,
          envelopeId,
          hash('initial-enrollment'),
          [privacyDomainId],
          firstId,
        ],
      );
      const login = async (authenticatedAt?: Date) => {
        const started = await repository.beginOidc({
          issuer,
          clientId,
          redirectUri: `${origin}/callback`,
        });
        return repository.completeOidc(started.authorization.transactionId, started.custody, {
          state: started.authorization.state,
          nonce: started.authorization.nonce,
          issuer,
          subject: 'recovered-subject',
          audience: clientId,
          authorizedParty: clientId,
          principalId: subjectId,
          participantId,
          issuedAt: new Date(Date.now() - 1000),
          expiresAt: new Date(Date.now() + 60000),
          authenticatedAt,
        });
      };
      const before = await login();
      await expect(
        repository.beginInitialWebAuthnEnrollment(before.sessionToken, 'recovery.example', origin),
      ).rejects.toMatchObject({ code: 'PC-AUTH-0006' });
      await admin.query(
        `update control.session set state='REVOKED',revoked_at=clock_timestamp(),revoked_reason='completed-recovery-fixture' where participant_id=$1`,
        [participantId],
      );
      await admin.query(
        `insert into control.recovery_challenge(recovery_challenge_id,participant_id,privacy_domain_id,principal_id,recovery_principal_id,challenge_digest,purpose_digest,action_intent_id,current_epoch,recovery_principal_epoch,custodian_one_principal_id,custodian_two_principal_id,custodian_one_epoch,custodian_two_epoch,issued_at,expires_at,consumed_at,outcome,replacement_required)
      values ($1,$2,$3,$4,$5,$6,$7,'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',1,1,$8,$9,1,1,$10,$10::timestamptz+interval '15 minutes',$11,'COMPLETED',true)`,
        [
          recoveryId,
          participantId,
          privacyDomainId,
          subjectId,
          executorId,
          hash('recovery-challenge'),
          hash('recovery-purpose'),
          firstId,
          secondId,
          new Date(consumedAt.getTime() - 5000),
          consumedAt,
        ],
      );
      for (const time of [
        undefined,
        new Date(consumedAt.getTime() - 1000),
        new Date(Math.floor(consumedAt.getTime() / 1000) * 1000),
        new Date(Date.now() + 60000),
      ])
        await expect(login(time)).rejects.toMatchObject({ code: 'PC-AUTH-0002' });
      const session = await login(new Date(Math.floor(Date.now() / 1000) * 1000));
      const enrollment = await repository.beginInitialWebAuthnEnrollment(
        session.sessionToken,
        'recovery.example',
        origin,
      );
      const response = createUnattestedTestRegistration(
        enrollment.challenge,
        origin,
        'recovery.example',
      );
      const context = await repository.initialWebAuthnEnrollmentContext(
        session.sessionToken,
        enrollment.enrollmentId,
      );
      const verified = await localWebAuthnRegistrationAdapter.verify({ response, ...context });
      expect(verified).toBeDefined();
      await admin.query(`update control.principal set authority_epoch=3 where principal_id=$1`, [
        subjectId,
      ]);
      await expect(
        repository.completeInitialWebAuthnEnrollment(
          session.sessionToken,
          enrollment.enrollmentId,
          verified!,
        ),
      ).rejects.toMatchObject({ code: 'PC-AUTH-0003' });
      expect(
        (
          await admin.query(
            `select count(*)::int count from control.credential where participant_id=$1 and kind='WEBAUTHN' and state='ACTIVE'`,
            [participantId],
          )
        ).rows[0].count,
      ).toBe(0);
      await admin.query(`update control.principal set authority_epoch=2 where principal_id=$1`, [
        subjectId,
      ]);
      const registered = await repository.completeInitialWebAuthnEnrollment(
        session.sessionToken,
        enrollment.enrollmentId,
        verified!,
      );
      expect(registered).toMatchObject({ state: 'ACTIVE', credentialEpoch: '1' });
      const stored = (
        await admin.query(
          `select replacement_credential_id,replacement_enrolled_at,row_version::text from control.recovery_challenge where recovery_challenge_id=$1`,
          [recoveryId],
        )
      ).rows[0];
      expect(stored).toMatchObject({
        replacement_credential_id: registered.credentialId,
        replacement_enrolled_at: expect.any(Date),
        row_version: '2',
      });
      const evidence = (
        await admin.query(
          `select payload_cbor,cose_sign1,privacy_domain_id from control.outbox_event where participant_id=$1 and aggregate_id=$2`,
          [participantId, registered.credentialId],
        )
      ).rows[0];
      expect(evidence.privacy_domain_id).toBe(privacyDomainId);
      expect(
        await signer.verifyCanonicalAssertion(evidence.payload_cbor, evidence.cose_sign1),
      ).toBeDefined();
      const restarted = new PostgresIdentityRepository(runtime, undefined, signer);
      expect(await restarted.sessionSnapshot(session.sessionToken)).toMatchObject({
        principalId: subjectId,
        authorityEpoch: '2',
      });
      await expect(
        restarted.completeInitialWebAuthnEnrollment(
          session.sessionToken,
          enrollment.enrollmentId,
          verified!,
        ),
      ).rejects.toMatchObject({ code: 'PC-AUTH-0006' });
      const nextSession = await login(new Date(Math.floor(Date.now() / 1000) * 1000));
      await expect(
        restarted.beginInitialWebAuthnEnrollment(
          nextSession.sessionToken,
          'recovery.example',
          origin,
        ),
      ).rejects.toMatchObject({ code: 'PC-AUTH-0006' });
      await admin.query(
        `update control.credential set state='REVOKED',credential_epoch=credential_epoch+1 where credential_id=$1`,
        [registered.credentialId],
      );
      await expect(
        restarted.beginInitialWebAuthnEnrollment(
          nextSession.sessionToken,
          'recovery.example',
          origin,
        ),
      ).rejects.toMatchObject({ code: 'PC-AUTH-0006' });
      expect(
        (
          await admin.query(
            `select count(*)::int count from control.credential where participant_id=$1 and kind='WEBAUTHN'`,
            [participantId],
          )
        ).rows[0].count,
      ).toBe(2);
    } finally {
      await Promise.all([admin.end(), runtime.end()]);
    }
  },
);
