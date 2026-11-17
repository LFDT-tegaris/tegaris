import { execFile } from 'node:child_process';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { cp, lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { z } from 'zod';
import { encodeCbor } from '../../../packages/security-kernel/src/canonical-cbor.js';
import { envelopeFixtureScope } from '../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  encodeEnvelopeScope,
  decodeEnvelopeScope,
  platformEnvelopeScopeDigest,
  type PlatformEnvelopeScopeAdmission,
} from '../../../packages/security-kernel/src/index.js';
import { installInitialPlatformEnvelopeScope } from '../../../scripts/operations/installation-platform-authority.mjs';
import { installInitialOperationsEnvironment } from '../../../scripts/operations/installation-generation-store.mjs';
import {
  installPlatformRecoveryEnrollment,
  provisionPlatformRecoveryInstallationLogin,
} from '../../../scripts/operations/installation-platform-recovery.mjs';
import { localRootExpiryRecoveryEnrollment } from '../../../services/identity-service/src/contracts/local-root-expiry-recovery.js';
import { localRootExpiryRecoveryCustodyPreimage } from '../../../services/identity-service/src/domain/local-root-expiry-recovery.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { createLocalIdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import {
  assertNativeRootExpiryDatabaseTarget,
  nativeRootExpiryInstallationInput,
} from './root-expiry-installation-native.js';
import { oidcProviderFixture } from './oidc-provider-fixture.js';
import { participantReadbackRuntime } from './participant-readback-runtime.js';
import { rootExpiryRecoveryClient, type RootRecoveryActor } from './root-expiry-recovery-client.js';
import { sha } from './public-governance-client.js';
import { verifyLocalWebAuthnAssertion } from '../../../services/identity-service/src/domain/local-webauthn-trust-adapter.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const container = process.env.OPENPC_PLATFORM_SCOPE_CONTAINER;
const integration = adminUrl && runtimeUrl && container ? it : it.skip;
const execute = promisify(execFile);
const periodMs = 120000;

it('authenticates finite Root recovery sources before database allocation', async () => {
  expect(
    (await nativeRootExpiryInstallationInput('root-recovery-preflight')).sourceAuthentication
      .version,
  ).toBe(2);
});

it('signs finite Root recovery authenticator assertions for the real verifier', () => {
  const origin = 'http://127.0.0.1:34567';
  const participantId = id(),
    principalId = id(),
    sessionId = id(),
    credentialId = id();
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = pair.publicKey.export({ type: 'spki', format: 'der' });
  const externalCredentialId = randomBytes(32).toString('base64url');
  const actor: RootRecoveryActor = {
    principalId,
    sessionId,
    credentialId,
    externalCredentialId,
    privateKey: pair.privateKey,
    sessionToken: 'unused-closed-crypto-input',
    counter: 1,
  };
  const challenge = {
    challengeId: id(),
    challenge: randomBytes(32).toString('base64url'),
    intentDigest: 'sha256:' + '12'.repeat(32),
    rpId: '127.0.0.1',
    credentialIds: [externalCredentialId],
  };
  const proof = rootExpiryRecoveryClient(origin, participantId, id()).proof(
    actor,
    id(),
    'REQUEST',
    challenge,
  );
  if (proof.kind !== 'PROVE') throw new Error('Expected an authenticator proof');
  const credential = {
    credentialId,
    externalCredentialId,
    publicKeySpkiDer: spki,
    publicKeyDigest: sha(spki),
  };
  const input = {
    principalId,
    sessionId,
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    resourceDigest: challenge.intentDigest,
    challenge: challenge.challenge,
    rpIdHash: 'sha256:' + sha('127.0.0.1').toString('hex'),
    allowedOrigin: origin,
    assertion: proof.proof.assertion,
  };
  expect(verifyLocalWebAuthnAssertion(credential, input)).toMatchObject({
    credentialId,
    principalId,
    sessionId,
    signCount: '2',
  });
  expect(
    verifyLocalWebAuthnAssertion(credential, {
      ...input,
      challenge: randomBytes(32).toString('base64url'),
    }),
  ).toBeUndefined();
  expect(
    verifyLocalWebAuthnAssertion(credential, { ...input, allowedOrigin: 'http://127.0.0.1:34568' }),
  ).toBeUndefined();
  const wrong = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
    type: 'spki',
    format: 'der',
  });
  expect(
    verifyLocalWebAuthnAssertion(
      { ...credential, publicKeySpkiDer: wrong, publicKeyDigest: sha(wrong) },
      input,
    ),
  ).toBeUndefined();
});

// Initial identities, OIDC bindings and external WebAuthn public credentials are
// explicit bootstrap inputs. Authenticator enrollment is not accepted here.
// All sessions, phase proofs, recovery evidence and Root effects use real owners.
integration(
  'recovers finite Root validity with real OIDC and independent authenticator proofs without adding permissions',
  async () => {
    const scratch = process.env.OPENPC_TEST_TMP_ROOT;
    if (!scratch) throw new Error('Owned fixture scratch is required');
    expect((await lstat(scratch)).isSymbolicLink()).toBe(false);
    expect(await realpath(scratch)).toBe(scratch);
    const inspected = await execute(
      'docker',
      [
        'inspect',
        '--format',
        '{"Id":{{json .Id}},"Name":{{json .Name}},"State":{"Running":{{json .State.Running}}},"Config":{"Labels":{{json .Config.Labels}}},"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}}}',
        container!,
      ],
      { timeout: 10000, maxBuffer: 16384 },
    );
    const target = assertNativeRootExpiryDatabaseTarget({
      container: container!,
      scratch,
      adminUrl: adminUrl!,
      runtimeUrl: runtimeUrl!,
      inspection: JSON.parse(inspected.stdout),
    });
    const directory = join(scratch, 'finite-root-recovery');
    await mkdir(directory, { mode: 0o700 });
    await mkdir(join(directory, 'private'), { mode: 0o700 });
    let admin = new Pool({ connectionString: adminUrl, max: 3 });
    const installerUrl = new URL(adminUrl!);
    installerUrl.username = 'openpc_finite_root_installer';
    installerUrl.password = randomBytes(32).toString('hex');
    const installer = new Pool({ connectionString: installerUrl.href, max: 1 });
    const receivingUrl = new URL(adminUrl!);
    receivingUrl.username = 'openpc_recovery_installation';
    receivingUrl.password = randomBytes(32).toString('hex');
    const receiving = new Pool({ connectionString: receivingUrl.href, max: 1 });
    await writeFile(
      join(directory, 'private', 'database-owners.json'),
      JSON.stringify({ initial: installerUrl.href, receiving: receivingUrl.href }) + '\n',
      { mode: 0o600, flag: 'wx' },
    );
    const participantId = id(),
      privacyDomainId = id(),
      otherPrivacy = id(),
      platformContextId = id();
    const administrators = [id(), id()] as const;
    const executor = id(),
      custodians = [id(), id()] as const;
    const negatives = [
      {
        label: 'current finite',
        principalId: id(),
        range:
          "tstzrange(clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour','[)')",
        state: 'ACTIVE',
        forbidden: true,
      },
      {
        label: 'current unbounded',
        principalId: id(),
        range: "tstzrange(clock_timestamp()-interval '1 minute',null,'[)')",
        state: 'ACTIVE',
        forbidden: true,
      },
      {
        label: 'future finite',
        principalId: id(),
        range:
          "tstzrange(clock_timestamp()+interval '5 minutes',clock_timestamp()+interval '1 hour','[)')",
        state: 'ACTIVE',
        forbidden: true,
      },
      {
        label: 'future unbounded',
        principalId: id(),
        range: "tstzrange(clock_timestamp()+interval '5 minutes',null,'[)')",
        state: 'ACTIVE',
        forbidden: true,
      },
      {
        label: 'expired finite',
        principalId: id(),
        range:
          "tstzrange(clock_timestamp()-interval '2 minutes',clock_timestamp()-interval '1 minute','[)')",
        state: 'ACTIVE',
        forbidden: false,
      },
      {
        label: 'revoked unbounded',
        principalId: id(),
        range: "tstzrange(clock_timestamp()-interval '1 minute',null,'[)')",
        state: 'REVOKED',
        forbidden: false,
      },
    ];
    const signers = [executor, ...custodians, ...negatives.map((v) => v.principalId)];
    const keys = new Map(
      signers.map((principal) => [
        principal,
        {
          pair: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
          credentialId: id(),
          external: randomBytes(32).toString('base64url'),
        },
      ]),
    );
    const provider = await oidcProviderFixture(participantId, executor, executor, {
      membershipHints: false,
    });
    let service: Awaited<ReturnType<typeof participantReadbackRuntime>> | undefined;
    let participantRuntime: Pool | undefined;
    const closed = new Set<Pool>();
    const end = async (p: Pool) => {
      if (!closed.has(p)) {
        closed.add(p);
        await p.end();
      }
    };
    try {
      expect(
        (
          await admin.query(
            "select pg_get_functiondef('openpc.root_expiry_recovery_executor_has_grants(uuid)'::regprocedure) body",
          )
        ).rows[0].body,
      ).toContain('upper_inf(a.valid_during)');
      await admin.query(
        `create role openpc_finite_root_installer login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls password '${installerUrl.password}'`,
      );
      await admin.query('grant openpc_control_owner to openpc_finite_root_installer');
      await admin.query('grant connect on database openpc_control to openpc_finite_root_installer');
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch,root_privacy_domain_id) values($1,'Finite Root recovery initial trust','ACTIVE',1,$2)",
        [participantId, privacyDomainId],
      );
      for (const privacy of [privacyDomainId, otherPrivacy])
        await admin.query(
          "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Finite Root recovery '||$1::uuid::text,'PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
          [privacy, participantId],
        );
      for (const principalId of [...administrators, ...signers]) {
        await admin.query(
          "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'PLATFORM_OPERATOR','Synthetic initial recovery identity '||$1::uuid::text,'ACTIVE',1)",
          [principalId, participantId],
        );
        await admin.query('insert into control.identity_subject(identity_subject_id) values($1)', [
          principalId,
        ]);
        await admin.query(
          'insert into control.participant_membership(membership_id,participant_id,identity_subject_id) values($1,$2,$1)',
          [principalId, participantId],
        );
        await admin.query(
          "insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,valid_from) values($1,$2,$3,'OIDC_SUBJECT',$4,$3::uuid::text,$5,'ACTIVE',1,clock_timestamp())",
          [id(), participantId, principalId, provider.issuer, provider.clientId],
        );
      }
      const participantRuntimeUrl = new URL(runtimeUrl!);
      participantRuntimeUrl.username = 'openpc_participant_runtime';
      participantRuntime = new Pool({ connectionString: participantRuntimeUrl.href, max: 1 });
      service = await participantReadbackRuntime({
        runtime: participantRuntime,
        identityDatabaseUrl: runtimeUrl!,
        participantId,
        privacyDomainId,
        operatorPrincipalId: administrators[0],
        checkerPrincipalId: administrators[1],
        oidc: provider,
        localQaFixture: true,
        preserveMaterial: true,
      });
      await cp(service.directory, join(directory, 'private', 'identity-original'), {
        recursive: true,
        errorOnExist: true,
        force: false,
      });
      for (const [principalId, key] of keys) {
        const spki = key.pair.publicKey.export({ type: 'spki', format: 'der' });
        await writeFile(
          join(directory, 'private', `${principalId}.pkcs8.der`),
          key.pair.privateKey.export({ type: 'pkcs8', format: 'der' }),
          { mode: 0o600, flag: 'wx' },
        );
        await admin.query(
          "insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_spki_der,public_key_digest,authenticator_sign_count,state,credential_epoch,valid_from) values($1,$2,$3,'WEBAUTHN','webauthn://127.0.0.1',$4,$5,$6,$7,1,'ACTIVE',1,clock_timestamp())",
          [
            key.credentialId,
            participantId,
            principalId,
            key.external,
            service.identityUrl,
            spki,
            sha(spki),
          ],
        );
      }
      const client = rootExpiryRecoveryClient(service.identityUrl, participantId, privacyDomainId);
      const actors = new Map<string, RootRecoveryActor>();
      for (const principalId of [...administrators, executor, ...custodians]) {
        const actor = await client.login(provider, principalId);
        const key = keys.get(principalId);
        if (key)
          Object.assign(actor, {
            credentialId: key.credentialId,
            externalCredentialId: key.external,
            privateKey: key.pair.privateKey,
          });
        actors.set(principalId, actor);
      }
      expect(provider.tokenExchanges()).toBe(5);
      await writeFile(
        join(directory, 'private', 'initial-actors.json'),
        JSON.stringify(
          {
            administrators,
            executor,
            custodians,
            negatives,
            actors: [...actors.values()].map((actor) => ({
              principalId: actor.principalId,
              sessionId: actor.sessionId,
              sessionToken: actor.sessionToken,
              credentialId: actor.credentialId,
              externalCredentialId: actor.externalCredentialId,
              counter: actor.counter,
            })),
          },
          null,
          2,
        ) + '\n',
        { mode: 0o600, flag: 'wx' },
      );
      const environmentId = `root-${id().slice(-12)}`;
      const operationsInput = await nativeRootExpiryInstallationInput(environmentId);
      const installationDigest = await installInitialOperationsEnvironment(
        installer,
        { participantId, privacyDomainId },
        operationsInput,
      );
      const grantable = envelopeFixtureScope();
      for (const key of Object.keys(
        grantable.administration,
      ) as (keyof typeof grantable.administration)[])
        grantable.administration[key] = [];
      grantable.runtime.participantIds = [participantId];
      grantable.runtime.privacyDomainIds = [privacyDomainId];
      grantable.onwardDelegationDepth = 0;
      const now = Date.now();
      grantable.validFromNs = (BigInt(now) * 1000000n).toString();
      grantable.validUntilNs = (BigInt(now + periodMs) * 1000000n).toString();
      const admission: PlatformEnvelopeScopeAdmission = {
        platformContextId,
        ownerParticipantId: participantId,
        installationPrivacyDomainId: privacyDomainId,
        platformAuthorityEpoch: '1',
        environmentId,
        installationDigest,
        grantable,
      };
      await installInitialPlatformEnvelopeScope(installer, admission);
      const envelope = async (principalId: string, actions: readonly string[]) => {
        const envelopeId = id(),
          semantic = encodeCbor([
            'SYNTHETIC_LOCAL_QA_CUSTODY',
            participantId,
            privacyDomainId,
            principalId,
            actions,
          ]);
        await admin.query(
          `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,representation,authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,runtime_capability_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,platform_context_id,platform_authority_epoch)
      values($1,$2,$3,$3,'LEGACY',1,0,'ACTIVE',clock_timestamp(),$4,$5,$6,ARRAY[$7]::text[],$8,ARRAY[]::text[],ARRAY[]::text[],ARRAY['STANDARD'],true,true,0,$9,1)`,
          [
            envelopeId,
            participantId,
            principalId,
            semantic,
            sha(semantic),
            Buffer.from('d28440a04040', 'hex'),
            privacyDomainId,
            actions,
            platformContextId,
          ],
        );
        return { envelopeId, digest: sha(semantic) };
      };
      for (const principalId of administrators) await envelope(principalId, []);
      for (const negative of negatives) {
        const role = id(),
          roleRef = `urn:openpc:role:${role}`;
        const actions = ['ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'];
        const e = await envelope(negative.principalId, actions);
        await admin.query(
          "insert into control.authority_role(authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id) values($1,$2,$3,'Independent executor denial fixture '||$5::uuid::text,$4,'BOOTSTRAP',$5)",
          [role, participantId, roleRef, actions, negative.principalId],
        );
        await admin.query(
          `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,role_id,delegation_epoch,scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,runtime_capability_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
      values($1,$2,$3,$4,$5,0,$6,${negative.range},$7,$3,ARRAY[$8]::text[],$9,ARRAY[]::text[],ARRAY[]::text[],ARRAY['STANDARD'],true,true,0)`,
          [
            id(),
            participantId,
            negative.principalId,
            e.envelopeId,
            roleRef,
            e.digest,
            negative.state,
            privacyDomainId,
            actions,
          ],
        );
      }
      const baseline = async () => {
        const tables = [
          'principal',
          'participant_membership',
          'authority_envelope',
          'authority_role',
          'assignment',
          'platform_envelope_scope',
          'operations_installation',
        ];
        const rows: Record<string, unknown> = {};
        for (const table of tables) {
          const column =
            table === 'platform_envelope_scope' ? 'owner_participant_id' : 'participant_id';
          rows[table] = (
            await admin.query(
              `select to_jsonb(t) row from control.${table} t where ${column}=$1 order by to_jsonb(t)::text`,
              [participantId],
            )
          ).rows;
        }
        rows.credentials = (
          await admin.query(
            'select credential_id,principal_id,kind,issuer,subject,audience,public_key_spki_der,public_key_digest,state,credential_epoch,valid_from,valid_until from control.credential where participant_id=$1 order by credential_id',
            [participantId],
          )
        ).rows;
        return rows;
      };
      const original = await baseline();
      await writeFile(
        join(directory, 'original.json'),
        JSON.stringify({ admission, original }, null, 2) + '\n',
        { mode: 0o600, flag: 'wx' },
      );
      const clock = async () =>
        BigInt(
          (
            await admin.query(
              'select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text now',
            )
          ).rows[0].now,
        );
      while ((await clock()) < BigInt(grantable.validUntilNs))
        await new Promise((resolve) => setTimeout(resolve, 500));
      const custody = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const spki = custody.publicKey.export({ type: 'spki', format: 'der' });
      await writeFile(
        join(directory, 'private', 'custody.pkcs8.der'),
        custody.privateKey.export({ type: 'pkcs8', format: 'der' }),
        { mode: 0o600, flag: 'wx' },
      );
      await provisionPlatformRecoveryInstallationLogin(admin, receivingUrl.href);
      const issued = Number((await clock()) / 1000000n),
        trustUntil = issued + 600000;
      const trust = {
        schema: 'pc.installation.local-root-expiry-recovery-receiving-trust',
        schemaVersion: 1,
        purpose: 'pc.installation.local-root-expiry-recovery-custody.v1',
        custodyTrustId: id(),
        participantId,
        privacyDomainId,
        platformContextId,
        installationDigest,
        installationEnvironmentId: environmentId,
        profile: 'LOCAL_QA',
        algorithm: 'ES256',
        issuerKeyId: 'sha256:' + sha(spki).toString('hex'),
        issuerPublicKeySpkiDer: spki.toString('base64'),
        issuerEpoch: '1',
        validFrom: new Date(issued).toISOString(),
        validUntil: new Date(trustUntil).toISOString(),
      };
      await writeFile(
        join(directory, 'private', 'receiving-trust.json'),
        JSON.stringify(trust, null, 2) + '\n',
        { mode: 0o600, flag: 'wx' },
      );
      const installed = await installPlatformRecoveryEnrollment(receiving, trust, {
        localQaEnabled: true,
      });
      expect(installed.state).toBe('INSTALLED');
      const signer = (principalId: string) => ({
        principalId,
        credentialId: keys.get(principalId)!.credentialId,
        principalEpoch: '1',
        credentialEpoch: '1',
      });
      const signedEnrollment = async (principalId: string) => {
        const current = Number((await clock()) / 1000000n);
        if (current + periodMs > trustUntil)
          throw new Error('Receiving custody trust is too old for a fresh bounded enrollment');
        const document = localRootExpiryRecoveryEnrollment.parse({
          schema: 'pc.identity.local-root-expiry-recovery-enrollment',
          schemaVersion: 1,
          purpose: trust.purpose,
          enrollmentId: id(),
          participantId,
          privacyDomainId,
          platformContextId,
          rootEpoch: '1',
          rootRevision: '1',
          rootDigest: platformEnvelopeScopeDigest(admission),
          custodyTrustId: trust.custodyTrustId,
          custodyTrustDigest: installed.digest,
          custodyIssuerKeyId: trust.issuerKeyId,
          custodyIssuerEpoch: '1',
          installationDigest,
          installationEnvironmentId: environmentId,
          profile: 'LOCAL_QA',
          administratorPrincipalIds: administrators,
          recoveryPrincipal: signer(principalId),
          custodians: custodians.map(signer),
          successorValidFrom: new Date(current).toISOString(),
          successorValidUntil: new Date(current + periodMs).toISOString(),
          validFrom: new Date(current).toISOString(),
          validUntil: new Date(current + periodMs).toISOString(),
          assurance: 'LOCAL_QA_VIRTUAL_AUTHENTICATOR',
        });
        const signed = {
          document,
          signature: sign('sha256', localRootExpiryRecoveryCustodyPreimage(document), {
            key: custody.privateKey,
            dsaEncoding: 'ieee-p1363',
          }).toString('base64url'),
        };
        await writeFile(
          join(directory, 'private', `enrollment-${document.enrollmentId}.json`),
          JSON.stringify(signed, null, 2) + '\n',
          { mode: 0o600, flag: 'wx' },
        );
        return signed;
      };
      const assertFresh = async (
        document: Awaited<ReturnType<typeof signedEnrollment>>['document'],
      ) => {
        const now = Number((await clock()) / 1000000n);
        expect(now - Date.parse(document.successorValidFrom)).toBeLessThanOrEqual(30000);
        expect(now).toBeGreaterThanOrEqual(Date.parse(document.validFrom));
        expect(now).toBeLessThan(Date.parse(document.validUntil));
        expect(now).toBeLessThan(trustUntil);
      };
      const acceptedInitialEnrollments = new Map<string, string>();
      for (const negative of negatives) {
        const signed = await signedEnrollment(negative.principalId);
        await assertFresh(signed.document);
        if (negative.forbidden) {
          await expect(
            installPlatformRecoveryEnrollment(receiving, signed, { localQaEnabled: true }),
          ).rejects.toThrow();
          await assertFresh(signed.document);
          expect(
            (
              await admin.query(
                'select count(*) from control.root_expiry_recovery_enrollment where enrollment_id=$1',
                [signed.document.enrollmentId],
              )
            ).rows[0].count,
          ).toBe('0');
        } else {
          expect(
            await installPlatformRecoveryEnrollment(receiving, signed, { localQaEnabled: true }),
          ).toMatchObject({ state: 'ENROLLED', authority: 'NONE' });
          acceptedInitialEnrollments.set(negative.principalId, signed.document.enrollmentId);
        }
      }
      const signed = await signedEnrollment(executor);
      expect(
        await installPlatformRecoveryEnrollment(receiving, signed, { localQaEnabled: true }),
      ).toMatchObject({ state: 'ENROLLED', authority: 'NONE' });
      const enrollmentId = signed.document.enrollmentId;
      await writeFile(
        join(directory, 'custody.json'),
        JSON.stringify({ trust, signed }, null, 2) + '\n',
        { mode: 0o600, flag: 'wx' },
      );
      const runner = actors.get(executor)!,
        first = actors.get(custodians[0])!,
        second = actors.get(custodians[1])!;
      const denialState = async () =>
        (
          await admin.query(
            `select jsonb_build_object(
      'root',(select to_jsonb(p) from control.platform_context p where platform_context_id=$1),
      'cases',(select coalesce(jsonb_agg(to_jsonb(c) order by recovery_id),'[]'::jsonb) from control.root_expiry_recovery_case c where participant_id=$2),
      'proofs',(select count(*) from control.root_expiry_recovery_proof where participant_id=$2),
      'challenges',(select coalesce(jsonb_agg(to_jsonb(h) order by challenge_id),'[]'::jsonb) from control.root_expiry_recovery_challenge h where participant_id=$2),
      'counters',(select jsonb_agg(jsonb_build_array(credential_id,authenticator_sign_count) order by credential_id) from control.credential where participant_id=$2 and kind='WEBAUTHN')) state`,
            [platformContextId, participantId],
          )
        ).rows[0].state;
      const denied = async (
        actor: RootRecoveryActor,
        command: Parameters<typeof client.command>[2],
        privacy = privacyDomainId,
      ) => {
        const before = await denialState();
        expect((await client.command(actor, enrollmentId, command, privacy)).status).toBe(403);
        expect(await denialState()).toEqual(before);
      };
      await denied(first, { kind: 'CREATE' });
      // Treat CREATE as an ambiguous response: discover the original case instead
      // of issuing another CREATE with a new recovery identity.
      await writeFile(
        join(directory, 'private', `create-${enrollmentId}.json`),
        JSON.stringify({ enrollmentId, command: { kind: 'CREATE' }, actor: runner.principalId }) +
          '\n',
        { mode: 0o600, flag: 'wx' },
      );
      expect((await client.command(runner, enrollmentId, { kind: 'CREATE' })).status).toBe(201);
      const source = await client.command(runner, enrollmentId, { kind: 'SOURCE' });
      expect(source.status).toBe(200);
      const recoveryId = z
        .object({ liveCase: z.object({ recoveryId: z.uuidv7() }) })
        .parse(source.body).liveCase.recoveryId;
      const optimizerPool = new Pool({ connectionString: runtimeUrl, max: 1 });
      const optimizerClient = await optimizerPool.connect();
      try {
        expect((await optimizerClient.query('show jit')).rows).toEqual([{ jit: 'on' }]);
        const metadata = (
          await optimizerClient.query(`select p.prosecdef,p.proconfig,r.rolname owner
            from pg_proc p join pg_roles r on r.oid=p.proowner
            where p.oid='openpc.root_expiry_recovery_proofs_current(control.root_expiry_recovery_case,uuid)'::regprocedure`)
        ).rows[0];
        expect(metadata).toMatchObject({ prosecdef: true, owner: 'openpc_control_owner' });
        expect(metadata.proconfig).toEqual(expect.arrayContaining(['row_security=on', 'jit=off']));
        await optimizerClient.query('begin read only');
        await optimizerClient.query(
          "set local row_security=on; set local jit=on; set local openpc.local_qa_runtime='1'",
        );
        await optimizerClient.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',true)",
          [participantId, privacyDomainId, recoveryId],
        );
        expect(
          (
            await optimizerClient.query(
              'select openpc.root_expiry_recovery_source_current($1) as "current"',
              [enrollmentId],
            )
          ).rows,
        ).toEqual([{ current: true }]);
        // A draft has no complete proof set. This denial must restore the caller's optimizer setting.
        expect(
          (
            await optimizerClient.query(
              `select openpc.root_expiry_recovery_proofs_current(c,null::uuid) permitted
                from control.root_expiry_recovery_case c where recovery_id=$1`,
              [recoveryId],
            )
          ).rows,
        ).toEqual([{ permitted: false }]);
        expect((await optimizerClient.query('show jit')).rows).toEqual([{ jit: 'on' }]);
        await optimizerClient.query('rollback');
      } finally {
        optimizerClient.release();
        await optimizerPool.end();
      }
      await denied(runner, { kind: 'SOURCE' }, otherPrivacy);
      await denied(runner, { kind: 'CHALLENGE', recoveryId, phase: 'ACTIVATE' });
      const consume = async (
        actor: RootRecoveryActor,
        phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE',
      ) => {
        const challenge = await client.challenge(actor, enrollmentId, recoveryId, phase);
        const proof = client.proof(actor, recoveryId, phase, challenge);
        if (proof.kind !== 'PROVE') throw new Error('Expected an exact authenticator proof');
        await writeFile(
          join(directory, 'private', `proof-${challenge.challengeId}.json`),
          JSON.stringify({ enrollmentId, actor: actor.principalId, command: proof }, null, 2) +
            '\n',
          { mode: 0o600, flag: 'wx' },
        );
        if (phase === 'REQUEST') {
          const assertion = z
            .record(z.string(), z.unknown())
            .parse(JSON.parse(proof.proof.assertion));
          const signature = Buffer.from(z.string().parse(assertion.signature), 'base64url');
          signature[signature.length - 1] = signature[signature.length - 1]! ^ 1;
          const invalid = {
            ...proof,
            proof: {
              ...proof.proof,
              assertion: JSON.stringify({
                ...assertion,
                signature: signature.toString('base64url'),
              }),
            },
          };
          await writeFile(
            join(directory, 'private', `invalid-proof-${challenge.challengeId}.json`),
            JSON.stringify({ enrollmentId, actor: actor.principalId, command: invalid }, null, 2) +
              '\n',
            { mode: 0o600, flag: 'wx' },
          );
          await denied(actor, invalid);
        }
        const result = await client.command(actor, enrollmentId, proof);
        expect(result.status).toBe(200);
        expect(await client.command(actor, enrollmentId, proof)).toEqual(result);
        return result;
      };
      await consume(runner, 'REQUEST');
      await consume(first, 'APPROVE');
      await denied(runner, { kind: 'CHALLENGE', recoveryId, phase: 'ACTIVATE' });
      await consume(second, 'APPROVE');
      const completed = await consume(runner, 'ACTIVATE');
      expect(completed.body).toMatchObject({
        state: 'COMPLETED',
        authority: 'NONE',
        result: { rootEpoch: '2', rootRevision: '2' },
      });
      const read = await client.command(runner, enrollmentId, { kind: 'READ', recoveryId });
      expect(read).toEqual(completed);
      const receipt = (
        await admin.query('select * from control.root_expiry_recovery_case where recovery_id=$1', [
          recoveryId,
        ])
      ).rows[0];
      expect(
        (
          await admin.query(
            'select authority_epoch::text epoch,row_version::text revision from control.platform_context where platform_context_id=$1',
            [platformContextId],
          )
        ).rows,
      ).toEqual([{ epoch: '2', revision: '2' }]);
      expect(
        (
          await admin.query(
            'select count(*) from control.root_expiry_recovery_challenge where recovery_id=$1 and consumed_at is not null',
            [recoveryId],
          )
        ).rows[0].count,
      ).toBe('4');
      expect(
        (
          await admin.query(
            "select count(*) from control.outbox_event where participant_id=$1 and aggregate_type='local-root-expiry-recovery' and aggregate_id=$2",
            [participantId, recoveryId],
          )
        ).rows[0].count,
      ).toBe('1');
      for (const principalId of signers)
        expect(
          (
            await admin.query(
              'select authenticator_sign_count::integer count from control.credential where credential_id=$1',
              [keys.get(principalId)!.credentialId],
            )
          ).rows,
        ).toEqual([{ count: actors.get(principalId)?.counter ?? 1 }]);
      const verifier = createLocalIdentityRuntimeVerifier([
        await readFile(join(service.directory, 'public.der')),
      ]);
      expect(
        await verifier.verifyCanonicalAssertion(receipt.evidence_cbor, receipt.evidence_cose),
      ).toBeDefined();
      expect(sha(receipt.evidence_cbor)).toEqual(receipt.evidence_digest);
      const corrupted = Buffer.from(receipt.evidence_cbor);
      corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1]! ^ 1;
      expect(
        await verifier.verifyCanonicalAssertion(corrupted, receipt.evidence_cose),
      ).toBeUndefined();
      const selected = (
        await admin.query(
          'select scope_cbor from control.root_expiry_recovery_scope where recovery_id=$1',
          [recoveryId],
        )
      ).rows[0];
      const successor = decodeEnvelopeScope(selected.scope_cbor);
      expect({
        ...successor,
        validFromNs: grantable.validFromNs,
        validUntilNs: grantable.validUntilNs,
      }).toEqual(grantable);
      expect(selected.scope_cbor).toEqual(
        encodeEnvelopeScope({
          ...grantable,
          validFromNs: (
            BigInt(Date.parse(signed.document.successorValidFrom)) * 1000000n
          ).toString(),
          validUntilNs: (
            BigInt(Date.parse(signed.document.successorValidUntil)) * 1000000n
          ).toString(),
        }),
      );
      expect(
        (
          await admin.query(
            'select count(*) from control.root_expiry_recovery_proof where recovery_id=$1',
            [recoveryId],
          )
        ).rows[0].count,
      ).toBe('4');
      expect(await baseline()).toEqual(original);
      const expiredFixture = negatives.find((v) => v.label === 'expired finite')!;
      const staleActor = await client.login(provider, expiredFixture.principalId);
      const staleEnrollmentId = acceptedInitialEnrollments.get(expiredFixture.principalId)!;
      const staleWindow = async () => {
        const selected = await admin.query(
          `select clock_timestamp() now,e.valid_from "validFrom",e.valid_until "validUntil",
            (e.document->>'successorValidFrom')::timestamptz "successorFrom",
            (e.document->>'successorValidUntil')::timestamptz "successorUntil",
            t.valid_from "trustFrom",t.valid_until "trustUntil",
            e.document->>'rootEpoch' "sourceEpoch",p.authority_epoch::text "currentEpoch"
            from control.root_expiry_recovery_enrollment e
            join control.root_expiry_recovery_trust t on t.custody_trust_id=e.custody_trust_id
              and t.participant_id=e.participant_id and t.privacy_domain_id=e.privacy_domain_id
            join control.platform_context p on p.platform_context_id=e.platform_context_id
              and p.owner_participant_id=e.participant_id
            where e.participant_id=$1 and e.enrollment_id=$2`,
          [participantId, staleEnrollmentId],
        );
        expect(selected.rowCount).toBe(1);
        const window = z
          .object({
            now: z.date(),
            validFrom: z.date(),
            validUntil: z.date(),
            successorFrom: z.date(),
            successorUntil: z.date(),
            trustFrom: z.date(),
            trustUntil: z.date(),
            sourceEpoch: z.literal('1'),
            currentEpoch: z.literal('2'),
          })
          .parse(selected.rows[0]);
        for (const start of [window.validFrom, window.successorFrom, window.trustFrom])
          expect(window.now.getTime()).toBeGreaterThanOrEqual(start.getTime());
        for (const end of [window.validUntil, window.successorUntil, window.trustUntil])
          expect(window.now.getTime()).toBeLessThan(end.getTime());
        expect(window.now.getTime()).toBeLessThan(Date.parse(signed.document.successorValidUntil));
        return window;
      };
      const staleBefore = await denialState();
      const staleWindowBefore = await staleWindow();
      const staleResult = await client.command(staleActor, staleEnrollmentId, { kind: 'SOURCE' });
      expect(staleResult.status).toBe(403);
      const staleWindowAfter = await staleWindow();
      expect(await denialState()).toEqual(staleBefore);
      process.stdout.write(
        JSON.stringify({
          boundary: 'finite_root_recovery_stale_source',
          before: staleWindowBefore,
          after: staleWindowAfter,
          currentRootValidUntil: signed.document.successorValidUntil,
          status: staleResult.status,
        }) + '\n',
      );
      await service.restartIdentity();
      expect(await client.command(runner, enrollmentId, { kind: 'READ', recoveryId })).toEqual(
        read,
      );
      expect(await baseline()).toEqual(original);
      await writeFile(
        join(directory, 'completed.json'),
        JSON.stringify(
          {
            read: read.body,
            evidenceDigest: receipt.evidence_digest.toString('hex'),
            allFiveOidcLogins: true,
            authenticatorEnrollmentQualified: false,
          },
          null,
          2,
        ) + '\n',
        { mode: 0o600, flag: 'wx' },
      );
      await service.stopIdentity();
      await end(installer);
      await end(receiving);
      await end(admin);
      await execute('docker', ['restart', target.id], { timeout: 60000, maxBuffer: 4096 });
      await execute(
        'docker',
        [
          'exec',
          target.id,
          'sh',
          '-c',
          'for n in $(seq 1 60); do pg_isready -h 127.0.0.1 -U postgres -d openpc_control >/dev/null 2>&1 && exit 0; sleep 0.1; done; exit 1',
        ],
        { timeout: 15000, maxBuffer: 4096 },
      );
      const published = (
        await execute('docker', ['port', target.id, '5432/tcp'], {
          timeout: 10000,
          maxBuffer: 4096,
        })
      ).stdout.trim();
      const port = /^127\.0\.0\.1:([0-9]+)$/u.exec(published)?.[1];
      expect(port).toBeDefined();
      const restarted = new URL(adminUrl!);
      restarted.port = port!;
      admin = new Pool({ connectionString: restarted.href, max: 1 });
      expect(await baseline()).toEqual(original);
      expect(
        (
          await admin.query(
            'select result,evidence_digest from control.root_expiry_recovery_case where recovery_id=$1',
            [recoveryId],
          )
        ).rows[0],
      ).toEqual({ result: receipt.result, evidence_digest: receipt.evidence_digest });
      await service.restartIdentity(Number(port));
      expect(await client.command(runner, enrollmentId, { kind: 'READ', recoveryId })).toEqual(
        read,
      );
    } finally {
      await service?.close();
      await provider.close();
      await Promise.all([
        end(admin),
        end(installer),
        end(receiving),
        ...(participantRuntime ? [end(participantRuntime)] : []),
      ]);
    }
  },
  // Includes real expiry, independent denial cases and retained-state restarts.
  // Enrollment, successor, proof and HTTP deadlines remain independently enforced.
  420000,
);
