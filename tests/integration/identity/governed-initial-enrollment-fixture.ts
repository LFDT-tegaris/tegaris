import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect } from 'vitest';
import { canonicalAuthorizationDigestBytes } from '../../../services/identity-service/src/contracts/authorization.js';
import type { GovernedInitialEnrollmentProfile } from '../../../services/identity-service/src/domain/governed-initial-enrollment.js';
import { createLocalIdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import { readGovernedInitialEnrollmentResult } from '../../../services/identity-service/src/db/governed-initial-enrollment-result.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  createHardwareAuthenticatorEmulator,
  createUnattestedTestRegistration,
} from './hardware-authenticator.js';
import { publicGovernanceClient } from './public-governance-client.js';
import type { participantReadbackRuntime } from './participant-readback-runtime.js';
import type { oidcProviderFixture } from './oidc-provider-fixture.js';
const participantId = '018f0000-0000-7000-8000-000000000101',
  privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const makerId = '018f0000-0000-7000-8000-000000000111',
  checkerId = '018f0000-0000-7000-8000-000000000112';
const origin = 'https://enrollment.example.test',
  stepUp = 'ACT-IDENTITY_UPDATE_STEP_UP-V1';
export interface EnrollmentFixtureRuntime {
  identityUrl: string;
  directory: string;
  identityInternalToken: string;
  restartIdentity: Awaited<ReturnType<typeof participantReadbackRuntime>>['restartIdentity'];
}
/** Shared connected suffix: a retained run must use the original database,
 * Identity keys, governed profile and existing completed result. */
export async function qualifyGovernedEnrollment(input: {
  admin: Pool;
  activeService: EnrollmentFixtureRuntime;
  activeProvider: Awaited<ReturnType<typeof oidcProviderFixture>>;
  profile: GovernedInitialEnrollmentProfile;
  client: Awaited<ReturnType<typeof publicGovernanceClient>>;
  codeFor: (authorization: {
    state: string;
    nonce: string;
    codeChallenge: string;
  }) => Promise<string>;
  hardware?: ReturnType<typeof createHardwareAuthenticatorEmulator>;
  makerProbeSessionId: string;
  originalCredentialIds: ReadonlyMap<string, string>;
  resume?: boolean;
  retainedCompletedPrincipalIds?: ReadonlySet<string>;
}) {
  const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
  if (!runtimeUrl) throw new Error('Real runtime database required');
  const { admin, activeService, activeProvider, profile, client, codeFor } = input;
  const accounts = profile.accounts,
    profileDigest = canonicalAuthorizationDigestBytes(profile);
  const verifier = createLocalIdentityRuntimeVerifier([
    await readFile(join(activeService.directory, 'public.der')),
  ]);
  const savedReceipts = [];
  const savedSessions = new Map<string, string>();
  for (const [n, account] of accounts.entries()) {
    activeProvider.setSubject(account.subject);
    const begin = await fetch(`${activeService.identityUrl}/v1/identity/oidc/begin`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ participantId }),
    });
    expect(begin.status).toBe(200);
    const started = await begin.json();
    const login = await fetch(`${activeService.identityUrl}/v1/identity/oidc/callback`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cookie': begin.headers.get('set-cookie')!.split(';')[0]!,
      },
      body: JSON.stringify({
        transactionId: started.transactionId,
        state: started.state,
        authorizationCode: await codeFor(started),
      }),
    });
    expect(login.status, JSON.stringify(await login.clone().json())).toBe(201);
    const sessionToken = login.headers
      .get('set-cookie')!
      .split(';')[0]!
      .split('=')
      .slice(1)
      .join('=');
    const actor = {
      principalId: account.principalId,
      sessionId: sessionToken.split('.')[1]!,
      sessionToken,
    };
    savedSessions.set(account.principalId, sessionToken);
    if (input.resume) {
      const completed = await admin.query(
        'select enrollment_id::text from control.governed_initial_enrollment_result where participant_id=$1 and principal_id=$2',
        [participantId, account.principalId],
      );
      if (completed.rowCount) {
        expect(completed.rowCount).toBe(1);
        expect(input.retainedCompletedPrincipalIds?.has(account.principalId)).toBe(true);
        const stored = await admin.connect();
        try {
          const receipt = await readGovernedInitialEnrollmentResult(
            stored,
            participantId,
            account.principalId,
            completed.rows[0].enrollment_id,
            verifier,
          );
          expect(receipt.account).toEqual(account);
          savedReceipts.push(receipt);
        } finally {
          stored.release();
        }
        continue;
      }
    }
    const enroll = async (path: string, body: unknown) =>
      client.request(
        `${activeService.identityUrl}/v1/identity/webauthn/initial-registration/${path}`,
        actor,
        body,
        {
          'X-CSRF-Token': await client.csrf(actor, stepUp, activeService.identityUrl),
          'Authorization': `Bearer ${activeService.identityInternalToken}`,
          'X-OpenPC-Browser-Origin': origin,
        },
      );
    if (n === 0)
      expect((await enroll('options', { hardwareAttestation: false })).status).not.toBe(201);
    const options = await enroll('options', { hardwareAttestation: n === 0 });
    expect(options.status, JSON.stringify(options.body)).toBe(201);
    if (n === 1) {
      const probe = new Pool({ connectionString: runtimeUrl });
      const c = await probe.connect();
      try {
        await c.query('begin');
        await c.query('set local role openpc_control_runtime');
        await c.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-IDENTITY_UPDATE_STEP_UP-V1',true)",
          [participantId, privacyDomainId, id()],
        );
        await c.query("select set_config('openpc.local_qa_runtime','1',true)");
        for (const [name, value] of Object.entries({
          'openpc.initial_enrollment_session_id': actor.sessionId,
          'openpc.initial_enrollment_principal_id': account.principalId,
          'openpc.initial_enrollment_profile_digest': `sha256:${profileDigest.toString('hex')}`,
          'openpc.initial_enrollment_id': String(options.body.enrollmentId),
        }))
          await c.query('select set_config($1,$2,true)', [name, value]);
        expect(
          (
            await c.query(
              'select profile_digest from control.governed_initial_enrollment_profile where profile_digest=$1 for share',
              [profileDigest],
            )
          ).rowCount,
        ).toBe(1);
        expect((await c.query('select 1 from control.authentication_occurrence')).rowCount).toBe(1);
        await c.query("select set_config('openpc.local_qa_runtime','0',true)");
        expect((await c.query('select 1 from control.authentication_occurrence')).rowCount).toBe(0);
        await c.query(
          "select set_config('openpc.local_qa_runtime','1',true),set_config('openpc.initial_enrollment_profile_digest',$1,true)",
          [`sha256:${'0'.repeat(64)}`],
        );
        expect((await c.query('select 1 from control.authentication_occurrence')).rowCount).toBe(0);
        await expect(
          c.query(
            'update control.governed_initial_enrollment_profile set created_at=created_at where profile_digest=$1',
            [profileDigest],
          ),
        ).rejects.toThrow();
        await c.query('rollback');
      } finally {
        c.release();
        await probe.end();
      }
    }
    const publicKey = options.body.publicKey as { challenge: string };
    const response = createUnattestedTestRegistration(
      Buffer.from(publicKey.challenge, 'base64url').toString(),
      origin,
      new URL(origin).hostname,
    );
    if (n === 0)
      expect(
        (await enroll('complete', { enrollmentId: options.body.enrollmentId, response })).status,
      ).not.toBe(201);
    const complete = {
      enrollmentId: options.body.enrollmentId,
      response: n === 0 ? input.hardware!.attest(response) : response,
    };
    if (n === 1) {
      const challenge = Buffer.from(publicKey.challenge, 'base64url').toString();
      for (const invalid of [
        createUnattestedTestRegistration('different-challenge', origin, new URL(origin).hostname),
        createUnattestedTestRegistration(
          challenge,
          'https://foreign.example.test',
          new URL(origin).hostname,
        ),
        createUnattestedTestRegistration(challenge, origin, 'foreign.example.test'),
        { ...response, response: { ...response.response, attestationObject: 'AA' } },
      ])
        expect(
          (await enroll('complete', { enrollmentId: options.body.enrollmentId, response: invalid }))
            .status,
        ).not.toBe(201);
      expect(
        (
          await admin.query(
            "select 1 from control.credential where participant_id=$1 and principal_id=$2 and kind='WEBAUTHN'",
            [participantId, account.principalId],
          )
        ).rowCount,
      ).toBe(0);
    }
    if (n === 2) {
      // A nontransactional fault counter proves the completion reached the
      // injected database failure; no business state is seeded or admitted.
      const existing = (
        await admin.query(
          "select to_regclass('openpc.test_initial_enrollment_fault_calls') is not null present",
        )
      ).rows[0].present;
      let previousCalls = 0;
      if (existing) {
        expect(input.resume).toBe(true);
        const owner = (
          await admin.query(
            "select prosrc,pg_get_userbyid(proowner) owner from pg_proc where oid='openpc.test_initial_enrollment_failure()'::regprocedure",
          )
        ).rows[0];
        expect(owner.owner).toBe('postgres');
        expect(owner.prosrc.replace(/\s+/gu, ' ').trim()).toBe(
          "begin perform nextval('openpc.test_initial_enrollment_fault_calls'); raise exception 'TEST-INITIAL-ENROLLMENT-COMMIT-FAULT';end",
        );
        const trigger = (
          await admin.query(
            "select pg_get_triggerdef(oid) definition from pg_trigger where tgname='test_initial_enrollment_failure' and tgrelid='control.governed_initial_enrollment_result'::regclass",
          )
        ).rows;
        expect(trigger).toEqual([
          {
            definition:
              'CREATE TRIGGER test_initial_enrollment_failure BEFORE INSERT ON control.governed_initial_enrollment_result FOR EACH ROW EXECUTE FUNCTION openpc.test_initial_enrollment_failure()',
          },
        ]);
        expect(
          (
            await admin.query(
              'select last_value::text,is_called from openpc.test_initial_enrollment_fault_calls',
            )
          ).rows[0],
        ).toMatchObject({ last_value: '1', is_called: true });
        previousCalls = 1;
      } else {
        await admin.query(`create sequence openpc.test_initial_enrollment_fault_calls;
          create function openpc.test_initial_enrollment_failure() returns trigger language plpgsql as $$
          begin perform nextval('openpc.test_initial_enrollment_fault_calls');
          raise exception 'TEST-INITIAL-ENROLLMENT-COMMIT-FAULT';end $$;
          create trigger test_initial_enrollment_failure before insert on control.governed_initial_enrollment_result
          for each row execute function openpc.test_initial_enrollment_failure()`);
      }
      await admin.query(
        'grant usage,select on sequence openpc.test_initial_enrollment_fault_calls to openpc_control_runtime,openpc_control_platform_runtime',
      );
      const failed = await enroll('complete', complete);
      expect(failed).toMatchObject({ status: 403, body: { error: { code: 'PC-IDENTITY-1004' } } });
      expect(
        (
          await admin.query(
            'select last_value::text,is_called from openpc.test_initial_enrollment_fault_calls',
          )
        ).rows[0],
      ).toMatchObject({ last_value: String(previousCalls + 1), is_called: true });
      expect(
        (
          await admin.query(
            "select 1 from control.credential where participant_id=$1 and principal_id=$2 and kind='WEBAUTHN'",
            [participantId, account.principalId],
          )
        ).rowCount,
      ).toBe(0);
      expect(
        (
          await admin.query(
            'select consumed_at,credential_id,attestation_digest from control.webauthn_enrollment where enrollment_id=$1',
            [options.body.enrollmentId],
          )
        ).rows[0],
      ).toMatchObject({ consumed_at: null, credential_id: null, attestation_digest: null });
      expect(
        (
          await admin.query(
            'select 1 from control.governed_initial_enrollment_result where enrollment_id=$1',
            [options.body.enrollmentId],
          )
        ).rowCount,
      ).toBe(0);
      expect(
        (
          await admin.query(
            "select count(*)::int n from control.outbox_event where event_type='openpc.identity.webauthn.governed-initial-enrollment.completed.v1'",
          )
        ).rows[0].n,
      ).toBe(2);
      expect(
        (
          await admin.query(
            'select step_up_verified_at from control.session where participant_id=$1 and session_id=$2',
            [participantId, actor.sessionId],
          )
        ).rows[0].step_up_verified_at,
      ).toBeNull();
      await admin.query(`drop trigger test_initial_enrollment_failure on control.governed_initial_enrollment_result;
          drop function openpc.test_initial_enrollment_failure();drop sequence openpc.test_initial_enrollment_fault_calls`);
    }

    const outcomes = await Promise.all(
      n === 1
        ? [enroll('complete', complete), enroll('complete', complete)]
        : [enroll('complete', complete)],
    );
    expect(outcomes.filter((x) => x.status === 201)).toHaveLength(1);
    expect((await enroll('complete', complete)).status).not.toBe(201);
    expect((await enroll('options', { hardwareAttestation: n === 0 })).status).not.toBe(201);
    const stored = await admin.connect();
    try {
      const receipt = await readGovernedInitialEnrollmentResult(
        stored,
        participantId,
        account.principalId,
        String(options.body.enrollmentId),
        verifier,
      );
      expect(receipt.permissionEffect).toBe('NONE');
      expect(receipt.account).toEqual(account);
      savedReceipts.push(receipt);
    } finally {
      stored.release();
    }
    expect(
      (
        await admin.query(
          'select 1 from control.assignment where participant_id=$1 and principal_id=$2',
          [participantId, account.principalId],
        )
      ).rowCount,
    ).toBe(0);
    expect(
      (
        await fetch(`${activeService.identityUrl}/v1/identity/principals`, {
          headers: {
            'cookie': `__Host-openpc_session=${actor.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          },
        })
      ).status,
    ).not.toBe(200);
  }
  await activeService.restartIdentity();
  for (const expected of savedReceipts) {
    const actual = await fetch(
      `${activeService.identityUrl}/v1/identity/webauthn/enrollments/${expected.enrollmentId}`,
      {
        headers: {
          cookie: `__Host-openpc_session=${savedSessions.get(expected.account.principalId)!}`,
        },
      },
    );
    expect(actual.status, JSON.stringify(await actual.clone().json())).toBe(200);
    expect(await actual.json()).toMatchObject({
      enrollmentId: expected.enrollmentId,
      state: 'COMPLETED',
      credential: { credentialId: expected.authenticatorCredentialId, active: true },
    });
    const stored = await admin.connect();
    try {
      expect(
        await readGovernedInitialEnrollmentResult(
          stored,
          participantId,
          expected.account.principalId,
          expected.enrollmentId,
          verifier,
        ),
      ).toEqual(expected);
    } finally {
      stored.release();
    }
  }
  // Actual runtime SQL privileges cannot create or edit a profile, overwrite
  // the factual result, or read login facts by inventing transaction settings.
  const sql = new Pool({ connectionString: runtimeUrl });
  const connection = await sql.connect();
  try {
    await connection.query('begin');
    await connection.query('set local role openpc_control_runtime');
    await connection.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-IDENTITY_UPDATE_STEP_UP-V1',true)",
      [participantId, privacyDomainId, id()],
    );
    await connection.query("select set_config('openpc.local_qa_runtime','1',true)");
    expect(
      (await connection.query("select current_setting('openpc.local_qa_runtime') value")).rows[0]
        .value,
    ).toBe('1');
    for (const [name, value] of Object.entries({
      'openpc.initial_enrollment_session_id': input.makerProbeSessionId,
      'openpc.initial_enrollment_principal_id': makerId,
      'openpc.initial_enrollment_profile_digest': `sha256:${profileDigest.toString('hex')}`,
      'openpc.initial_enrollment_id': id(),
    }))
      await connection.query('select set_config($1,$2,true)', [name, value]);
    expect(
      (await connection.query('select 1 from control.authentication_occurrence')).rowCount,
    ).toBe(0);
    await connection.query('rollback');
    for (const query of [
      'update control.governed_initial_enrollment_profile set document=document',
      'insert into control.governed_initial_enrollment_profile select * from control.governed_initial_enrollment_profile',
      'update control.governed_initial_enrollment_result set document=document',
    ]) {
      await connection.query('begin');
      await connection.query('set local role openpc_control_runtime');
      await expect(connection.query(query)).rejects.toThrow();
      await connection.query('rollback');
    }
  } finally {
    connection.release();
    await sql.end();
  }
  for (const principalId of [makerId, checkerId])
    expect(
      (
        await admin.query(
          "select credential_id from control.credential where participant_id=$1 and principal_id=$2 and kind='WEBAUTHN'",
          [participantId, principalId],
        )
      ).rows.map((row) => row.credential_id),
    ).toEqual([input.originalCredentialIds.get(principalId)!]);
}
