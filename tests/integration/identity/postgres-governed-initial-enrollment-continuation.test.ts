import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { governedInitialEnrollmentProfileSchema } from '../../../services/identity-service/src/domain/governed-initial-enrollment.js';
import { oidcProviderFixture } from './oidc-provider-fixture.js';
import { publicGovernanceClient } from './public-governance-client.js';
import { retainedGovernedEnrollmentRuntime } from './governed-initial-enrollment-retained-runtime.js';
import { qualifyGovernedEnrollment } from './governed-initial-enrollment-fixture.js';
import { closeFixtureResources } from './close-fixture-resources.js';

const directory = process.env.OPENPC_GOVERNED_ENROLLMENT_RETAINED_DIRECTORY;
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const retained = directory && adminUrl && runtimeUrl ? it : it.skip;
retained(
  'continues the original governed enrollment fixture without replacing its signer, identities or completed result',
  async () => {
    const admin = new Pool({ connectionString: adminUrl });
    let provider: Awaited<ReturnType<typeof oidcProviderFixture>> | undefined;
    let service: Awaited<ReturnType<typeof retainedGovernedEnrollmentRuntime>> | undefined;
    let failure: { error: unknown } | undefined;
    try {
      const profile = governedInitialEnrollmentProfileSchema.parse(
        JSON.parse(await readFile(join(directory!, 'initial-enrollment.json'), 'utf8')),
      );
      const account = profile.accounts[0]!,
        issuer = new URL(account.issuer);
      expect(issuer.hostname).toBe('127.0.0.1');
      expect(issuer.protocol).toBe('http:');
      const original = (
        await admin.query(`select operation_id,principal_id,enrollment_id,credential_id,document_digest,evidence_digest,cose_sign1
      from control.governed_initial_enrollment_result order by operation_id`)
      ).rows;
      const expectedCompleted = Number(
        process.env.OPENPC_GOVERNED_ENROLLMENT_EXPECTED_COMPLETED ?? '1',
      );
      expect([1, 2]).toContain(expectedCompleted);
      expect(original).toHaveLength(expectedCompleted);
      const retainedCompletedPrincipalIds = new Set(
        profile.accounts.slice(0, expectedCompleted).map((value) => value.principalId),
      );
      expect(original.map((row) => row.principal_id)).toEqual([...retainedCompletedPrincipalIds]);
      const credentials = (
        await admin.query(`select principal_id,credential_id from control.credential
      where principal_id in ('018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000112') and kind='WEBAUTHN' order by principal_id`)
      ).rows;
      expect(credentials).toHaveLength(2);
      const originalCredentialIds = new Map<string, string>(
        credentials.map((row) => [row.principal_id, row.credential_id]),
      );
      const maker = (
        await admin.query(
          "select session_id from control.session where principal_id='018f0000-0000-7000-8000-000000000111' order by issued_at limit 1",
        )
      ).rows[0];
      expect(maker).toBeDefined();
      const activeProvider = await oidcProviderFixture(
        account.participantId,
        account.principalId,
        account.subject,
        { membershipHints: false, listenPort: Number(issuer.port) },
      );
      provider = activeProvider;
      expect(activeProvider.issuer).toBe(account.issuer);
      const activeService = await retainedGovernedEnrollmentRuntime(directory!, runtimeUrl!);
      service = activeService;
      const client = await publicGovernanceClient({
        admin,
        identityUrl: activeService.identityUrl,
        policyUrl: 'http://127.0.0.1:1',
        participantId: account.participantId,
        privacyDomainId: account.privacyDomainId,
        devices: new Map(),
      });
      const codeFor = async (authorization: {
        state: string;
        nonce: string;
        codeChallenge: string;
      }) => {
        const url = new URL(`${activeProvider.issuer}/authorize`);
        url.search = new URLSearchParams({
          client_id: account.audience,
          redirect_uri: `${profile.origin}/callback`,
          response_type: 'code',
          scope: 'openid',
          state: authorization.state,
          nonce: authorization.nonce,
          code_challenge: authorization.codeChallenge,
          code_challenge_method: 'S256',
        }).toString();
        const response = await fetch(url, { redirect: 'manual' });
        expect(response.status).toBe(302);
        return new URL(response.headers.get('location')!).searchParams.get('code')!;
      };
      await qualifyGovernedEnrollment({
        admin,
        activeService,
        activeProvider,
        profile,
        client,
        codeFor,
        makerProbeSessionId: maker.session_id,
        originalCredentialIds,
        resume: true,
        retainedCompletedPrincipalIds,
      });
      expect(
        (
          await admin.query(
            'select operation_id,principal_id,enrollment_id,credential_id,document_digest,evidence_digest,cose_sign1 from control.governed_initial_enrollment_result where operation_id=any($1::uuid[]) order by operation_id',
            [original.map((row) => row.operation_id)],
          )
        ).rows,
      ).toEqual(original);
    } catch (error) {
      failure = { error };
      throw error;
    } finally {
      await closeFixtureResources(
        [
          async () => {
            await service?.close();
          },
          async () => {
            await provider?.close();
          },
          async () => {
            await admin.end();
          },
        ],
        failure,
      );
    }
  },
  180000,
);
