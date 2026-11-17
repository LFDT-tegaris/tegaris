import { writeFile } from 'node:fs/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import type { CiglSettingsDefinition } from '../../../services/control-api/src/configuration/cigl/settings-contract.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const action = 'ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1';

// UF-CIGL-001 source governance: real authentication, independent approval,
// WebAuthn, atomic persistence/evidence, RLS, replay and restart readback. This
// stages immutable settings, not an effective profile or invocation permission.
integration(
  'stages exact scoped CIGL settings through governed publication and durable readback',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const participantId = id(),
      privacyDomainId = id();
    const fixture = await contractAdministrationFixture(
      admin,
      runtimeUrl!,
      participantId,
      privacyDomainId,
    );
    let other: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    try {
      const definition: CiglSettingsDefinition = {
        schemaVersion: '1.0',
        scope: { kind: 'ALL_CHAINS' },
        mode: 'HYBRID_STRICT',
        enforcement: {
          ethCall: true,
          ethEstimateGas: true,
          prepareWrite: true,
          rawSubmission: true,
          deploymentConstructors: true,
          runtimeTraceForWrites: true,
          reviewedSchemaSubset: true,
          failClosed: true,
          rejectExternalStateOverrides: true,
        },
        traceLimits: { maxDepth: 16, maxFrames: 32, maxResponseBytes: 100_000, timeoutMs: 5000 },
        traceProvider: 'DEBUG_TRACE_CALL',
        readinessScope: 'METHOD',
        schemaFallbackEnabled: false,
        precompileAllowlist: ['0x0000000000000000000000000000000000000001'],
        systemContractAllowlist: [],
        postMine: { enabled: true, freezeOnDivergence: true },
      };
      const prepared = await fixture.prepareCreation('cigl-settings', action, { definition });
      expect((await prepared.commit()).status).toBe(403);
      expect(
        (await admin.query('select count(*)::int n from control.cigl_settings')).rows[0].n,
      ).toBe(0);
      expect(
        (await prepared.commit({ ...prepared.body, definition: { ...definition, mode: 'OFF' } }))
          .status,
      ).toBe(412);
      await prepared.stepUp();
      const committed = await prepared.commit();
      expect(committed.status, JSON.stringify(committed)).toBe(202);
      expect(committed.body).toMatchObject({
        state: 'SUCCEEDED',
        resourceRef: `urn:openpc:resource:${prepared.resourceId}`,
      });
      for (const replay of await Promise.all([prepared.commit(), prepared.commit()]))
        expect(replay).toEqual(committed);
      const path = `cigl-settings/${committed.body.resourceRef}`;
      const read = await fixture.read(path);
      expect(read.status, JSON.stringify(read)).toBe(200);
      expect(read.body).toMatchObject({
        definition,
        definitionDigest: sha256(definition),
        revision: '1',
        state: 'STAGED',
        runtimePermission: 'NONE',
        publicationOperationId: committed.body.operationId,
      });
      for (const table of ['mutation_evidence', 'outbox_event'])
        expect(
          (
            await admin.query(
              `select count(*)::int n from control.${table} where aggregate_id=$1`,
              [prepared.resourceId],
            )
          ).rows[0].n,
        ).toBe(1);
      expect(read.body.configurationArtifactCbor).toMatch(/^0x(?:[0-9a-f]{2})+$/u);
      expect(read.body.configurationArtifactDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
      if (process.env.OPENPC_CIGL_SETTINGS_PUBLICATION_FIXTURE)
        await writeFile(
          process.env.OPENPC_CIGL_SETTINGS_PUBLICATION_FIXTURE,
          JSON.stringify({ participantId, privacyDomainId, source: read.body }),
          { mode: 0o600 },
        );
      await fixture.restartConfiguration();
      const restarted = await fixture.read(path);
      expect(restarted.status).toBe(read.status);
      expect(restarted.body).toEqual(read.body);
      expect(restarted.headers.get('etag')).toBe(read.headers.get('etag'));
      expect(await prepared.commit()).toEqual(committed);

      const chain: CiglSettingsDefinition = {
        ...definition,
        mode: 'OFF',
        scope: {
          kind: 'CHAIN',
          chainId: '18446744073709551615',
          networkId: 'isolated-testnet',
          genesisDigest: sha256('chain'),
        },
      };
      const chainCreated = await fixture.create('cigl-settings', action, { definition: chain });
      expect(
        (await fixture.read(`cigl-settings/${chainCreated.body.resourceRef}`)).body,
      ).toMatchObject({ definition: chain, state: 'STAGED', runtimePermission: 'NONE' });
      const afterChainCreation = await fixture.read(path);
      expect(afterChainCreation.status).toBe(read.status);
      expect(afterChainCreation.body).toEqual(read.body);
      expect(afterChainCreation.headers.get('etag')).toBe(read.headers.get('etag'));

      // A correct document/digest and scoped SQL role cannot manufacture the
      // independent approval, consumed candidate and atomic publication receipt.
      const client = await admin.connect();
      try {
        const forgedId = id(),
          operationId = id();
        await client.query('begin');
        await client.query('set local role openpc_configuration_runtime');
        await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          participantId,
          privacyDomainId,
          operationId,
          action,
        ]);
        await expect(
          (async () => {
            await client.query(
              `insert into control.cigl_settings(cigl_settings_id,participant_id,privacy_domain_id,
          definition,definition_digest,publication_operation_id,publication_authority_digest) values ($1,$2,$3,$4::jsonb,$5,$6,$7)`,
              [
                forgedId,
                participantId,
                privacyDomainId,
                JSON.stringify(definition),
                sha256(definition),
                operationId,
                sha256('forged'),
              ],
            );
            await client.query('commit');
          })(),
        ).rejects.toThrow();
        await client.query('rollback');
        await client.query('begin');
        await client.query('set local role openpc_configuration_runtime');
        await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          participantId,
          privacyDomainId,
          id(),
          action,
        ]);
        await expect(
          client.query(
            'update control.cigl_settings set definition=$2::jsonb where cigl_settings_id=$1',
            [prepared.resourceId, JSON.stringify(chain)],
          ),
        ).rejects.toThrow();
        await client.query('rollback');
        await client.query('begin');
        await client.query('set local role openpc_configuration_runtime');
        await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          participantId,
          id(),
          id(),
          action,
        ]);
        expect((await client.query('select 1 from control.cigl_settings')).rowCount).toBe(0);
        await client.query('rollback');
      } finally {
        await client.query('rollback');
        client.release();
      }
      other = await contractAdministrationFixture(admin, runtimeUrl!, id(), id());
      expect((await other.read(path)).status).toBe(403);
      expect(
        (await admin.query('select count(*)::int n from control.cigl_settings')).rows[0].n,
      ).toBe(2);
    } finally {
      await other?.close();
      await fixture.close();
      await admin.end();
    }
  },
  120_000,
);
