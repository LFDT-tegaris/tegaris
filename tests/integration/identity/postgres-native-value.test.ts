import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { nativeValueCore } from '../../../services/control-api/src/configuration/native-value/core.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
import { assertNativeValueAuthorityLocks } from './native-value-lock-fixture.js';
import { sha } from './public-governance-client.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const action = 'ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1';

// NATIVE-CONTRACT-001, DCC-074..081: this slice proves independent Native Value
// issuance, never an endowment or a consumed grant. Initial Participant trust is
// the only bootstrap; wallet association and grant approval use real HTTP owners.
integration(
  'issues exact Native Value authority with independent approval and durable scoped readback',
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
      const wallet = await fixture.createWalletBinding('92870', `0x${'21'.repeat(20)}`);
      const fields = {
        walletBindingId: `urn:openpc:resource:${wallet.walletBindingId}`,
        chainId: '92870',
        networkId: 'devnet',
        genesisDigest: sha256('controlled local native value chain'),
        amountMode: 'EXACT',
        maxAmountWei: '1000000000000000',
        validUntil: new Date(Date.now() + 240_000).toISOString(),
      };
      const prepared = await fixture.prepareCreation('native-value-authorizations', action, fields);
      expect((await prepared.commit()).status).toBe(403);
      expect(
        (await admin.query('select count(*)::int n from control.native_value_authorization'))
          .rows[0].n,
      ).toBe(0);
      expect(
        (await prepared.commit({ ...prepared.body, maxAmountWei: '2000000000000000' })).status,
      ).toBe(412);
      await prepared.stepUp();
      const committed = await prepared.commit();
      expect(committed.status, JSON.stringify(committed)).toBe(202);
      expect(committed.body).toMatchObject({
        state: 'SUCCEEDED',
        resourceRef: `urn:openpc:resource:${prepared.resourceId}`,
      });
      const duplicates = await Promise.all([prepared.commit(), prepared.commit()]);
      for (const duplicate of duplicates) expect(duplicate).toEqual(committed);
      const path = `native-value-authorizations/${committed.body.resourceRef}`;
      const read = await fixture.read(path);
      expect(read.status, JSON.stringify(read)).toBe(200);
      expect(read.body).toMatchObject({
        state: 'UNUSED',
        revision: '1',
        runtimePermission: 'NONE',
        creationOperationId: committed.body.operationId,
        walletBindingId: fields.walletBindingId,
        validUntil: fields.validUntil,
        authorizationDigest: read.body.issuedAuthorizationDigest,
      });
      const document = JSON.parse(
        Buffer.from(read.body.authorizationDocument.slice(2), 'hex').toString('utf8'),
      );
      expect(document).toMatchObject({
        authorizationId: committed.body.resourceRef,
        participantId,
        actorSubjectId: wallet.actorPrincipalId,
        participantEpoch: 1,
        chainId: fields.chainId,
        chainEnvironmentId: `${fields.chainId}:${fields.networkId}:${fields.genesisDigest}`,
        genesisHash: fields.genesisDigest.slice(7),
        purpose: 'CONTRACT_CREATION_ENDOWMENT',
        amountMode: fields.amountMode,
        maxAmountWei: fields.maxAmountWei,
        oneUse: true,
        used: false,
      });
      const { semanticDigest, ...semantic } = document;
      expect(sha256(semantic)).toBe(`sha256:${semanticDigest}`);
      for (const table of ['mutation_evidence', 'outbox_event']) {
        expect(
          (
            await admin.query(
              `select count(*)::int n from control.${table} where aggregate_id=$1`,
              [prepared.resourceId],
            )
          ).rows[0].n,
        ).toBe(1);
      }
      expect(
        (await admin.query('select count(*)::int n from control.deployment_address_reservation'))
          .rows[0].n,
      ).toBe(0);
      await fixture.restartConfiguration();
      const restarted = await fixture.read(path);
      expect(restarted.status).toBe(read.status);
      expect(restarted.body).toEqual(read.body);
      expect(restarted.headers.get('etag')).toBe(read.headers.get('etag'));
      expect(await prepared.commit()).toEqual(committed);

      // A correctly encoded document and runtime SQL role cannot substitute for
      // the real candidate, independent approval, receipt and evidence transaction.
      const forgedId = id(),
        operationId = id();
      const forged = nativeValueCore('ENCODE_NATIVE_VALUE_AUTHORIZATION', {
        document: {
          ...semantic,
          authorizationId: `urn:openpc:resource:${forgedId}`,
          participantEpoch: '1',
        },
      });
      const connection = await admin.connect();
      try {
        await connection.query('begin');
        await connection.query('set local role openpc_configuration_runtime');
        await connection.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)",
          [participantId, privacyDomainId, operationId, action],
        );
        await expect(
          (async () => {
            await connection.query(
              `insert into control.native_value_authorization(native_value_authorization_id,
          participant_id,privacy_domain_id,actor_principal_id,wallet_binding_id,wallet_binding_epoch,
          document_bytes,semantic_digest,creation_operation_id,creation_authority_digest,valid_until)
          values($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10)`,
              [
                forgedId,
                participantId,
                privacyDomainId,
                wallet.actorPrincipalId,
                wallet.walletBindingId,
                Buffer.from(forged.documentBytes.slice(2), 'hex'),
                `sha256:${forged.semanticDigest}`,
                operationId,
                `sha256:${document.policyDecisionDigest}`,
                fields.validUntil,
              ],
            );
            await connection.query('commit');
          })(),
        ).rejects.toThrow('NATIVE-VALUE-PROVENANCE');
      } finally {
        await connection.query('rollback');
        connection.release();
      }
      expect(
        (await admin.query('select count(*)::int n from control.native_value_authorization'))
          .rows[0].n,
      ).toBe(1);
      other = await contractAdministrationFixture(admin, runtimeUrl!, id(), id());
      expect((await other.read(path)).status).toBe(403);
      await other.create('native-value-authorizations', action, fields, 0);
      await fixture.create(
        'native-value-authorizations',
        action,
        { ...fields, executionWorkloadId: `urn:openpc:workload:${id()}` },
        0,
      );
      await fixture.create(
        'native-value-authorizations',
        action,
        { ...fields, validUntil: new Date(Date.now() + 600_000).toISOString() },
        0,
      );
      await wallet.revoke();
      await fixture.refresh();
      const revoked = await fixture.read(path);
      expect(revoked.status, JSON.stringify(revoked)).toBe(200);
      expect(revoked.body).toMatchObject({
        state: 'INVALIDATED',
        authorizationDocument: read.body.authorizationDocument,
      });
      // A new deadline creates a fresh candidate; an identical consumed
      // candidate is correctly rejected by the separate idempotency owner.
      await fixture.create(
        'native-value-authorizations',
        action,
        { ...fields, validUntil: new Date(Date.now() + 180_000).toISOString() },
        0,
      );
      await fixture.restartConfiguration();
      const revokedAfterRestart = await fixture.read(path);
      expect(revokedAfterRestart.status).toBe(revoked.status);
      expect(revokedAfterRestart.body).toEqual(revoked.body);
      expect(revokedAfterRestart.headers.get('etag')).toBe(revoked.headers.get('etag'));
    } finally {
      await other?.close();
      await fixture.close();
      await admin.end();
    }
  },
  120_000,
);

integration(
  'binds workload endowment issuance to its credential owner and publicly governed wallet',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const participantId = id(),
      privacyDomainId = id(),
      principalId = id(),
      workloadId = `urn:openpc:workload:${id()}`;
    const fixture = await contractAdministrationFixture(
      admin,
      runtimeUrl!,
      participantId,
      privacyDomainId,
    );
    let tls: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>> | undefined;
    try {
      // External workload identity is initial trust. This test exercises its
      // management binding; transport mTLS acceptance belongs to the runtime.
      const uri = `urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`;
      tls = await runtimeSnapshotTlsFixture(uri);
      const publicKey = tls.parsed.publicKey.export({ type: 'spki', format: 'der' });
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
         values($1,$2,'WORKLOAD','Native Value workload','ACTIVE',1)`,
        [principalId, participantId],
      );
      await admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
         public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
         values($1,$2,$3,'WORKLOAD_MTLS','local-test-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
        [
          id(),
          participantId,
          principalId,
          uri,
          workloadId,
          sha(publicKey),
          publicKey,
          sha(tls.parsed.raw),
          new Date(tls.parsed.validFrom),
          new Date(tls.parsed.validTo),
        ],
      );
      const wallet = await fixture.createWalletBinding(
        '31337',
        `0x${'23'.repeat(20)}`,
        principalId,
      );
      const fields = {
        walletBindingId: `urn:openpc:resource:${wallet.walletBindingId}`,
        chainId: '31337',
        networkId: 'openpc-local',
        genesisDigest: sha256('local workload chain'),
        amountMode: 'EXACT',
        maxAmountWei: '10',
        validUntil: new Date(Date.now() + 240_000).toISOString(),
      };
      await fixture.create('native-value-authorizations', action, fields, 0);
      const committed = await fixture.create('native-value-authorizations', action, {
        ...fields,
        executionWorkloadId: workloadId,
      });
      const path = `native-value-authorizations/${committed.body.resourceRef}`;
      const read = await fixture.read(path);
      expect(read.status, JSON.stringify(read)).toBe(200);
      const document = JSON.parse(
        Buffer.from(read.body.authorizationDocument.slice(2), 'hex').toString('utf8'),
      );
      expect(document).toMatchObject({
        actorSubjectId: principalId,
        oneUse: true,
        used: false,
        maxAmountWei: '10',
      });
      expect(read.body.state).toBe('UNUSED');
      await assertNativeValueAuthorityLocks(
        admin,
        participantId,
        privacyDomainId,
        wallet.walletBindingId,
        principalId,
      );
      await fixture.restartConfiguration();
      const restarted = await fixture.read(path);
      expect(restarted.status).toBe(read.status);
      expect(restarted.body).toEqual(read.body);
      expect(restarted.headers.get('etag')).toBe(read.headers.get('etag'));
      await wallet.revoke();
      await fixture.refresh();
      expect((await fixture.read(path)).body.state).toBe('INVALIDATED');
      expect(
        (await admin.query('select count(*)::int n from control.deployment_address_reservation'))
          .rows[0].n,
      ).toBe(0);
    } finally {
      await tls?.close();
      await fixture.close();
      await admin.end();
    }
  },
  120_000,
);
