import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { lockEvidenceLifecycle } from '../../../services/control-api/src/evidence/lifecycle-fence.js';
import {
  loadProtectedRemoteArchiveSource,
  protectedRemoteArchiveIntentBytes,
  type BoundProtectedRemoteArchiveSource,
} from '../../../services/control-api/src/evidence/protected-remote-archive-source.js';
import { ProtectedRemoteArchiveCustody } from '../../../services/control-api/src/evidence/protected-remote-custody.js';
import { RemoteEvidenceArchive } from '../../../services/control-api/src/evidence/remote-archive.js';
import { PostgresRemoteArchiveAttemptOwner } from '../../../services/control-api/src/evidence/remote-archive-owner.js';
import type {
  RemoteArchiveIntent,
  RemoteArchiveProfile,
} from '../../../services/control-api/src/evidence/remote-archive-contracts.js';
import type { S3ArchiveCredentials } from '../../../services/control-api/src/evidence/remote-archive-s3.js';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';
import { evidenceArchiveAuthorityFixture } from './evidence-archive-authority-fixture.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && workerUrl && runtimeUrl ? it : it.skip;
const time = (offset: number) =>
  new Date(Date.now() + offset).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
type Scope = { participantId: string; privacyDomainId: string };
type Governance = Awaited<ReturnType<typeof contractAdministrationFixture>>;
interface ExternalArchive {
  endpoint: string;
  faults: { dropPutResponse: boolean; dropHoldResponse: boolean };
  counts: { puts: number; holds: number; gets: number; lists: number };
  close(): Promise<void>;
}
const fixtureUrl = new URL('../local-runtime/evidence-remote-archive-fixture.mjs', import.meta.url);
const { startRemoteArchiveFixture } = (await import(fixtureUrl.href)) as {
  startRemoteArchiveFixture(options: {
    root: string;
    bucket: string;
    expectedOwner: string;
    region: string;
    credentials: S3ArchiveCredentials;
  }): Promise<ExternalArchive>;
};

// SEM-138/139, 057/059: real governed proof source, typed signed remote custody,
// mounted worker, hold recovery and independent local retirement. Only the
// external archive is a fixture; provider WORM qualification remains open.
integration(
  'preserves governed protected copies through signed remote custody, packaged recovery and local retirement',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const participantId = id(),
      rootPrivacy = id(),
      childPrivacy = id();
    const scope = {
      participantId,
      privacyDomainId: childPrivacy,
      streamId: 'protected-remote-source',
    };
    const sinkId = 'protected-remote-test';
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'protected-remote-source-'));
    const executable = join(root, 'evidence-worker.mjs');
    const ordinaryKey = randomBytes(32);
    const fixtures: Governance[] = [];
    const signers: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>>[] = [];
    let external: ExternalArchive | undefined;
    let archiveAuthority: Awaited<ReturnType<typeof evidenceArchiveAuthorityFixture>> | undefined;
    const keys = {
      activeKeyId: 'source-proof-key',
      keys: new Map([['source-proof-key', randomBytes(32)]]),
    };

    async function fenced<T>(
      pool: Pool,
      context: Scope,
      work: (client: PoolClient) => Promise<T>,
      action = 'ACT-EVIDENCE_EXPORT_RECORDS-V1',
    ) {
      const client = await pool.connect();
      try {
        await client.query('begin');
        await client.query('set local row_security=on');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)",
          [context.participantId, context.privacyDomainId, id(), action],
        );
        await lockEvidenceLifecycle(client, context.participantId, context.privacyDomainId);
        return await work(client);
      } finally {
        try {
          await client.query('rollback');
        } finally {
          client.release();
        }
      }
    }
    const read = (objectRef: string) =>
      fenced(worker, scope, (client) =>
        loadProtectedRemoteArchiveSource(client, {
          participantId,
          privacyDomainId: childPrivacy,
          objectRef,
          sinkId,
        }),
      );
    const bound = async (objectRef: string): Promise<BoundProtectedRemoteArchiveSource> => {
      const facts = await read(objectRef);
      expect(facts.state).toBe('BOUND');
      if (facts.state !== 'BOUND') throw new Error(`protected source ${facts.reason}`);
      return facts;
    };
    try {
      // Stable packaged executable is prepared before acquiring live authority.
      await promisify(execFile)(
        'pnpm',
        [
          '--dir',
          'services/control-api',
          'exec',
          'esbuild',
          'src/evidence/runtime.ts',
          '--bundle',
          '--platform=node',
          '--format=esm',
          '--banner:js=import { createRequire } from "node:module"; const require = createRequire(import.meta.url);',
          `--outfile=${executable}`,
        ],
        { timeout: 20000, maxBuffer: 16384 },
      );
      const installed = await admin.query(
        "select to_regprocedure('openpc.protected_remote_archive_source(uuid,uuid,uuid,text)') is not null installed",
      );
      expect(
        installed.rows[0]?.installed,
        'Actual exported protected source predicates must be installed',
      ).toBe(true);
      const parent = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        rootPrivacy,
      );
      fixtures.push(parent);
      // Initial trust/scope only. Every proof, hold and release below uses public
      // real Identity, policy, maker/checker and immutable mutation owners.
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
      values($1,$2,'Protected remote child','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [childPrivacy, participantId],
      );
      const child = await contractAdministrationFixture(
        admin,
        runtimeUrl!,
        participantId,
        childPrivacy,
        {
          existingScope: true,
          initialPrivacyDomainIds: [rootPrivacy, childPrivacy],
          protectedProofKeys: keys,
        },
      );
      fixtures.push(child);
      await child.selectPrivacyContext('maker', { freshStepUp: true });
      await child.selectPrivacyContext('checker', { freshStepUp: true });
      for (const privacy of [rootPrivacy, childPrivacy]) {
        const signer = await evidenceGovernanceSigningFixture(
          admin,
          participantId,
          privacy,
          'evidence-hold',
        );
        signers.push(signer);
        // The shared bootstrap fixture uses one fixed label per family. These
        // two initial workload identities share a Participant, not a scope.
        // Name them distinctly before creating any governed business state.
        await admin.query(
          `update control.principal set display_label=$1 where participant_id=$2
          and principal_id=(select principal_id from control.credential where credential_id=$3 and participant_id=$2)`,
          [`protected-archive-hold-${privacy}`, participantId, signer.trust.workloadCredentialId],
        );
      }
      await parent.restartConfiguration(signers[0]!.evidence);
      await child.restartConfiguration(signers[1]!.evidence);

      const participantHold = await parent.create(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1',
        {
          participantId: `urn:openpc:participant:${participantId}`,
          holdKind: 'LEGAL',
          selector: { type: 'PARTICIPANT' },
        },
      );
      const participantHoldRef = String(participantHold.body.resourceRef);
      await child.governance.client.stepUp(
        child.governance.maker,
        'ACT-POLICY_SETS_CREATE_RESOURCE-V1',
        id(),
        sha256({ purpose: 'remote proof source' }),
      );
      await new EvidenceCustody(worker).ingestAuthentication(
        scope,
        { keyId: 'ordinary-auth-key', key: ordinaryKey },
        time(86400000),
        1048576,
      );
      const source = (
        await admin.query(
          `select c.evidence_id::text id from control.evidence_catalogue c
      join control.authentication_occurrence a on a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id
       and a.occurrence_id::text=c.record_id where c.participant_id=$1 and c.privacy_domain_id=$2
       and c.stream_id=$3 and a.method='WEBAUTHN_ASSERTION' order by c.sequence desc limit 1`,
          [participantId, childPrivacy, scope.streamId],
        )
      ).rows[0];
      expect(source).toBeDefined();
      const discovery = await child.read(
        `evidence-records/urn:openpc:resource:${source.id}/protected-proof-source`,
      );
      expect(discovery.status).toBe(200);
      const retain = async (caseReference: string, retainUntil = time(86400000)) => {
        const result = await child.create(
          'protected-proofs',
          'ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1',
          {
            participantId: `urn:openpc:participant:${participantId}`,
            source: discovery.body,
            purpose: 'Exact protected remote source',
            caseReference,
            retainUntil,
          },
        );
        return String(result.body.resourceRef);
      };
      const firstRef = await retain('first-proof-before-release');
      const first = await bound(firstRef);
      expect(first.retention).toEqual({ state: 'UNKNOWN', reason: 'PROFILE_NOT_ADMITTED' });
      expect(first.rules).toMatchObject([
        { holdId: participantHoldRef.slice(-36), state: 'ACTIVE', revision: '1' },
      ]);
      expect(first.lineage.evidenceId).toBe(first.object.source.evidenceId);
      const stored = (
        await admin.query(
          'select key_id,nonce,ciphertext from control.protected_proof_payload where object_id=$1',
          [firstRef.slice(-36)],
        )
      ).rows[0];
      expect(first.packet!.keyId).toBe(stored.key_id);
      expect(Buffer.from(first.packet!.nonceBase64, 'base64').equals(stored.nonce)).toBe(true);
      expect(Buffer.from(first.packet!.ciphertextBase64, 'base64').equals(stored.ciphertext)).toBe(
        true,
      );
      expect(first.payloadBytes).toBe(Buffer.byteLength(canonicalJson(first.packet)));
      expect(first.object.ciphertextBytes).toBe(stored.ciphertext.length);
      expect(first.object.objectDigest).not.toBe(first.object.payloadDigest);

      // A released parent rule remains history for an existing proof but cannot
      // be inherited by a later proof merely because both share an older source.
      await parent.create(
        `evidence-holds/${participantHoldRef}/release`,
        'ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1',
        {
          targetRef: participantHoldRef,
          expectedRevision: '1',
        },
      );
      expect((await bound(firstRef)).rules).toMatchObject([
        { holdId: participantHoldRef.slice(-36), state: 'RELEASED', revision: '2' },
      ]);
      const laterRef = await retain('later-proof-after-release');
      expect((await bound(laterRef)).rules).toEqual([]);

      const selectors = [
        { type: 'PRIVACY_DOMAIN' },
        { type: 'DIGEST', recordDigest: first.object.objectDigest },
        { type: 'DIGEST', recordDigest: first.object.payloadDigest },
        { type: 'DIGEST', recordDigest: first.object.source.sourceReceiptDigest },
        {
          type: 'SEQUENCE_RANGE',
          streamId: first.lineage.streamId,
          fromSequence: first.lineage.sequence,
          throughSequence: first.lineage.sequence,
        },
      ];
      const matching: string[] = [];
      for (const selector of selectors) {
        const held = await child.create('evidence-holds', 'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1', {
          participantId: `urn:openpc:participant:${participantId}`,
          holdKind: 'INCIDENT',
          selector,
        });
        matching.push(String(held.body.resourceRef));
      }
      const unrelated = await child.create(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
        {
          participantId: `urn:openpc:participant:${participantId}`,
          holdKind: 'LEGAL',
          selector: { type: 'DIGEST', recordDigest: sha256('unrelated') },
        },
      );
      // A child privacy rule never leaks into its sibling/root preservation scope.
      const rootOnly = await parent.create(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
        {
          participantId: `urn:openpc:participant:${participantId}`,
          holdKind: 'LEGAL',
          selector: { type: 'PRIVACY_DOMAIN' },
        },
      );
      const held = await bound(firstRef);
      expect(
        held.rules
          .filter((rule) => rule.state === 'ACTIVE')
          .map((rule) => rule.holdId)
          .sort(),
      ).toEqual(matching.map((ref) => ref.slice(-36)).sort());
      expect(held.rules.map((rule) => rule.holdId)).not.toContain(
        String(unrelated.body.resourceRef).slice(-36),
      );
      expect(held.rules.map((rule) => rule.holdId)).not.toContain(
        String(rootOnly.body.resourceRef).slice(-36),
      );
      await child.create(
        `evidence-holds/${matching[0]}/release`,
        'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1',
        {
          targetRef: matching[0],
          expectedRevision: '1',
        },
      );
      const afterRelease = await bound(firstRef);
      expect(
        afterRelease.rules.find((rule) => rule.holdId === matching[0]!.slice(-36))?.state,
      ).toBe('RELEASED');
      expect(afterRelease.rules.filter((rule) => rule.state === 'ACTIVE')).toHaveLength(4);

      // Source reads do not consume or extend the separately approved disclosure.
      await child.create(
        'protected-proof-access',
        'ACT-PROTECTED_PROOF_ACCESS_CREATE_RESOURCE-V1',
        {
          participantId: `urn:openpc:participant:${participantId}`,
          object: {
            objectRef: firstRef,
            objectVersion: '1',
            objectDigest: first.object.objectDigest,
            source: first.object.source,
          },
          purpose: 'Separate disclosure',
          caseReference: 'independent-access',
          recipientPrincipalId: child.governance.maker.principalId,
          expiresAt: time(60000),
        },
      );
      await bound(firstRef);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.protected_proof_access where object_id=$1 and consumed_at is null',
            [firstRef.slice(-36)],
          )
        ).rows[0].n,
      ).toBe(1);
      const publicObject = await child.read(`protected-proofs/${firstRef}`);
      expect(publicObject.status).toBe(200);
      expect(JSON.stringify(publicObject.body)).not.toMatch(
        /ciphertext|nonceBase64|assertionBase64|coseSign1Base64|keyId/u,
      );

      await expect(
        fenced(runtime, scope, (client) =>
          loadProtectedRemoteArchiveSource(client, {
            participantId,
            privacyDomainId: childPrivacy,
            objectRef: firstRef,
            sinkId,
          }),
        ),
      ).rejects.toThrow();
      await expect(
        fenced(worker, scope, (client) =>
          loadProtectedRemoteArchiveSource(client, {
            participantId,
            privacyDomainId: rootPrivacy,
            objectRef: firstRef,
            sinkId,
          }),
        ),
      ).rejects.toThrow('PC-AUTH-0005');
      expect(
        await fenced(worker, { participantId, privacyDomainId: rootPrivacy }, (client) =>
          loadProtectedRemoteArchiveSource(client, {
            participantId,
            privacyDomainId: rootPrivacy,
            objectRef: firstRef,
            sinkId,
          }),
        ),
      ).toEqual({ state: 'UNKNOWN', reason: 'OBJECT_UNAVAILABLE' });
      await expect(
        fenced(
          worker,
          scope,
          (client) =>
            loadProtectedRemoteArchiveSource(client, {
              participantId,
              privacyDomainId: childPrivacy,
              objectRef: firstRef,
              sinkId,
            }),
          'ACT-PROTECTED_PROOFS_READ_RESOURCE-V1',
        ),
      ).rejects.toThrow('PC-AUTH-0005');

      // Existing S3 fixture plus the real common owner: a changed packet is
      // rejected BEFORE any journal/transport dispatch. No mock internal owner.
      const credentials = {
        accessKeyId: 'SOURCEFIXTUREKEY',
        secretAccessKey: randomBytes(32).toString('hex'),
      };
      external = await startRemoteArchiveFixture({
        root: join(root, 's3'),
        bucket: 'proof-source',
        expectedOwner: '123456789012',
        region: 'local-1',
        credentials,
      });
      const profile: RemoteArchiveProfile = {
        profileId: 'proof-source',
        sinkId,
        endpoint: external.endpoint,
        transport: 'LOOPBACK_TEST',
        region: 'local-1',
        bucket: 'proof-source',
        expectedBucketOwner: '123456789012',
        prefix: 'archive',
        lockMode: 'COMPLIANCE',
        requestTimeoutMs: 1000,
        maxVersionPages: 2,
      };
      const current = await bound(firstRef);
      const intent: RemoteArchiveIntent = {
        intentId: id(),
        profileDigest: sha256(profile),
        source: { kind: 'PROTECTED_PROOF', object: current.object },
        payloadDigest: current.object.payloadDigest,
        payloadBytes: current.payloadBytes,
        initialProtection: { revision: '1', rules: current.rules },
      };
      const packetBytes = protectedRemoteArchiveIntentBytes(current, intent);
      const changed = Buffer.from(packetBytes);
      changed[changed.length - 1] = 0;
      archiveAuthority = await evidenceArchiveAuthorityFixture(
        admin,
        worker,
        scope,
        [scope.streamId],
        profile,
        { directory: root, credentials },
        'PROTECTED_PROOF',
      );
      const archive = new RemoteEvidenceArchive(
        profile,
        async () => credentials,
        new PostgresRemoteArchiveAttemptOwner(worker, scope, archiveAuthority.authority),
      );
      await expect(archive.put(intent, changed, id())).rejects.toThrow('Remote archive integrity');
      expect(external.counts).toMatchObject({ puts: 0, holds: 0, gets: 0, lists: 0 });
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.evidence_remote_archive_intent where participant_id=$1',
            [participantId],
          )
        ).rows[0].n,
      ).toBe(0);

      const owner = new PostgresRemoteArchiveAttemptOwner(
        worker,
        scope,
        archiveAuthority.authority,
      );
      const custody = () =>
        new ProtectedRemoteArchiveCustody(
          owner,
          archiveAuthority!.authority,
          async () => credentials,
        );
      external.faults.dropPutResponse = true;
      await expect(custody().exportNext()).rejects.toMatchObject({ code: 'AMBIGUOUS' });
      expect(external.counts.puts).toBe(1);
      const journal = (
        await admin.query(
          `select i.intent,i.source_kind,i.protected_object_id::text object_id,a.state
       from control.evidence_remote_archive_intent i join control.evidence_remote_archive_attempt a using(participant_id,privacy_domain_id,intent_id)
       where i.participant_id=$1`,
          [participantId],
        )
      ).rows;
      expect(journal).toHaveLength(1);
      expect(journal[0]).toMatchObject({
        source_kind: 'PROTECTED_PROOF',
        object_id: firstRef.slice(-36),
        state: 'AMBIGUOUS',
      });
      const pending = await child.read(`protected-proofs/${firstRef}/deletion-plan`);
      expect(pending.status).toBe(200);
      expect(pending.body.blockers).toContain('REFERENCES');
      const fault = `proof_commit_${participantId.replaceAll('-', '')}`;
      await admin.query(`create function openpc.${fault}() returns trigger language plpgsql as $$
        begin if NEW.participant_id::text=TG_ARGV[0] then raise exception 'TEST_PROTECTED_CUSTODY_COMMIT'; end if; return NEW; end $$;
        create constraint trigger ${fault} after insert on control.evidence_archive_receipt deferrable initially deferred
         for each row execute function openpc.${fault}('${participantId}')`);
      try {
        await expect(custody().exportNext()).rejects.toThrow('TEST_PROTECTED_CUSTODY_COMMIT');
        expect(
          (
            await admin.query(
              'select count(*)::int n from control.evidence_archive_receipt where participant_id=$1',
              [participantId],
            )
          ).rows[0].n,
        ).toBe(0);
        expect(
          (
            await admin.query(
              'select count(*)::int n from control.evidence_archive_outbox where participant_id=$1',
              [participantId],
            )
          ).rows[0].n,
        ).toBe(0);
        expect(
          (
            await admin.query(
              'select count(*)::int n from control.evidence_archive_commit_nonce where participant_id=$1',
              [participantId],
            )
          ).rows[0].n,
        ).toBe(0);
        expect(
          (
            await admin.query(
              'select count(*)::int n from control.protected_proof_checkpoint where participant_id=$1',
              [participantId],
            )
          ).rows[0].n,
        ).toBe(0);
        expect(external.counts.puts).toBe(1);
      } finally {
        await admin.query(
          `drop trigger ${fault} on control.evidence_archive_receipt; drop function openpc.${fault}()`,
        );
      }
      const checkpoint = await custody().exportNext();
      expect(checkpoint).toMatchObject({
        kind: 'SIGNED_REMOTE_PROTECTED_ARCHIVE_V1',
        result: 'CHECKPOINT',
      });
      expect(external.counts.puts).toBe(1);
      const sealed = (
        await admin.query(
          `select count(*)::int n from control.evidence_archive_receipt r
        join control.evidence_archive_outbox o using(participant_id,privacy_domain_id,receipt_id)
        join control.protected_proof_checkpoint c using(participant_id,privacy_domain_id,receipt_digest)
        where r.participant_id=$1`,
          [participantId],
        )
      ).rows[0].n;
      expect(sealed).toBe(1);
      const completed = await child.read(`protected-proofs/${firstRef}/deletion-plan`);
      expect(completed.status).toBe(200);
      expect(completed.body.blockers).not.toContain('INCOMPLETE_CHECKPOINT');
      // The live disclosure still blocks local deletion independently of archive custody.
      expect(completed.body.blockers).toContain('REFERENCES');
      const releasedHold = matching[1]!;
      await child.create(
        `evidence-holds/${releasedHold}/release`,
        'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1',
        { targetRef: releasedHold, expectedRevision: '1' },
      );
      external.faults.dropHoldResponse = false;
      expect(await custody().reconcileHolds()).toMatchObject({ result: 'PROTECTION' });
      expect(external.counts.puts).toBe(1);
      expect((await child.read(`evidence-holds/${releasedHold}`)).status).toBe(200);
      expect(await custody().reconcileHolds()).toBeNull();

      // Natural expiry is observable preservation state, never fresh admission.
      const expiresAt = time(10000);
      const expiringRef = await retain('held-expiring-proof', expiresAt);
      expect((await bound(expiringRef)).retention.reason).toBe('PROFILE_NOT_ADMITTED');
      const expiring = await bound(expiringRef);
      const originalExpiring: RemoteArchiveIntent = {
        intentId: id(),
        profileDigest: sha256(profile),
        source: { kind: 'PROTECTED_PROOF', object: expiring.object },
        payloadDigest: expiring.object.payloadDigest,
        payloadBytes: expiring.payloadBytes,
        initialProtection: { revision: '1', rules: expiring.rules },
      };
      const expiringBytes = protectedRemoteArchiveIntentBytes(expiring, originalExpiring),
        originalAttempt = id();
      external.faults.dropPutResponse = true;
      await expect(
        archive.put(originalExpiring, expiringBytes, originalAttempt),
      ).rejects.toMatchObject({ code: 'AMBIGUOUS' });
      const originalPuts = external.counts.puts;
      await delay(Math.max(0, Date.parse(expiresAt) - Date.now() + 25));
      await expect(
        archive.put(originalExpiring, expiringBytes, originalAttempt),
      ).resolves.toMatchObject({ intent: originalExpiring });
      expect(external.counts.puts).toBe(originalPuts);
      const expired = await bound(expiringRef);
      expect(expired.retention).toEqual({ state: 'UNKNOWN', reason: 'PROOF_DEADLINE_ELAPSED' });
      expect(expired.object.retainUntil).toBe(expiresAt);
      expect(expired.rules.some((rule) => rule.state === 'ACTIVE')).toBe(true);
      const expiredIntent: RemoteArchiveIntent = {
        intentId: id(),
        profileDigest: sha256(profile),
        source: { kind: 'PROTECTED_PROOF', object: expired.object },
        payloadDigest: expired.object.payloadDigest,
        payloadBytes: expired.payloadBytes,
        initialProtection: { revision: '1', rules: expired.rules },
      };
      const beforeExpired = external.counts.puts;
      await expect(
        archive.put(expiredIntent, protectedRemoteArchiveIntentBytes(expired, expiredIntent), id()),
      ).rejects.toThrow();
      expect(external.counts.puts).toBe(beforeExpired);
      const database = new URL(workerUrl!),
        passwordFile = join(root, 'password'),
        keyFile = join(root, 'ordinary-key'),
        configuration = join(root, 'worker.json');
      await writeFile(passwordFile, decodeURIComponent(database.password), { mode: 0o600 });
      await writeFile(keyFile, ordinaryKey, { mode: 0o600 });
      await writeFile(
        configuration,
        JSON.stringify({
          database: {
            host: database.hostname,
            port: Number(database.port),
            database: database.pathname.slice(1),
            user: database.username,
            passwordFile,
          },
          vaultDirectory: join(root, 'local-vault'),
          sinkId: 'protected-runtime-local',
          remoteArchives: [archiveAuthority.runtimeConfiguration],
          scopes: [
            {
              ...scope,
              source: 'AUTHENTICATION',
              activeKeyId: 'ordinary-auth-key',
              keys: [{ keyId: 'ordinary-auth-key', keyFile }],
              retentionSeconds: 86400,
              capacityBytes: 1048576,
            },
          ],
        }),
        { mode: 0o600 },
      );
      const runWorker = () =>
        promisify(execFile)(process.execPath, [executable, '--once'], {
          env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
          timeout: 30000,
          maxBuffer: 16384,
        });
      await runWorker(); // Later independent unexpired proof gets its first copy.
      await runWorker(); // Original expired attempt obtains signed custody without another PUT.
      const packagedPuts = external.counts.puts;
      await runWorker();
      expect(external.counts.puts).toBe(packagedPuts);
      expect(
        (
          await admin.query(
            `select count(*)::int n from control.protected_proof_checkpoint
        where participant_id=$1 and sink_id=$2 and receipt->>'kind'='SIGNED_REMOTE_PROTECTED_ARCHIVE_V1'`,
            [participantId, sinkId],
          )
        ).rows[0].n,
      ).toBe(3);
      // Release only the real rules that covered this proof, then use the
      // ordinary independent retention-policy and deletion command owners.
      for (const holdRef of matching.slice(2)) {
        await child.create(
          `evidence-holds/${holdRef}/release`,
          'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1',
          { targetRef: holdRef, expectedRevision: '1' },
        );
      }
      for (let remaining = 3; remaining > 0; remaining--) await custody().reconcileHolds();
      expect(await custody().reconcileHolds()).toBeNull();
      const policySigner = await evidenceGovernanceSigningFixture(
        admin,
        participantId,
        childPrivacy,
        'retention-policy',
      );
      const deletionSigner = await evidenceGovernanceSigningFixture(
        admin,
        participantId,
        childPrivacy,
        'evidence-deletion',
      );
      signers.push(policySigner, deletionSigner);
      const govern = async (path: string, action: string, fields: Record<string, unknown>) => {
        const prepared = await child.prepareMutation(path, action, fields, true);
        await prepared.stepUp();
        const committed = await prepared.commit();
        expect(committed.status, JSON.stringify(committed)).toBe(202);
        return committed;
      };
      await child.restartConfiguration(policySigner.evidence);
      await govern('retention-policies', 'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1', {
        participantId: `urn:openpc:participant:${participantId}`,
        predecessorPolicyId: null,
        policy: {
          dataClass: 'RAW_SOURCE_BODY',
          policyVersion: '1.0.0',
          retentionPeriodMs: '0',
          localGraceMs: '0',
          sinkQuorum: 1,
          deletionMode: 'ROW_DELETE',
          makerCheckerRequired: true,
        },
      });
      const deletionPlan = await child.read(`protected-proofs/${expiringRef}/deletion-plan`);
      expect(deletionPlan).toMatchObject({ status: 200, body: { eligible: true, blockers: [] } });
      await child.restartConfiguration(deletionSigner.evidence);
      const deleted = await govern(
        'evidence-deletions/raw-batches',
        'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1',
        {
          participantId: `urn:openpc:participant:${participantId}`,
          selection: deletionPlan.body.selection,
          beforeDigest: deletionPlan.body.beforeDigest,
        },
      );
      expect(deleted.body.resourceRef).toBeDefined();
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.protected_proof_payload where object_id=$1',
            [expiringRef.slice(-36)],
          )
        ).rows[0].n,
      ).toBe(0);
      expect(await read(expiringRef)).toEqual({ state: 'UNKNOWN', reason: 'PAYLOAD_UNAVAILABLE' });
      const retainedFacts = await fenced(worker, scope, (client) =>
        loadProtectedRemoteArchiveSource(client, {
          participantId,
          privacyDomainId: childPrivacy,
          objectRef: expiringRef,
          sinkId,
          originalIntentId: originalExpiring.intentId,
        }),
      );
      expect(retainedFacts).toMatchObject({ state: 'BOUND', packet: null, object: expired.object });
      await child.restartConfiguration(signers[1]!.evidence);
      const postDeletionHold = await govern(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
        {
          participantId: `urn:openpc:participant:${participantId}`,
          holdKind: 'LEGAL',
          selector: { type: 'DIGEST', recordDigest: expired.object.objectDigest },
        },
      );
      const heldRef = String(postDeletionHold.body.resourceRef);
      expect((await child.read(`evidence-holds/${heldRef}`)).body.coverage).toBe('PENDING');
      const holdsBefore = external.counts.holds;
      external.faults.dropHoldResponse = true;
      await expect(custody().reconcileHolds()).rejects.toMatchObject({ code: 'AMBIGUOUS' });
      expect(external.counts.holds).toBe(holdsBefore + 1);
      expect(await custody().reconcileHolds()).toMatchObject({ result: 'PROTECTION' });
      expect(external.counts.holds).toBe(holdsBefore + 1);
      expect(external.counts.puts).toBe(packagedPuts);
      // These separately encrypted copies share plaintext identity, so this
      // digest hold intentionally covers all three, including the retired one.
      expect((await child.read(`evidence-holds/${heldRef}`)).body.coverage).toBe('PENDING');
      for (let remaining = 2; remaining > 0; remaining--)
        expect(await custody().reconcileHolds()).toMatchObject({ result: 'PROTECTION' });
      expect(external.counts.holds).toBe(holdsBefore + 3);
      expect(external.counts.puts).toBe(packagedPuts);
      expect((await child.read(`evidence-holds/${heldRef}`)).body.coverage).toBe('VERIFIED');
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.protected_proof_payload where object_id=$1',
            [expiringRef.slice(-36)],
          )
        ).rows[0].n,
      ).toBe(0);
      await child.restartConfiguration(signers[1]!.evidence);
      const restarted = await bound(firstRef);
      expect(restarted.object).toEqual(current.object);
      expect(restarted.rules).toEqual((await bound(firstRef)).rules);
      expect(sha256(restarted.packet)).toBe(current.object.payloadDigest);
    } finally {
      ordinaryKey.fill(0);
      archiveAuthority?.close();
      await external?.close();
      for (const fixture of fixtures.reverse()) await fixture.close();
      for (const signer of signers) await signer.close();
      await Promise.all([admin.end(), worker.end(), runtime.end()]);
      await rm(root, { recursive: true, force: true });
    }
  },
  120000,
);
