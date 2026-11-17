import { generateKeyPairSync } from 'node:crypto';
import { Pool, type PoolClient } from 'pg';
import { expect } from 'vitest';
import {
  evidenceKeyId,
  signNotificationClaim,
  type NotificationRoutingProfileClaims,
} from '../../../packages/security-kernel/src/index.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  installEvidenceExportProducer,
  withdrawEvidenceExportProducer,
} from '../../../services/control-api/src/evidence/export-producer-installation.js';
import { notificationPayloadEncryptionProfileDigest } from '../../../services/control-api/src/evidence/notification-payload-crypto.js';
import {
  installInitialNotificationRouting,
  withCurrentNotificationRouting,
  withdrawNotificationRouting,
  readInstalledNotificationRouting,
  type NotificationRoutingSelector,
} from '../../../services/control-api/src/notifications/routing-installation.js';
import { type NotificationRoutingInstallation } from '../../../services/control-api/src/notifications/routing-installation-contract.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { renderEvidenceExportNotification } from '../../../services/control-api/src/notifications/template-renderer.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';

/** Joins a genuinely activated endpoint from the existing signed API journey.
 * Only the distinct producer workload/key and signed initial configuration are
 * fixtures. This proves installation/current fences, not a completed export,
 * delivery, TLS producer request or Evidence wrapped-key custody. */
export async function assertNotificationRoutingInstallationCases(
  admin: Pool,
  runtimeUrl: string,
  participantId: string,
  privacyDomainId: string,
  endpointId: string,
) {
  const runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
  const installer = new Pool({
    connectionString: process.env.OPENPC_I02_ADMIN_DATABASE_URL!,
    options: '-c role=openpc_control_owner',
    max: 2,
  });
  const workloadId = `urn:openpc:workload:${id()}`,
    principalId = id(),
    credentialId = id();
  const tls = await runtimeSnapshotTlsFixture(
    `urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`,
  );
  const scoped = async <T>(
    pool: Pool,
    operation: (client: PoolClient) => Promise<T>,
    privacy = privacyDomainId,
  ) => {
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query(
        `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
        [participantId, privacy, id()],
      );
      const result = await operation(client);
      await client.query('commit');
      return result;
    } catch (error) {
      await client.query('rollback');
      throw error;
    } finally {
      client.release();
    }
  };
  try {
    const endpoint = (
      await admin.query(
        `select e.*,c.channel_trust from control.notification_endpoint e join control.installed_notification_channel c using(participant_id,privacy_domain_id,credential_ref) where e.participant_id=$1 and e.privacy_domain_id=$2 and e.endpoint_id=$3`,
        [participantId, privacyDomainId, endpointId],
      )
    ).rows[0];
    expect(endpoint.state).toBe('ACTIVE');
    expect(endpoint.verification_id).toBeTruthy();
    const environmentId = endpoint.channel_trust.environmentId as string;
    const tlsSpki = tls.parsed.publicKey.export({ type: 'spki', format: 'der' });
    await admin.query(
      `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Routing export producer','ACTIVE',1)`,
      [principalId, participantId],
    );
    await admin.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until) values($1,$2,$3,'WORKLOAD_MTLS','routing-test-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
      [
        credentialId,
        participantId,
        principalId,
        `urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`,
        workloadId,
        Buffer.from(sha256(tlsSpki).slice(7), 'hex'),
        tlsSpki,
        Buffer.from(sha256(tls.parsed.raw).slice(7), 'hex'),
        tls.parsed.validFrom,
        tls.parsed.validTo,
      ],
    );
    const sourceKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
        type: 'spki',
        format: 'der',
      }),
      now = BigInt(Date.now()) * 1000000n;
    const producerTrustDigest = await installEvidenceExportProducer(installer, {
      owner: 'LS-EVIDENCE-EXPORT',
      purpose: 'pc.cose.evidence-export-completion-receipt.v1',
      environmentId,
      participantId,
      privacyDomainId,
      sourceId: id(),
      principalId,
      workloadCredentialId: credentialId,
      workloadId,
      workloadEpoch: '1',
      secretClass: 'SECRET-SIGNING-KEY',
      secretReference: 'secret://local/routing-export-signer#1',
      secretVersion: '1',
      publicKeySpkiHex: sourceKey.toString('hex'),
      keyEpoch: '1',
      validFromNs: String(now - 1000000000n),
      validUntilNs: String(now + 600000000000n),
      installationReference: 'routing-initial-producer',
    });
    const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
      issuerSpki = issuer.publicKey.export({ type: 'spki', format: 'der' });
    const template: NotificationRoutingInstallation['template'] = {
      schema: 'OPENPC_EVIDENCE_EXPORT_NOTIFICATION_TEMPLATE_V1',
      templateId: id(),
      revision: '1',
      sourceEvent: 'EvidenceExportCompleted',
      format: 'PLAIN_TEXT',
      subject: [{ kind: 'TEXT', value: 'Evidence export completed' }],
      body: [
        { kind: 'FIELD', field: 'evidenceExportId' },
        { kind: 'FIELD', field: 'checkpoint' },
      ],
    };
    const recipientSet: NotificationRoutingInstallation['recipientSet'] = {
      schema: 'OPENPC_NOTIFICATION_ENDPOINT_RECIPIENT_V1',
      endpointId,
      channel: endpoint.channel,
      destinationRef: endpoint.destination_ref,
    };
    const redaction: NotificationRoutingInstallation['redaction'] = {
      schema: 'OPENPC_EVIDENCE_EXPORT_NOTIFICATION_FIELDS_V1',
      allowedFields: ['checkpoint', 'evidenceExportId'],
    };
    const build = (changes: Partial<NotificationRoutingProfileClaims> = {}) => {
      const claims: NotificationRoutingProfileClaims = {
        environmentId,
        participantId,
        privacyDomainId,
        profileId: id(),
        revision: '1',
        validFromMs: Date.now() - 1000,
        validUntilMs: Date.now() + 300000,
        sourceEvent: 'EvidenceExportCompleted',
        endpointId,
        endpointRevision: String(endpoint.revision),
        signedChannelProfileDigest: endpoint.channel_profile_digest,
        templateDigest: sha256(template),
        recipientSetDigest: sha256(recipientSet),
        redactionProfileDigest: sha256(redaction),
        preferenceGeneration: '1',
        encryptionProfileDigest: notificationPayloadEncryptionProfileDigest,
        payloadKeyPolicyDigest: `sha256:${'a'.repeat(64)}`,
        issuerKeyId: evidenceKeyId(issuerSpki),
        ...changes,
      };
      const signed = signNotificationClaim(
        'NotificationRoutingProfileV1',
        issuer.privateKey.export({ type: 'pkcs8', format: 'der' }),
        issuerSpki,
        claims,
      );
      const value: NotificationRoutingInstallation = {
        trust: {
          environmentId: claims.environmentId,
          participantId,
          privacyDomainId,
          signedProfileDigest: sha256(signed.cose),
          issuerSpkiHex: issuerSpki.toString('hex'),
        },
        signed: {
          payloadHex: signed.payload.toString('hex'),
          coseHex: signed.cose.toString('hex'),
        },
        template,
        recipientSet,
        redaction,
        producerTrustDigest,
        installationReference: 'local-routing-initial-trust',
      };
      const selector = {
        participantId,
        privacyDomainId,
        profileId: claims.profileId,
        revision: claims.revision,
        signedProfileDigest: value.trust.signedProfileDigest,
        producerTrustDigest,
      };
      return { value, selector };
    };
    const first = build();
    // Rendering fixtures only: these four values do not assert that an export
    // completed or that its durable signed producer/publication path ran.
    const renderingInput = {
      evidenceExportId: `urn:openpc:resource:${id()}`,
      checkpoint: '7',
      outputDigest: `sha256:${'d'.repeat(64)}`,
      recordCount: '3',
    };
    const noEffects = async () => {
      // Payload/delivery declarations are not yet enrolled in the installed
      // migration set. Preserve that absence as an observable state; once an
      // owner enrolls them, this same check must examine their actual rows.
      const snapshot: Record<string, unknown> = {};
      for (const table of [
        'notification',
        'notification_payload_object',
        'notification_payload',
        'notification_occurrence',
        'notification_delivery',
        'notification_delivery_attempt',
        'notification_source_cursor',
      ] as const) {
        const present = await admin.query('select to_regclass($1)::text name', [
          `control.${table}`,
        ]);
        if (present.rows[0].name === null) {
          expect(table).not.toBe('notification');
          snapshot[table] = { installed: false };
          continue;
        }
        // Identifiers come exclusively from the closed list above.
        const projection =
          table === 'notification_source_cursor'
            ? "coalesce(jsonb_agg(to_jsonb(c) order by c.subscription_id,c.source,c.partition),'[]'::jsonb)"
            : 'count(*)::text';
        const result = await admin.query(
          `select ${projection} value from control.${table} c where participant_id=$1 and privacy_domain_id=$2`,
          [participantId, privacyDomainId],
        );
        snapshot[table] = { installed: true, value: result.rows[0].value };
      }
      return snapshot;
    };
    const unchangedEffects = await noEffects();
    let renderCalls = 0;
    const renderCurrent = (
      client: PoolClient,
      selector: NotificationRoutingSelector = first.selector,
    ) =>
      withCurrentNotificationRouting(client, selector, async (routing) => {
        renderCalls++;
        return renderEvidenceExportNotification(routing.input, renderingInput);
      });
    const deniedRender = async (
      selector: NotificationRoutingSelector = first.selector,
      privacy = privacyDomainId,
    ) => {
      const before = renderCalls;
      await expect(scoped(runtime, (c) => renderCurrent(c, selector), privacy)).rejects.toThrow();
      expect(renderCalls).toBe(before);
    };
    await expect(
      scoped(runtime, (c) => installInitialNotificationRouting(c, first.value)),
    ).rejects.toThrow();
    await scoped(installer, (c) => installInitialNotificationRouting(c, first.value));
    await scoped(installer, (c) => installInitialNotificationRouting(c, first.value));
    const original = await scoped(runtime, (c) =>
      withCurrentNotificationRouting(c, first.selector, async (r) => ({
        bytes: r.bytes,
        digest: r.installationDigest,
        endpoint: r.endpoint,
        authority: r.producer.authorityDigest,
        rendered: renderEvidenceExportNotification(r.input, renderingInput),
      })),
    );
    expect(original.endpoint.revision).toBe(String(endpoint.revision));
    expect(original.rendered.subject).toBe('Evidence export completed');
    expect(original.rendered.body).toBe(renderingInput.evidenceExportId + '7');
    expect(original.rendered.payloadDigest).toBe(sha256(original.rendered.bytes));
    expect(original.rendered.payloadDigest).not.toBe(original.digest);
    const restarted = new Pool({ connectionString: runtimeUrl, max: 1 });
    try {
      expect(
        (await scoped(restarted, (c) => readInstalledNotificationRouting(c, first.selector))).bytes,
      ).toEqual(original.bytes);
      expect(await scoped(restarted, (c) => renderCurrent(c))).toEqual(original.rendered);
    } finally {
      await restarted.end();
    }
    for (const change of [
      { revision: '2' },
      { signedProfileDigest: `sha256:${'b'.repeat(64)}` },
      { producerTrustDigest: `sha256:${'c'.repeat(64)}` },
    ])
      await deniedRender({ ...first.selector, ...change });
    const foreignPrivacy = id();
    await deniedRender({ ...first.selector, privacyDomainId: foreignPrivacy });
    await deniedRender(first.selector, foreignPrivacy);
    await expect(
      scoped(runtime, (c) =>
        readInstalledNotificationRouting(c, { ...first.selector, privacyDomainId: id() }),
      ),
    ).rejects.toThrow();
    for (const bad of [
      build({ endpointRevision: String(BigInt(endpoint.revision) + 1n) }),
      build({ signedChannelProfileDigest: `sha256:${'b'.repeat(64)}` }),
      build({ environmentId: 'wrong-environment' }),
      build({ validFromMs: 1, validUntilMs: 2 }),
      build({ profileId: first.selector.profileId, revision: '2' }),
    ])
      await expect(
        scoped(installer, (c) => installInitialNotificationRouting(c, bad.value)),
      ).rejects.toThrow();
    for (const sql of [
      'update control.installed_notification_routing set revision=revision+1',
      'delete from control.installed_notification_routing',
    ])
      await expect(scoped(runtime, (c) => c.query(sql))).rejects.toThrow();
    await expect(
      scoped(installer, (c) =>
        c.query('update control.installed_notification_routing set revision=revision+1'),
      ),
    ).rejects.toThrow('DATA-6020-NOTIFICATION-ROUTING-IMMUTABLE');
    let enter!: () => void, release!: () => void;
    const entered = new Promise<void>((r) => {
        enter = r;
      }),
      released = new Promise<void>((r) => {
        release = r;
      });
    const held = scoped(runtime, (c) =>
      withCurrentNotificationRouting(c, first.selector, async (routing) => {
        const rendered = renderEvidenceExportNotification(routing.input, renderingInput);
        enter();
        await released;
        return rendered;
      }),
    );
    try {
      await Promise.race([
        entered,
        held.then(() => {
          throw new Error('Routing lease ended before the race');
        }),
      ]);
      await expect(
        scoped(installer, (c) => withdrawNotificationRouting(c, first.selector)),
      ).rejects.toThrow();
    } finally {
      release();
    }
    expect(await held).toEqual(original.rendered);
    await scoped(installer, (c) => withdrawNotificationRouting(c, first.selector));
    await deniedRender();
    await expect(
      scoped(installer, (c) => installInitialNotificationRouting(c, first.value)),
    ).rejects.toThrow();
    const history = await scoped(runtime, (c) =>
      readInstalledNotificationRouting(c, first.selector),
    );
    expect(history.state).toBe('REVOKED');
    expect(history.bytes).toEqual(original.bytes);
    const expiresAt = Date.now() + 3000;
    const expiring = build({ validUntilMs: expiresAt });
    await scoped(installer, (c) => installInitialNotificationRouting(c, expiring.value));
    let renderedBeforeExpiry = false;
    await expect(
      scoped(runtime, (c) =>
        withCurrentNotificationRouting(c, expiring.selector, async (routing) => {
          expect(renderEvidenceExportNotification(routing.input, renderingInput)).toEqual(
            original.rendered,
          );
          renderedBeforeExpiry = true;
          await new Promise((resolve) =>
            setTimeout(resolve, Math.max(0, expiresAt - Date.now() + 25)),
          );
          return 'must-not-escape-expired-callback';
        }),
      ),
    ).rejects.toThrow();
    expect(renderedBeforeExpiry).toBe(true);
    await deniedRender(expiring.selector);
    const second = build();
    await scoped(installer, (c) => installInitialNotificationRouting(c, second.value));
    expect(await scoped(runtime, (c) => renderCurrent(c, second.selector))).toEqual(
      original.rendered,
    );
    await withdrawEvidenceExportProducer(
      installer,
      { participantId, privacyDomainId },
      producerTrustDigest,
    );
    await deniedRender(second.selector);
    expect(
      (await scoped(runtime, (c) => readInstalledNotificationRouting(c, second.selector))).state,
    ).toBe('ACTIVE');
    expect(await noEffects()).toEqual(unchangedEffects);
    process.stdout.write(
      'OPENPC_NOTIFICATION_ROUTING|PASS|real-activated-endpoint|initial-signed-template|current-producer-channel|fixture-plain-text-rendering|scope-revision-denial|withdrawal-fence|expiry-recheck|historical-readback|no-delivery-or-key-effect\n',
    );
  } finally {
    await runtime.end();
    await installer.end();
    await tls.close();
  }
}
