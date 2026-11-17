import { Pool, type PoolClient } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../../identity-service/src/db/scoped-transaction.js';
import { lockAuthorityFence } from '../../../identity-service/src/db/authority-fence.js';
import { stepUpRuntimeAssertion } from '../../../identity-service/src/domain/configuration-step-up-admission.js';
import { fenceConfigurationMutation } from '../configuration/persistence/authority-fence.js';
import { verifyConfigurationRuntimeAuthorization } from '../configuration/persistence/runtime-authorization.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../configuration/persistence/types.js';
import { sha256 } from '../configuration/digest.js';
import {
  verifyInstalledNotificationChannel,
  type NotificationGatewayInstalledTrust,
  type SignedNotificationChannelProfile,
  type NotificationSignedReceipt,
} from './gateway-contracts.js';
import {
  verifyInstalledNotificationVerification,
  type NotificationVerificationTrust,
} from '../configuration/notification-verification-contract.js';
import {
  notificationChannelCredential,
  assertNotificationEndpointConstruction,
  notificationEndpointReplacementDigest,
  type NotificationChannelCredential,
  type NotificationEndpointConstruction,
} from './endpoint-owner-contract.js';
import {
  endpointBinding,
  readNotificationEndpointBusinessState,
  type NotificationEndpointBusinessState,
} from './endpoint-business-state.js';
import {
  endpointRequest,
  type EndpointCreateInput,
  type EndpointUpdateInput,
} from './endpoint-resolution.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';

function rejected(): never {
  throw new ConfigurationRepositoryError('PC-DATA-6007');
}
/** The existing scope fence, never business or Identity authorization. Try-only
 * acquisition is safe even when a caller already holds a business row lock. */
export async function lockNotificationInstallation(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string },
  exclusive = false,
): Promise<void> {
  const result = await client.query<{ acquired: boolean }>(
    `select pg_try_advisory_xact_lock${exclusive ? '' : '_shared'}(hashtextextended('notification-installation:'||$1::text||':'||$2::text,0)) acquired`,
    [scope.participantId, scope.privacyDomainId],
  );
  if (result.rows[0]?.acquired !== true) rejected();
}

/** Bound checkout; a connection delivered after timeout is destroyed, never
 * allowed to start a late admission or consume a spare pool slot indefinitely. */
async function checkoutNotificationFence(pool: Pool): Promise<PoolClient> {
  let expired = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const pending = pool.connect().then((client) => {
    if (expired) {
      client.release(true);
      rejected();
    }
    return client;
  });
  try {
    return await Promise.race([
      pending,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          expired = true;
          reject(new ConfigurationRepositoryError('PC-DATA-6007'));
        }, 5000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/** Retain a fresh READ COMMITTED source transaction BEFORE the business owner
 * begins SERIALIZABLE. The pooled source slot bounds admission concurrency; a
 * private one-connection pool (same actual DB identity/configuration) avoids
 * borrowing a second slot from a saturated pool. Existing AtomicConfigurationMutation
 * still owns every effect, retry, authorization, receipt and idempotency decision.
 * Its ordinary current-channel reads now begin after this fence, so they observe
 * committed revocation rather than a pre-wait historical snapshot. */
export async function acquireNotificationInstallationFence(
  pool: Pool,
  context: MutationContext,
  verifier: IdentityRuntimeVerifier,
) {
  const client = await checkoutNotificationFence(pool);
  let failed = false,
    released = false;
  const fail = () => {
    failed = true;
  };
  client.on('error', fail);
  let mutationPool: Pool | undefined;
  let closing: Promise<void> | undefined;
  const started = performance.now();
  const release = (): Promise<void> =>
    (closing ??= (async () => {
      released = true;
      let uncertain = false;
      try {
        await mutationPool?.end();
      } catch {
        uncertain = true;
      }
      try {
        await client.query('rollback');
      } catch {
        uncertain = true;
      } finally {
        client.off('error', fail);
        try {
          client.release(true);
        } catch {
          uncertain = true;
        }
      }
      if (uncertain)
        throw new ConfigurationRepositoryError(
          'PC-OPS-9002',
          503,
          'notification-installation-fence-cleanup-unknown',
        );
    })());
  try {
    await client.query('begin isolation level read committed');
    await client.query('set local row_security=on');
    await client.query("set local statement_timeout='5s'");
    await client.query("set local lock_timeout='2s'");
    await client.query("set local idle_in_transaction_session_timeout='30s'");
    const a = context.authorization;
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)",
      [a.participantId, a.privacyDomainId, localOperationId(), context.actionIntentId],
    );
    const role = await client.query<{ allowed: boolean }>(
      `select not rolsuper and not rolbypassrls and current_setting('row_security')='on'
       and pg_has_role(current_user,'openpc_control_runtime','MEMBER') allowed from pg_roles where rolname=current_user`,
    );
    if (role.rows[0]?.allowed !== true) rejected();
    await authorizeNotificationPreparation(client, context, verifier);
    await lockNotificationInstallation(client, a);
    // Snapshot creation and all actual installation reads happen only after the
    // retained source fence. No readiness flag or fabricated construction escapes.
    mutationPool = new Pool({
      ...pool.options,
      password: pool.options.password,
      max: 1,
      connectionTimeoutMillis: 5000,
      statement_timeout: 5000,
      idle_in_transaction_session_timeout: 30000,
    });
    mutationPool.on('error', fail);
    const revalidate = async () => {
      if (failed || released || performance.now() - started >= 20000) rejected();
      await client.query('select 1');
      if (failed || released || performance.now() - started >= 20000) rejected();
    };
    await revalidate();
    return { mutationPool, revalidate, release };
  } catch (error) {
    try {
      await release();
    } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], 'Notification installation admission failed');
    }
    throw error;
  }
}

export interface NotificationChannelInstallation {
  readonly credential: NotificationChannelCredential;
  readonly channelTrust: NotificationGatewayInstalledTrust;
  readonly channelSigned: SignedNotificationChannelProfile;
  readonly verification?: {
    readonly trust: NotificationVerificationTrust;
    readonly signed: NotificationSignedReceipt;
  };
  readonly principalId: string;
  readonly workloadCredentialId: string;
  readonly workloadId: string;
  readonly workloadEpoch: string;
  readonly admissionReference: string;
}
export function notificationRequestAuthorityDigest(context: MutationContext): string {
  const a = context.authorization;
  return sha256({
    participantId: a.participantId,
    privacyDomainId: a.privacyDomainId,
    principalId: a.principalId,
    sessionId: a.sessionId,
    sessionEpoch: a.sessionEpoch,
    participantEpoch: a.participantEpoch,
    principalEpoch: a.principalEpoch,
    assignmentId: a.assignmentId,
    assignmentEpoch: a.assignmentEpoch,
    authorityEnvelopeId: a.authorityEnvelopeId,
    authorityEpoch: a.authorityEpoch,
    delegationEpoch: a.delegationEpoch,
  });
}
export async function notificationDatabaseTime(client: PoolClient): Promise<number> {
  const row = (
    await client.query<{ now: string }>(
      'select floor(extract(epoch from clock_timestamp())*1000)::text now',
    )
  ).rows[0];
  const now = Number(row?.now);
  if (!Number.isSafeInteger(now) || now < 0) rejected();
  return now;
}
function authenticateInstallation(value: NotificationChannelInstallation, now: number) {
  try {
    const installation = immutableJsonCopy(value);
    const credential = notificationChannelCredential.parse(installation.credential);
    const channel = verifyInstalledNotificationChannel(
      installation.channelTrust,
      installation.channelSigned,
    );
    if (
      channel.claims.participantId !== credential.participantId ||
      channel.claims.privacyDomainId !== credential.privacyDomainId ||
      channel.transport.credentialRef !== credential.credentialRef ||
      channel.transport.channel !== credential.channel ||
      channel.transport.destinationRef !== credential.destinationRef ||
      credential.state !== 'ACTIVE' ||
      credential.validFromMs > now ||
      credential.validUntilMs <= now ||
      channel.claims.validFromMs > now ||
      channel.claims.validUntilMs <= now ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        installation.principalId,
      ) ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        installation.workloadCredentialId,
      ) ||
      !/^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        installation.workloadId,
      ) ||
      !/^[1-9][0-9]{0,19}$/u.test(installation.workloadEpoch) ||
      !installation.admissionReference ||
      installation.admissionReference.length > 256
    )
      rejected();
    const verification = installation.verification
      ? verifyInstalledNotificationVerification(
          installation.verification.trust,
          installation.verification.signed,
          installation.channelTrust,
          installation.channelSigned,
        )
      : undefined;
    if (verification && verification.claims.credentialBindingDigest !== sha256(credential))
      rejected();
    return { installation, credential, channel, verification };
  } catch {
    return rejected();
  }
}
/** Privileged initial trust only. No endpoint, replacement, observation, activation
 * or intermediate business state is installed here. Exact replay cannot reactivate. */
export async function installInitialNotificationChannel(
  client: PoolClient,
  value: NotificationChannelInstallation,
): Promise<void> {
  if (
    (
      await client.query<{ allowed: boolean }>(
        "select pg_has_role(current_user,'openpc_control_owner','USAGE') allowed",
      )
    ).rows[0]?.allowed !== true
  )
    rejected();
  const {
    installation: i,
    credential: c,
    channel,
  } = authenticateInstallation(value, await notificationDatabaseTime(client));
  await lockAuthorityFence(client, c.participantId, {
    participant: [{ id: c.participantId }],
    privacy_domain: [{ id: c.privacyDomainId }],
    principal: [{ id: i.principalId }],
    credential: [{ id: i.workloadCredentialId }],
  });
  await lockNotificationInstallation(client, c, true);
  await currentNotificationWorkload(client, i, c.participantId, c.privacyDomainId);
  const previous = await client.query(
    'select * from control.installed_notification_channel where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3',
    [c.participantId, c.privacyDomainId, c.credentialRef],
  );
  if (previous.rowCount) {
    if (
      previous.rowCount !== 1 ||
      previous.rows[0].state !== 'ACTIVE' ||
      sha256(installationFromRow(previous.rows[0])) !== sha256(i)
    )
      rejected();
    return;
  }
  await client.query(
    `insert into control.installed_notification_channel
    (participant_id,privacy_domain_id,credential_ref,channel,destination_ref,channel_profile_digest,credential,channel_trust,channel_signed,
     verification_trust,verification_signed,principal_id,workload_credential_id,workload_epoch,admission_reference,workload_id)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
    [
      c.participantId,
      c.privacyDomainId,
      c.credentialRef,
      c.channel,
      c.destinationRef,
      channel.signedProfileDigest,
      c,
      i.channelTrust,
      i.channelSigned,
      i.verification?.trust ?? null,
      i.verification?.signed ?? null,
      i.principalId,
      i.workloadCredentialId,
      i.workloadEpoch,
      i.admissionReference,
      i.workloadId,
    ],
  );
}
interface InstallationRow {
  credential: NotificationChannelCredential;
  channel_trust: NotificationGatewayInstalledTrust;
  channel_signed: SignedNotificationChannelProfile;
  verification_trust: NotificationVerificationTrust | null;
  verification_signed: NotificationSignedReceipt | null;
  principal_id: string;
  workload_credential_id: string;
  workload_id: string;
  workload_epoch: string;
  admission_reference: string;
  state: string;
}
function installationFromRow(row: InstallationRow): NotificationChannelInstallation {
  return {
    credential: row.credential,
    channelTrust: row.channel_trust,
    channelSigned: row.channel_signed,
    ...(row.verification_trust && row.verification_signed
      ? { verification: { trust: row.verification_trust, signed: row.verification_signed } }
      : {}),
    principalId: row.principal_id,
    workloadCredentialId: row.workload_credential_id,
    workloadId: row.workload_id,
    workloadEpoch: row.workload_epoch,
    admissionReference: row.admission_reference,
  };
}
async function currentNotificationWorkload(
  client: PoolClient,
  i: NotificationChannelInstallation,
  participantId: string,
  privacyDomainId: string,
) {
  const current = await client.query(
    `select 1 from control.participant p join control.privacy_domain d on d.participant_id=p.participant_id
    join control.principal a on a.participant_id=p.participant_id join control.credential c on c.participant_id=a.participant_id and c.principal_id=a.principal_id
    where p.participant_id=$1 and d.privacy_domain_id=$2 and a.principal_id=$3 and c.credential_id=$4
      and p.state='ACTIVE' and d.state='ACTIVE' and a.state='ACTIVE' and a.kind='WORKLOAD'
      and c.state='ACTIVE' and c.kind='WORKLOAD_MTLS' and c.audience=$6 and c.credential_epoch=$5
      and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()`,
    [
      participantId,
      privacyDomainId,
      i.principalId,
      i.workloadCredentialId,
      i.workloadEpoch,
      i.workloadId,
    ],
  );
  if (current.rowCount !== 1) rejected();
}
/** Read under the transaction's retained installation/Identity fences. The caller
 * owns actor policy admission; no secret bytes or network effects are returned. */
export async function currentNotificationChannel(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string },
  credentialRef: string,
) {
  const values = [scope.participantId, scope.privacyDomainId, credentialRef];
  // Discover immutable workload dependencies before acquiring business row locks.
  const discovered = await client.query<InstallationRow>(
    'select * from control.installed_notification_channel where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3',
    values,
  );
  if (discovered.rowCount !== 1 || !discovered.rows[0]) rejected();
  const i = installationFromRow(discovered.rows[0]);
  await lockAuthorityFence(client, scope.participantId, {
    participant: [{ id: scope.participantId }],
    privacy_domain: [{ id: scope.privacyDomainId }],
    principal: [{ id: i.principalId }],
    credential: [{ id: i.workloadCredentialId }],
  });
  await lockNotificationInstallation(client, scope);
  const selected = await client.query<InstallationRow>(
    'select * from control.installed_notification_channel where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3',
    values,
  );
  if (
    selected.rowCount !== 1 ||
    selected.rows[0]?.state !== 'ACTIVE' ||
    sha256(installationFromRow(selected.rows[0])) !== sha256(i)
  )
    rejected();
  const result = authenticateInstallation(i, await notificationDatabaseTime(client));
  if (
    result.credential.participantId !== scope.participantId ||
    result.credential.privacyDomainId !== scope.privacyDomainId ||
    result.credential.credentialRef !== credentialRef
  )
    rejected();
  await currentNotificationWorkload(client, i, scope.participantId, scope.privacyDomainId);
  return result;
}
/** Preparation verifies the existing Identity runtime proof; the shared candidate
 * store is intentionally not used because it requires maker/checker. Fresh step-up
 * is consumed only by the subsequent AtomicConfigurationMutation. */
export async function authorizeNotificationPreparation(
  client: PoolClient,
  context: MutationContext,
  verifier: IdentityRuntimeVerifier,
) {
  await fenceConfigurationMutation(client, context, false);
  if (
    !['IDENTITY_RUNTIME', 'IDENTITY_RUNTIME_STEP_UP'].includes(context.authorization.evidenceKind)
  )
    rejected();
  const bound =
    context.authorization.evidenceKind === 'IDENTITY_RUNTIME_STEP_UP'
      ? { ...context, authorization: stepUpRuntimeAssertion(context.authorization) }
      : context;
  await verifyConfigurationRuntimeAuthorization(
    client,
    bound,
    Buffer.from(sha256(context.candidate).slice(7), 'hex'),
    verifier,
  );
}
function replacementConstruction(
  before: Readonly<NotificationEndpointBusinessState>,
  credential: NotificationChannelCredential,
  channelProfileDigest: string,
) {
  return {
    binding: {
      ...endpointBinding(before),
      revision: String(BigInt(before.revision) + 1n),
      channel: credential.channel,
      destinationRef: credential.destinationRef,
      credentialRef: credential.credentialRef,
      channelProfileDigest,
    },
    credential,
  };
}

/** Informational choices from a scoped READ snapshot. PATCH rechecks the current
 * installation and workload under its own real authority and retained fences. */
export async function readNotificationReplacementChoices(
  client: PoolClient,
  before: Readonly<NotificationEndpointBusinessState>,
) {
  if (before.state === 'RETIRED') rejected();
  const rows = await client.query<InstallationRow>(
    `select * from control.installed_notification_channel
     where participant_id=$1 and privacy_domain_id=$2 and state='ACTIVE'
     order by credential_ref limit 65`,
    [before.participantId, before.privacyDomainId],
  );
  if (rows.rows.length > 64) rejected();
  const now = await notificationDatabaseTime(client);
  const items = [];
  for (const row of rows.rows) {
    const installation = installationFromRow(row);
    const { credential, channel } = authenticateInstallation(installation, now);
    await currentNotificationWorkload(
      client,
      installation,
      before.participantId,
      before.privacyDomainId,
    );
    const construction = replacementConstruction(before, credential, channel.signedProfileDigest);
    items.push({
      channel: credential.channel,
      destinationRef: credential.destinationRef,
      replacementDigest: notificationEndpointReplacementDigest(
        endpointBinding(before),
        construction,
      ),
    });
  }
  return items;
}

export class NotificationEndpointAdmission {
  constructor(
    private readonly pool: Pool,
    private readonly verifier: IdentityRuntimeVerifier,
  ) {}
  async resolveCreate(client: PoolClient, context: MutationContext, input: EndpointCreateInput) {
    endpointRequest(context, 'CREATE', input);
    const a = context.authorization;
    const selected = await client.query<{ credential_ref: string }>(
      `select credential_ref from control.installed_notification_channel
      where participant_id=$1 and privacy_domain_id=$2 and channel=$3 and destination_ref=$4 and state='ACTIVE'`,
      [a.participantId, a.privacyDomainId, input.channel, input.destinationRef],
    );
    if (selected.rowCount !== 1 || !selected.rows[0]) rejected();
    const { credential, channel } = await currentNotificationChannel(
      client,
      a,
      selected.rows[0].credential_ref,
    );
    const binding = {
      participantId: a.participantId,
      privacyDomainId: a.privacyDomainId,
      endpointId: context.resourceId,
      revision: '1',
      channel: credential.channel,
      destinationRef: credential.destinationRef,
      channelProfileDigest: channel.signedProfileDigest,
      credentialRef: credential.credentialRef,
    };
    return assertNotificationEndpointConstruction(
      binding,
      { binding, credential },
      await notificationDatabaseTime(client),
    );
  }
  async prepareReplacement(context: MutationContext, credentialRef: string): Promise<string> {
    const input = endpointRequest(context, 'UPDATE', context.candidate as EndpointUpdateInput);
    return runScopedTransaction(
      this.pool,
      { ...context.authorization, actionIntentId: context.actionIntentId },
      localOperationId,
      async (client) => {
        await authorizeNotificationPreparation(client, context, this.verifier);
        const { credential, channel } = await currentNotificationChannel(
          client,
          context.authorization,
          credentialRef,
        );
        const before = await readNotificationEndpointBusinessState(client, {
          participantId: context.authorization.participantId,
          privacyDomainId: context.authorization.privacyDomainId,
          aggregateId: context.resourceId,
        });
        if (!before || before.revision !== context.expectedRevision || before.state === 'RETIRED')
          rejected();
        const predecessor = endpointBinding(before);
        const construction = replacementConstruction(
          before,
          credential,
          channel.signedProfileDigest,
        );
        const digest = notificationEndpointReplacementDigest(predecessor, construction);
        if (digest !== input.replacementDigest) rejected();
        await this.retainReplacement(
          client,
          context,
          before,
          construction,
          digest,
          channel.claims.validUntilMs,
        );
        await this.resolveReplacement(client, context, before, input);
        return digest;
      },
    );
  }
  private async retainReplacement(
    client: PoolClient,
    context: MutationContext,
    before: Readonly<NotificationEndpointBusinessState>,
    construction: ReturnType<typeof replacementConstruction>,
    digest: string,
    channelExpiresAt: number,
  ) {
    const predecessor = endpointBinding(before);
    const credential = construction.credential;
    const now = await notificationDatabaseTime(client),
      a = context.authorization;
    const expires = Math.min(now + 300000, credential.validUntilMs, channelExpiresAt);
    await client.query(
      `insert into control.notification_endpoint_candidate
    (participant_id,privacy_domain_id,endpoint_id,replacement_digest,predecessor,construction,principal_id,session_id,authority_digest,expires_at_ms)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) on conflict do nothing`,
      [
        a.participantId,
        a.privacyDomainId,
        context.resourceId,
        digest,
        predecessor,
        construction,
        a.principalId,
        a.sessionId,
        notificationRequestAuthorityDigest(context),
        expires,
      ],
    );
  }
  async resolveReplacement(
    client: PoolClient,
    context: MutationContext,
    before: Readonly<NotificationEndpointBusinessState>,
    input: EndpointUpdateInput,
  ): Promise<NotificationEndpointConstruction> {
    endpointRequest(context, 'UPDATE', input);
    const a = context.authorization;
    // Candidate rows are INSERT-only: the SQL guard rejects UPDATE and DELETE.
    // Their immutable identity needs no row-lock privilege. Current installation
    // and predecessor/expiry checks below remain mandatory.
    const readCandidate = () =>
      client.query<{
        construction: {
          binding: ReturnType<typeof endpointBinding>;
          credential: NotificationChannelCredential;
        };
        predecessor: ReturnType<typeof endpointBinding>;
        authority_digest: string;
        expires_at_ms: string;
      }>(
        `select * from control.notification_endpoint_candidate where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3 and replacement_digest=$4 and principal_id=$5 and session_id=$6`,
        [
          a.participantId,
          a.privacyDomainId,
          context.resourceId,
          input.replacementDigest,
          a.principalId,
          a.sessionId,
        ],
      );
    let candidate = await readCandidate();
    if (candidate.rowCount === 0) {
      const installed = await client.query<{ credential_ref: string }>(
        `select credential_ref from control.installed_notification_channel
         where participant_id=$1 and privacy_domain_id=$2 and state='ACTIVE'
         order by credential_ref limit 65`,
        [a.participantId, a.privacyDomainId],
      );
      if (installed.rows.length > 64) rejected();
      const matches = [];
      for (const row of installed.rows) {
        const { credential, channel } = await currentNotificationChannel(
          client,
          a,
          row.credential_ref,
        );
        const construction = replacementConstruction(
          before,
          credential,
          channel.signedProfileDigest,
        );
        if (
          notificationEndpointReplacementDigest(endpointBinding(before), construction) ===
          input.replacementDigest
        )
          matches.push({ construction, expiresAt: channel.claims.validUntilMs });
      }
      if (matches.length !== 1 || !matches[0]) rejected();
      const selected = matches[0];
      await this.retainReplacement(
        client,
        context,
        before,
        selected.construction,
        input.replacementDigest,
        selected.expiresAt,
      );
      // Read the persisted candidate through the same actor/session binding below.
      candidate = await readCandidate();
    }
    const row = candidate.rows[0],
      now = await notificationDatabaseTime(client);
    if (
      candidate.rowCount !== 1 ||
      !row ||
      row.authority_digest !== notificationRequestAuthorityDigest(context) ||
      Number(row.expires_at_ms) <= now ||
      sha256(row.predecessor) !== sha256(endpointBinding(before))
    )
      rejected();
    const { credential, channel } = await currentNotificationChannel(
      client,
      a,
      row.construction.binding.credentialRef,
    );
    if (
      sha256(credential) !== sha256(row.construction.credential) ||
      channel.signedProfileDigest !== row.construction.binding.channelProfileDigest ||
      notificationEndpointReplacementDigest(endpointBinding(before), row.construction) !==
        input.replacementDigest
    )
      rejected();
    return assertNotificationEndpointConstruction(row.construction.binding, row.construction, now);
  }
}
