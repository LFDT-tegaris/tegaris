import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { z } from 'zod';
import { canonicalJson, sha256 } from '../../services/control-api/src/configuration/digest.ts';
import { verifyInstalledSecretRecipient } from '../../packages/security-kernel/src/secret-recipient/profile.ts';
import { evidenceKeyId } from '../../packages/security-kernel/src/business-transition/cose.ts';
import { isExactSigningSecretReference } from '../../packages/security-kernel/src/business-transition/secret-reference.ts';
import { effectiveProjectionCanonicalJson } from './installation-effective-projection.mjs';
import {
  readInstallationProcessIdentity,
  InstallationProcessObservationError,
} from './installation-process-observation.mjs';

const fail = () => {
  throw new Error('OPS_SECRET_ASSOCIATION_REJECTED');
};
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const uint = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);
const ms = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const containerIdentity = z.strictObject({
  id: z.string().regex(/^[0-9a-f]{64}$/u),
  imageId: digest,
  owner: z.string().min(1).max(128),
  startedAt: z.string().min(1).max(64),
  engineEndpoint: z.literal('unix:///var/run/docker.sock'),
  networkId: z.string().regex(/^[0-9a-f]{64}$/u),
  address: z.ipv4(),
});
const processIdentity = z.strictObject({
  pid: z.number().int().positive(),
  startTicks: uint,
  bootId: z.string().uuid(),
  startedAtMs: ms,
  executable: z.string(),
  uid: z.number().int().min(0),
  container: containerIdentity.optional(),
});
export const operationsSecretAssociationSchema = z.strictObject({
  profile: z.literal('test'),
  associationId: uuid,
  environmentId: z.string().regex(/^[a-z][a-z0-9-]{2,31}$/u),
  participantId: uuid,
  privacyDomainId: uuid,
  generationId: uuid,
  operationsInstallationDigest: digest,
  candidateDigest: digest,
  recipientBindingDigest: digest,
  recipientInstallationDigest: digest,
  recipientGeneration: uint.refine((v) => v !== '0'),
  recipientIssuerSpkiHex: z.string().regex(/^3059[0-9a-f]{178}$/u),
  recipientPayloadHex: z.string().regex(/^(?:[0-9a-f]{2}){1,65536}$/u),
  recipientCoseHex: z.string().regex(/^(?:[0-9a-f]{2}){65,66560}$/u),
  field: z.literal('postgres.candidateIndexDsnSecretRef'),
  consumerId: z.literal('LS-FACT-BRIDGE'),
  storeId: z.literal('STORE-CANDIDATE-INDEX-PG'),
  reference: z.string().max(512),
  version: z.string().max(96),
  referenceFingerprint: digest,
  fingerprint: digest,
  principalId: uuid,
  workloadCredentialId: uuid,
  workloadCredentialEpoch: uint,
  consumerInstanceId: uuid,
  consumerStartedAtMs: ms,
  consumerProcess: processIdentity,
  observerInstanceId: uuid,
  observerStartedAtMs: ms,
  observerProcess: processIdentity,
  observerBackendPid: z.number().int().positive(),
  observerBackendStart: z.string().min(1).max(64),
  issuerSpkiHex: z.string().regex(/^3059[0-9a-f]{178}$/u),
  issuerKeyId: digest,
  issuerEpoch: uint.refine((v) => v !== '0'),
  issuerValidFromMs: ms,
  issuerValidUntilMs: ms,
});
export function parseOperationsSecretAssociation(input) {
  const value = JSON.parse(effectiveProjectionCanonicalJson(input));
  const result = operationsSecretAssociationSchema.safeParse(value);
  if (!result.success) fail();
  const association = result.data;
  if (
    association.consumerProcess.uid !== 65532 ||
    !association.consumerProcess.container ||
    association.consumerProcess.executable !== '/usr/local/bin/openpc-fact-local-runtime' ||
    !isExactSigningSecretReference(association.reference, association.version) ||
    !association.reference.startsWith('secret://test-memory-resolver/') ||
    !/^[A-Za-z0-9._-]{1,96}$/u.test(association.version) ||
    ['latest', 'current'].includes(association.version.toLowerCase()) ||
    association.consumerStartedAtMs !== association.consumerProcess.startedAtMs ||
    association.observerStartedAtMs !== association.observerProcess.startedAtMs ||
    association.issuerValidFromMs >= association.issuerValidUntilMs ||
    evidenceKeyId(Buffer.from(association.issuerSpkiHex, 'hex')) !== association.issuerKeyId ||
    sha256(Buffer.from(association.reference)) !== association.referenceFingerprint
  )
    fail();
  return Object.freeze(association);
}

/** Host installation identity, not caller-declared process readiness. Linux is
 * the supported deployment substrate; missing procfs/getconf fails closed. */
export async function readOperationsProcessIdentity(pid, container) {
  if (!Number.isSafeInteger(pid) || pid < 1) fail();
  let executableRead;
  if (container !== undefined) {
    const expected = containerIdentity.parse(container);
    // Host installation observer only. No Docker socket or capabilities are
    // given to the publisher/consumer. Read bounded identity fields, never env,
    // commands, secret mounts or unrestricted inspection documents.
    const format =
      '{"id":{{json .Id}},"image":{{json .Image}},"pid":{{json .State.Pid}},"started":{{json .State.StartedAt}},"running":{{json .State.Running}},"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},"dead":{{json .State.Dead}},"oom":{{json .State.OOMKilled}},"user":{{json .Config.User}},"path":{{json .Path}},"args":{{json .Args}},"owner":{{json (index .Config.Labels "io.openpc.fixture.owner")}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"privileged":{{json .HostConfig.Privileged}},"capadd":{{json .HostConfig.CapAdd}},"capdrop":{{json .HostConfig.CapDrop}},"pidmode":{{json .HostConfig.PidMode}},"networks":{{json .NetworkSettings.Networks}}}';
    const result = await promisify(execFile)(
      'docker',
      ['--host', expected.engineEndpoint, 'inspect', '--format', format, expected.id],
      { timeout: 3000, maxBuffer: 8192 },
    );
    const actual = JSON.parse(result.stdout.trim());
    const networks = Object.values(actual.networks ?? {});
    if (
      actual.id !== expected.id ||
      actual.image !== expected.imageId ||
      actual.pid !== pid ||
      actual.started !== expected.startedAt ||
      actual.running !== true ||
      actual.paused !== false ||
      actual.restarting !== false ||
      actual.dead !== false ||
      actual.oom !== false ||
      actual.user !== '65532:65532' ||
      actual.path !== '/usr/local/bin/openpc-fact-local-runtime' ||
      canonicalJson(actual.args) !== '[]' ||
      actual.owner !== expected.owner ||
      actual.readonly !== true ||
      actual.privileged !== false ||
      (actual.capadd?.length ?? 0) !== 0 ||
      canonicalJson(actual.capdrop) !== '["ALL"]' ||
      actual.pidmode !== '' ||
      networks.length !== 1 ||
      networks[0]?.NetworkID !== expected.networkId ||
      networks[0]?.IPAddress !== expected.address
    )
      fail();
    executableRead = Promise.resolve(actual.path);
  }
  try {
    return processIdentity.parse({
      ...(await readInstallationProcessIdentity(pid, executableRead)),
      ...(container === undefined ? {} : { container: containerIdentity.parse(container) }),
    });
  } catch (error) {
    if (error instanceof InstallationProcessObservationError) return fail();
    throw error;
  }
}
export async function assertOperationsProcessIdentity(expected) {
  if (
    canonicalJson(await readOperationsProcessIdentity(expected.pid, expected.container)) !==
    canonicalJson(expected)
  )
    fail();
}
export function operationsSecretRecipientPins(a) {
  return Object.freeze({
    issuerSpkiDer: Buffer.from(a.recipientIssuerSpkiHex, 'hex'),
    signedBindingDigest: a.recipientBindingDigest,
    installationDigest: a.recipientInstallationDigest,
    environmentId: a.environmentId,
    generation: a.recipientGeneration,
    participantId: a.participantId,
    privacyDomainId: a.privacyDomainId,
    principalId: a.principalId,
    workloadCredentialId: a.workloadCredentialId,
    workloadCredentialEpoch: a.workloadCredentialEpoch,
  });
}

/** Privileged initial installation only. The caller supplies independently
 * custodied TEST observer public trust, not values copied from an observation.
 * It retains this dedicated observer connection/lease for the instance lifetime.
 * No runtime/HTTP installation and no replacement/reactivation are supported. */
export async function installOperationsSecretAssociation(client, input) {
  const a = parseOperationsSecretAssociation(input);
  const owner = await client.query(
    "select pg_has_role(current_user,'openpc_control_owner','USAGE') allowed,current_setting('transaction_isolation') isolation",
  );
  if (owner.rows[0]?.allowed !== true || owner.rows[0]?.isolation !== 'read committed') fail();
  await client.query('select openpc.assert_request_context(true)');
  const lock = await client.query(
    "select pg_try_advisory_xact_lock(hashtextextended('operations-generation:'||$1,0)) held",
    [a.environmentId],
  );
  if (lock.rows[0]?.held !== true) fail();
  await Promise.all([
    assertOperationsProcessIdentity(a.consumerProcess),
    assertOperationsProcessIdentity(a.observerProcess),
  ]);
  const source = await client.query(
    `select i.installation_digest,g.candidate_digest,g.state,
    g.candidate->'configuration' configuration,i.installation->'pins'->>'profile' profile,
    floor(extract(epoch from clock_timestamp())*1000)::text now,
    pg_backend_pid() pid,openpc.operations_observer_backend_start() started
    from control.operations_installation i join control.operations_generation g using(environment_id)
    where i.environment_id=$1 and g.generation_id=$2 and i.state='ACTIVE'
      and i.participant_id=$3 and i.privacy_domain_id=$4 for share of i,g`,
    [a.environmentId, a.generationId, a.participantId, a.privacyDomainId],
  );
  const row = source.rows[0];
  if (
    source.rowCount !== 1 ||
    row.state !== 'STAGED' ||
    row.profile !== 'test' ||
    row.installation_digest !== a.operationsInstallationDigest ||
    row.candidate_digest !== a.candidateDigest ||
    row.configuration.postgres.candidateIndexDsnSecretRef !== a.reference ||
    row.pid !== a.observerBackendPid ||
    row.started !== a.observerBackendStart ||
    Number(row.now) < a.issuerValidFromMs ||
    Number(row.now) >= a.issuerValidUntilMs
  )
    fail();
  const recipient = verifyInstalledSecretRecipient(
    operationsSecretRecipientPins(a),
    Buffer.from(a.recipientPayloadHex, 'hex'),
    Buffer.from(a.recipientCoseHex, 'hex'),
    Number(row.now),
  );
  if (recipient.reference !== a.reference || recipient.version !== a.version) fail();
  const installed = await client.query(
    `select 1 from control.installed_secret_recipient where
    participant_id=$1 and privacy_domain_id=$2 and consumer_id='LS-FACT-BRIDGE' and store_id='STORE-CANDIDATE-INDEX-PG'
    and state='ACTIVE' and binding_digest=$3 and installation_digest=$4 and generation=$5
    and payload=$6 and cose=$7 and issuer_spki=$8 for share`,
    [
      a.participantId,
      a.privacyDomainId,
      a.recipientBindingDigest,
      a.recipientInstallationDigest,
      a.recipientGeneration,
      Buffer.from(a.recipientPayloadHex, 'hex'),
      Buffer.from(a.recipientCoseHex, 'hex'),
      Buffer.from(a.recipientIssuerSpkiHex, 'hex'),
    ],
  );
  if (installed.rowCount !== 1) fail();
  const bytes = Buffer.from(effectiveProjectionCanonicalJson(a));
  const prior = await client.query(
    'select association_bytes,state from control.operations_secret_association where association_id=$1',
    [a.associationId],
  );
  if (prior.rowCount) {
    if (
      prior.rowCount !== 1 ||
      prior.rows[0].state !== 'ACTIVE' ||
      !prior.rows[0].association_bytes.equals(bytes)
    )
      fail();
  } else
    await client.query(
      `insert into control.operations_secret_association
    (association_id,participant_id,privacy_domain_id,environment_id,generation_id,association,association_bytes,association_digest)
    values($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        a.associationId,
        a.participantId,
        a.privacyDomainId,
        a.environmentId,
        a.generationId,
        a,
        bytes,
        sha256(bytes),
      ],
    );
  return { associationId: a.associationId, associationDigest: sha256(bytes) };
}

export async function loadOperationsSecretAssociation(client, associationId) {
  uuid.parse(associationId);
  const selected = await client.query(
    'select association,state from control.operations_secret_association where association_id=$1',
    [associationId],
  );
  if (selected.rowCount !== 1 || selected.rows[0].state !== 'ACTIVE') fail();
  return parseOperationsSecretAssociation(selected.rows[0].association);
}
