import type { PoolClient } from 'pg';
import { z } from 'zod';
import { qualificationCanonicalJson as canonical } from '../../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import {
  deploymentCopy,
  parseQualificationDeploymentPins,
  qualificationDeploymentDigest as digest,
  qualificationDeploymentSelectionSchema,
  qualificationDeploymentIntentSchema,
  qualificationDeploymentPeerSchema,
  qualificationDeploymentPinsSchema,
  qualificationDeploymentMeasurementSchema,
  readCollectedQualificationDeployment,
  type QualificationDeploymentSelection,
  type QualificationDeploymentIntent,
  type QualificationDeploymentPeer,
  type QualificationDeploymentPins,
  type CollectedQualificationDeployment,
  type QualificationDeploymentMeasurement,
} from '../../../../../scripts/operations/qualification-deployment-observation.mjs';
export type {
  QualificationDeploymentSelection,
  QualificationDeploymentIntent,
  QualificationDeploymentPins,
};
const ms = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const hash = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const qualificationDeploymentRequestSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    observationId: z.uuidv7(),
    operationId: z.uuidv7(),
    installationDigest: hash,
    pins: qualificationDeploymentPinsSchema,
    separatedPins: z.array(qualificationDeploymentPinsSchema).max(8),
    issuedAtMs: ms,
    deadlineAtMs: ms,
  })
  .superRefine((v, c) => {
    const peers = [v.pins, ...v.separatedPins];
    if (
      v.deadlineAtMs <= v.issuedAtMs ||
      v.deadlineAtMs - v.issuedAtMs > 30000 ||
      v.installationDigest !== digest(v.pins) ||
      canonical(v.separatedPins.map((p) => p.installationId).sort()) !==
        canonical([...v.pins.separatedFrom].sort()) ||
      v.separatedPins.some(
        (p) =>
          p.participantId !== v.pins.participantId ||
          p.privacyDomainId !== v.pins.privacyDomainId ||
          p.environmentId !== v.pins.environmentId ||
          p.operationsInstallationDigest !== v.pins.operationsInstallationDigest ||
          p.daemonId !== v.pins.daemonId,
      ) ||
      ['principalId', 'credentialId', 'keyDigest', 'certificateDigest'].some(
        (field) =>
          new Set(peers.map((p) => p.peer[field as keyof QualificationDeploymentPeer])).size !==
          peers.length,
      )
    )
      c.addIssue({ code: 'custom', message: 'Deployment source closure rejected' });
  });
export type QualificationDeploymentRequest = z.infer<typeof qualificationDeploymentRequestSchema>;
export const qualificationDeploymentObservationSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    observationId: z.uuidv7(),
    requestDigest: hash,
    state: z.enum(['OBSERVED', 'HISTORICAL', 'UNKNOWN']),
    measurement: qualificationDeploymentMeasurementSchema.nullable(),
    identityRecheckedAtMs: ms.nullable(),
    retainedAtMs: ms,
  })
  .superRefine((v, c) => {
    if (
      (v.state === 'UNKNOWN') !== (v.measurement === null) ||
      (v.state === 'UNKNOWN' && v.identityRecheckedAtMs !== null) ||
      (v.state === 'OBSERVED' &&
        (v.identityRecheckedAtMs === null ||
          v.identityRecheckedAtMs < v.measurement!.completedAtMs)) ||
      (v.state === 'HISTORICAL' && v.identityRecheckedAtMs !== null) ||
      (v.identityRecheckedAtMs !== null && v.identityRecheckedAtMs > v.retainedAtMs)
    )
      c.addIssue({ code: 'custom', message: 'Deployment observation rejected' });
  });
export type QualificationDeploymentObservation = z.infer<
  typeof qualificationDeploymentObservationSchema
>;
function assertMeasurementOriginal(
  original: QualificationDeploymentRequest,
  m: QualificationDeploymentMeasurement,
) {
  if (
    m.observationId !== original.observationId ||
    m.requestDigest !== digest(original) ||
    m.installationDigest !== original.installationDigest ||
    m.startedAtMs < original.issuedAtMs ||
    m.completedAtMs >= original.deadlineAtMs ||
    m.daemon.id !== original.pins.daemonId ||
    m.daemon.hostBootId !== original.pins.installedProcess.process.bootId ||
    canonical(m.separatedInstances.map((v) => v.installationId).sort()) !==
      canonical([...original.pins.separatedFrom].sort())
  )
    fail();
  const instances = [m.instance, ...m.separatedInstances];
  for (const p of [original.pins, ...original.separatedPins]) {
    const instance = instances.find((v) => v.installationId === p.installationId);
    if (
      !instance ||
      instance.containerId !== p.containerId ||
      instance.imageId !== p.imageId ||
      instance.startedAt !== p.containerStartedAt ||
      canonical(instance.process) !== canonical(p.installedProcess) ||
      instance.networkId !== p.networkId ||
      instance.address !== p.address ||
      instance.memoryBytes !== p.memoryBytes ||
      instance.nanoCpus !== p.nanoCpus ||
      instance.pidsLimit !== p.pidsLimit
    )
      fail();
  }
  if (
    m.instance.installationId !== original.pins.installationId ||
    m.artifacts.length !== original.pins.artifacts.length ||
    new Set(m.artifacts.map((v) => v.path)).size !== m.artifacts.length ||
    m.artifacts.some(
      (v) =>
        !original.pins.artifacts.some(
          (p) =>
            p.path === v.path && p.digest === v.digest && v.bytes > 0 && v.bytes <= p.maximumBytes,
        ),
    )
  )
    fail();
}
function fail(): never {
  throw new Error('QUALIFICATION_DEPLOYMENT_REJECTED');
}
const bytes = (v: unknown) => Buffer.from(canonical(v));
async function context(
  c: PoolClient,
  selection: QualificationDeploymentSelection,
  bootstrap = false,
) {
  const s = deploymentCopy(qualificationDeploymentSelectionSchema.parse(selection));
  await c.query('select openpc.assert_request_context(true)');
  const read = async () =>
    (
      await c.query<{ role: string; tx: string; request: string; valid: boolean }>(
        `select current_user::text role,pg_current_xact_id()::text tx,openpc.current_operation_id()::text request,
    openpc.current_participant_id()=$1::uuid and openpc.current_privacy_domain_id()=$2::uuid
    and current_setting('transaction_isolation')='read committed' and current_setting('row_security')='on'
    and openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' valid`,
        [s.participantId, s.privacyDomainId],
      )
    ).rows[0];
  const original = await read();
  if (
    !original?.valid ||
    !(
      bootstrap
        ? ['openpc_operations_qualification_bootstrap']
        : ['openpc_control_owner', 'openpc_operations_qualification_owner']
    ).includes(original.role)
  )
    fail();
  return async () => {
    const now = await read();
    if (
      !now?.valid ||
      now.role !== original.role ||
      now.tx !== original.tx ||
      now.request !== original.request
    )
      fail();
  };
}
const values = (s: QualificationDeploymentSelection) => [
  s.installationId,
  s.participantId,
  s.privacyDomainId,
];
async function installationLock(
  c: PoolClient,
  s: QualificationDeploymentSelection,
  exclusive = false,
) {
  await c.query(
    `select ${exclusive ? 'pg_advisory_xact_lock' : 'pg_advisory_xact_lock_shared'}(hashtextextended('qualification-deployment:'||$1,0))`,
    [s.installationId],
  );
}
async function observationLock(c: PoolClient, id: string) {
  z.uuidv7().parse(id);
  await c.query(
    "select pg_advisory_xact_lock(hashtextextended('qualification-deployment-observation:'||$1,0))",
    [id],
  );
}
async function now(c: PoolClient) {
  return ms.parse(
    Number(
      (
        await c.query<{ ms: string }>(
          'select floor(extract(epoch from clock_timestamp())*1000)::text ms',
        )
      ).rows[0]?.ms,
    ),
  );
}
async function installed(c: PoolClient, s: QualificationDeploymentSelection) {
  const r = await c.query<{
    pins: unknown;
    pins_bytes: Buffer;
    pins_digest: string;
    state: string;
  }>(
    'select pins,pins_bytes,pins_digest,state from control.qualification_deployment_installation where installation_id=$1 and participant_id=$2 and privacy_domain_id=$3 for share',
    values(s),
  );
  if (r.rowCount !== 1) fail();
  const row = r.rows[0]!,
    pins = parseQualificationDeploymentPins(row.pins);
  if (
    pins.installationId !== s.installationId ||
    pins.participantId !== s.participantId ||
    pins.privacyDomainId !== s.privacyDomainId ||
    !bytes(pins).equals(row.pins_bytes) ||
    digest(pins) !== row.pins_digest
  )
    fail();
  return { pins, digest: row.pins_digest, state: row.state };
}
async function liveEnvironment(c: PoolClient, p: QualificationDeploymentPins) {
  const r = await c.query(
    "select 1 from control.operations_installation where environment_id=$1 and participant_id=$2 and privacy_domain_id=$3 and state='ACTIVE' and installation_digest=$4 for share",
    [p.environmentId, p.participantId, p.privacyDomainId, p.operationsInstallationDigest],
  );
  if (r.rowCount !== 1) fail();
}
/** Initial public deployment trust. It does not authenticate source authors or
 * create executor/reviewer/signer capability. This API cannot replace/revive. */
export async function installInitialQualificationDeployment(c: PoolClient, input: unknown) {
  const p = parseQualificationDeploymentPins(input),
    confirm = await context(
      c,
      {
        installationId: p.installationId,
        participantId: p.participantId,
        privacyDomainId: p.privacyDomainId,
      },
      true,
    );
  await installationLock(c, p, true);
  await liveEnvironment(c, p);
  const prior = await c.query<{ pins_bytes: Buffer; state: string }>(
    'select pins_bytes,state from control.qualification_deployment_installation where installation_id=$1',
    [p.installationId],
  );
  if (prior.rowCount) {
    if (
      prior.rowCount !== 1 ||
      prior.rows[0]!.state !== 'ACTIVE' ||
      !prior.rows[0]!.pins_bytes.equals(bytes(p))
    )
      fail();
  } else
    await c.query(
      `insert into control.qualification_deployment_installation(installation_id,participant_id,privacy_domain_id,environment_id,pins,pins_bytes,pins_digest) values($1,$2,$3,$4,$5,$6,$7)`,
      [...values(p), p.environmentId, p, bytes(p), digest(p)],
    );
  await confirm();
  return digest(p);
}
export async function withdrawQualificationDeployment(
  c: PoolClient,
  selection: QualificationDeploymentSelection,
) {
  const s = deploymentCopy(qualificationDeploymentSelectionSchema.parse(selection)),
    confirm = await context(c, s, true);
  await installationLock(c, s, true);
  const r = await c.query(
    `update control.qualification_deployment_installation set state='REVOKED' where installation_id=$1 and participant_id=$2 and privacy_domain_id=$3 returning state`,
    values(s),
  );
  if (r.rowCount !== 1) fail();
  await confirm();
}
async function request(c: PoolClient, s: QualificationDeploymentSelection, observationId: string) {
  const r = await c.query<{
    request: unknown;
    request_bytes: Buffer;
    request_digest: string;
    operation_id: string;
  }>(
    'select request,request_bytes,request_digest,operation_id from control.qualification_deployment_attempt where observation_id=$1 and installation_id=$2 and participant_id=$3 and privacy_domain_id=$4',
    [observationId, ...values(s)],
  );
  if (!r.rowCount) return undefined;
  if (r.rowCount !== 1) fail();
  const row = r.rows[0]!,
    original = deploymentCopy(qualificationDeploymentRequestSchema.parse(row.request));
  if (
    original.observationId !== observationId ||
    original.operationId !== row.operation_id ||
    original.installationDigest !== digest(original.pins) ||
    canonical(values(original.pins)) !== canonical(values(s)) ||
    !bytes(original).equals(row.request_bytes) ||
    digest(original) !== row.request_digest
  )
    fail();
  return original;
}
/** Native peer adapter only, on its current Identity-fenced client. Caller JSON
 * cannot bypass this composition. Returning is not the commit boundary. */
export async function reserveQualificationDeployment(
  c: PoolClient,
  selection: QualificationDeploymentSelection,
  peer: QualificationDeploymentPeer,
  intent: QualificationDeploymentIntent,
) {
  const s = deploymentCopy(qualificationDeploymentSelectionSchema.parse(selection)),
    wanted = deploymentCopy(qualificationDeploymentIntentSchema.parse(intent));
  const actual = deploymentCopy(qualificationDeploymentPeerSchema.parse(peer)),
    confirm = await context(c, s);
  await installationLock(c, s);
  await observationLock(c, wanted.observationId);
  const prior = await request(c, s, wanted.observationId);
  if (prior) {
    if (
      prior.operationId !== wanted.operationId ||
      canonical(prior.pins.peer) !== canonical(actual)
    )
      fail();
    await confirm();
    return { collect: false, request: prior };
  }
  const current = await installed(c, s);
  if (current.state !== 'ACTIVE' || canonical(current.pins.peer) !== canonical(actual)) fail();
  await liveEnvironment(c, current.pins);
  // All immutable sibling sources are locked in UUID order, including target.
  // Installation withdrawal acquires only its own lock, never another source.
  const separatedPins: QualificationDeploymentPins[] = [];
  for (const id of [...current.pins.separatedFrom].sort()) {
    const other = { ...s, installationId: id };
    await installationLock(c, other);
    const selected = await installed(c, other);
    if (selected.state !== 'ACTIVE' || selected.pins.environmentId !== current.pins.environmentId)
      fail();
    await liveEnvironment(c, selected.pins);
    separatedPins.push(selected.pins);
  }
  const issuedAtMs = await now(c);
  const original = deploymentCopy(
    qualificationDeploymentRequestSchema.parse({
      schemaVersion: 1,
      ...wanted,
      installationDigest: current.digest,
      pins: current.pins,
      separatedPins,
      issuedAtMs,
      deadlineAtMs: issuedAtMs + 30000,
    }),
  );
  await c.query(
    `insert into control.qualification_deployment_attempt(observation_id,installation_id,participant_id,privacy_domain_id,operation_id,request,request_bytes,request_digest) values($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      wanted.observationId,
      ...values(s),
      wanted.operationId,
      original,
      bytes(original),
      digest(original),
    ],
  );
  await confirm();
  return { collect: true, request: original };
}
/** Rechecks local sources at this transaction time. Never an external-process
 * lease; the native measurement remains a historical bracket. */
export async function confirmQualificationDeployment(
  c: PoolClient,
  selection: QualificationDeploymentSelection,
  observationId: string,
  peer: QualificationDeploymentPeer,
) {
  const s = deploymentCopy(qualificationDeploymentSelectionSchema.parse(selection)),
    confirm = await context(c, s);
  await installationLock(c, s);
  const original = await request(c, s, observationId);
  if (!original) fail();
  if (canonical(original.pins.peer) !== canonical(qualificationDeploymentPeerSchema.parse(peer)))
    fail();
  for (const p of [original.pins, ...original.separatedPins].sort((a, b) =>
    a.installationId.localeCompare(b.installationId),
  )) {
    await installationLock(c, p);
    const current = await installed(c, p);
    if (current.state !== 'ACTIVE' || current.digest !== digest(p)) fail();
    await liveEnvironment(c, p);
  }
  const checked = await now(c);
  if (checked >= original.deadlineAtMs) fail();
  await confirm();
  return checked;
}
export async function retainQualificationDeployment(
  c: PoolClient,
  selection: QualificationDeploymentSelection,
  observationId: string,
  collected: CollectedQualificationDeployment | null,
  identityRecheckedAtMs: number | null,
) {
  const s = deploymentCopy(qualificationDeploymentSelectionSchema.parse(selection)),
    confirm = await context(c, s);
  await installationLock(c, s);
  await observationLock(c, observationId);
  const original = await request(c, s, observationId);
  if (!original) fail();
  const measurement = collected === null ? null : readCollectedQualificationDeployment(collected);
  if (measurement) assertMeasurementOriginal(original, measurement);
  const result = deploymentCopy(
    qualificationDeploymentObservationSchema.parse({
      schemaVersion: 1,
      observationId,
      requestDigest: digest(original),
      state:
        measurement === null
          ? 'UNKNOWN'
          : identityRecheckedAtMs === null
            ? 'HISTORICAL'
            : 'OBSERVED',
      measurement,
      identityRecheckedAtMs: measurement === null ? null : identityRecheckedAtMs,
      retainedAtMs: await now(c),
    }),
  );
  if (measurement && measurement.completedAtMs > result.retainedAtMs) fail();
  const existing = await c.query<{ observation_bytes: Buffer }>(
    'select observation_bytes from control.qualification_deployment_observation where observation_id=$1 and participant_id=$2 and privacy_domain_id=$3',
    [observationId, s.participantId, s.privacyDomainId],
  );
  // The first result is permanent, including UNKNOWN. A repeated native result
  // cannot rewrite timestamps, repair a gap or promote an earlier observation.
  if (existing.rowCount) fail();
  await c.query(
    `insert into control.qualification_deployment_observation(observation_id,participant_id,privacy_domain_id,observation,observation_bytes,observation_digest) values($1,$2,$3,$4,$5,$6)`,
    [observationId, s.participantId, s.privacyDomainId, result, bytes(result), digest(result)],
  );
  await confirm();
  return result;
}
export async function readQualificationDeployment(
  c: PoolClient,
  selection: QualificationDeploymentSelection,
  observationId: string,
) {
  const s = deploymentCopy(qualificationDeploymentSelectionSchema.parse(selection)),
    confirm = await context(c, s);
  z.uuidv7().parse(observationId);
  const original = await request(c, s, observationId);
  if (!original) fail();
  const r = await c.query<{
    observation: unknown;
    observation_bytes: Buffer;
    observation_digest: string;
  }>(
    'select observation,observation_bytes,observation_digest from control.qualification_deployment_observation where observation_id=$1 and participant_id=$2 and privacy_domain_id=$3',
    [observationId, s.participantId, s.privacyDomainId],
  );
  let observation: QualificationDeploymentObservation | null = null;
  if (r.rowCount) {
    if (r.rowCount !== 1) fail();
    const row = r.rows[0]!;
    observation = deploymentCopy(qualificationDeploymentObservationSchema.parse(row.observation));
    if (observation.measurement) assertMeasurementOriginal(original, observation.measurement);
    if (
      observation.observationId !== observationId ||
      observation.requestDigest !== digest(original) ||
      !bytes(observation).equals(row.observation_bytes) ||
      digest(observation) !== row.observation_digest ||
      (observation.measurement &&
        observation.measurement.installationDigest !== original.installationDigest)
    )
      fail();
  }
  await confirm();
  return deploymentCopy({ request: original, observation, readback: 'HISTORICAL_ONLY' as const });
}
