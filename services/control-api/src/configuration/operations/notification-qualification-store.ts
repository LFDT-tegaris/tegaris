import { createHash, X509Certificate } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { WorkloadPeerDependencyResolver } from '../../../../identity-service/src/domain/workload-peer.js';
import { z } from 'zod';
import {
  withInstalledQualificationIssuer,
  withInstalledNotificationAsyncAuthority,
} from './provider-retry-qualification.js';
import {
  verifyNotificationAsyncEnvelope,
  encodeNotificationAsync,
  type NotificationAsyncCapacityClaims,
} from '../../../../../packages/security-kernel/src/operations-configuration/notification-async.js';
import {
  canonical,
  copy,
  digest,
  document,
  inputClaims,
  reject,
  qualificationInstallationSchema,
  qualificationOriginRequestSchema,
  qualificationOriginProofSchema,
  qualificationPeerSchema,
  qualificationRecordSchema,
  qualificationRunRequestSchema,
  qualificationRunSelectorSchema,
  qualificationSelectionSchema,
  qualificationTime,
  verifyQualificationOrigin,
  qualificationHash,
  type QualificationInstallation,
  type QualificationSelection,
  type QualificationPeer,
  type NotificationQualificationSelector,
  type QualificationOriginal,
  type QualificationRecordKind,
  type QualificationRunAdmission,
  type QualificationSigningIntent,
  type QualificationSigningSelector,
  type QualificationSignerTransport,
  type QualificationSignedOriginal,
  type QualificationCapacitySourceClaims,
} from './notification-qualification-contract.js';

type Stored = { body: unknown; body_bytes: Buffer; body_digest: string };
function stored(row: Stored | undefined) {
  if (
    !row ||
    !Buffer.isBuffer(row.body_bytes) ||
    !row.body_bytes.equals(Buffer.from(canonical(row.body))) ||
    digest(row.body_bytes) !== row.body_digest
  )
    reject('EVIDENCE');
  return row.body;
}
export async function qualificationNow(c: PoolClient) {
  const r = await c.query<{ at: string }>(
    'select floor(extract(epoch from clock_timestamp())*1000)::text at',
  );
  return qualificationTime.parse(Number(r.rows[0]?.at));
}
export async function qualificationContext(
  c: PoolClient,
  s: QualificationSelection,
  bootstrap = false,
) {
  qualificationSelectionSchema.parse({
    participantId: s.participantId,
    privacyDomainId: s.privacyDomainId,
    installationId: s.installationId,
  });
  await c.query('select openpc.assert_request_context(true)');
  const read = async () =>
    (
      await c.query<{ role: string; tx: string; operation: string; valid: boolean }>(
        `select current_user::text role,pg_current_xact_id()::text tx,openpc.current_operation_id()::text operation,
     openpc.current_participant_id()=$1::uuid and openpc.current_privacy_domain_id()=$2::uuid
     and current_setting('transaction_isolation')='read committed' and current_setting('row_security')='on'
     and current_setting('session_replication_role')='origin'
     and openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
     and not exists(select 1 from pg_roles where rolname=current_user and (rolsuper or rolbypassrls)) valid`,
        [s.participantId, s.privacyDomainId],
      )
    ).rows[0];
  const original = await read();
  if (
    !original?.valid ||
    original.role !==
      (bootstrap
        ? 'openpc_operations_qualification_bootstrap'
        : 'openpc_operations_qualification_owner')
  )
    reject('CONTEXT');
  const confirm = async () => {
    if (canonical(await read()) !== canonical(original)) reject('CONTEXT');
  };
  await confirm();
  return { ...original, confirm };
}
async function lock(c: PoolClient, name: string, shared = false) {
  await c.query(
    `select ${shared ? 'pg_advisory_xact_lock_shared' : 'pg_advisory_xact_lock'}(hashtextextended($1,0))`,
    [name],
  );
}
const scope = (s: QualificationSelection) => [s.participantId, s.privacyDomainId, s.installationId];
export async function readQualificationInstallation(
  c: PoolClient,
  s: QualificationSelection,
  current = false,
) {
  const ctx = await qualificationContext(c, s);
  const r = await c.query<Stored & { state: string }>(
    'select body,body_bytes,body_digest,state from control.notification_qualification_installation where participant_id=$1 and privacy_domain_id=$2 and installation_id=$3',
    scope(s),
  );
  if (r.rowCount !== 1) reject('UNBOUND');
  const pins = qualificationInstallationSchema.parse(stored(r.rows[0]));
  if (current) {
    await lock(c, `operations-generation:${pins.environmentId}`, true);
    await lock(c, `notification-qualification-installation:${s.installationId}`, true);
    const state = await c.query<{ state: string; body_digest: string }>(
      'select state,body_digest from control.notification_qualification_installation where participant_id=$1 and privacy_domain_id=$2 and installation_id=$3',
      scope(s),
    );
    if (state.rows[0]?.state !== 'ACTIVE' || state.rows[0].body_digest !== r.rows[0]!.body_digest)
      reject('UNBOUND');
    const at = await qualificationNow(c);
    if (r.rows[0]!.state !== 'ACTIVE' || at < pins.validFromMs || at >= pins.validUntilMs)
      reject('EXPIRED');
    const input = inputClaims(pins.input);
    const bound = await c.query<{ candidate: unknown }>(
      `select g.candidate from control.operations_installation i join control.operations_generation g using(environment_id)
       where i.environment_id=$1 and i.participant_id=$2 and i.privacy_domain_id=$3 and i.state='ACTIVE'
       and i.installation_digest=$4 and g.generation_id=$5 and g.state='STAGED'
       and openpc.operations_generation_source_authenticated(g.environment_id,g.generation_id) for share of i,g`,
      [
        pins.environmentId,
        s.participantId,
        s.privacyDomainId,
        pins.operationsInstallationDigest,
        input.generationId,
      ],
    );
    const candidate = bound.rows[0]?.candidate as
      { configuration?: { generation?: { contentDigest?: string } } } | undefined;
    if (
      bound.rowCount !== 1 ||
      candidate?.configuration?.generation?.contentDigest !== input.configurationDigest
    )
      reject('UNBOUND');
  }
  await ctx.confirm();
  return pins;
}
/** Installer can pin public capabilities and revoke them; it cannot create an
 * authored origin, run, measured result or review. No private keys are stored. */
export async function installNotificationQualification(c: PoolClient, value: unknown) {
  const pins = qualificationInstallationSchema.parse(copy(value));
  const ctx = await qualificationContext(c, pins, true),
    d = document(pins);
  await lock(c, `notification-qualification-installation:${pins.installationId}`);
  await c.query(
    `insert into control.notification_qualification_installation(participant_id,privacy_domain_id,installation_id,environment_id,body,body_bytes,body_digest)
   values($1,$2,$3,$4,$5,$6,$7)`,
    [...scope(pins), pins.environmentId, d.body, d.bytes, d.digest],
  );
  await ctx.confirm();
  return d.digest;
}
export async function revokeNotificationQualification(
  c: PoolClient,
  selection: QualificationSelection,
) {
  const s = qualificationSelectionSchema.parse(selection),
    ctx = await qualificationContext(c, s, true);
  await lock(c, `notification-qualification-installation:${s.installationId}`);
  await c.query(
    "update control.notification_qualification_installation set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and installation_id=$3",
    scope(s),
  );
  await ctx.confirm();
}
export async function assertQualificationActor(
  c: PoolClient,
  s: QualificationSelection,
  peer: QualificationPeer,
  capability: 'executor' | 'reviewer' | 'signer' | 'subjectAuthor' | 'harnessAuthor',
) {
  const pins = await readQualificationInstallation(c, s, true),
    p = qualificationPeerSchema.parse(peer);
  if (canonical(p) !== canonical(pins[capability])) reject('CONTEXT');
  await assertInstalledQualificationPeer(c, s, p);
  return pins;
}
async function assertInstalledQualificationPeer(
  c: PoolClient,
  s: QualificationSelection,
  p: QualificationPeer,
) {
  const r = await c.query(
    `select 1 from control.participant t join control.principal p on p.participant_id=t.participant_id
   join control.credential k on k.participant_id=t.participant_id and k.principal_id=p.principal_id
   where t.participant_id=$1 and p.principal_id=$2 and k.credential_id=$3
   and t.state='ACTIVE' and t.archived_at is null and p.state='ACTIVE' and p.kind='WORKLOAD' and k.state='ACTIVE' and k.kind='WORKLOAD_MTLS'
   and t.authority_epoch=$4 and p.authority_epoch=$5 and k.credential_epoch=$6 and k.audience=$7
   and k.public_key_digest=decode($8,'hex') and k.secret_fingerprint=$9
   and k.valid_from<=clock_timestamp() and k.valid_until>clock_timestamp()`,
    [
      s.participantId,
      p.principalId,
      p.credentialId,
      p.participantEpoch,
      p.principalEpoch,
      p.credentialEpoch,
      p.workloadId,
      p.keyDigest.slice(7),
      Buffer.from(p.certificateDigest.slice(7), 'hex'),
    ],
  );
  if (r.rowCount !== 1) reject('CONTEXT');
}
/** Read-only immutable selection for the shared native Identity owner. This
 * deliberately takes no generation/installation/run locks before Identity. */
export function resolveNotificationQualificationSigningAuthorities(
  selector: QualificationSigningSelector,
): WorkloadPeerDependencyResolver {
  const { family, ...source } = copy(selector),
    s = qualificationRunSelectorSchema.parse(source);
  if (family !== 'input' && family !== 'capacity') reject();
  return async (c, identity) => {
    if (identity.participantId !== s.participantId) reject('CONTEXT');
    const pins = await readQualificationInstallation(c, s),
      dependencies = family === 'capacity' ? [pins.signer, pins.reviewer] : [pins.signer];
    return {
      dependencies,
      confirmCurrent: async () => {
        if (canonical(await readQualificationInstallation(c, s)) !== canonical(pins))
          reject('CONTEXT');
        for (const p of dependencies) await assertInstalledQualificationPeer(c, s, p);
      },
    };
  };
}
/** New-origin publication must be performed by the actual author peer. Raw
 * source/build bytes and its server-issued request survive restart; historical
 * authorship cannot be supplied as a label during installation. */
export async function prepareQualificationOrigin(
  c: PoolClient,
  selection: QualificationSelection,
  peer: QualificationPeer,
  kind: 'SUBJECT' | 'HARNESS',
  source: Uint8Array,
  build: Uint8Array,
) {
  const s = qualificationSelectionSchema.parse(selection),
    ctx = await qualificationContext(c, s);
  if (
    !['SUBJECT', 'HARNESS'].includes(kind) ||
    !Buffer.isBuffer(source) ||
    !Buffer.isBuffer(build) ||
    source.length < 1 ||
    build.length < 1 ||
    source.length > 16777216 ||
    build.length > 16777216
  )
    reject();
  const sourceBytes = Buffer.from(source),
    buildBytes = Buffer.from(build);
  const pins = await assertQualificationActor(
    c,
    s,
    peer,
    kind === 'SUBJECT' ? 'subjectAuthor' : 'harnessAuthor',
  );
  const originId = kind === 'SUBJECT' ? pins.subjectOriginId : pins.harnessOriginId;
  await lock(c, `notification-qualification-origin:${originId}`);
  const original = await c.query<Stored>(
    'select body,body_bytes,body_digest from control.notification_qualification_origin where participant_id=$1 and privacy_domain_id=$2 and origin_id=$3',
    [s.participantId, s.privacyDomainId, originId],
  );
  if (original.rowCount) {
    const r = qualificationOriginRequestSchema.parse(stored(original.rows[0]));
    if (
      r.kind !== kind ||
      r.sourceDigest !== digest(sourceBytes) ||
      r.buildDigest !== digest(buildBytes) ||
      canonical(r.author) !== canonical(peer)
    )
      reject('IMMUTABLE');
    await ctx.confirm();
    return r;
  }
  const at = await qualificationNow(c),
    input = inputClaims(pins.input);
  if (
    kind === 'SUBJECT' &&
    (digest(sourceBytes) !== input.sourceTreeDigest || digest(buildBytes) !== input.buildDigest)
  )
    reject('EVIDENCE');
  const request = qualificationOriginRequestSchema.parse({
    schemaVersion: 1,
    mode: 'NEW_AUTHENTICATED_ORIGIN',
    originId,
    ...s,
    environmentId: pins.environmentId,
    installationDigest: document(pins).digest,
    kind,
    author: peer,
    operationId: ctx.operation,
    sourceDigest: digest(sourceBytes),
    buildDigest: digest(buildBytes),
    issuedAtMs: at,
    deadlineAtMs: Math.min(at + 30000, pins.validUntilMs),
  });
  const d = document(request);
  await c.query(
    `insert into control.notification_qualification_origin(participant_id,privacy_domain_id,origin_id,installation_id,body,body_bytes,body_digest,source_bytes,build_bytes) values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      s.participantId,
      s.privacyDomainId,
      originId,
      s.installationId,
      d.body,
      d.bytes,
      d.digest,
      sourceBytes,
      buildBytes,
    ],
  );
  await ctx.confirm();
  return request;
}
export async function retainQualificationOrigin(
  c: PoolClient,
  s: QualificationSelection,
  peer: QualificationPeer,
  originId: string,
  signatureHex: string,
) {
  z.uuidv7().parse(originId);
  const ctx = await qualificationContext(c, s);
  const pins = await readQualificationInstallation(c, s, true);
  await lock(c, `notification-qualification-origin:${originId}`);
  const row = await c.query<Stored>(
    'select body,body_bytes,body_digest from control.notification_qualification_origin where participant_id=$1 and privacy_domain_id=$2 and origin_id=$3 and installation_id=$4',
    [s.participantId, s.privacyDomainId, originId, s.installationId],
  );
  const request = qualificationOriginRequestSchema.parse(stored(row.rows[0]));
  await assertQualificationActor(
    c,
    s,
    peer,
    request.kind === 'SUBJECT' ? 'subjectAuthor' : 'harnessAuthor',
  );
  verifyQualificationOrigin(request, signatureHex, pins);
  const previous = await c.query<Stored>(
    'select body,body_bytes,body_digest from control.notification_qualification_origin_proof where participant_id=$1 and privacy_domain_id=$2 and origin_id=$3',
    [s.participantId, s.privacyDomainId, originId],
  );
  if (previous.rowCount) {
    const value = qualificationOriginProofSchema.parse(stored(previous.rows[0]));
    if (value.signatureHex !== signatureHex) reject('IMMUTABLE');
    return previous.rows[0]!.body_digest;
  }
  const at = await qualificationNow(c);
  const d = document(
    qualificationOriginProofSchema.parse({
      schemaVersion: 1,
      originId,
      requestDigest: row.rows[0]!.body_digest,
      signatureHex,
      retainedAtMs: at,
      state: at < request.deadlineAtMs ? 'ORIGINAL_VERIFIED_WITHIN_WINDOW' : 'HISTORICAL_ONLY',
    }),
  );
  await c.query(
    'insert into control.notification_qualification_origin_proof(participant_id,privacy_domain_id,origin_id,body,body_bytes,body_digest) values($1,$2,$3,$4,$5,$6)',
    [s.participantId, s.privacyDomainId, originId, d.body, d.bytes, d.digest],
  );
  await ctx.confirm();
  return d.digest;
}
async function origin(
  c: PoolClient,
  s: QualificationSelection,
  pins: QualificationInstallation,
  id: string,
) {
  const r = await c.query<
    Stored & {
      proof: unknown;
      proof_bytes: Buffer;
      proof_digest: string;
      source_bytes: Buffer;
      build_bytes: Buffer;
    }
  >(
    `select o.body,o.body_bytes,o.body_digest,o.source_bytes,o.build_bytes,p.body proof,p.body_bytes proof_bytes,p.body_digest proof_digest from control.notification_qualification_origin o join control.notification_qualification_origin_proof p using(origin_id,participant_id,privacy_domain_id) where o.participant_id=$1 and o.privacy_domain_id=$2 and o.origin_id=$3 and o.installation_id=$4`,
    [s.participantId, s.privacyDomainId, id, s.installationId],
  );
  if (r.rowCount !== 1) reject('UNBOUND');
  const row = r.rows[0]!,
    request = qualificationOriginRequestSchema.parse(stored(row));
  const proof = qualificationOriginProofSchema.parse(
    stored({ body: row.proof, body_bytes: row.proof_bytes, body_digest: row.proof_digest }),
  );
  if (
    proof.state !== 'ORIGINAL_VERIFIED_WITHIN_WINDOW' ||
    proof.originId !== id ||
    proof.requestDigest !== row.body_digest ||
    digest(row.source_bytes) !== request.sourceDigest ||
    digest(row.build_bytes) !== request.buildDigest ||
    proof.retainedAtMs >= request.deadlineAtMs
  )
    reject('EVIDENCE');
  verifyQualificationOrigin(request, proof.signatureHex, pins);
  return { request, digest: row.proof_digest };
}
export async function reserveNotificationQualificationRun(
  c: PoolClient,
  selector: NotificationQualificationSelector,
  peer: QualificationPeer,
) {
  const s = qualificationRunSelectorSchema.parse(selector),
    ctx = await qualificationContext(c, s),
    pins = await assertQualificationActor(c, s, peer, 'executor');
  await lock(c, `notification-qualification-run:${s.runId}`);
  const prior = await c.query<Stored>(
    'select body,body_bytes,body_digest from control.notification_qualification_run where participant_id=$1 and privacy_domain_id=$2 and run_id=$3',
    [s.participantId, s.privacyDomainId, s.runId],
  );
  if (prior.rowCount) {
    const request = qualificationRunRequestSchema.parse(stored(prior.rows[0]));
    if (request.installationDigest !== document(pins).digest) reject('IMMUTABLE');
    return { created: false, request };
  }
  const subject = await origin(c, s, pins, pins.subjectOriginId),
    harness = await origin(c, s, pins, pins.harnessOriginId),
    input = inputClaims(pins.input);
  if (
    subject.request.kind !== 'SUBJECT' ||
    harness.request.kind !== 'HARNESS' ||
    subject.request.sourceDigest !== input.sourceTreeDigest ||
    subject.request.buildDigest !== input.buildDigest
  )
    reject('EVIDENCE');
  const payload = encodeNotificationAsync('input', input),
    at = await qualificationNow(c);
  const request = qualificationRunRequestSchema.parse({
    schemaVersion: 1,
    purpose: 'QUALIFICATION_RUN',
    ...s,
    operationId: ctx.operation,
    installationDigest: document(pins).digest,
    subjectOriginDigest: subject.digest,
    harnessOriginDigest: harness.digest,
    inputPayloadHex: payload.toString('hex'),
    inputPayloadDigest: digest(payload),
    executor: peer,
    reservedAtMs: at,
    deadlineAtMs: Math.min(at + pins.maximumRunMs, pins.validUntilMs, input.validUntilMs),
  });
  if (request.deadlineAtMs <= at) reject('EXPIRED');
  const d = document(request);
  await c.query(
    `insert into control.notification_qualification_run(participant_id,privacy_domain_id,run_id,installation_id,reservation_transaction,body,body_bytes,body_digest) values($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      s.participantId,
      s.privacyDomainId,
      s.runId,
      s.installationId,
      ctx.tx,
      d.body,
      d.bytes,
      d.digest,
    ],
  );
  await ctx.confirm();
  return { created: true, request };
}
export async function readNotificationQualificationOriginal(
  c: PoolClient,
  selector: NotificationQualificationSelector,
): Promise<QualificationOriginal> {
  const s = qualificationRunSelectorSchema.parse(selector),
    ctx = await qualificationContext(c, s);
  const r = await c.query<Stored>(
    'select body,body_bytes,body_digest from control.notification_qualification_run where participant_id=$1 and privacy_domain_id=$2 and run_id=$3 and installation_id=$4',
    [s.participantId, s.privacyDomainId, s.runId, s.installationId],
  );
  if (r.rowCount !== 1) reject('UNBOUND');
  const request = qualificationRunRequestSchema.parse(stored(r.rows[0]));
  const records = await c.query<Stored>(
    'select body,body_bytes,body_digest from control.notification_qualification_record where participant_id=$1 and privacy_domain_id=$2 and run_id=$3 order by kind,record_key',
    [s.participantId, s.privacyDomainId, s.runId],
  );
  const result = {
    request,
    records: records.rows.map((row) => ({
      record: qualificationRecordSchema.parse(stored(row)),
      bytes: Buffer.from(row.body_bytes),
      digest: row.body_digest,
    })),
  };
  if (result.records.some((r) => r.record.runId !== s.runId)) reject('EVIDENCE');
  await ctx.confirm();
  return result;
}
export function recordValue(
  original: QualificationOriginal,
  kind: QualificationRecordKind,
  key = 'original',
) {
  const records = original.records.filter((r) => r.record.kind === kind && r.record.key === key);
  if (records.length > 1) reject('EVIDENCE');
  return records[0];
}
/** Native owner write; callers cannot replace originals. Application endpoints
 * expose selectors, never this arbitrary-document internal function. SQL limits
 * the protected owner and every cross-record transition independently. */
export async function appendQualificationRecord(
  c: PoolClient,
  s: NotificationQualificationSelector,
  kind: QualificationRecordKind,
  key: string,
  value: unknown,
) {
  const ctx = await qualificationContext(c, s);
  await lock(c, `notification-qualification-run:${s.runId}`);
  const original = await readNotificationQualificationOriginal(c, s),
    prior = recordValue(original, kind, key);
  if (prior) {
    if (canonical(prior.record.value) !== canonical(value)) reject('IMMUTABLE');
    return prior;
  }
  const record = qualificationRecordSchema.parse({
      schemaVersion: 1,
      runId: s.runId,
      kind,
      key,
      operationId: ctx.operation,
      recordedAtMs: await qualificationNow(c),
      value: copy(value),
    }),
    d = document(record);
  const pins = await readQualificationInstallation(c, s),
    total = original.records.reduce((n, r) => n + r.bytes.length, 0);
  if (total + d.bytes.length > pins.maximumEvidenceBytes) reject('EVIDENCE');
  await c.query(
    'insert into control.notification_qualification_record(participant_id,privacy_domain_id,run_id,kind,record_key,body,body_bytes,body_digest) values($1,$2,$3,$4,$5,$6,$7,$8)',
    [s.participantId, s.privacyDomainId, s.runId, kind, key, d.body, d.bytes, d.digest],
  );
  await ctx.confirm();
  return { record, bytes: d.bytes, digest: d.digest };
}
async function installedInput(
  c: PoolClient,
  s: NotificationQualificationSelector,
  pins: QualificationInstallation,
  original: QualificationOriginal,
) {
  const record = recordValue(original, 'INPUT');
  if (!record) reject('UNBOUND');
  const value = z
      .strictObject({
        payloadHex: z.string(),
        coseHex: z.string(),
        attemptId: z.uuidv7(),
        sourceDigest: qualificationHash,
      })
      .parse(record.record.value),
    claims = inputClaims(pins.input);
  if (value.payloadHex !== original.request.inputPayloadHex) reject('EVIDENCE');
  const ctx = await qualificationContext(c, s);
  return withInstalledQualificationIssuer(
    c,
    { ...s, requestId: ctx.operation },
    pins.environmentId,
    {
      authorityId: claims.authorityId,
      keyId: claims.issuerKeyId,
      epoch: claims.issuerEpoch,
      purpose: 'pc.cose.operations-notification-async-input.v1',
    },
    async (_same, issuer) => {
      const checked = verifyNotificationAsyncEnvelope(
        'input',
        Buffer.from(issuer.publicKeySpkiHex, 'hex'),
        { payload: Buffer.from(value.payloadHex, 'hex'), cose: Buffer.from(value.coseHex, 'hex') },
      );
      const at = await qualificationNow(c);
      if (at < checked.validFromMs || at >= checked.validUntilMs) reject('EXPIRED');
      return checked;
    },
  );
}
/** Stable early interface for canonical delivery-limit integration. It requires
 * a committed, dispatched original run and signed369, actual executor identity,
 * held installation/generation/run fences and exact isolated store/gateway pins.
 * A callback cannot commit/release, switch client/role or extend the deadline. */
export async function withNotificationQualificationRun<T>(
  c: PoolClient,
  selector: NotificationQualificationSelector,
  peer: QualificationPeer,
  consume: (sameClient: PoolClient, admitted: Readonly<QualificationRunAdmission>) => Promise<T>,
): Promise<T> {
  const s = qualificationRunSelectorSchema.parse(selector),
    ctx = await qualificationContext(c, s),
    pins = await assertQualificationActor(c, s, peer, 'executor');
  await lock(c, `notification-qualification-run:${s.runId}`, true);
  // Actual live native executor bracket is installed only by the peer adapter.
  // The check intentionally stays closed before canonical supplies that owner.
  await requireQualificationNativeExecution(c, s, 'QUALIFICATION_RUN');
  const original = await readNotificationQualificationOriginal(c, s),
    dispatch = recordValue(original, 'DISPATCH');
  if (
    !dispatch ||
    recordValue(original, 'RESULT') ||
    original.request.installationDigest !== document(pins).digest
  )
    reject('UNBOUND');
  const input = await installedInput(c, s, pins, original),
    harness = await origin(c, s, pins, pins.harnessOriginId);
  if ((await qualificationNow(c)) >= original.request.deadlineAtMs) reject('EXPIRED');
  const admitted = Object.freeze({
    purpose: 'QUALIFICATION_RUN' as const,
    selector: Object.freeze({ ...s }),
    input: Object.freeze(copy(input)),
    deadlineAtMs: original.request.deadlineAtMs,
    storeIdentityDigest: pins.storeIdentityDigest,
    gatewayIdentityDigest: pins.gatewayIdentityDigest,
    harnessDigest: harness.request.buildDigest,
  });
  const release = c.release,
    query = c.query;
  let attempted = false;
  const heldRelease: PoolClient['release'] = () => {
    attempted = true;
    return reject('CONTEXT');
  };
  c.release = heldRelease;
  try {
    const result = await consume(c, admitted);
    if (attempted || c.release !== heldRelease || c.query !== query) reject('CONTEXT');
    await ctx.confirm();
    await assertQualificationActor(c, s, peer, 'executor');
    await installedInput(c, s, pins, original);
    if ((await qualificationNow(c)) >= admitted.deadlineAtMs) reject('EXPIRED');
    return result;
  } finally {
    c.release = release;
    c.query = query;
  }
}
export async function dispatchNotificationQualification(
  c: PoolClient,
  s: NotificationQualificationSelector,
  peer: QualificationPeer,
) {
  const ctx = await qualificationContext(c, s),
    pins = await assertQualificationActor(c, s, peer, 'executor');
  await lock(c, `notification-qualification-run:${s.runId}`);
  const original = await readNotificationQualificationOriginal(c, s);
  if (recordValue(original, 'DISPATCH')) return { execute: false, original };
  await requireQualificationNativeExecution(c, s, 'QUALIFICATION_RUN');
  const tx = await c.query<{ reservation_transaction: string }>(
    'select reservation_transaction from control.notification_qualification_run where participant_id=$1 and privacy_domain_id=$2 and run_id=$3',
    [s.participantId, s.privacyDomainId, s.runId],
  );
  if (tx.rows[0]?.reservation_transaction === ctx.tx) reject('CONTEXT');
  await installedInput(c, s, pins, original);
  if ((await qualificationNow(c)) >= original.request.deadlineAtMs) reject('EXPIRED');
  await appendQualificationRecord(c, s, 'DISPATCH', 'original', {
    executor: peer,
    startedAtMs: await qualificationNow(c),
  });
  await ctx.confirm();
  return { execute: true, original };
}
/** Canonical SIGN/ORIGINAL_LOOKUP consumes only these owner-derived payloads.
 * This function performs no signing, provider I/O or signing-result fabrication. */
async function signingIntent(
  c: PoolClient,
  s: NotificationQualificationSelector,
  peer: QualificationPeer,
  family: 'input' | 'capacity',
): Promise<QualificationSigningIntent> {
  const ctx = await qualificationContext(c, s);
  const pins = await assertQualificationActor(c, s, peer, 'signer');
  await lock(c, `notification-qualification-run:${s.runId}`);
  const original = await readNotificationQualificationOriginal(c, s),
    input = inputClaims(pins.input);
  if (family === 'input')
    return {
      family: 'input',
      selector: { ...s, family: 'input' },
      payload: Buffer.from(original.request.inputPayloadHex, 'hex'),
      sourceDigest: document(original.request).digest,
      issuer: {
        authorityId: input.authorityId,
        keyId: input.issuerKeyId,
        epoch: input.issuerEpoch,
        purpose: 'pc.cose.operations-notification-async-input.v1' as const,
      },
    };
  await assertQualificationActor(c, s, pins.reviewer, 'reviewer');
  const normalized = recordValue(original, 'NORMALIZED'),
    review = recordValue(original, 'REVIEW');
  if (!normalized || !review) reject('UNBOUND');
  const { qualificationNormalizedSchema, qualificationReviewSchema } =
    await import('./notification-qualification-contract.js');
  const n = qualificationNormalizedSchema.parse(normalized.record.value),
    r = qualificationReviewSchema.parse(review.record.value);
  if (
    n.status !== 'PASS' ||
    !n.measurements ||
    r.decision !== 'ACCEPTED' ||
    r.normalizedResultsDigest !== normalized.digest ||
    canonical(r.reviewer) !== canonical(pins.reviewer)
  )
    reject('EVIDENCE');
  const harness = await origin(c, s, pins, pins.harnessOriginId);
  // Receipt ID/issuance are reserved by canonical signer custody; return exact
  // owner-derived fields, never let callers supply the evidence/principal tuple.
  await ctx.confirm();
  return {
    family: 'capacity',
    selector: { ...s, family: 'capacity' },
    sourceDigest: review.digest,
    claims: {
      ...Object.fromEntries(
        Object.entries(input).filter(([key]) =>
          [
            'authorityId',
            'environmentId',
            'profile',
            'participantId',
            'privacyDomainId',
            'task',
            'generationId',
            'configurationDigest',
            'configurationSchemaDigest',
            'namedProfileDigest',
            'buildDigest',
            'sourceTreeDigest',
            'workloadIdentityDigest',
            'environmentIdentityDigest',
            'storeProfileDigest',
            'gatewayProfileDigest',
            'ratePolicyDigest',
          ].includes(key),
        ),
      ),
      inputPayloadDigest: original.request.inputPayloadDigest,
      issuerKeyId: pins.capacityIssuer.keyId,
      issuerEpoch: pins.capacityIssuer.epoch,
      runId: s.runId,
      harnessDigest: harness.request.buildDigest,
      rawEvidenceDigest: n.rawEvidenceDigest,
      originalSignedOutcomesDigest: n.originalSignedOutcomesDigest,
      normalizedResultsDigest: normalized.digest,
      reviewerAttestationDigest: review.digest,
      subjectAuthorPrincipalId: pins.subjectAuthor.principalId,
      harnessAuthorPrincipalId: pins.harnessAuthor.principalId,
      reviewerPrincipalId: pins.reviewer.principalId,
      signerPrincipalId: pins.signer.principalId,
      ...n.measurements,
      runStartedAtMs: n.runStartedAtMs,
      runCompletedAtMs: n.runCompletedAtMs,
    } as QualificationCapacitySourceClaims,
    issuer: {
      authorityId: input.authorityId,
      keyId: pins.capacityIssuer.keyId,
      epoch: pins.capacityIssuer.epoch,
      purpose: 'pc.cose.operations-notification-async-capacity-receipt.v1' as const,
    },
  };
}
async function retainCurrentSigned(
  c: PoolClient,
  s: NotificationQualificationSelector,
  peer: QualificationPeer,
  family: 'input' | 'capacity',
  payload: Buffer,
  cose: Buffer,
  providerSource: { attemptId: string; sourceDigest: string },
) {
  if (
    !Buffer.isBuffer(payload) ||
    !Buffer.isBuffer(cose) ||
    payload.length > 65536 ||
    cose.length > 66560
  )
    reject();
  payload = Buffer.from(payload);
  cose = Buffer.from(cose);
  const intent = await signingIntent(c, s, peer, family),
    ctx = await qualificationContext(c, s),
    pins = await readQualificationInstallation(c, s, true);
  return withInstalledQualificationIssuer(
    c,
    { ...s, requestId: ctx.operation },
    pins.environmentId,
    intent.issuer,
    async (_same, issuer) => {
      const claims = verifyNotificationAsyncEnvelope(
        family,
        Buffer.from(issuer.publicKeySpkiHex, 'hex'),
        { payload, cose },
      );
      if (family === 'input') {
        if (intent.family !== 'input' || !payload.equals(intent.payload)) reject('EVIDENCE');
      } else {
        if (intent.family !== 'capacity') reject();
        const claim = claims as NotificationAsyncCapacityClaims;
        for (const [key, value] of Object.entries(intent.claims)) {
          if (
            !(key in claim) ||
            canonical(claim[key as keyof NotificationAsyncCapacityClaims]) !== canonical(value)
          )
            reject('EVIDENCE');
        }
        if (
          claim.inputPayloadDigest !==
            digest(encodeNotificationAsync('input', inputClaims(pins.input))) ||
          claim.keysetPayloadDigest !== issuer.keysetDigest ||
          claim.revocationPayloadDigest !== issuer.revocationsDigest ||
          claim.issuedAtMs > (await qualificationNow(c)) ||
          claim.expiresAtMs > issuer.validUntilMs
        )
          reject('EVIDENCE');
      }
      if (family === 'capacity') {
        const original = await readNotificationQualificationOriginal(c, s);
        const input = recordValue(original, 'INPUT');
        if (!input) reject('UNBOUND');
        const value = input.record.value as { payloadHex: string; coseHex: string };
        return withInstalledNotificationAsyncAuthority(
          c,
          { ...s, requestId: ctx.operation },
          pins.environmentId,
          inputClaims(pins.input).generationId,
          {
            input: {
              payload: Buffer.from(value.payloadHex, 'hex'),
              cose: Buffer.from(value.coseHex, 'hex'),
            },
            capacity: { payload, cose },
          },
          () =>
            appendQualificationRecord(c, s, 'CAPACITY', 'original', {
              payloadHex: payload.toString('hex'),
              coseHex: cose.toString('hex'),
              ...providerSource,
            }),
        );
      }
      return appendQualificationRecord(c, s, 'INPUT', 'original', {
        payloadHex: payload.toString('hex'),
        coseHex: cose.toString('hex'),
        ...providerSource,
      });
    },
  );
}
export async function bindNotificationQualificationSource(
  c: PoolClient,
  s: NotificationQualificationSelector,
  peer: QualificationPeer,
  eventId: string,
) {
  z.uuidv7().parse(eventId);
  return withNotificationQualificationRun(c, s, peer, async (same) => {
    const original = await readNotificationQualificationOriginal(same, s),
      pins = await readQualificationInstallation(same, s, true);
    if (
      original.records.filter((r) => r.record.kind === 'SOURCE').length >= pins.maximumSources &&
      !recordValue(original, 'SOURCE', eventId)
    )
      reject();
    const dispatch = recordValue(original, 'DISPATCH');
    if (!dispatch) reject('UNBOUND');
    const row = await same.query<{ original: unknown }>(
      `select openpc.check_notification_delivery_requested_event(e),to_jsonb(e) original from control.outbox_event e where e.participant_id=$1 and e.privacy_domain_id=$2 and e.event_id=$3 and e.aggregate_type='notification-occurrence' and floor(extract(epoch from e.occurred_at)*1000)>=$4`,
      [
        s.participantId,
        s.privacyDomainId,
        eventId,
        (dispatch.record.value as { startedAtMs: number }).startedAtMs,
      ],
    );
    if (row.rowCount !== 1) reject('EVIDENCE');
    return appendQualificationRecord(same, s, 'SOURCE', eventId, {
      eventId,
      original: row.rows[0]!.original,
    });
  });
}
export function validatedQualificationDigest(value: unknown) {
  return qualificationHash.parse(value);
}

// Native evidence is process-local and transaction-bound in addition to durable
// run custody, like the existing TLS owner. Only the peer adapter enters a
// bracket supplied by the canonical native host owner. Nothing stored here is
// an execution result, historical lease or substitute for durable readback.
const nativeBrackets = new WeakMap<
  PoolClient,
  { selector: string; capability: string; transaction: string }
>();
export async function withQualificationNativeBracket<T>(
  c: PoolClient,
  s: NotificationQualificationSelector,
  capability: 'QUALIFICATION_RUN' | 'QUALIFICATION_REVIEW',
  socket: import('node:tls').TLSSocket,
  owner: import('./notification-qualification-contract.js').QualificationNativeExecutionOwner,
  consume: (same: PoolClient) => Promise<T>,
): Promise<T> {
  if (!owner || typeof owner.withCurrentExecution !== 'function' || nativeBrackets.has(c))
    reject('UNBOUND');
  const context = await qualificationContext(c, s);
  return owner.withCurrentExecution(c, s, capability, socket, async (same) => {
    if (same !== c) reject('CONTEXT');
    await context.confirm();
    nativeBrackets.set(c, { selector: canonical(s), capability, transaction: context.tx });
    try {
      const result = await consume(c);
      await context.confirm();
      return result;
    } finally {
      nativeBrackets.delete(c);
    }
  });
}
export async function requireQualificationNativeExecution(
  c: PoolClient,
  s: NotificationQualificationSelector,
  capability: 'QUALIFICATION_RUN' | 'QUALIFICATION_REVIEW',
) {
  const context = await qualificationContext(c, s),
    native = nativeBrackets.get(c);
  if (
    !native ||
    native.selector !== canonical(s) ||
    native.capability !== capability ||
    native.transaction !== context.tx
  )
    reject('UNBOUND');
}

/** Root-local reconciliation retains a verified late external build response
 * after author/installation withdrawal. It can only create HISTORICAL_ONLY,
 * never an executable origin or replace an already retained original. */
export async function retainLateQualificationOrigin(
  c: PoolClient,
  s: QualificationSelection,
  originId: string,
  signatureHex: string,
) {
  const ctx = await qualificationContext(c, s),
    pins = await readQualificationInstallation(c, s);
  await lock(c, `notification-qualification-origin:${originId}`);
  const row = await c.query<Stored>(
    'select body,body_bytes,body_digest from control.notification_qualification_origin where participant_id=$1 and privacy_domain_id=$2 and origin_id=$3 and installation_id=$4',
    [s.participantId, s.privacyDomainId, originId, s.installationId],
  );
  const request = qualificationOriginRequestSchema.parse(stored(row.rows[0]));
  verifyQualificationOrigin(request, signatureHex, pins);
  const prior = await c.query<Stored>(
    'select body,body_bytes,body_digest from control.notification_qualification_origin_proof where participant_id=$1 and privacy_domain_id=$2 and origin_id=$3',
    [s.participantId, s.privacyDomainId, originId],
  );
  if (prior.rowCount) {
    const proof = qualificationOriginProofSchema.parse(stored(prior.rows[0]));
    if (proof.signatureHex !== signatureHex) reject('IMMUTABLE');
    return proof;
  }
  const proof = qualificationOriginProofSchema.parse({
      schemaVersion: 1,
      originId,
      requestDigest: row.rows[0]!.body_digest,
      signatureHex,
      retainedAtMs: await qualificationNow(c),
      state: 'HISTORICAL_ONLY',
    }),
    d = document(proof);
  await c.query(
    'insert into control.notification_qualification_origin_proof(participant_id,privacy_domain_id,origin_id,body,body_bytes,body_digest) values($1,$2,$3,$4,$5,$6)',
    [s.participantId, s.privacyDomainId, originId, d.body, d.bytes, d.digest],
  );
  await ctx.confirm();
  return proof;
}

function signingPeer(
  s: NotificationQualificationSelector,
  transport: QualificationSignerTransport,
): QualificationPeer {
  const { socket, identity } = transport,
    raw = socket.getPeerCertificate(true).raw;
  if (
    !raw ||
    socket.destroyed ||
    !socket.authorized ||
    socket.getProtocol() !== 'TLSv1.3' ||
    identity.participantId !== s.participantId
  )
    reject('CONTEXT');
  const key = new X509Certificate(raw).publicKey.export({ format: 'der', type: 'spki' });
  if (digest(key) !== identity.keyId) reject('CONTEXT');
  return qualificationPeerSchema.parse({
    principalId: identity.principalId,
    credentialId: identity.credentialId,
    participantEpoch: identity.participantEpoch,
    principalEpoch: identity.principalEpoch,
    credentialEpoch: identity.workloadEpoch,
    workloadId: identity.workloadId,
    keyDigest: identity.keyId,
    certificateDigest: 'sha256:' + createHash('sha256').update(raw).digest('hex'),
  });
}
/** B calls within its actual authenticated workload transaction. This callback
 * is DB-only: reserve B's exact immutable signing intent, then commit before I/O.
 * A retains all current source/run/generation/installation locks and rechecks
 * after the callback; no public caller supplies its measured claims. */
export async function notificationQualificationSigningIntent<T>(
  c: PoolClient,
  selector: QualificationSigningSelector,
  transport: QualificationSignerTransport,
  consume: (sameClient: PoolClient, intent: QualificationSigningIntent) => Promise<T>,
): Promise<T> {
  const { family, ...source } = selector,
    s = qualificationRunSelectorSchema.parse(source);
  if (family !== 'input' && family !== 'capacity') reject();
  const ctx = await qualificationContext(c, s);
  await transport.confirmCurrent();
  // This live owner capability proves the exact installed signer/reviewer
  // were included in the initial Identity union, before any business locks.
  const pins = await readQualificationInstallation(c, s);
  await transport.confirmAuthorities(
    c,
    family === 'capacity' ? [pins.signer, pins.reviewer] : [pins.signer],
  );
  const peer = signingPeer(s, transport),
    sourceIntent = await signingIntent(c, s, peer, family);
  const stable = {
    selector: Object.freeze({ ...sourceIntent.selector }),
    issuer: Object.freeze({ ...sourceIntent.issuer }),
    sourceDigest: sourceIntent.sourceDigest,
  };
  const payload = sourceIntent.family === 'input' ? Buffer.from(sourceIntent.payload) : undefined;
  const intent: QualificationSigningIntent =
    sourceIntent.family === 'input'
      ? Object.freeze({
          ...stable,
          family: 'input' as const,
          get payload() {
            return Buffer.from(payload!);
          },
        })
      : Object.freeze({
          ...stable,
          family: 'capacity' as const,
          claims: Object.freeze({ ...sourceIntent.claims }),
        });
  const snapshot =
    intent.family === 'input'
      ? { ...intent, payloadHex: intent.payload.toString('hex'), payload: undefined }
      : { ...intent };
  const release = c.release,
    query = c.query;
  let releaseAttempted = false;
  const heldRelease: PoolClient['release'] = () => {
    releaseAttempted = true;
    return reject('CONTEXT');
  };
  c.release = heldRelease;
  try {
    const result = await consume(c, intent);
    if (releaseAttempted || c.release !== heldRelease || c.query !== query) reject('CONTEXT');
    await ctx.confirm();
    await transport.confirmCurrent();
    const after = await signingIntent(c, s, signingPeer(s, transport), family);
    const compared =
      after.family === 'input'
        ? { ...after, payloadHex: after.payload.toString('hex'), payload: undefined }
        : { ...after };
    // JSON serialization omits only the explicitly removed Buffer; every actual
    // selector/claim/issuer byte remains part of the before/after comparison.
    if (JSON.stringify(snapshot) !== JSON.stringify(compared)) reject('EVIDENCE');
    return result;
  } finally {
    c.release = release;
    c.query = query;
  }
}
/** CURRENT_ADOPTION_ONLY. B first commits its immutable original provider result
 * under its own custody owner. Failure here preserves that original in B and
 * denies A publication. Historical readback is B's original lookup + A's read
 * original; this method never re-signs or turns expired history into authority. */
export async function retainNotificationQualificationSignedOriginal(
  c: PoolClient,
  selector: QualificationSigningSelector,
  transport: QualificationSignerTransport,
  value: QualificationSignedOriginal,
) {
  z.uuidv7().parse(value.attemptId);
  const original = { ...value, payload: Buffer.from(value.payload), cose: Buffer.from(value.cose) };
  if (original.family !== selector.family) reject('EVIDENCE');
  return notificationQualificationSigningIntent(c, selector, transport, async (same, intent) => {
    if (original.sourceDigest !== intent.sourceDigest) reject('EVIDENCE');
    const { family, ...s } = selector;
    if (intent.family === 'capacity') {
      if (original.family !== 'capacity') reject('EVIDENCE');
      const expected = encodeNotificationAsync('capacity', {
        ...intent.claims,
        ...original.issuance,
      });
      if (!expected.equals(original.payload)) reject('EVIDENCE');
    } else if (!original.payload.equals(intent.payload)) reject('EVIDENCE');
    return retainCurrentSigned(
      same,
      s,
      signingPeer(s, transport),
      family,
      original.payload,
      original.cose,
      { attemptId: original.attemptId, sourceDigest: original.sourceDigest },
    );
  });
}
