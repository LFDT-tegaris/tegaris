import { randomBytes } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import {
  qualificationCanonicalJson,
  qualificationDigest,
} from '../../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import {
  qualificationKeyCopy,
  qualificationKeyInstallation,
  qualificationKeyRequestSchema,
  qualificationKeyRequestDigest,
  qualificationKeyDescriptorDigest,
  validateQualificationKeyRequest,
  validateQualificationKeyObservation,
  QualificationKeyProviderUnknown,
  type QualificationKeyPeer,
  type QualificationKeyInstallation,
  type QualificationKeyObservation,
} from '../../../../identity-service/src/domain/qualification-key-provider.js';
import {
  withInstalledQualificationIssuer,
  type InstalledQualificationIssuer,
  type ProviderRetryQualificationScope,
} from './provider-retry-qualification.js';

export interface QualificationKeySelection {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly installationId: string;
}
export type QualificationKeyIntent = {
  readonly attemptId: string;
  readonly operationId: string;
} & (
  | { readonly method: 'INSPECT' }
  | { readonly method: 'PROVE'; readonly inspectionAttemptId: string }
);
const uuid = z.uuidv7();
export const qualificationKeySelectionSchema = z.strictObject({
  participantId: uuid,
  privacyDomainId: uuid,
  installationId: uuid,
});
export const qualificationKeyIntentSchema = z.discriminatedUnion('method', [
  z.strictObject({ method: z.literal('INSPECT'), attemptId: uuid, operationId: uuid }),
  z.strictObject({
    method: z.literal('PROVE'),
    attemptId: uuid,
    operationId: uuid,
    inspectionAttemptId: uuid,
  }),
]);
function fail(): never {
  throw new QualificationKeyProviderUnknown();
}
const bytes = (v: unknown) => Buffer.from(qualificationCanonicalJson(v));

async function context(client: PoolClient, s: QualificationKeySelection, bootstrap = false) {
  [s.participantId, s.privacyDomainId, s.installationId].forEach((v) => uuid.parse(v));
  await client.query('select openpc.assert_request_context(true)');
  const read = async () =>
    (
      await client.query<{ role: string; tx: string; request: string; valid: boolean }>(
        `select current_user::text role,pg_current_xact_id()::text tx,
    openpc.current_operation_id()::text request,openpc.current_participant_id()=$1::uuid and openpc.current_privacy_domain_id()=$2::uuid
    and current_setting('transaction_isolation')='read committed' and current_setting('row_security')='on'
    and openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' valid`,
        [s.participantId, s.privacyDomainId],
      )
    ).rows[0];
  const start = await read();
  if (
    !start?.valid ||
    !(
      bootstrap
        ? ['openpc_operations_qualification_bootstrap']
        : ['openpc_control_owner', 'openpc_operations_qualification_owner']
    ).includes(start.role)
  )
    fail();
  const confirm = async () => {
    const r = await read();
    if (!r?.valid || r.tx !== start.tx || r.role !== start.role || r.request !== start.request)
      fail();
  };
  await confirm();
  return {
    confirm,
    scope: {
      participantId: s.participantId,
      privacyDomainId: s.privacyDomainId,
      requestId: start.request,
    } satisfies ProviderRetryQualificationScope,
  };
}
async function lock(client: PoolClient, s: QualificationKeySelection, exclusive = false) {
  // Existing source fences precede the local installation/attempt fences on
  // every live and historical path. This read only selects immutable identities.
  const source = await client.query<{ environment_id: string; authority: string }>(
    `select environment_id,pins->>'authorityId' authority
    from control.qualification_key_installation where installation_id=$1 and participant_id=$2 and privacy_domain_id=$3`,
    [s.installationId, s.participantId, s.privacyDomainId],
  );
  if (source.rowCount) {
    if (source.rowCount !== 1) fail();
    const p = source.rows[0]!;
    if (
      !/^[a-z][a-z0-9-]{2,31}$/u.test(p.environment_id) ||
      !/^[a-z][a-z0-9-]{2,31}$/u.test(p.authority)
    )
      fail();
    await client.query(
      "select pg_advisory_xact_lock_shared(hashtextextended('operations-generation:'||$1,0))",
      [p.environment_id],
    );
    await client.query(
      "select pg_advisory_xact_lock_shared(hashtextextended('operations-qualification:'||$1||':'||$2,0))",
      [p.environment_id, p.authority],
    );
  }
  await client.query(
    `select ${exclusive ? 'pg_advisory_xact_lock' : 'pg_advisory_xact_lock_shared'}(hashtextextended('qualification-key-installation:'||$1,0))`,
    [s.installationId],
  );
}
export async function installInitialQualificationKeyCustody(client: PoolClient, value: unknown) {
  const installed = qualificationKeyInstallation(value),
    p = installed.pins;
  const { confirm } = await context(client, p, true);
  await lock(client, p, true);
  const prior = await client.query<{ pins_bytes: Buffer; state: string }>(
    'select pins_bytes,state from control.qualification_key_installation where installation_id=$1',
    [p.installationId],
  );
  if (prior.rowCount) {
    if (
      prior.rowCount !== 1 ||
      prior.rows[0]!.state !== 'ACTIVE' ||
      !prior.rows[0]!.pins_bytes.equals(installed.bytes)
    )
      fail();
  } else
    await client.query(
      `insert into control.qualification_key_installation(installation_id,participant_id,privacy_domain_id,environment_id,pins,pins_bytes,pins_digest)
    values($1,$2,$3,$4,$5,$6,$7)`,
      [
        p.installationId,
        p.participantId,
        p.privacyDomainId,
        p.environmentId,
        p,
        installed.bytes,
        installed.digest,
      ],
    );
  await confirm();
  return installed.digest;
}
export async function withdrawQualificationKeyCustody(
  client: PoolClient,
  s: QualificationKeySelection,
) {
  const { confirm } = await context(client, s, true);
  await lock(client, s, true);
  const r = await client.query(
    `update control.qualification_key_installation set state='REVOKED'
    where installation_id=$1 and participant_id=$2 and privacy_domain_id=$3 and state in ('ACTIVE','REVOKED') returning state`,
    [s.installationId, s.participantId, s.privacyDomainId],
  );
  if (r.rowCount !== 1) fail();
  await confirm();
}
export async function readQualificationKeyInstallation(
  client: PoolClient,
  s: QualificationKeySelection,
  holdSource = true,
) {
  const { confirm } = await context(client, s);
  if (holdSource) await lock(client, s);
  const r = await client.query<{
    pins: unknown;
    pins_bytes: Buffer;
    pins_digest: string;
    state: string;
  }>(
    `select pins,pins_bytes,pins_digest,state from control.qualification_key_installation
    where installation_id=$1 and participant_id=$2 and privacy_domain_id=$3${holdSource ? ' for share' : ''}`,
    [s.installationId, s.participantId, s.privacyDomainId],
  );
  if (r.rowCount !== 1) fail();
  const row = r.rows[0]!,
    installed = qualificationKeyInstallation(row.pins);
  if (
    !installed.bytes.equals(row.pins_bytes) ||
    installed.digest !== row.pins_digest ||
    installed.pins.installationId !== s.installationId ||
    installed.pins.participantId !== s.participantId ||
    installed.pins.privacyDomainId !== s.privacyDomainId
  )
    fail();
  await confirm();
  return { ...installed, state: row.state };
}
export async function readQualificationKeyAttempt(
  client: PoolClient,
  s: QualificationKeySelection,
  attemptId: string,
) {
  uuid.parse(attemptId);
  const { confirm } = await context(client, s),
    installed = await readQualificationKeyInstallation(client, s);
  const r = await client.query<{
    request: unknown;
    request_bytes: Buffer;
    request_digest: string;
    state: string;
    observation: unknown;
    observation_bytes: Buffer | null;
    observation_digest: string | null;
  }>(
    `select a.request,a.request_bytes,a.request_digest,a.state,o.observation,o.observation_bytes,o.observation_digest
    from control.qualification_key_attempt a left join control.qualification_key_observation o using(attempt_id)
    where a.attempt_id=$1 and a.installation_id=$2 and a.participant_id=$3 and a.privacy_domain_id=$4`,
    [attemptId, s.installationId, s.participantId, s.privacyDomainId],
  );
  if (r.rowCount !== 1) fail();
  const row = r.rows[0]!,
    request = validateQualificationKeyRequest(row.request, installed.pins);
  if (
    request.attemptId !== attemptId ||
    !bytes(request).equals(row.request_bytes) ||
    qualificationKeyRequestDigest(request) !== row.request_digest
  )
    fail();
  const observation =
    row.observation === null
      ? undefined
      : validateQualificationKeyObservation(request, row.observation, installed.pins);
  if (
    observation &&
    (!row.observation_bytes?.equals(bytes(observation)) ||
      row.observation_digest !== qualificationDigest(bytes(observation)))
  )
    fail();
  await confirm();
  return { installed, request, observation, state: row.state };
}

/** Called only inside the native peer owner. The SQL role is trusted storage
 * authority; this function is not a network endpoint or an identity verifier. */
export async function reserveQualificationKeyObservation(
  client: PoolClient,
  s: QualificationKeySelection,
  peer: QualificationKeyPeer,
  intent: QualificationKeyIntent,
) {
  const selected = qualificationKeyCopy(qualificationKeySelectionSchema.parse(s)),
    actual = qualificationKeyCopy(peer),
    wanted = qualificationKeyCopy(qualificationKeyIntentSchema.parse(intent));
  uuid.parse(wanted.attemptId);
  uuid.parse(wanted.operationId);
  const { confirm, scope } = await context(client, selected);
  const installed = await readQualificationKeyInstallation(client, selected),
    p = installed.pins;
  if (
    installed.state !== 'ACTIVE' ||
    qualificationCanonicalJson(p.peer) !== qualificationCanonicalJson(actual)
  )
    fail();
  return withInstalledQualificationIssuer(
    client,
    scope,
    p.environmentId,
    { authorityId: p.authorityId, keyId: p.keyId, epoch: p.keyEpoch, purpose: p.purpose },
    async (_, issuer) => {
      const clock = await client.query<{ at: string }>(
          'select floor(extract(epoch from clock_timestamp())*1000)::text at',
        ),
        at = Number(clock.rows[0]?.at);
      if (
        issuer.rootEpoch !== p.rootEpoch ||
        issuer.publicKeySpkiHex !== p.publicKeySpkiHex ||
        at < p.validFromMs ||
        at >= p.validUntilMs
      )
        fail();
      await client.query(
        "select pg_advisory_xact_lock(hashtextextended('qualification-key-attempt:'||$1,0))",
        [wanted.attemptId],
      );
      const exists = await client.query(
        'select 1 from control.qualification_key_attempt where attempt_id=$1',
        [wanted.attemptId],
      );
      if (exists.rowCount) {
        const old = await readQualificationKeyAttempt(client, selected, wanted.attemptId);
        if (
          old.request.operationId !== wanted.operationId ||
          old.request.method !== wanted.method ||
          old.state !== 'DISPATCHED'
        )
          fail();
        if (wanted.method === 'PROVE') {
          const inspection = await readQualificationKeyAttempt(
            client,
            selected,
            wanted.inspectionAttemptId,
          );
          if (
            inspection.request.method !== 'INSPECT' ||
            !inspection.observation?.descriptor ||
            old.request.method !== 'PROVE' ||
            old.request.inspectionAttemptId !== wanted.inspectionAttemptId ||
            old.request.descriptorDigest !==
              qualificationKeyDescriptorDigest(inspection.observation.descriptor)
          )
            fail();
        }
        await confirm();
        return { ...old, dispatch: false };
      }
      let proof:
        | {
            method: 'PROVE';
            inspectionAttemptId: string;
            challengeHex: string;
            descriptorDigest: string;
          }
        | { method: 'INSPECT' } = { method: 'INSPECT' };
      if (wanted.method === 'PROVE') {
        const inspection = await readQualificationKeyAttempt(
          client,
          selected,
          wanted.inspectionAttemptId,
        );
        if (
          inspection.request.method !== 'INSPECT' ||
          inspection.observation?.outcome !== 'OBSERVED' ||
          !inspection.observation.descriptor ||
          inspection.request.deadlineAtMs <= at
        )
          fail();
        proof = {
          method: 'PROVE',
          inspectionAttemptId: wanted.inspectionAttemptId,
          challengeHex: randomBytes(32).toString('hex'),
          descriptorDigest: qualificationKeyDescriptorDigest(inspection.observation.descriptor),
        };
      }
      const request = validateQualificationKeyRequest(
        qualificationKeyRequestSchema.parse({
          schemaVersion: p.schemaVersion,
          ...(p.schemaVersion === 2 ? { observer: p.observer } : {}),
          installationDigest: installed.digest,
          participantId: p.participantId,
          privacyDomainId: p.privacyDomainId,
          environmentId: p.environmentId,
          authorityId: p.authorityId,
          rootEpoch: p.rootEpoch,
          keysetDigest: issuer.keysetDigest,
          revocationsDigest: issuer.revocationsDigest,
          keyId: p.keyId,
          keyEpoch: p.keyEpoch,
          purpose: p.purpose,
          providerId: p.providerId,
          reference: p.reference,
          version: p.version,
          peer: actual,
          operationId: wanted.operationId,
          attemptId: wanted.attemptId,
          issuedAtMs: at,
          deadlineAtMs: Math.min(at + 10000, p.validUntilMs, issuer.validUntilMs),
          ...proof,
        }),
        p,
      );
      await client.query(
        `insert into control.qualification_key_attempt(attempt_id,participant_id,privacy_domain_id,operation_id,installation_id,request,request_bytes,request_digest)
      values($1,$2,$3,$4,$5,$6,$7,$8)`,
        [
          request.attemptId,
          p.participantId,
          p.privacyDomainId,
          request.operationId,
          p.installationId,
          request,
          bytes(request),
          qualificationKeyRequestDigest(request),
        ],
      );
      const dispatched = await client.query(
        "update control.qualification_key_attempt set state='DISPATCHED' where attempt_id=$1 and state='PREPARED' returning state",
        [request.attemptId],
      );
      if (dispatched.rowCount !== 1) fail();
      await confirm();
      return { installed, request, observation: undefined, state: 'DISPATCHED', dispatch: true };
    },
  );
}

/** Historical attachment intentionally survives expiry/revocation. It grants no
 * current use and never replaces an original. Root recovery owns this scope. */
export async function retainQualificationKeyObservation(
  client: PoolClient,
  s: QualificationKeySelection,
  attemptId: string,
  value: unknown,
) {
  const copied = qualificationKeyCopy(value),
    { confirm } = await context(client, s);
  await readQualificationKeyInstallation(client, s);
  await client.query(
    "select pg_advisory_xact_lock(hashtextextended('qualification-key-attempt:'||$1,0))",
    [uuid.parse(attemptId)],
  );
  const old = await readQualificationKeyAttempt(client, s, attemptId);
  if (old.state !== 'DISPATCHED') fail();
  const observation = validateQualificationKeyObservation(
    old.request,
    copied,
    old.installed.pins,
    old.observation,
  );
  if (!old.observation)
    await client.query(
      `insert into control.qualification_key_observation(attempt_id,participant_id,privacy_domain_id,observation,observation_bytes,observation_digest)
    values($1,$2,$3,$4,$5,$6)`,
      [
        attemptId,
        s.participantId,
        s.privacyDomainId,
        observation,
        bytes(observation),
        qualificationDigest(bytes(observation)),
      ],
    );
  await confirm();
  return observation;
}
export async function readCurrentQualificationKeyObservation(
  client: PoolClient,
  s: QualificationKeySelection,
  peer: QualificationKeyPeer,
  attemptId: string,
) {
  const { scope, confirm } = await context(client, s),
    old = await readQualificationKeyAttempt(client, s, attemptId),
    p = old.installed.pins;
  if (
    old.installed.state !== 'ACTIVE' ||
    qualificationCanonicalJson(peer) !== qualificationCanonicalJson(p.peer) ||
    old.observation?.outcome !== 'OBSERVED'
  )
    fail();
  return withInstalledQualificationIssuer(
    client,
    scope,
    p.environmentId,
    { authorityId: p.authorityId, keyId: p.keyId, epoch: p.keyEpoch, purpose: p.purpose },
    async (_, issuer) => {
      const now = Number(
        (
          await client.query<{ at: string }>(
            'select floor(extract(epoch from clock_timestamp())*1000)::text at',
          )
        ).rows[0]?.at,
      );
      if (
        now >= p.validUntilMs ||
        now >= old.request.deadlineAtMs ||
        issuer.rootEpoch !== old.request.rootEpoch ||
        issuer.keysetDigest !== old.request.keysetDigest ||
        issuer.revocationsDigest !== old.request.revocationsDigest ||
        issuer.publicKeySpkiHex !== p.publicKeySpkiHex
      )
        fail();
      await confirm();
      return old.observation!;
    },
  );
}
export type { QualificationKeyInstallation, QualificationKeyObservation };

/** Trusted native composition only. Subject TLS and observer key possession
 * are checked by the peer owner before entering this database-only callback.
 * Issuer trust does not grant SIGN, execution, review or qualification. */
export async function withCurrentQualificationKeyIssuer<T>(
  client: PoolClient,
  selection: QualificationKeySelection,
  subject: QualificationKeyPeer,
  consume: (
    sameClient: PoolClient,
    installed: Awaited<ReturnType<typeof readQualificationKeyInstallation>>,
    issuer: Readonly<InstalledQualificationIssuer>,
  ) => Promise<T>,
): Promise<T> {
  const { scope, confirm } = await context(client, selection);
  const installed = await readQualificationKeyInstallation(client, selection),
    p = installed.pins;
  if (
    p.schemaVersion !== 2 ||
    installed.state !== 'ACTIVE' ||
    qualificationCanonicalJson(subject) !== qualificationCanonicalJson(p.peer)
  )
    fail();
  return withInstalledQualificationIssuer(
    client,
    scope,
    p.environmentId,
    { authorityId: p.authorityId, keyId: p.keyId, epoch: p.keyEpoch, purpose: p.purpose },
    async (same, issuer) => {
      const current = async () => {
        await confirm();
        const clock = await same.query<{ at: string }>(
          'select floor(extract(epoch from clock_timestamp())*1000)::text at',
        );
        const at = Number(clock.rows[0]?.at);
        if (
          !Number.isSafeInteger(at) ||
          at < p.validFromMs ||
          at >= p.validUntilMs ||
          issuer.rootEpoch !== p.rootEpoch ||
          issuer.publicKeySpkiHex !== p.publicKeySpkiHex
        )
          fail();
      };
      await current();
      const result = await consume(same, installed, issuer);
      await current();
      return result;
    },
  );
}
