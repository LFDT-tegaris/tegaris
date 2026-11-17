import { createPublicKey, timingSafeEqual } from 'node:crypto';
import type { Pool } from 'pg';
import { z } from 'zod';
import {
  retirementHost,
  retirementWireBytes,
  retirementWireDigest,
} from './store-retirement-wire.js';

const pinsSchema = z.strictObject({
  host: retirementHost,
  controlSpki: z.instanceof(Buffer),
  targetSpki: z.instanceof(Buffer),
  verifierSecret: z.instanceof(Buffer).refine((value) => value.length === 32),
  databaseRole: z.string().regex(/^[a-z_][a-z0-9_]{0,62}$/u),
  workloadCredentialId: z.uuidv7(),
  workloadCredentialEpoch: z
    .string()
    .max(20)
    .regex(/^(0|[1-9][0-9]*)$/u),
  validFromMs: z.number().int().nonnegative().safe(),
  validUntilMs: z.number().int().positive().safe(),
  installationReference: z.string().min(1).max(256),
});
export type StoreRetirementInstallation = z.infer<typeof pinsSchema>;
const rejected = () => new Error('Store retirement installation rejected');

/** Operational trust supplied by the installer, never an HTTP proposal. This
 * does not admit an attempt, assert source eligibility or grant a physical effect. */
export function validateStoreRetirementInstallation(input: StoreRetirementInstallation) {
  try {
    const pins = pinsSchema.parse(input);
    z.uuidv7().parse(pins.host.scope.participant_id);
    z.uuidv7().parse(pins.host.scope.privacy_domain_id);
    if (
      pins.validUntilMs <= pins.validFromMs ||
      BigInt(pins.workloadCredentialEpoch) > 18446744073709551615n ||
      pins.controlSpki.equals(pins.targetSpki)
    )
      throw rejected();
    for (const bytes of [pins.controlSpki, pins.targetSpki]) {
      const key = createPublicKey({ key: bytes, type: 'spki', format: 'der' });
      if (
        bytes.length !== 91 ||
        key.asymmetricKeyType !== 'ec' ||
        key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
        !key.export({ type: 'spki', format: 'der' }).equals(bytes)
      )
        throw rejected();
    }
    return pins;
  } catch {
    throw rejected();
  }
}

/** Owns the transaction so host pins and their verifier secret cannot be
 * installed separately. Repeating setup only accepts the exact original pins;
 * expired/revoked trust is never renewed or replaced through this entrypoint. */
export async function installStoreRetirementHost(pool: Pool, input: StoreRetirementInstallation) {
  const valid = validateStoreRetirementInstallation(input);
  const pins = {
    ...valid,
    host: structuredClone(valid.host),
    controlSpki: Buffer.from(valid.controlSpki),
    targetSpki: Buffer.from(valid.targetSpki),
    verifierSecret: Buffer.from(valid.verifierSecret),
  };
  const hostDigest = retirementWireDigest(pins.host);
  const expected = {
    participant_id: pins.host.scope.participant_id,
    privacy_domain_id: pins.host.scope.privacy_domain_id,
    host_digest: hostDigest,
    host_wire: retirementWireBytes(pins.host),
    control_spki: pins.controlSpki,
    target_spki: pins.targetSpki,
    database_role: pins.databaseRole,
    workload_credential_id: pins.workloadCredentialId,
    workload_credential_epoch: pins.workloadCredentialEpoch,
    valid_from_ms: String(pins.validFromMs),
    valid_until_ms: String(pins.validUntilMs),
    installation_reference: pins.installationReference,
  };
  let client;
  let commitStarted = false;
  let discardConnection = false;
  try {
    client = await pool.connect();
    await client.query('begin');
    await client.query(
      "set local lock_timeout='2s'; set local statement_timeout='5s'; set local idle_in_transaction_session_timeout='5s'",
    );
    await client.query(
      "select pg_advisory_xact_lock(hashtextextended('openpc:retirement-install:'||$1,0))",
      [hostDigest],
    );
    const authority = await client.query<{ allowed: boolean }>(
      `select
      current_database()='openpc_control' and current_user=session_user
      and (pg_has_role(session_user,'openpc_control_owner','USAGE') or pg_has_role(session_user,'openpc_control_key_governor','USAGE'))
      and exists(select 1 from pg_roles r where r.rolname=$1 and r.rolcanlogin
        and not r.rolsuper and not r.rolbypassrls and not r.rolcreaterole
        and pg_has_role(r.oid,'openpc_control_worker','USAGE')
        and not pg_has_role(r.oid,'openpc_control_owner','MEMBER')
        and not pg_has_role(r.oid,'openpc_control_key_governor','MEMBER')) allowed`,
      [pins.databaseRole],
    );
    if (authority.rows[0]?.allowed !== true) throw rejected();
    const identity = await client.query(
      `select c.credential_id from control.credential c
      join control.principal w using(participant_id,principal_id)
      join control.participant p using(participant_id)
      join control.privacy_domain d on d.participant_id=p.participant_id and d.privacy_domain_id=$2
      where c.participant_id=$1 and c.credential_id=$3 and c.credential_epoch=$4
       and c.kind in ('WORKLOAD_MTLS','WORKLOAD_OIDC') and c.state='ACTIVE'
       and w.kind='WORKLOAD' and w.state='ACTIVE' and p.state='ACTIVE' and p.archived_at is null and d.state='ACTIVE'
       and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()
       and floor(extract(epoch from c.valid_from)*1000)<=$5 and floor(extract(epoch from c.valid_until)*1000)>=$6
       and c.public_key_digest is distinct from sha256($7::bytea) and c.public_key_digest is distinct from sha256($8::bytea)
      for share of c,w,p,d`,
      [
        expected.participant_id,
        expected.privacy_domain_id,
        pins.workloadCredentialId,
        pins.workloadCredentialEpoch,
        pins.validFromMs,
        pins.validUntilMs,
        pins.controlSpki,
        pins.targetSpki,
      ],
    );
    if (identity.rowCount !== 1) throw rejected();
    const scope = [expected.participant_id, expected.privacy_domain_id, hostDigest];
    const existing = await client.query(
      `select h.*,k.verifier_secret from control.store_retirement_host h
      left join control.store_retirement_verifier_key k using(participant_id,privacy_domain_id,host_digest)
      where h.participant_id=$1 and h.privacy_domain_id=$2 and h.host_digest=$3`,
      scope,
    );
    const reused = existing.rowCount === 1;
    if (reused) {
      const row = existing.rows[0];
      try {
        if (
          !Buffer.isBuffer(row.verifier_secret) ||
          row.verifier_secret.length !== 32 ||
          !timingSafeEqual(row.verifier_secret, pins.verifierSecret)
        )
          throw rejected();
      } finally {
        if (Buffer.isBuffer(row.verifier_secret)) row.verifier_secret.fill(0);
      }
      for (const [field, value] of Object.entries(expected)) {
        if (
          Buffer.isBuffer(value)
            ? !Buffer.isBuffer(row[field]) || !value.equals(row[field])
            : row[field] !== value
        )
          throw rejected();
      }
    } else {
      if (existing.rowCount !== 0) throw rejected();
      await client.query(
        `insert into control.store_retirement_host(participant_id,privacy_domain_id,host_digest,host_wire,
        control_spki,target_spki,database_role,workload_credential_id,workload_credential_epoch,valid_from_ms,valid_until_ms,installation_reference)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        Object.values(expected),
      );
      await client.query(
        `insert into control.store_retirement_verifier_key(participant_id,privacy_domain_id,host_digest,verifier_secret)
        values($1,$2,$3,$4)`,
        [...scope, pins.verifierSecret],
      );
    }
    const live = await client.query<{ live: boolean }>(
      `select floor(extract(epoch from clock_timestamp())*1000) >= $1
      and floor(extract(epoch from clock_timestamp())*1000) < $2 live`,
      [pins.validFromMs, pins.validUntilMs],
    );
    if (live.rows[0]?.live !== true) throw rejected();
    commitStarted = true;
    await client.query('commit');
    return { hostDigest, state: reused ? ('REUSED' as const) : ('INSTALLED' as const) };
  } catch {
    if (client)
      await client.query('rollback').catch(() => {
        discardConnection = true;
      });
    if (commitStarted)
      throw new Error('Store retirement installation outcome unknown; reuse original pins');
    throw rejected();
  } finally {
    pins.verifierSecret.fill(0);
    client?.release(discardConnection);
  }
}
