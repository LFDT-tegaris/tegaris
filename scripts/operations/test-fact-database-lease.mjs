import { setTimeout as delay } from 'node:timers/promises';
import { testFactCandidateDatabaseConsumer as consumer } from './installation-consumer-bindings.mjs';

const failure = () => new Error('OPS_TEST_FACT_DATABASE_LEASE_UNAVAILABLE');
const role = consumer.databaseRole;

/** Installation owner for one isolated TEST candidate database's existing reader
 * login. Never pass this privileged connection to the Fact workload. The exact
 * role is reserved with a session lock before publication; no other reader
 * sessions may exist. There is no role creation, password replacement, migration,
 * business-state seeding or automatic restoration of the original LOGIN state.
 * PostgreSQL VALID UNTIL also prevents password login after signed expiry when
 * the publisher dies. It cannot terminate an existing session by itself.
 */
export async function reserveTestFactDatabaseLease(pool) {
  const client = await pool.connect();
  let identity,
    released = false,
    closed = false,
    failed = false,
    closing;
  client.on('error', () => {
    failed = true;
  });
  const query = (...args) => {
    if (failed || released) throw failure();
    return client.query(...args);
  };
  async function checkOwner() {
    const result = await query(
      `select d.oid::text database_oid,r.oid::text role_oid,
      current_database() database_name,r.rolsuper,r.rolbypassrls,r.rolcreaterole,r.rolcreatedb,r.rolreplication,
      r.rolcanlogin,r.rolvaliduntil,
      exists(select 1 from pg_auth_members where member=r.oid) memberships
      from pg_database d cross join pg_roles r where d.datname=current_database() and r.rolname=$1`,
      [role],
    );
    const row = result.rows[0];
    if (
      result.rowCount !== 1 ||
      row.database_name !== consumer.databaseName ||
      row.rolsuper ||
      row.rolbypassrls ||
      row.rolcreaterole ||
      row.rolcreatedb ||
      row.rolreplication ||
      row.memberships ||
      (identity &&
        (row.database_oid !== identity.database_oid || row.role_oid !== identity.role_oid))
    )
      throw failure();
    return row;
  }
  async function sessions() {
    return query('select pid from pg_stat_activity where datid=$1::oid and usesysid=$2::oid', [
      identity.database_oid,
      identity.role_oid,
    ]);
  }
  async function close() {
    if (closing) return closing;
    closed = true;
    closing = (async () => {
      try {
        await checkOwner();
        await query(`alter role ${role} nologin valid until 'epoch'`);
        const active = await sessions();
        for (const { pid } of active.rows) {
          const result = await query(
            `select pg_terminate_backend(pid) stopped from pg_stat_activity
            where pid=$1 and datid=$2::oid and usesysid=$3::oid`,
            [pid, identity.database_oid, identity.role_oid],
          );
          if (result.rows.some((row) => row.stopped !== true)) throw failure();
        }
        const deadline = performance.now() + 5000;
        while ((await sessions()).rowCount !== 0) {
          if (performance.now() >= deadline) throw failure();
          await delay(25);
        }
        const row = await checkOwner();
        if (row.rolcanlogin) throw failure();
      } catch {
        failed = true;
        throw failure();
      } finally {
        // Destroying the dedicated admin session releases only this reservation.
        // Any failure above remains UNKNOWN; the installer must retain ownership.
        released = true;
        client.release(true);
      }
    })();
    return closing;
  }
  try {
    await query("set statement_timeout='5s'");
    await query("set lock_timeout='2s'");
    identity = await checkOwner();
    const lock = await query(
      "select pg_try_advisory_lock(hashtextextended('openpc:test:fact-candidate-secret-lease:v1',0)) held",
    );
    if (lock.rows[0]?.held !== true || (await sessions()).rowCount !== 0) throw failure();
    // Denial only. Authenticated recipient admission below is required to enable.
    await query(`alter role ${role} nologin valid until 'epoch'`);
  } catch {
    released = true;
    client.release(true);
    throw failure();
  }
  let expiresAt;
  return Object.freeze({
    /** Only the real withInstalledSecretRecipient callback may invoke activation.
     * Its caller must close this owner if that transaction/post-check fails. */
    async activate(profile) {
      if (
        closed ||
        failed ||
        profile.consumerId !== consumer.workload ||
        profile.store !== consumer.store ||
        !Number.isSafeInteger(profile.validUntilMs) ||
        profile.validUntilMs <= Date.now() ||
        (expiresAt !== undefined && expiresAt !== profile.validUntilMs)
      )
        throw failure();
      await checkOwner();
      const date = new Date(profile.validUntilMs).toISOString();
      if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/u.test(date)) throw failure();
      await query(`alter role ${role} login valid until '${date}'`);
      expiresAt = profile.validUntilMs;
      await this.check(profile);
    },
    async check(profile) {
      if (
        closed ||
        failed ||
        expiresAt === undefined ||
        expiresAt !== profile.validUntilMs ||
        expiresAt <= Date.now()
      )
        throw failure();
      const row = await checkOwner();
      if (
        !row.rolcanlogin ||
        !(row.rolvaliduntil instanceof Date) ||
        row.rolvaliduntil.getTime() !== expiresAt
      )
        throw failure();
    },
    close,
  });
}
