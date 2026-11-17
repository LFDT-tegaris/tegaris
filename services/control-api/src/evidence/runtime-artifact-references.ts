import type { PoolClient } from 'pg';
import { z } from 'zod';
import { lockModuleLifecycleReferences } from '../../../module-registry/src/db/module-lifecycle-preflight.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';

// @ts-expect-error The JavaScript migration declaration is validated below and bundled statically.
import * as declaration from './runtime-artifact-reference-guards.mjs';
const catalogue = z
  .array(
    z.strictObject({ kind: z.string().regex(/^[A-Z_]+$/u), table: z.string().regex(/^[a-z_]+$/u) }),
  )
  .min(1)
  .max(32)
  .parse(declaration.runtimeArtifactReferenceOwners);
const limit = z.number().int().min(1).max(256).parse(declaration.runtimeArtifactReferenceLimit);
const kinds = new Set(catalogue.map((owner) => owner.kind));
if (kinds.size !== catalogue.length)
  throw new Error('Runtime artifact observation declaration unavailable');
const kind = z.string().refine((value) => kinds.has(value));
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const id = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_./:-]{0,255}$/u);
const ordinal = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
export const runtimeArtifactReferenceSelector = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  inputId: z.uuidv7(),
  configurationDigest: digest,
});
export type RuntimeArtifactReferenceSelector = z.infer<typeof runtimeArtifactReferenceSelector>;
const fields = <T extends z.ZodType>(value: T) =>
  z
    .record(z.string().regex(/^[a-zA-Z][a-zA-Z0-9]{0,63}$/u), value)
    .refine((v) => Object.keys(v).length <= 16);
const reference = z.strictObject({ kind, id, required: z.boolean() });
const token = z.strictObject({ kind: z.enum(['CONFIGURATION', 'POLICY', 'CAPSULE']), digest });
const ownerRow = z.strictObject({
  kind,
  id,
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  revision: ordinal.nullable(),
  state: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/u),
  digests: fields(digest.nullable()),
  references: z.array(reference).max(1026),
  tokens: z.array(token).max(8),
  checks: fields(z.boolean().nullable()),
  details: fields(z.string().max(256).nullable()),
});
export type RuntimeArtifactReferenceOwner = z.infer<typeof ownerRow>;
const branch = z.strictObject({ overflow: z.boolean(), rows: z.array(ownerRow).max(limit) });
const inventory = z
  .strictObject({
    participantId: z.uuidv7(),
    privacyDomainId: z.uuidv7(),
    runtimeProducerFencesObserved: z.boolean(),
    dependencyProducerFencesObserved: z.boolean().default(false),
    root: ownerRow.nullable(),
    owners: z.record(z.string(), branch),
  })
  .refine(
    (value) =>
      Object.keys(value.owners).length === kinds.size &&
      Object.keys(value.owners).every((name) => kinds.has(name)),
  );
export class RuntimeArtifactReferenceError extends Error {
  constructor(readonly reason: 'UNAVAILABLE' | 'INVALID' | 'CHANGED' = 'UNAVAILABLE') {
    super(`Runtime artifact observation ${reason}`);
  }
}
const key = (row: Pick<RuntimeArtifactReferenceOwner, 'kind' | 'id'>) => `${row.kind}:${row.id}`;
const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
function normalized(row: RuntimeArtifactReferenceOwner) {
  return {
    ...row,
    references: [...row.references].sort((a, b) => compare(canonicalJson(a), canonicalJson(b))),
    tokens: [...row.tokens].sort((a, b) => compare(canonicalJson(a), canonicalJson(b))),
  };
}

/** Pure classification of a database observation. Tests may supply rows here;
 * doing so establishes no authentication, transaction, writer fence or custody.
 * The production reader below supplies the real scoped SQL snapshot. No output
 * is an eligibility flag, disposition receipt or authority to delete/reselect. */
export function inspectRuntimeArtifactReferences(selected: unknown, value: unknown) {
  try {
    const selector = runtimeArtifactReferenceSelector.parse(immutableJsonCopy(selected));
    const observed = inventory.parse(immutableJsonCopy(value));
    if (
      observed.participantId !== selector.participantId ||
      observed.privacyDomainId !== selector.privacyDomainId
    )
      throw new Error();
    const unresolved = new Set<string>();
    const rows = new Map<string, RuntimeArtifactReferenceOwner>();
    const scoped = (row: RuntimeArtifactReferenceOwner) => {
      if (
        row.participantId !== selector.participantId ||
        row.privacyDomainId !== selector.privacyDomainId
      )
        throw new Error();
      return normalized(row);
    };
    for (const [name, owner] of Object.entries(observed.owners)) {
      if (owner.overflow) unresolved.add(`TRUNCATED_OWNER:${name}`);
      for (const raw of owner.rows) {
        const row = scoped(raw),
          identity = key(row);
        if (row.kind !== name || rows.has(identity)) throw new Error();
        rows.set(identity, row);
      }
    }
    const root = observed.root === null ? null : scoped(observed.root);
    if (root) {
      if (
        root.kind !== 'INPUT' ||
        root.id !== selector.inputId ||
        root.digests.configuration !== selector.configurationDigest
      )
        throw new Error();
      const duplicate = rows.get(key(root));
      if (duplicate && canonicalJson(duplicate) !== canonicalJson(root)) throw new Error();
      if (!duplicate && !observed.owners.INPUT?.overflow) throw new Error();
      rows.set(key(root), root);
    } else unresolved.add('INPUT_NOT_OBSERVED');
    // Follow dependencies and downstream consumers, including target history
    // and both activation directions. Shared module/resource parents do not
    // turn unrelated inputs into consumers. Typed digest namespaces never
    // conflate a configuration with a capsule.
    const downstream = new Set([
      'WORK',
      'RUNTIME_GENERATION',
      'TARGET',
      'PROBE',
      'POLICY_OCCURRENCE',
      'POLICY_AUTHORIZATION',
      'TARGET_DISPOSITION_ADMISSION',
      'TARGET_DISPOSITION_DELIVERY',
    ]);
    const edges = new Map<string, Set<string>>();
    const digestUsers = new Map<string, string[]>();
    const connect = (a: string, b: string, bidirectional = true) => {
      if (!edges.has(a)) edges.set(a, new Set());
      if (!edges.has(b)) edges.set(b, new Set());
      edges.get(a)!.add(b);
      if (bidirectional) edges.get(b)!.add(a);
    };
    for (const [identity, row] of rows) {
      for (const ref of row.references)
        if (rows.has(key(ref))) connect(identity, key(ref), downstream.has(ref.kind));
      for (const token of row.tokens) {
        const tokenKey = `${token.kind}:${token.digest}`,
          users = digestUsers.get(tokenKey) ?? [];
        // A star has the same connected closure without quadratic fan-out.
        if (users[0]) connect(identity, users[0]);
        users.push(identity);
        digestUsers.set(tokenKey, users);
      }
    }
    const visited = new Set<string>(),
      pending = root ? [key(root)] : [];
    for (let at = 0; at < pending.length; at++) {
      const identity = pending[at]!;
      if (visited.has(identity)) continue;
      visited.add(identity);
      for (const next of edges.get(identity) ?? []) if (!visited.has(next)) pending.push(next);
    }
    const references = [...visited].sort(compare).map((identity) => rows.get(identity)!);
    for (const row of references) {
      for (const ref of row.references)
        if (ref.required && !rows.has(key(ref)))
          unresolved.add(`MISSING_OWNER:${key(row)}:${key(ref)}`);
      for (const [check, passed] of Object.entries(row.checks))
        if (passed === false) unresolved.add(`OWNER_INTEGRITY:${key(row)}:${check}`);
      if (row.kind === 'INPUT' && row.checks.bytesMatch !== true)
        unresolved.add(`INPUT_BYTES_UNVERIFIED:${row.id}`);
      if (row.kind === 'INPUT' && row.checks.bindingsKnown !== true)
        unresolved.add(`INPUT_BINDINGS_UNVERIFIED:${row.id}`);
      if (
        row.kind === 'WORK' &&
        row.state === 'COMPLETED' &&
        (row.checks.resultMatch !== true || !row.digests.result)
      )
        unresolved.add(`WORK_RESULT_UNVERIFIED:${row.id}`);
      if (
        row.kind === 'PROBE' &&
        row.state === 'OBSERVED' &&
        (row.checks.observationMatch !== true || !row.digests.observation)
      )
        unresolved.add(`PROBE_RESULT_UNVERIFIED:${row.id}`);
      if (
        row.kind === 'ACTIVATION_OBSERVATION' &&
        (row.checks.receiptMatch !== true || !row.digests.receipt)
      )
        unresolved.add(`ACTIVATION_RESULT_UNVERIFIED:${row.id}`);
      if (row.kind === 'WORK' || row.kind === 'PROBE') {
        // These original owners store the configuration digest, not an input
        // row identity. Preserve every match and expose ambiguity explicitly.
        const inputs = references.filter(
          (input) =>
            input.kind === 'INPUT' && input.digests.configuration === row.digests.configuration,
        );
        if (!inputs.length) unresolved.add(`CONFIGURATION_SOURCE_NOT_OBSERVED:${row.id}`);
        if (inputs.length > 1) unresolved.add(`CONFIGURATION_SOURCE_AMBIGUOUS:${row.id}`);
      }
    }
    // Database locks do not observe a signed target journal/bootstrap, an input
    // source file or a fenced backup/restore set. Neither absence nor age is a
    // successor disposition. Canonical owns the missing producer-fence closure.
    if (!observed.runtimeProducerFencesObserved)
      unresolved.add('RUNTIME_PRODUCER_FENCES_UNVERIFIED');
    if (!observed.dependencyProducerFencesObserved)
      unresolved.add('DEPENDENCY_PRODUCER_FENCES_UNVERIFIED');
    const databaseCoverage = unresolved.size ? ('INCOMPLETE' as const) : ('OBSERVED' as const);
    unresolved.add('INPUT_REDELIVERY_DISPOSITION_UNPROVEN');
    unresolved.add('RUNTIME_CUSTODY_DISPOSITION_UNOBSERVED');
    unresolved.add('BACKUP_RESTORE_DISPOSITION_UNOBSERVED');
    unresolved.add('GOVERNED_REFERENCE_DISPOSITION_REQUIRED');
    const obligations = references.map((row) => ({
      owner: key(row),
      state: row.state,
      reason:
        row.kind === 'INPUT'
          ? row.state === 'SELECTED'
            ? 'SELECTED_INPUT'
            : 'RETAINED_RELOAD_INPUT'
          : row.kind === 'WORK'
            ? row.state === 'COMPLETED'
              ? 'COMPLETED_WORK_REFERENCE'
              : 'WORK_RECONCILIATION_OR_DISPOSITION'
            : row.kind === 'POLICY_TARGET' && row.details.phase === 'ROLLBACK'
              ? 'ROLLBACK_REFERENCE'
              : row.kind === 'TARGET'
                ? 'TARGET_CUSTODY_REFERENCE'
                : `${row.kind}_REFERENCE`,
    }));
    const result = {
      selector,
      runtimeProducerFencesObserved: observed.runtimeProducerFencesObserved,
      dependencyProducerFencesObserved: observed.dependencyProducerFencesObserved,
      databaseCoverage,
      authority: 'NONE' as const,
      disposition: 'UNPROVEN' as const,
      root,
      references,
      obligations,
      unresolved: [...unresolved].sort(compare),
    };
    return immutableJsonCopy({ ...result, observationDigest: sha256(result) });
  } catch {
    throw new RuntimeArtifactReferenceError('INVALID');
  }
}
export type RuntimeArtifactReferenceObservation = ReturnType<
  typeof inspectRuntimeArtifactReferences
>;

/** Internal reader only, called by the existing authenticated/authorized owner.
 * The caller owns a READ COMMITTED transaction and real Identity scope.
 * Lock order: existing authority fences; existing participant evidence lifecycle
 * fence; then shared module-release-catalog, exclusive
 * module-admission, shared policy-generations via the existing owner; then reads.
 * Call before any reference row lock. Lock acquisition fails fast, never upgrades
 * a row-held transaction. Do not use a returned observation after COMMIT as a
 * grant: reread on the same live owner before any later governed transition.
 * No callback, new transaction, source mutation, external I/O or grant escapes. */
export async function readRuntimeArtifactReferences(
  client: PoolClient,
  value: unknown,
): Promise<RuntimeArtifactReferenceObservation> {
  try {
    const selector = runtimeArtifactReferenceSelector.parse(immutableJsonCopy(value));
    const context = await client.query<{ allowed: boolean }>(
      `select openpc.assert_request_context(true),
      openpc.current_participant_id()=$1::uuid and openpc.current_privacy_domain_id()=$2::uuid
      and current_setting('transaction_isolation')='read committed' and current_setting('row_security')='on'
      and current_setting('session_replication_role')='origin' and not r.rolsuper and not r.rolbypassrls allowed
      from pg_roles r where r.rolname=current_user`,
      [selector.participantId, selector.privacyDomainId],
    );
    if (context.rowCount !== 1 || context.rows[0]?.allowed !== true)
      throw new RuntimeArtifactReferenceError();
    await lockEvidenceLifecycle(client, selector.participantId, selector.privacyDomainId);
    await lockModuleLifecycleReferences(client, selector);
    const result = await client.query<{ observation: unknown }>(
      'select openpc.observe_runtime_artifact_references($1,$2) observation',
      [selector.inputId, selector.configurationDigest],
    );
    if (result.rowCount !== 1) throw new RuntimeArtifactReferenceError();
    return inspectRuntimeArtifactReferences(selector, result.rows[0]!.observation);
  } catch (error) {
    if (error instanceof RuntimeArtifactReferenceError) throw error;
    throw new RuntimeArtifactReferenceError();
  }
}

/** Comparison is data validation only. It cannot extend transaction lifetime or
 * convert an unresolved obligation into an authorization or a clear predicate. */
export function assertRuntimeArtifactObservationUnchanged(
  expected: string,
  current: RuntimeArtifactReferenceObservation,
) {
  if (!digest.safeParse(expected).success || current.observationDigest !== expected)
    throw new RuntimeArtifactReferenceError('CHANGED');
}
