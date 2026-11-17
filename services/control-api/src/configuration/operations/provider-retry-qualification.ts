import type { Pool, PoolClient } from 'pg';
import {
  verifyProviderRetryInput,
  type VerifiedProviderRetryInput,
} from '../../../../../packages/security-kernel/src/operations-configuration/provider-retry-input.js';
import {
  decodeNotificationAsync,
  verifyNotificationAsyncInstalledPair,
  type NotificationAsyncEnvelope,
} from '../../../../../packages/security-kernel/src/operations-configuration/notification-async.js';
import {
  ProviderRetryQualificationError,
  assertProviderRetryAuthoritySuccessor,
  copyQualificationBytes,
  decodeProviderRetryQualification,
  qualificationCanonicalJson,
  qualificationDigest,
  qualificationSpki,
  qualificationOnlinePurposes,
  requireQualificationIssuerKey,
  type QualificationOnlinePurpose,
  verifyProviderRetryAuthority,
  verifyProviderRetryReceipt,
  type QualificationAuthorityEnvelope,
  type QualificationDocumentEnvelope,
  type QualificationEnvelope,
  type QualificationRoot,
  type QualificationInputClaims,
  type VerifiedProviderRetryReceipt,
  type VerifiedQualificationAuthority,
} from '../../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';

export interface ProviderRetryQualificationScope {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly requestId: string;
}
export interface ProviderRetryQualificationBundle {
  readonly input: QualificationEnvelope;
  readonly receipt: QualificationDocumentEnvelope;
}
/** Result of canonical openpc.operations_provider_retry_evidence_current(text,
 * uuid,text,text). It must derive these exact documents from current provider
 * method/subject owners, independently controlled KMS/HSM custody, retained raw
 * execution and independent reviewer evidence, including environment-dedicated
 * online keys and principal separation, holding their source fences on
 * this same client through consumption. Digests select originals; they do not
 * authorize caller documents. An absent owner throws, never returns a default.
 * This contract deliberately has no current/ready/pass boolean. */
export interface ProviderRetryQualificationEvidence {
  readonly input: Readonly<QualificationInputClaims>;
  readonly receiptDocument: Readonly<Record<string, unknown>>;
}
interface RootRow {
  authority_id: string;
  root_key_id: string;
  root_epoch: string;
  root_spki: Buffer;
  policy_signer: QualificationRoot['policySigner'];
  valid_from_ms: string;
  valid_until_ms: string;
  state: string;
}
interface StateRow {
  sequence: string;
  root_epoch: string;
  keyset_digest: string;
  revocations_digest: string;
  custody: Record<string, unknown>;
  custody_bytes: Buffer;
  custody_digest: string;
}
interface BindingRow {
  authority_id: string;
  issuance_sequence: string;
  input_digest: string;
  receipt_digest: string;
  custody: Record<string, unknown>;
  custody_bytes: Buffer;
  custody_digest: string;
}
const denied = (): never => {
  throw new ProviderRetryQualificationError();
};
function object(v: unknown): Record<string, unknown> {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return denied();
  return v as Record<string, unknown>;
}
function root(row: RootRow): QualificationRoot {
  return {
    authorityId: row.authority_id,
    rootKeyId: row.root_key_id,
    rootEpoch: row.root_epoch,
    rootSpki: row.root_spki,
    policySigner: row.policy_signer,
    validFromMs: Number(row.valid_from_ms),
    validUntilMs: Number(row.valid_until_ms),
  };
}
function envelope(value: QualificationEnvelope, doc = false): Record<string, string> {
  const result: Record<string, string> = {
    payloadHex: copyQualificationBytes(value.payload, 65536).toString('hex'),
    coseHex: copyQualificationBytes(value.cose, 66560).toString('hex'),
  };
  if (doc)
    result.documentHex = copyQualificationBytes(
      (value as QualificationDocumentEnvelope).document,
      524288,
    ).toString('hex');
  return result;
}
function stateCustody(bundle: QualificationAuthorityEnvelope): Record<string, unknown> {
  return {
    keyset: {
      ...envelope(bundle.keyset),
      documentHex: copyQualificationBytes(bundle.keyset.document, 131072).toString('hex'),
    },
    revocations: {
      ...envelope(bundle.revocations),
      documentHex: copyQualificationBytes(bundle.revocations.document, 4194304).toString('hex'),
    },
  };
}
function custodyEnvelope(value: unknown, maximum?: number): QualificationDocumentEnvelope {
  const v = object(value),
    keys = maximum ? ['payloadHex', 'coseHex', 'documentHex'] : ['payloadHex', 'coseHex'];
  if (Object.keys(v).sort().join() !== keys.sort().join()) return denied();
  const read = (name: string, max: number) => {
    const s = v[name];
    if (typeof s !== 'string' || s.length > max * 2 || !/^(?:[0-9a-f]{2})+$/u.test(s))
      return denied();
    return Buffer.from(s, 'hex');
  };
  return {
    payload: read('payloadHex', 65536),
    cose: read('coseHex', 66560),
    document: maximum ? read('documentHex', maximum) : Buffer.alloc(0),
  };
}
function stateBundle(custody: Record<string, unknown>): QualificationAuthorityEnvelope {
  if (Object.keys(custody).sort().join() !== 'keyset,revocations') return denied();
  return {
    keyset: custodyEnvelope(custody.keyset, 131072),
    revocations: custodyEnvelope(custody.revocations, 4194304),
  };
}
function receiptBundle(custody: Record<string, unknown>): ProviderRetryQualificationBundle {
  if (Object.keys(custody).sort().join() !== 'input,receipt') return denied();
  return {
    input: custodyEnvelope(custody.input),
    receipt: custodyEnvelope(custody.receipt, 524288),
  };
}
function checkedCustody(row: {
  custody: Record<string, unknown>;
  custody_bytes: Buffer;
  custody_digest: string;
}): Record<string, unknown> {
  if (
    !Buffer.from(qualificationCanonicalJson(row.custody)).equals(row.custody_bytes) ||
    qualificationDigest(row.custody_bytes) !== row.custody_digest
  )
    return denied();
  return row.custody;
}
async function now(client: PoolClient): Promise<number> {
  return Number(
    (
      await client.query<{ now: string }>(
        'select floor(extract(epoch from clock_timestamp())*1000)::text now',
      )
    ).rows[0]!.now,
  );
}
async function transaction<T>(
  pool: Pool,
  scope: ProviderRetryQualificationScope,
  role: 'openpc_operations_qualification_owner' | 'openpc_operations_qualification_bootstrap',
  work: (client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('begin isolation level read committed');
    await client.query(`set local role ${role}`);
    await client.query('set local row_security=on');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
      [scope.participantId, scope.privacyDomainId, scope.requestId],
    );
    const result = await work(client);
    await client.query('commit');
    return result;
  } catch (error) {
    await client.query('rollback').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}
async function lock(
  client: PoolClient,
  environment: string,
  authority: string,
  exclusive = false,
): Promise<void> {
  if (!/^[a-z][a-z0-9-]{2,31}$/u.test(environment) || !/^[a-z][a-z0-9-]{2,31}$/u.test(authority))
    return denied();
  await client.query(
    "select pg_advisory_xact_lock_shared(hashtextextended('operations-generation:'||$1,0))",
    [environment],
  );
  await client.query(
    `select ${exclusive ? 'pg_advisory_xact_lock' : 'pg_advisory_xact_lock_shared'}(hashtextextended('operations-qualification:'||$1||':'||$2,0))`,
    [environment, authority],
  );
}
async function installedRoot(
  client: PoolClient,
  environment: string,
  authority: string,
  epoch?: string,
): Promise<RootRow> {
  const result = await client.query<RootRow>(
    `select authority_id,root_key_id,root_epoch::text,root_spki,policy_signer,valid_from_ms::text,valid_until_ms::text,state from control.operations_qualification_root where environment_id=$1 and authority_id=$2 ${epoch ? 'and root_epoch=$3' : ''} order by root_epoch desc limit 1 for share`,
    epoch ? [environment, authority, epoch] : [environment, authority],
  );
  if (result.rowCount !== 1) throw new Error('OPS_PROVIDER_RETRY_ROOT_UNBOUND');
  return result.rows[0]!;
}
async function currentState(
  client: PoolClient,
  environment: string,
  authority: string,
): Promise<StateRow> {
  const result = await client.query<StateRow>(
    'select sequence::text,root_epoch::text,keyset_digest,revocations_digest,custody,custody_bytes,custody_digest from control.operations_qualification_state where environment_id=$1 and authority_id=$2 order by sequence desc limit 1',
    [environment, authority],
  );
  if (result.rowCount !== 1) return denied();
  return result.rows[0]!;
}
async function verifiedState(
  client: PoolClient,
  environment: string,
  authority: string,
  row: StateRow,
  at?: number,
): Promise<VerifiedQualificationAuthority> {
  const installed = await installedRoot(client, environment, authority, row.root_epoch),
    bundle = stateBundle(checkedCustody(row));
  if (installed.state !== 'ACTIVE') return denied();
  const k = decodeProviderRetryQualification('keyset', bundle.keyset.payload),
    r = decodeProviderRetryQualification('revocations', bundle.revocations.payload);
  const state = verifyProviderRetryAuthority(
    root(installed),
    bundle,
    at ?? Math.max(k.issuedAtMs, r.issuedAtMs),
  );
  if (
    state.keysetDigest !== row.keyset_digest ||
    state.revocationsDigest !== row.revocations_digest ||
    state.keyset.sequence !== row.sequence
  )
    return denied();
  return state;
}
/** Sole installation seam. Must run on a separately privileged bootstrap pool.
 * The caller is the real offline/threshold root owner, not an HTTP/receipt issuer.
 * Canonical grants this capability; this module never creates roles/memberships. */
export async function installProviderRetryQualificationRoot(
  pool: Pool,
  scope: ProviderRetryQualificationScope,
  environment: string,
  pins: QualificationRoot,
): Promise<void> {
  const value = { ...pins, rootSpki: qualificationSpki(pins.rootSpki) };
  if (qualificationDigest(value.rootSpki) !== value.rootKeyId) return denied();
  await transaction(pool, scope, 'openpc_operations_qualification_bootstrap', async (client) => {
    await lock(client, environment, value.authorityId, true);
    const existing = await client.query<RootRow>(
      'select authority_id,root_key_id,root_epoch::text,root_spki,policy_signer,valid_from_ms::text,valid_until_ms::text,state from control.operations_qualification_root where environment_id=$1 and authority_id=$2 order by root_epoch desc limit 1 for share',
      [environment, value.authorityId],
    );
    if (existing.rows[0]?.root_epoch === value.rootEpoch) {
      const original = existing.rows[0];
      if (
        original.state !== 'ACTIVE' ||
        original.root_key_id !== value.rootKeyId ||
        !original.root_spki.equals(value.rootSpki) ||
        original.policy_signer !== value.policySigner ||
        Number(original.valid_from_ms) !== value.validFromMs ||
        Number(original.valid_until_ms) !== value.validUntilMs
      )
        return denied();
      return;
    }
    await client.query(
      `insert into control.operations_qualification_root(participant_id,privacy_domain_id,environment_id,authority_id,root_epoch,root_key_id,root_spki,policy_signer,valid_from_ms,valid_until_ms) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        environment,
        value.authorityId,
        value.rootEpoch,
        value.rootKeyId,
        value.rootSpki,
        value.policySigner,
        value.validFromMs,
        value.validUntilMs,
      ],
    );
  });
}
/** Dedicated internal adapter, not a public route or general binding writer.
 * Every async entry copies bytes before yielding and retains original envelopes. */
export class ProviderRetryQualificationStore {
  constructor(private readonly pool: Pool) {}
  async installAuthorityState(
    scope: ProviderRetryQualificationScope,
    environment: string,
    authority: string,
    bundle: QualificationAuthorityEnvelope,
  ): Promise<{ sequence: string; custodyDigest: string }> {
    const custody = stateCustody(bundle),
      bytes = Buffer.from(qualificationCanonicalJson(custody)),
      digest = qualificationDigest(bytes);
    return transaction(
      this.pool,
      scope,
      'openpc_operations_qualification_owner',
      async (client) => {
        await lock(client, environment, authority, true);
        const installed = await installedRoot(client, environment, authority);
        if (installed.state !== 'ACTIVE') return denied();
        const state = verifyProviderRetryAuthority(
          root(installed),
          stateBundle(custody),
          await now(client),
        );
        const priorResult = await client.query<StateRow>(
          'select sequence::text,root_epoch::text,keyset_digest,revocations_digest,custody,custody_bytes,custody_digest from control.operations_qualification_state where environment_id=$1 and authority_id=$2 order by sequence desc limit 1',
          [environment, authority],
        );
        const prior = priorResult.rows[0];
        if (prior) {
          checkedCustody(prior);
          if (prior.custody_bytes.equals(bytes))
            return { sequence: prior.sequence, custodyDigest: prior.custody_digest };
          assertProviderRetryAuthoritySuccessor(
            await verifiedState(client, environment, authority, prior),
            state,
          );
        }
        await client.query(
          `insert into control.operations_qualification_state(participant_id,privacy_domain_id,environment_id,authority_id,sequence,snapshot_sequence,root_epoch,custody,custody_bytes,custody_digest,keyset_digest,revocations_digest,valid_until_ms) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [
            scope.participantId,
            scope.privacyDomainId,
            environment,
            authority,
            state.keyset.sequence,
            state.revocations.sequence,
            state.keyset.rootEpoch,
            custody,
            bytes,
            digest,
            state.keysetDigest,
            state.revocationsDigest,
            Math.min(
              state.keyset.validUntilMs,
              state.revocations.validUntilMs,
              Number(installed.valid_until_ms),
            ),
          ],
        );
        return { sequence: state.keyset.sequence, custodyDigest: digest };
      },
    );
  }
  async admit(
    scope: ProviderRetryQualificationScope,
    environment: string,
    generation: string,
    bundle: ProviderRetryQualificationBundle,
  ): Promise<{ inputDigest: string; receiptDigest: string }> {
    const custody = { input: envelope(bundle.input), receipt: envelope(bundle.receipt, true) };
    const bytes = Buffer.from(qualificationCanonicalJson(custody)),
      copy = receiptBundle(custody);
    return transaction(
      this.pool,
      scope,
      'openpc_operations_qualification_owner',
      async (client) => {
        await lock(
          client,
          environment,
          decodeProviderRetryQualification('input', copy.input.payload).authorityId,
          true,
        );
        const { verified, issuance } = await verifyBound(client, environment, generation, copy);
        const inputDigest = qualificationDigest(copy.input.payload),
          receiptDigest = qualificationDigest(copy.receipt.payload);
        const original = await client.query<{ custody_bytes: Buffer }>(
          'select custody_bytes from control.operations_provider_retry_qualification where environment_id=$1 and generation_id=$2',
          [environment, generation],
        );
        if (original.rowCount) {
          if (!original.rows[0]!.custody_bytes.equals(bytes)) return denied();
          return { inputDigest, receiptDigest };
        }
        await client.query(
          `insert into control.operations_provider_retry_qualification(participant_id,privacy_domain_id,environment_id,authority_id,generation_id,issuance_sequence,input_digest,receipt_digest,custody,custody_bytes,custody_digest,valid_until_ms) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [
            scope.participantId,
            scope.privacyDomainId,
            environment,
            verified.input.authorityId,
            generation,
            issuance.sequence,
            inputDigest,
            receiptDigest,
            custody,
            bytes,
            qualificationDigest(bytes),
            verified.receipt.expiresAtMs,
          ],
        );
        return { inputDigest, receiptDigest };
      },
    );
  }
  /** Callback is database-only, using this SAME client. Recheck time and every
   * real owner before COMMIT. Holding source fences prevents concurrent revoke;
   * failed/expired callbacks roll back, never write a generic CURRENT attestation. */
  async withCurrent<T>(
    scope: ProviderRetryQualificationScope,
    environment: string,
    generation: string,
    consume: (client: PoolClient, receipt: VerifiedProviderRetryReceipt) => Promise<T>,
  ): Promise<T> {
    return transaction(this.pool, scope, 'openpc_operations_qualification_owner', (client) =>
      this.withCurrentInTransaction(client, scope, environment, generation, consume),
    );
  }
  /** Canonical generation/other live observers compose on an ALREADY scoped
   * transaction. No role switch, BEGIN, COMMIT or synthetic readiness flag.
   * The caller rolls back on error and consumes before releasing this client. */
  async withCurrentInTransaction<T>(
    client: PoolClient,
    scope: ProviderRetryQualificationScope,
    environment: string,
    generation: string,
    consume: (client: PoolClient, receipt: VerifiedProviderRetryReceipt) => Promise<T>,
  ): Promise<T> {
    return withCurrentProviderRetryQualification(client, scope, environment, generation, consume);
  }
  /** Retained original identifiers only. Expiry/revocation must not erase
   * historical readback, and this method grants no present qualification. */
  async readOriginal(
    scope: ProviderRetryQualificationScope,
    environment: string,
    generation: string,
  ): Promise<{ inputDigest: string; receiptDigest: string; qualificationRef: string }> {
    return transaction(
      this.pool,
      scope,
      'openpc_operations_qualification_owner',
      async (client) => {
        const result = await client.query<BindingRow>(
          'select authority_id,issuance_sequence::text,input_digest,receipt_digest,custody,custody_bytes,custody_digest from control.operations_provider_retry_qualification where environment_id=$1 and generation_id=$2',
          [environment, generation],
        );
        if (result.rowCount !== 1) return denied();
        const row = result.rows[0]!,
          bundle = receiptBundle(checkedCustody(row));
        if (
          qualificationDigest(bundle.input.payload) !== row.input_digest ||
          qualificationDigest(bundle.receipt.payload) !== row.receipt_digest
        )
          return denied();
        const input = decodeProviderRetryQualification('input', bundle.input.payload);
        const receipt = decodeProviderRetryQualification('receipt', bundle.receipt.payload);
        if (
          receipt.inputPayloadDigest !== row.input_digest ||
          receipt.qualificationRef !==
            `qualification://${input.authorityId}/${input.inputId}@${row.input_digest}`
        )
          return denied();
        return {
          inputDigest: row.input_digest,
          receiptDigest: row.receipt_digest,
          qualificationRef: receipt.qualificationRef,
        };
      },
    );
  }
}

async function verifyBound(
  client: PoolClient,
  environment: string,
  generation: string,
  bundle: ProviderRetryQualificationBundle,
): Promise<{ verified: VerifiedProviderRetryReceipt; issuance: StateRow }> {
  const input = decodeProviderRetryQualification('input', bundle.input.payload),
    receipt = decodeProviderRetryQualification('receipt', bundle.receipt.payload);
  await lock(client, environment, input.authorityId);
  const installed = await installedRoot(client, environment, input.authorityId),
    current = await currentState(client, environment, input.authorityId);
  if (installed.state !== 'ACTIVE' || current.root_epoch !== installed.root_epoch) return denied();
  const issuanceResult = await client.query<StateRow>(
    'select sequence::text,root_epoch::text,keyset_digest,revocations_digest,custody,custody_bytes,custody_digest from control.operations_qualification_state where environment_id=$1 and authority_id=$2 and keyset_digest=$3 and revocations_digest=$4',
    [environment, input.authorityId, receipt.keysetPayloadDigest, receipt.revocationPayloadDigest],
  );
  if (issuanceResult.rowCount !== 1) return denied();
  const issuance = issuanceResult.rows[0]!,
    at = await now(client);
  const verified = verifyProviderRetryReceipt(
    bundle.input,
    bundle.receipt,
    await verifiedState(client, environment, input.authorityId, issuance, receipt.issuedAtMs),
    await verifiedState(client, environment, input.authorityId, current, at),
    at,
  );
  const selected = await client.query<{
    candidate: unknown;
    installation: unknown;
    authenticated: boolean;
  }>(
    `select g.candidate,i.installation,openpc.operations_generation_source_authenticated(g.environment_id,g.generation_id) authenticated from control.operations_generation g join control.operations_installation i using(environment_id) where g.environment_id=$1 and g.generation_id=$2 and g.state='STAGED' and i.state='ACTIVE' for share of g,i`,
    [environment, generation],
  );
  if (selected.rowCount !== 1 || selected.rows[0]!.authenticated !== true) return denied();
  const selectedRow = selected.rows[0]!,
    configuration = object(object(selectedRow.candidate).configuration),
    installation = object(selectedRow.installation),
    pins = object(installation.pins),
    named = object(installation.namedProfile);
  if (
    input.environmentId !== environment ||
    configuration.environmentId !== environment ||
    input.profile !== configuration.profile ||
    input.slot !== object(named.requiredSettingInputs)['provider.read_retry_limit'] ||
    input.value !== object(configuration.settings)['provider.read_retry_limit'] ||
    input.configurationSchemaDigest !== pins.configurationSchemaDigest ||
    input.namedProfileDigest !== pins.namedProfileDigest ||
    verified.qualificationRef !==
      object(configuration.qualificationInputBindings)['provider.read_retry_limit']
  )
    return denied();
  const evidence = await client.query<{ evidence: unknown }>(
    'select openpc.require_provider_retry_evidence($1,$2,$3,$4) evidence',
    [
      environment,
      generation,
      qualificationDigest(bundle.input.payload),
      verified.receipt.receiptDocumentDigest,
    ],
  );
  const actual = object(evidence.rows[0]?.evidence);
  if (
    qualificationCanonicalJson(actual.input) !== qualificationCanonicalJson(verified.input) ||
    qualificationCanonicalJson(actual.receiptDocument) !==
      qualificationCanonicalJson(verified.receiptDocument)
  )
    return denied();
  return { verified, issuance };
}

/** Consume the current qualification on the caller's already scoped transaction.
 * No pool, role switch or transaction creation: every source and ES256 check is
 * shared with admission and repeated after database-only consumption. The caller
 * must roll back the transaction on any failure before releasing this client. */
export async function withCurrentProviderRetryQualification<T>(
  client: PoolClient,
  scope: ProviderRetryQualificationScope,
  environment: string,
  generation: string,
  consume: (client: PoolClient, receipt: VerifiedProviderRetryReceipt) => Promise<T>,
): Promise<T> {
  const sameTransaction = await qualificationTransaction(client, scope);
  const result = await client.query<BindingRow>(
    'select authority_id,issuance_sequence::text,input_digest,receipt_digest,custody,custody_bytes,custody_digest from control.operations_provider_retry_qualification where environment_id=$1 and generation_id=$2',
    [environment, generation],
  );
  if (result.rowCount !== 1) return denied();
  const row = result.rows[0]!,
    copy = receiptBundle(checkedCustody(row));
  if (
    qualificationDigest(copy.input.payload) !== row.input_digest ||
    qualificationDigest(copy.receipt.payload) !== row.receipt_digest
  )
    return denied();
  const before = await verifyBound(client, environment, generation, copy);
  if (
    before.issuance.sequence !== row.issuance_sequence ||
    before.verified.input.authorityId !== row.authority_id
  )
    return denied();
  const value = await consume(client, before.verified);
  await sameTransaction();
  await verifyBound(client, environment, generation, copy);
  return value;
}

/** Shared actual-client admission. This detects transaction changes; it cannot
 * undo a COMMIT deliberately performed by a trusted callback. Callers must keep
 * transaction ownership and roll back any failure before releasing the client. */
async function qualificationTransaction(
  client: PoolClient,
  scope: ProviderRetryQualificationScope,
) {
  const expected = { ...scope };
  await client.query('select openpc.assert_request_context(true)');
  const readContext = async () =>
    (
      await client.query<{
        role: string;
        isolation: string;
        participant: string;
        privacy: string;
        request: string;
        action: string;
        mode: string;
        row_security: string;
        transaction_id: string;
      }>(`select current_user::text role,current_setting('transaction_isolation') isolation,
    current_setting('openpc.participant_id',true) participant,
    current_setting('openpc.privacy_domain_id',true) privacy,
    current_setting('openpc.operation_id',true) request,
    current_setting('openpc.action_intent_id',true) action,
    current_setting('openpc.context_mode',true) mode,current_setting('row_security') row_security,
    pg_current_xact_id()::text transaction_id`)
    ).rows[0];
  const context = await readContext();
  if (
    !context ||
    !['openpc_control_owner', 'openpc_operations_qualification_owner'].includes(context.role) ||
    context.isolation !== 'read committed' ||
    context.mode !== 'PARTICIPANT' ||
    context.row_security !== 'on' ||
    context.participant !== expected.participantId ||
    context.privacy !== expected.privacyDomainId ||
    context.request !== expected.requestId ||
    context.action !== 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
  )
    return denied();
  const sameTransaction = async () => {
    const current = await readContext();
    if (
      current?.transaction_id !== context.transaction_id ||
      current.role !== context.role ||
      current.isolation !== context.isolation ||
      current.row_security !== context.row_security ||
      current.mode !== context.mode ||
      current.participant !== expected.participantId ||
      current.privacy !== expected.privacyDomainId ||
      current.request !== expected.requestId ||
      current.action !== context.action
    )
      return denied();
  };
  // Detect an autocommit caller BEFORE its effect callback, not afterwards.
  await sameTransaction();
  return sameTransaction;
}

export interface QualificationIssuerSelector {
  readonly authorityId: string;
  readonly keyId: string;
  readonly epoch: string;
  readonly purpose: QualificationOnlinePurpose;
}
export interface InstalledQualificationIssuer extends QualificationIssuerSelector {
  readonly environmentId: string;
  readonly rootEpoch: string;
  readonly keysetDigest: string;
  readonly revocationsDigest: string;
  readonly publicKeySpkiHex: string;
  readonly validUntilMs: number;
}

/** Current public issuer trust only, for a database-local reservation. This
 * neither authorizes key access nor run/review/signing. The caller owns rollback;
 * a trusted callback must retain this transaction and perform no external I/O. */
export async function withInstalledQualificationIssuer<T>(
  client: PoolClient,
  scope: ProviderRetryQualificationScope,
  environment: string,
  selected: QualificationIssuerSelector,
  consume: (client: PoolClient, issuer: Readonly<InstalledQualificationIssuer>) => Promise<T>,
): Promise<T> {
  const expected = { ...scope },
    selector = { ...selected };
  if (
    !/^[a-z][a-z0-9-]{2,31}$/u.test(environment) ||
    !/^[a-z][a-z0-9-]{2,31}$/u.test(selector.authorityId) ||
    !/^sha256:[0-9a-f]{64}$/u.test(selector.keyId) ||
    !/^[1-9][0-9]{0,15}$/u.test(selector.epoch) ||
    !Number.isSafeInteger(Number(selector.epoch)) ||
    !qualificationOnlinePurposes.includes(selector.purpose)
  )
    return denied();
  const sameTransaction = await qualificationTransaction(client, expected);
  await lock(client, environment, selector.authorityId);
  const read = async (): Promise<Readonly<InstalledQualificationIssuer>> => {
    const installed = await installedRoot(client, environment, selector.authorityId);
    const current = await currentState(client, environment, selector.authorityId);
    if (installed.state !== 'ACTIVE' || current.root_epoch !== installed.root_epoch)
      return denied();
    const source = await client.query(
      `select 1 from control.operations_installation
      where environment_id=$1 and participant_id=$2 and privacy_domain_id=$3 and state='ACTIVE' for share`,
      [environment, expected.participantId, expected.privacyDomainId],
    );
    if (source.rowCount !== 1) return denied();
    const at = await now(client);
    const state = await verifiedState(client, environment, selector.authorityId, current, at);
    const key = requireQualificationIssuerKey(
      state,
      selector.keyId,
      selector.epoch,
      selector.purpose,
      at,
      at,
      at,
      true,
    );
    return Object.freeze({
      ...selector,
      environmentId: environment,
      rootEpoch: installed.root_epoch,
      keysetDigest: state.keysetDigest,
      revocationsDigest: state.revocationsDigest,
      publicKeySpkiHex: key.publicKeySpkiHex,
      validUntilMs: Math.min(
        key.validUntilMs,
        state.keyset.validUntilMs,
        state.revocations.validUntilMs,
        Number(installed.valid_until_ms),
      ),
    });
  };
  const issuer = await read();
  await sameTransaction();
  const release = client.release,
    query = client.query;
  const forbiddenRelease = () => {
    throw new ProviderRetryQualificationError();
  };
  client.release = forbiddenRelease;
  try {
    const result = await consume(client, issuer);
    if (client.query !== query || client.release !== forbiddenRelease) return denied();
    await sameTransaction();
    const current = await read();
    if (qualificationCanonicalJson(current) !== qualificationCanonicalJson(issuer)) return denied();
    await sameTransaction();
    return result;
  } finally {
    client.query = query;
    client.release = release;
  }
}

/** Receipt-free authentication for a NEW database-local reservation. This owns
 * no transaction, provider I/O, execution/reviewer eligibility or receipt
 * admission. The source-authenticated staged configuration binds the exact
 * signed input reference (including its method/workload/subject claims); it
 * does not establish those claims' missing native execution provenance.
 * The trusted callback must use this client, keep transaction ownership, and
 * the caller MUST roll back on any error before returning the client to a pool.
 */
export async function withInstalledProviderRetryInput<T>(
  client: PoolClient,
  scope: ProviderRetryQualificationScope,
  environment: string,
  generation: string,
  original: QualificationEnvelope,
  consume: (sameClient: PoolClient, input: VerifiedProviderRetryInput) => Promise<T>,
): Promise<T> {
  const expected = { ...scope };
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
  if (
    ![expected.participantId, expected.privacyDomainId, expected.requestId, generation].every((v) =>
      uuid.test(v),
    )
  )
    return denied();
  const envelope = {
    payload: copyQualificationBytes(original.payload, 65536),
    cose: copyQualificationBytes(original.cose, 66560),
  };
  const claims = decodeProviderRetryQualification('input', envelope.payload);
  if (claims.environmentId !== environment) return denied();
  const sameTransaction = await qualificationTransaction(client, expected);
  await lock(client, environment, claims.authorityId);
  const verify = async () => {
    const installed = await installedRoot(client, environment, claims.authorityId),
      current = await currentState(client, environment, claims.authorityId);
    if (installed.state !== 'ACTIVE' || current.root_epoch !== installed.root_epoch)
      return denied();
    const selected = await client.query<{
      candidate: unknown;
      installation: unknown;
      authenticated: boolean;
    }>(
      `select g.candidate,i.installation,openpc.operations_generation_source_authenticated(g.environment_id,g.generation_id) authenticated
       from control.operations_generation g join control.operations_installation i using(environment_id)
       where g.environment_id=$1 and g.generation_id=$2 and g.state='STAGED' and i.state='ACTIVE'
        and g.participant_id=$3 and g.privacy_domain_id=$4 and i.participant_id=$3 and i.privacy_domain_id=$4
       for share of g,i`,
      [environment, generation, expected.participantId, expected.privacyDomainId],
    );
    if (selected.rowCount !== 1 || selected.rows[0]!.authenticated !== true) return denied();
    const configuration = object(object(selected.rows[0]!.candidate).configuration),
      installation = object(selected.rows[0]!.installation),
      pins = object(installation.pins),
      named = object(installation.namedProfile);
    if (
      configuration.environmentId !== environment ||
      configuration.profile !== claims.profile ||
      object(configuration.generation).generationId !== `urn:openpc:generation:${generation}` ||
      pins.environmentId !== environment ||
      pins.profile !== claims.profile ||
      named.profile !== claims.profile ||
      claims.configurationSchemaDigest !== pins.configurationSchemaDigest ||
      claims.namedProfileDigest !== pins.namedProfileDigest ||
      claims.slot !== object(named.requiredSettingInputs)['provider.read_retry_limit'] ||
      claims.value !== object(configuration.settings)['provider.read_retry_limit'] ||
      `qualification://${claims.authorityId}/${claims.inputId}@${qualificationDigest(envelope.payload)}` !==
        object(configuration.qualificationInputBindings)['provider.read_retry_limit']
    )
      return denied();
    const authority = await verifiedState(
      client,
      environment,
      claims.authorityId,
      current,
      await now(client),
    );
    return verifyProviderRetryInput(envelope, authority, await now(client));
  };
  const verified = await verify();
  await sameTransaction();
  const release = client.release,
    query = client.query;
  let releaseAttempted = false;
  const heldRelease: PoolClient['release'] = () => {
    releaseAttempted = true;
    return denied();
  };
  client.release = heldRelease;
  try {
    const result = await consume(client, verified);
    if (releaseAttempted || client.release !== heldRelease || client.query !== query)
      return denied();
    await sameTransaction();
    await verify();
    await sameTransaction();
    return result;
  } finally {
    client.query = query;
    client.release = release;
  }
}
export interface NotificationAsyncSignedOriginals {
  readonly input: NotificationAsyncEnvelope;
  readonly capacity: NotificationAsyncEnvelope;
}

/** Authenticate supplied original envelopes against the ACTUALLY installed
 * issuance/current trust on the caller's transaction and staged configuration.
 * This performs no custody INSERT and grants no execution, independent-review,
 * capacity, consumer or dispatch admission. Only a future native evidence owner
 * may bind its own immutable executed originals to that separate admission. */
export async function withInstalledNotificationAsyncAuthority<T>(
  client: PoolClient,
  scope: ProviderRetryQualificationScope,
  environment: string,
  generation: string,
  originals: NotificationAsyncSignedOriginals,
  consume: (
    client: PoolClient,
    signatures: ReturnType<typeof verifyNotificationAsyncInstalledPair>,
  ) => Promise<T>,
): Promise<T> {
  const expected = { ...scope };
  const copy = (envelope: NotificationAsyncEnvelope) => ({
    payload: copyQualificationBytes(envelope.payload, 65536),
    cose: copyQualificationBytes(envelope.cose, 66560),
  });
  const inputEnvelope = copy(originals.input),
    capacityEnvelope = copy(originals.capacity);
  const input = decodeNotificationAsync('input', inputEnvelope.payload),
    capacity = decodeNotificationAsync('capacity', capacityEnvelope.payload);
  if (
    input.participantId !== expected.participantId ||
    input.privacyDomainId !== expected.privacyDomainId ||
    input.environmentId !== environment ||
    input.generationId !== generation
  )
    return denied();
  const sameTransaction = await qualificationTransaction(client, expected);
  await lock(client, environment, input.authorityId);
  const verify = async () => {
    const installed = await installedRoot(client, environment, input.authorityId),
      current = await currentState(client, environment, input.authorityId);
    if (installed.state !== 'ACTIVE' || current.root_epoch !== installed.root_epoch)
      return denied();
    const issuanceResult = await client.query<StateRow>(
      'select sequence::text,root_epoch::text,keyset_digest,revocations_digest,custody,custody_bytes,custody_digest from control.operations_qualification_state where environment_id=$1 and authority_id=$2 and keyset_digest=$3 and revocations_digest=$4',
      [
        environment,
        input.authorityId,
        capacity.keysetPayloadDigest,
        capacity.revocationPayloadDigest,
      ],
    );
    if (issuanceResult.rowCount !== 1) return denied();
    const selected = await client.query<{
      candidate: unknown;
      installation: unknown;
      authenticated: boolean;
    }>(
      `select g.candidate,i.installation,openpc.operations_generation_source_authenticated(g.environment_id,g.generation_id) authenticated
       from control.operations_generation g join control.operations_installation i using(environment_id)
       where g.environment_id=$1 and g.generation_id=$2 and g.state='STAGED' and i.state='ACTIVE' for share of g,i`,
      [environment, generation],
    );
    if (selected.rowCount !== 1 || selected.rows[0]!.authenticated !== true) return denied();
    const row = selected.rows[0]!,
      configuration = object(object(row.candidate).configuration),
      configuredGeneration = object(configuration.generation),
      pins = object(object(row.installation).pins);
    if (
      configuration.environmentId !== environment ||
      input.profile !== configuration.profile ||
      configuredGeneration.generationId !== `urn:openpc:generation:${generation}` ||
      configuredGeneration.contentDigest !== input.configurationDigest ||
      pins.configurationSchemaDigest !== input.configurationSchemaDigest ||
      pins.namedProfileDigest !== input.namedProfileDigest
    )
      return denied();
    return verifyNotificationAsyncInstalledPair(
      inputEnvelope,
      capacityEnvelope,
      await verifiedState(
        client,
        environment,
        input.authorityId,
        issuanceResult.rows[0]!,
        capacity.issuedAtMs,
      ),
      await verifiedState(client, environment, input.authorityId, current, await now(client)),
      await now(client),
    );
  };
  const signatures = await verify();
  await sameTransaction();
  const result = await consume(client, signatures);
  await sameTransaction();
  await verify();
  return result;
}
