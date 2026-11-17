import { z } from 'zod';
import { evidenceKeyId } from '../../packages/security-kernel/src/business-transition/cose.ts';
import { canonicalJson, sha256 } from '../../services/control-api/src/configuration/digest.ts';
import { localOperationId } from '../../services/identity-service/src/domain/local-operation-id.ts';
import { withCurrentProviderRetryQualification } from '../../services/control-api/src/configuration/operations/provider-retry-qualification.ts';
import {
  InstallationConfigError,
  parseConfigurationJson,
  parseNamedProfile,
} from './installation-config-inputs.mjs';
import { prepareSignedInstallationCandidate } from './installation-config-signature.mjs';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const scopeSchema = z.strictObject({ participantId: z.uuidv7(), privacyDomainId: z.uuidv7() });
const pinSchema = z.strictObject({
  issuerSpkiHex: z.string().regex(/^[0-9a-f]{182}$/u),
  issuerEpoch: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  issuerValidFromMs: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  issuerValidUntilMs: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  environmentId: z.string().regex(/^[a-z][a-z0-9-]{2,31}$/u),
  profile: z.enum(['local', 'development', 'test', 'staging', 'production']),
  configurationSchemaDigest: digest,
  namedProfileDigest: digest,
});
const unavailable = (reason) => {
  throw new InstallationConfigError(reason);
};
const genId = (value) => {
  if (typeof value !== 'string' || !value.startsWith('urn:openpc:generation:'))
    unavailable('GENERATION_ID');
  return z.uuidv7().parse(value.slice('urn:openpc:generation:'.length));
};
export async function withInstallationTransaction(pool, scope, action) {
  const s = scopeSchema.parse(scope),
    client = await pool.connect();
  try {
    await client.query('begin isolation level read committed');
    await client.query('set local role openpc_control_owner');
    await client.query(
      `select set_config('openpc.context_mode','PARTICIPANT',true),
      set_config('openpc.context_scope','TRANSACTION_LOCAL',true),set_config('openpc.participant_id',$1,true),
      set_config('openpc.privacy_domain_id',$2,true),set_config('openpc.operation_id',$3,true),
      set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)`,
      [s.participantId, s.privacyDomainId, localOperationId()],
    );
    const result = await action(client, s);
    await client.query('commit');
    return result;
  } catch (error) {
    await client.query('rollback');
    if (error instanceof InstallationConfigError) throw error;
    if (error?.message === 'OPS_PROVIDER_RETRY_EVIDENCE_OWNER_UNBOUND')
      unavailable('OPS_PROVIDER_RETRY_EVIDENCE_OWNER_UNBOUND');
    unavailable('GENERATION_STORE_REJECTED');
  } finally {
    client.release();
  }
}
const transaction = withInstallationTransaction;
export async function lockInstallationEnvironment(client, environment) {
  if (
    (
      await client.query(
        `select pg_try_advisory_xact_lock(hashtextextended('operations-generation:'||$1,0)) allowed`,
        [environment],
      )
    ).rows[0]?.allowed !== true
  )
    unavailable('GENERATION_BUSY');
}
const lock = lockInstallationEnvironment;

/** Privileged initial public trust only. This does not admit a configuration,
 * qualification, resolved secret or service observation. No HTTP enrollment. */
export async function installInitialOperationsEnvironment(pool, scope, input) {
  const pins = pinSchema.parse(input.pins),
    initialBaseGenerationId = z.uuidv7().parse(input.initialBaseGenerationId);
  evidenceKeyId(Buffer.from(pins.issuerSpkiHex, 'hex'));
  if (
    pins.issuerValidFromMs >= pins.issuerValidUntilMs ||
    BigInt(pins.issuerEpoch) > 18446744073709551615n
  )
    unavailable('INSTALLATION_INVALID');
  const schema = parseConfigurationJson(input.schemaBytes),
    namedProfile = parseNamedProfile(input.profileBytes);
  if (
    sha256(input.schemaBytes) !== pins.configurationSchemaDigest ||
    sha256(input.profileBytes) !== pins.namedProfileDigest ||
    schema.$id !== 'urn:openpc:schema:effective-configuration:1.0' ||
    namedProfile.profile !== pins.profile
  )
    unavailable('INSTALLATION_SOURCE_BINDING');
  const installation = { pins, schema, namedProfile, initialBaseGenerationId };
  if (Object.hasOwn(input, 'sourceAuthentication')) {
    try {
      installation.sourceAuthentication = JSON.parse(canonicalJson(input.sourceAuthentication));
    } catch {
      unavailable('C17_SOURCE_AUTHENTICATION_FAILED');
    }
  }
  const bytes = Buffer.from(canonicalJson(installation));
  return transaction(pool, scope, async (client, s) => {
    await lock(client, pins.environmentId);
    if (
      Object.hasOwn(installation, 'sourceAuthentication') &&
      (
        await client.query(
          'select openpc.operations_source_authentication_valid($1::jsonb) valid',
          [JSON.stringify(installation)],
        )
      ).rows[0]?.valid !== true
    )
      unavailable('C17_SOURCE_AUTHENTICATION_FAILED');
    const existing = (
      await client.query(
        'select installation_bytes,state from control.operations_installation where environment_id=$1',
        [pins.environmentId],
      )
    ).rows[0];
    if (existing) {
      if (existing.state !== 'ACTIVE' || !existing.installation_bytes.equals(bytes))
        unavailable('INSTALLATION_IMMUTABLE');
      return sha256(bytes);
    }
    await client.query(
      `insert into control.operations_installation(participant_id,privacy_domain_id,environment_id,installation,installation_bytes,installation_digest)
      values($1,$2,$3,$4,$5,$6)`,
      [s.participantId, s.privacyDomainId, pins.environmentId, installation, bytes, sha256(bytes)],
    );
    return sha256(bytes);
  });
}

/** Stages real signed input. All requirements are derived from the installed
 * schema and full candidate, never supplied as readiness flags by this caller.
 * Follow-up governed reload admission is separate from initial installation. */
export async function stageInitialOperationsGeneration(pool, scope, sources, signed) {
  return transaction(pool, scope, async (client, s) => {
    const environment = sources.environment.environmentId ?? sources.site.environmentId;
    await lock(client, environment);
    const row = (
      await client.query(
        'select installation,state from control.operations_installation where environment_id=$1 for share',
        [environment],
      )
    ).rows[0];
    if (!row || row.state !== 'ACTIVE') unavailable('INSTALLATION_UNAVAILABLE');
    if (
      (
        await client.query(
          'select 1 from control.operations_generation_commit where environment_id=$1',
          [environment],
        )
      ).rowCount
    )
      unavailable('GOVERNED_RELOAD_ADMISSION_UNAVAILABLE');
    const now = Number(
      (await client.query('select floor(extract(epoch from clock_timestamp())*1000)::text now'))
        .rows[0].now,
    );
    const pins = {
      ...row.installation.pins,
      issuerSpki: Buffer.from(row.installation.pins.issuerSpkiHex, 'hex'),
    };
    delete pins.issuerSpkiHex;
    const candidate = prepareSignedInstallationCandidate(sources, pins, signed, now, {
      expectedBaseGenerationId: `urn:openpc:generation:${row.installation.initialBaseGenerationId}`,
    });
    const generationId = genId(candidate.configuration.generation.generationId),
      baseGenerationId = genId(candidate.configuration.generation.baseGenerationId);
    const stored = {
      configuration: candidate.configuration,
      sourceClasses: candidate.sourceClasses,
      siteSignature: candidate.siteSignature,
      source: {
        siteHex: Buffer.from(sources.siteBytes).toString('hex'),
        payloadHex: Buffer.from(signed.payload).toString('hex'),
        coseHex: Buffer.from(signed.cose).toString('hex'),
      },
    };
    const bytes = Buffer.from(canonicalJson(stored)),
      candidateDigest = sha256(bytes);
    const requirements = (
      await client.query('select openpc.operations_generation_requirements($1,$2) required', [
        row.installation.schema,
        candidate.configuration,
      ])
    ).rows[0].required;
    const prior = (
      await client.query(
        'select candidate_bytes,state from control.operations_generation where environment_id=$1 and generation_id=$2',
        [environment, generationId],
      )
    ).rows[0];
    if (prior) {
      if (prior.state !== 'STAGED') unavailable('GENERATION_FENCED');
      if (!prior.candidate_bytes.equals(bytes)) unavailable('GENERATION_IMMUTABLE');
    } else
      await client.query(
        `insert into control.operations_generation(participant_id,privacy_domain_id,environment_id,generation_id,base_generation_id,candidate,candidate_bytes,candidate_digest,requirements)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [
          s.participantId,
          s.privacyDomainId,
          environment,
          generationId,
          baseGenerationId,
          stored,
          bytes,
          candidateDigest,
          JSON.stringify(requirements),
        ],
      );
    return {
      environmentId: environment,
      generationId,
      candidateDigest,
      state: 'STAGED',
      effective: false,
      missingBindings: (
        await client.query('select openpc.operations_generation_missing($1,$2) missing', [
          environment,
          generationId,
        ])
      ).rows[0].missing,
    };
  });
}

/** Atomic compare-and-commit path. At present the independent binding producers
 * have no DML grants, so missing real evidence is an enforced typed denial. This
 * is intentionally not a fixture backdoor to manufacture positive acceptance. */
export async function commitOperationsGeneration(pool, scope, environment, generationId) {
  return transaction(pool, scope, (client, s) =>
    commitOperationsGenerationInTransaction(client, s, environment, generationId),
  );
}

/** Uses the caller's existing privileged, scoped READ COMMITTED transaction.
 * The native provider-retry owner verifies current ES256/source custody before
 * and after insertion on this SAME client. Other live source observers still
 * enclose consumption. This function neither opens nor commits a transaction;
 * the caller must roll back on failure. No observation history grants readiness.
 * Every original advisory lock, binding check and SQL commit guard still runs. */
export async function commitOperationsGenerationInTransaction(
  client,
  scope,
  environment,
  generationId,
) {
  const s = scopeSchema.parse(scope);
  await client.query('select openpc.assert_request_context(true)');
  const context = (
    await client.query(
      `select current_user::text role,current_setting('transaction_isolation') isolation,
      current_setting('openpc.participant_id',true) participant,
      current_setting('openpc.privacy_domain_id',true) privacy,
      current_setting('openpc.operation_id',true) request,
      current_setting('openpc.action_intent_id',true) action,
      current_setting('openpc.context_mode',true) mode,current_setting('row_security') row_security`,
    )
  ).rows[0];
  if (
    context?.role !== 'openpc_control_owner' ||
    context.isolation !== 'read committed' ||
    context.participant !== s.participantId ||
    context.privacy !== s.privacyDomainId ||
    context.action !== 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' ||
    context.mode !== 'PARTICIPANT' ||
    context.row_security !== 'on'
  )
    unavailable('GENERATION_TRANSACTION_CONTEXT');
  await lock(client, environment);
  const candidate = (
    await client.query(
      'select candidate,state from control.operations_generation where environment_id=$1 and generation_id=$2 for share',
      [environment, z.uuidv7().parse(generationId)],
    )
  ).rows[0];
  if (!candidate || candidate.state !== 'STAGED') unavailable('GENERATION_UNAVAILABLE');
  const missing = (
    await client.query('select openpc.operations_generation_missing($1,$2) missing', [
      environment,
      generationId,
    ])
  ).rows[0].missing;
  if (missing.length) unavailable('GENERATION_BINDINGS_UNAVAILABLE');
  // Take the generation root exclusively before the qualification owner's
  // shared generation/authority fences. Never upgrade after taking authority.
  return withCurrentProviderRetryQualification(
    client,
    { ...s, requestId: context.request },
    environment,
    generationId,
    async (sameClient) => {
      const inserted = await sameClient.query(
        `insert into control.operations_generation_commit(participant_id,privacy_domain_id,environment_id,generation_id,sequence,effective_digest)
    select $1,$2,$3,$4,coalesce(max(sequence),0)+1,$5 from control.operations_generation_commit where environment_id=$3
    returning generation_id,effective_digest`,
        [
          s.participantId,
          s.privacyDomainId,
          environment,
          generationId,
          candidate.candidate.configuration.generation.contentDigest,
        ],
      );
      return inserted.rows[0];
    },
  );
}

/** Redacted durable status only; original documents and secret-reference names
 * are not returned. Historical commit and current usability remain distinct. */
export async function readOperationsGeneration(pool, scope, environment, generationId) {
  return transaction(pool, scope, async (client) => {
    const row = (
      await client.query(
        `select g.generation_id,g.base_generation_id,g.candidate_digest,g.state,
      c.effective_digest,openpc.operations_generation_missing(g.environment_id,g.generation_id) missing
      from control.operations_generation g left join control.operations_generation_commit c using(environment_id,generation_id)
      where g.environment_id=$1 and g.generation_id=$2`,
        [environment, z.uuidv7().parse(generationId)],
      )
    ).rows[0];
    if (!row) unavailable('GENERATION_UNAVAILABLE');
    return row;
  });
}
