import {
  runtimeArtifactFenceSql,
  runtimeArtifactRuntimeProducers,
  runtimeArtifactDependencyProducers,
} from './runtime-artifact-fence.mjs';

/** Observation declarations only. Canonical owns registration, grants and all
 * producer fences. Nothing here grants disposition or changes an owner row. */
export const runtimeArtifactReferenceLimit = 128;
const timestamp = (column) =>
  `to_char(${column} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const h = (column) => `'sha256:'||encode(${column},'hex')`;
const json = (fields = {}) =>
  `jsonb_build_object(${Object.entries(fields)
    .flatMap(([key, value]) => [`'${key}'`, value])
    .join(',')})`;
const link = (kind, column, required = true) =>
  `case when ${column} is null then null else ${json({ kind: `'${kind}'`, id: `(${column})::text`, required: String(required) })} end`;
const list = (items = []) =>
  `(select coalesce(jsonb_agg(value),'[]'::jsonb) from jsonb_array_elements(jsonb_build_array(${items.join(',')})) where value<>'null'::jsonb)`;
const token = (kind, value) =>
  `case when ${value} is null then null else ${json({ kind: `'${kind}'`, digest: value })} end`;
const bindingKind =
  "case binding->>'kind' when 'ProviderProfile' then 'PROVIDER' when 'ClientIndexerProfile' then 'INDEXER' when 'ProjectionPlan' then 'PROJECTION' when 'CiglSettings' then 'CIGL_SETTINGS' else null end";
const bindingReferences = `(select coalesce(jsonb_agg(jsonb_build_object('kind',${bindingKind},'id',binding->>'id','required',true)),'[]'::jsonb)
 from jsonb_array_elements(resource_bindings) binding where (${bindingKind}) is not null)`;
const owners = [
  {
    kind: 'INPUT',
    table: 'runtime_configuration_input',
    id: 'runtime_configuration_input_id',
    state: "case when selected then 'SELECTED' else 'RETAINED' end",
    revision: null,
    digests: {
      configuration: h('configuration_digest'),
      bindings: h("sha256(convert_to(openpc.signing_canonical_json(resource_bindings),'UTF8'))"),
    },
    additionalReferences: bindingReferences,
    references: [
      link('MODULE_CONFIGURATION', 'module_configuration_generation_id'),
      link('MODULE_INSTALLATION', 'module_installation_id'),
    ],
    tokens: [token('CONFIGURATION', h('configuration_digest'))],
    checks: {
      bytesMatch:
        "(openpc.runtime_artifact_input_information(runtime_configuration_input_id)->>'bytesMatch')::boolean",
      bindingsKnown: `not exists(select 1 from jsonb_array_elements(resource_bindings) binding where (${bindingKind}) is null)`,
    },
    details: {
      byteLength:
        "openpc.runtime_artifact_input_information(runtime_configuration_input_id)->>'byteLength'",
      createdAt: timestamp('created_at'),
    },
  },
  {
    kind: 'MODULE_CONFIGURATION',
    table: 'module_configuration_generation',
    id: 'generation_id',
    state: "case when active then 'ACTIVE' else 'INACTIVE' end",
    revision: 'generation',
    digests: { configuration: h('configuration_digest') },
    references: [link('MODULE_INSTALLATION', 'module_installation_id')],
  },
  {
    kind: 'MODULE_INSTALLATION',
    table: 'module_installation',
    id: 'module_installation_id',
    state: 'state',
    revision: 'aggregate_version',
    digests: { manifest: h('active_manifest_digest'), lifecycle: h('lifecycle_evaluation_digest') },
    details: { lifecycleOperationId: 'lifecycle_operation_id::text' },
  },
  {
    kind: 'WORK',
    table: 'configuration_work',
    id: 'configuration_work_id',
    state: 'state',
    revision: 'attempt_count',
    digests: {
      configuration: 'configuration_digest',
      generation: 'generation_digest',
      predecessor: 'predecessor_digest',
      policy: 'policy_generation_digest',
      result: 'result_receipt_digest',
      input: 'input_digest',
    },
    references: [
      link('RUNTIME_GENERATION', 'runtime_configuration_generation_id'),
      link('TARGET', 'runtime_target_id'),
    ],
    tokens: [
      token('CONFIGURATION', 'configuration_digest'),
      token('POLICY', 'policy_generation_digest'),
      token('CAPSULE', 'predecessor_digest'),
    ],
    checks: {
      resultMatch:
        "case when result_receipt is null then null else result_receipt_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(result_receipt),'UTF8')),'hex') end",
    },
    details: {
      workKind: 'work_kind',
      operationId: 'operation_id::text',
      resourceId: 'resource_id::text',
      executionAttemptId: 'execution_attempt_id::text',
      executionStartedAt: timestamp('execution_started_at'),
      leaseUntil: timestamp('lease_until'),
      reconcileAfter: timestamp('reconcile_after'),
      completedAt: timestamp('completed_at'),
    },
  },
  {
    kind: 'RUNTIME_GENERATION',
    table: 'runtime_configuration_generation',
    id: 'runtime_configuration_generation_id',
    state: 'state',
    revision: 'revision',
    digests: {
      generation: 'generation_digest',
      predecessor: 'predecessor_digest',
      policy: 'policy_generation_digest',
    },
    references: [
      link('TARGET', 'runtime_target_id'),
      link('PROVIDER', 'provider_profile_id'),
      link('PROJECTION', 'projection_plan_id'),
    ],
    tokens: [token('CAPSULE', 'predecessor_digest'), token('POLICY', 'policy_generation_digest')],
  },
  {
    kind: 'TARGET',
    table: 'runtime_target',
    id: 'runtime_target_id',
    state: 'state',
    revision: 'revision',
    digests: {
      active: 'active_generation_digest',
      desired: 'desired_generation_digest',
      policy: 'policy_generation_digest',
      xds: 'xds_version_digest',
    },
    tokens: [
      token('CAPSULE', 'active_generation_digest'),
      token('CAPSULE', 'desired_generation_digest'),
      token('POLICY', 'policy_generation_digest'),
    ],
  },
  {
    kind: 'TARGET_CONNECTION',
    table: 'runtime_target_connection',
    id: 'runtime_target_id',
    state: "case when connected then 'CONNECTED' else 'DISCONNECTED' end",
    revision: 'credential_epoch',
    digests: { certificate: 'certificate_digest' },
    references: [link('TARGET', 'runtime_target_id')],
    details: {
      connectionId: 'connection_id::text',
      principalEpoch: 'principal_epoch::text',
      observedAt: timestamp('observed_at'),
      validUntil: timestamp('valid_until'),
    },
  },
  {
    kind: 'ACTIVATION_OBSERVATION',
    table: 'runtime_activation_observation',
    id: 'runtime_activation_observation_id',
    state: "'RETAINED'",
    revision: null,
    digests: {
      generation: 'generation_digest',
      capsule: 'capsule_digest',
      receipt: 'activation_receipt_digest',
      xds: 'xds_version_digest',
    },
    references: [
      link('WORK', 'configuration_work_id'),
      link('RUNTIME_GENERATION', 'runtime_configuration_generation_id'),
      link('TARGET', 'runtime_target_id'),
    ],
    tokens: [token('CAPSULE', 'capsule_digest')],
    checks: {
      receiptMatch:
        "activation_receipt_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(activation_receipt),'UTF8')),'hex')",
    },
    details: {
      operationId: 'operation_id::text',
      executionAttemptId: 'execution_attempt_id::text',
    },
  },
  {
    kind: 'ROUTE_PUBLICATION',
    table: 'runtime_route_publication',
    id: 'runtime_route_publication_id',
    state: "'RETAINED'",
    revision: 'provider_revision',
    digests: {
      generation: 'generation_digest',
      policy: 'policy_generation_digest',
      qualification: 'qualification_observation_digest',
      routing: 'routing_source_digest',
      certification: 'certification_source_digest',
      routingAuthority: 'routing_authority_digest',
      certificationAuthority: 'certification_authority_digest',
    },
    references: [
      link('WORK', 'configuration_work_id'),
      link('RUNTIME_GENERATION', 'runtime_configuration_generation_id'),
      link('TARGET', 'runtime_target_id'),
      link('PROVIDER', 'provider_profile_id'),
      link('PROBE', 'qualification_observation_id'),
    ],
    tokens: [token('POLICY', 'policy_generation_digest')],
    details: { validUntil: timestamp('valid_until') },
  },
  {
    kind: 'PROBE',
    table: 'provider_probe_observation',
    id: 'observation_id',
    state: 'state',
    revision: 'source_revision',
    digests: {
      configuration: 'configuration_digest',
      input: 'input_digest',
      observation: 'observation_digest',
    },
    references: [link('PROVIDER', 'provider_profile_id')],
    tokens: [token('CONFIGURATION', 'configuration_digest')],
    checks: {
      observationMatch:
        "case when observation is null then null else observation_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(observation),'UTF8')),'hex') end",
    },
    details: {
      observedRevision: 'observed_revision::text',
      leaseUntil: timestamp('lease_until'),
      completedAt: timestamp('completed_at'),
      validUntil: timestamp('valid_until'),
    },
  },
  {
    kind: 'POLICY_OCCURRENCE',
    table: 'policy_activation_occurrence',
    id: 'activation_occurrence_id',
    state: 'state',
    revision: 'revision',
    digests: { generation: h('target_generation_digest'), cohort: h('exact_cohort_digest') },
    references: [
      link('POLICY_GENERATION', 'policy_generation_id'),
      link('POLICY_AUTHORIZATION', 'activation_occurrence_id', false),
    ],
    tokens: [token('POLICY', h('target_generation_digest'))],
    details: {
      matchedTargetCount: 'matched_target_count::text',
      totalTargetCount: 'total_target_count::text',
      rollbackStartedAt: timestamp('rollback_started_at'),
      rolledBackAt: timestamp('rolled_back_at'),
    },
  },
  {
    kind: 'POLICY_TARGET',
    table: 'policy_activation_occurrence_target',
    id: "activation_occurrence_id::text||'/'||runtime_target_id::text||'/'||phase",
    state: 'state',
    revision: 'expected_target_revision',
    digests: {
      predecessor: 'expected_predecessor_digest',
      observed: 'observed_generation_digest',
      receipt: 'activation_receipt_digest',
    },
    references: [
      link('POLICY_OCCURRENCE', 'activation_occurrence_id'),
      link('TARGET', 'runtime_target_id'),
      link('RUNTIME_GENERATION', 'runtime_configuration_generation_id'),
      link('WORK', 'configuration_work_id'),
    ],
    tokens: [
      token('CAPSULE', 'expected_predecessor_digest'),
      token('CAPSULE', 'observed_generation_digest'),
    ],
    details: { phase: 'phase', commandOperationId: 'command_operation_id::text' },
  },
  {
    kind: 'POLICY_AUTHORIZATION',
    table: 'policy_activation',
    id: 'policy_activation_id',
    state: 'state',
    revision: 'row_version',
    digests: {
      prior: h('prior_generation_digest'),
      cohort: h('exact_cohort_digest'),
      receipt: h('receipt_digest'),
    },
    references: [
      link('POLICY_GENERATION', 'policy_generation_id'),
      link('POLICY_OCCURRENCE', 'policy_activation_id', false),
    ],
    tokens: [token('POLICY', h('prior_generation_digest'))],
    details: { retiredAt: timestamp('retired_at') },
  },
  {
    kind: 'POLICY_PREREQUISITE',
    table: 'policy_activation_prerequisite',
    id: "policy_activation_id::text||'/'||prerequisite_type::text",
    state: "case when ready then 'READY' else 'NOT_READY' end",
    revision: null,
    digests: { subject: h('prerequisite_subject_digest'), receipt: h('receipt_digest') },
    references: [link('POLICY_AUTHORIZATION', 'policy_activation_id')],
    details: { prerequisiteType: 'prerequisite_type::text' },
  },
  {
    kind: 'POLICY_GENERATION',
    table: 'policy_generation',
    id: 'policy_generation_id',
    state: 'state',
    revision: 'generation',
    digests: {
      generation: h('generation_digest'),
      artifact: h('artifact_digest'),
      dependency: h('dependency_closure_digest'),
    },
    tokens: [token('POLICY', h('generation_digest'))],
    details: { active: 'active::text' },
  },
  {
    kind: 'PROVIDER',
    table: 'provider_profile',
    id: 'provider_profile_id',
    state: 'state',
    revision: 'revision',
    digests: { artifact: 'behavior_fingerprint', policy: 'policy_generation_digest' },
    references: [link('PROBE', 'qualification_observation_id')],
    tokens: [token('POLICY', 'policy_generation_digest')],
  },
  {
    kind: 'INDEXER',
    table: 'indexer_profile',
    id: 'indexer_profile_id',
    state: 'state',
    revision: 'revision',
    digests: { artifact: 'method_profile_digest', policy: 'policy_generation_digest' },
    tokens: [token('POLICY', 'policy_generation_digest')],
  },
  {
    kind: 'CIGL_SETTINGS',
    table: 'cigl_settings',
    id: 'cigl_settings_id',
    state: "'RETAINED'",
    revision: null,
    digests: { artifact: 'definition_digest', authority: 'publication_authority_digest' },
    details: { publicationOperationId: 'publication_operation_id::text' },
  },
  {
    kind: 'PROJECTION',
    table: 'projection_plan',
    id: 'projection_plan_id',
    state: 'state',
    revision: 'revision',
    digests: { artifact: 'plan_digest', policy: 'policy_generation_digest' },
    references: [link('INDEXER', 'indexer_profile_id')],
    tokens: [token('POLICY', 'policy_generation_digest')],
    details: { readiness: 'readiness' },
  },
  {
    kind: 'TARGET_DISPOSITION_ADMISSION',
    table: 'runtime_target_disposition_admission',
    id: "runtime_target_id::text||':'||revision::text",
    state: "'RETAINED'",
    revision: 'revision',
    digests: { admission: 'admission_digest' },
    references: [
      link('TARGET', 'runtime_target_id'),
      link('INPUT', "binding->'source'->>'runtime_configuration_input_id'"),
      link('WORK', "binding->'source'->>'original_work_id'"),
      link('WORK', "binding->'cause'->>'work_id'"),
    ],
    tokens: [token('CONFIGURATION', "'sha256:'||(binding->'source'->>'configuration_digest')")],
  },
  {
    kind: 'TARGET_DISPOSITION_DELIVERY',
    table: 'runtime_target_disposition_delivery',
    id: 'delivery_digest',
    state: "'RETAINED'",
    revision: 'revision',
    digests: { delivery: 'delivery_digest' },
    references: [
      link('TARGET_DISPOSITION_ADMISSION', "runtime_target_id::text||':'||revision::text"),
    ],
    checks: { bytesMatch: "delivery_digest='sha256:'||encode(sha256(signed_delivery),'hex')" },
  },
  {
    kind: 'TARGET_DISPOSITION_ACK',
    table: 'runtime_target_disposition_acknowledgement',
    id: 'acknowledgement_digest',
    state: "'RETAINED'",
    digests: { acknowledgement: 'acknowledgement_digest' },
    references: [link('TARGET_DISPOSITION_DELIVERY', 'delivery_digest')],
    checks: {
      bytesMatch: "acknowledgement_digest='sha256:'||encode(sha256(signed_acknowledgement),'hex')",
    },
  },
];
export const runtimeArtifactReferenceOwners = Object.freeze(
  owners.map(({ kind, table }) => Object.freeze({ kind, table })),
);
const row = (owner) =>
  json({
    kind: `'${owner.kind}'`,
    id: `(${owner.id})::text`,
    participantId: 'participant_id::text',
    privacyDomainId: 'privacy_domain_id::text',
    revision: owner.revision ? `${owner.revision}::text` : 'null',
    state: owner.state,
    digests: json(owner.digests),
    references: owner.additionalReferences
      ? `(${list(owner.references)}||${owner.additionalReferences})`
      : list(owner.references),
    tokens: list(owner.tokens),
    checks: json(owner.checks),
    details: json(owner.details),
  });
const branches = owners
  .map(
    (
      o,
    ) => `'${o.kind}',(select jsonb_build_object('overflow',count(*)>${runtimeArtifactReferenceLimit},'rows',coalesce(jsonb_agg(value order by value->>'id') filter(where row_rank<=${runtimeArtifactReferenceLimit}),'[]'::jsonb))
 from (select value,row_number() over(order by value->>'id') row_rank from (select ${row(o)} value from control.${o.table}
 where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id()
 order by (${o.id})::text limit ${runtimeArtifactReferenceLimit + 1}) bounded) ranked)`,
  )
  .join(',');

// Validate the installed producer contract against its canonical declaration,
// never a duplicate trigger implementation. Failure remains an observation gap.
const producerTables = [
  ...runtimeArtifactFenceSql.matchAll(/ON control\.([a-z_]+) FOR EACH STATEMENT/g),
].map((match) => match[1]);
const fenceBody = runtimeArtifactFenceSql
  .split('SET search_path=pg_catalog AS $$')[1]
  ?.split('$$;')[0];
if (
  !fenceBody ||
  producerTables.length !== owners.length ||
  new Set(producerTables).size !== owners.length ||
  producerTables.some((table) => !owners.some((owner) => owner.table === table)) ||
  new Set([...runtimeArtifactRuntimeProducers, ...runtimeArtifactDependencyProducers]).size !==
    owners.length
)
  throw new Error('Runtime artifact producer declaration unavailable');
const sqlText = (value) => `'${value.replaceAll("'", "''")}'`;
const producerFencesObserved = (
  tables,
) => `not exists(select 1 from unnest(array[${tables.map(sqlText).join(',')}]) expected(table_name)
 where not exists(select 1 from pg_trigger t join pg_class c on c.oid=t.tgrelid
 join pg_namespace n on n.oid=c.relnamespace join pg_roles co on co.oid=c.relowner
 join pg_proc p on p.oid=t.tgfoid join pg_namespace pn on pn.oid=p.pronamespace
 join pg_roles po on po.oid=p.proowner join pg_language lang on lang.oid=p.prolang
 where n.nspname='control' and c.relname=expected.table_name and co.rolname='openpc_control_owner'
 and c.relkind='r' and c.relrowsecurity and not c.relispartition
 and not exists(select 1 from pg_inherits i where i.inhparent=c.oid or i.inhrelid=c.oid)
 and t.tgname='artifact_lifecycle_fence' and t.tgtype=62 and t.tgenabled in ('O','A') and not t.tgisinternal
 and t.tgconstraint=0 and t.tgparentid=0 and not t.tgdeferrable and not t.tginitdeferred
 and t.tgnargs=0 and octet_length(t.tgargs)=0 and t.tgattr::text='' and t.tgqual is null
 and t.tgoldtable is null and t.tgnewtable is null
 and pn.nspname='openpc' and po.rolname='openpc_control_owner' and p.proname='guard_runtime_artifact_lifecycle_fence'
 and lang.lanname='plpgsql' and p.prokind='f' and p.provolatile='v' and not p.prosecdef and not p.proisstrict
 and not p.proleakproof and p.proparallel='u' and not p.proretset and p.prosupport=0
 and p.prorettype='pg_catalog.trigger'::regtype and p.pronargs=0 and p.pronargdefaults=0 and p.provariadic=0 and p.proargmodes is null
 and p.proconfig=array['search_path=pg_catalog']::text[] and p.prosrc=${sqlText(fenceBody)}))`;

export const runtimeArtifactReferenceGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.observe_runtime_artifact_references(p_input uuid,p_digest text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE lock_key text; expected_mode text;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
 OR current_setting('session_replication_role')<>'origin' OR openpc.current_participant_id() IS NULL OR openpc.current_privacy_domain_id() IS NULL
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR (p_digest ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true OR p_input IS NULL
 THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-OBSERVATION-CONTEXT'; END IF;
 -- Exactly the existing lockModuleLifecycleReferences order; the application
 -- obtains these before this read. Never upgrade/acquire after owner row locks.
 FOREACH lock_key IN ARRAY ARRAY['evidence-lifecycle:'||openpc.current_participant_id()::text,'module-release-catalog','module-admission:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,
 'openpc-policy-generations:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text] LOOP
  expected_mode:=case when lock_key like 'module-admission:%' or lock_key like 'evidence-lifecycle:%' then 'ExclusiveLock' else 'ShareLock' end;
  IF NOT EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory' AND l.granted AND l.mode=expected_mode
   AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND l.classid=((hashtextextended(lock_key,0)>>32)&4294967295)::oid
   AND l.objid=(hashtextextended(lock_key,0)&4294967295)::oid AND l.objsubid=1)
  THEN RAISE EXCEPTION 'RUNTIME-ARTIFACT-OBSERVATION-FENCE'; END IF;
 END LOOP;
 -- All branches use one SQL statement snapshot and original tables, including
 -- terminal rows. The cap produces unresolved coverage, never an empty proof.
 RETURN (select jsonb_build_object('participantId',openpc.current_participant_id()::text,'privacyDomainId',openpc.current_privacy_domain_id()::text,
 'root', (select ${row(owners[0])} from control.runtime_configuration_input where participant_id=openpc.current_participant_id()
  and privacy_domain_id=openpc.current_privacy_domain_id() and runtime_configuration_input_id=p_input and configuration_digest=decode(substr(p_digest,8),'hex')),
 'runtimeProducerFencesObserved',${producerFencesObserved(runtimeArtifactRuntimeProducers)},
 'dependencyProducerFencesObserved',${producerFencesObserved(runtimeArtifactDependencyProducers)},'owners',jsonb_build_object(${branches})));
END $$;
REVOKE ALL ON FUNCTION openpc.observe_runtime_artifact_references(uuid,text) FROM PUBLIC;
`;
