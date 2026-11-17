import { getTableConfig } from 'drizzle-orm/pg-core';
import { notificationSourceInbox, notificationSourceCursors } from './schema.ts';
import {
  notificationCompletionDispositionSigners,
  notificationCompletionSources,
  notificationCompletionAttempts,
  notificationCompletionDispositionSigning,
  notificationCompletionDispositions,
} from './completion-disposition-schema.ts';
import { notificationCompletionDispositionGuardsSql } from './completion-disposition-guards.mjs';
import { notificationCompletionDispositionPublicationSql } from './completion-disposition-publication.mjs';
import {
  notificationOccurrenceGuardsSql,
  notificationOccurrencePublicationGuardsSql,
} from './occurrence-guards.mjs';
import {
  workItemLifecycleGuardsSql,
  workItemReceiptGuardsSql,
} from '../../../identity-service/src/db/work-item-receipt-guards.mjs';
import { notificationCompletionAdmissionSql } from '../../../identity-service/src/db/notification-completion-admission-guards.mjs';

const sharedEffectsSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.check_notification_completion_shared_publication(event uuid) RETURNS control.notification_completion_disposition
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE d control.notification_completion_disposition%ROWTYPE;s control.notification_completion_disposition_signing%ROWTYPE;
BEGIN
 PERFORM openpc.assert_notification_completion_disposition_shared_owner();
 SELECT * INTO STRICT d FROM control.notification_completion_disposition WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=event;
 SELECT * INTO STRICT s FROM control.notification_completion_disposition_signing WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=event;
 PERFORM openpc.check_notification_completion_phase_source(event,'PUBLISH');
 PERFORM openpc.check_notification_completion_receipt_admission(event,'PUBLISH',s.observation);
 PERFORM openpc.check_notification_completion_disposition_signed(event,d.transition);
 RETURN d;
END $$;

CREATE OR REPLACE FUNCTION openpc.check_notification_completion_inbox_effect(item control.notification_source_inbox,previous control.notification_source_inbox) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE d control.notification_completion_disposition%ROWTYPE;s control.notification_completion_source%ROWTYPE;e control.outbox_event%ROWTYPE;
BEGIN
 d:=openpc.check_notification_completion_shared_publication(item.event_id);
 SELECT * INTO STRICT s FROM control.notification_completion_source WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=d.event_id;
 SELECT * INTO STRICT e FROM control.outbox_event WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=d.event_id;
 IF item.participant_id IS DISTINCT FROM d.participant_id OR item.privacy_domain_id IS DISTINCT FROM d.privacy_domain_id
 OR item.subscription_id IS DISTINCT FROM 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'
 OR item.source IS DISTINCT FROM e.source OR item.partition IS DISTINCT FROM 'urn:openpc:resource:'||e.aggregate_id::text
 OR item.source_sequence IS DISTINCT FROM e.business_sequence OR item.data_digest IS DISTINCT FROM s.source->'reference'->>'dataDigest'
 OR item.envelope_digest IS DISTINCT FROM s.source->'reference'->>'envelopeDigest'
 OR item.envelope IS DISTINCT FROM convert_to(openpc.signing_canonical_json(s.source->'envelope'),'UTF8')
 THEN RAISE EXCEPTION 'COMPLETION-SHARED-INBOX-BINDING'; END IF;
 IF previous.participant_id IS NOT NULL THEN
  -- Generated operation columns are computed after BEFORE triggers. They are
  -- independently fixed by their expressions and operation-specific FKs.
  IF previous.state IS DISTINCT FROM 'PENDING' OR previous.admission_operation_id IS NOT NULL OR previous.safe_problem_code IS NOT NULL
   OR to_jsonb(previous)-ARRAY['state','safe_problem_code','admission_operation_id','occurrence_admission_operation_id','completion_admission_operation_id']
    IS DISTINCT FROM to_jsonb(item)-ARRAY['state','safe_problem_code','admission_operation_id','occurrence_admission_operation_id','completion_admission_operation_id']
   OR item.state IS DISTINCT FROM d.disposition
  THEN RAISE EXCEPTION 'COMPLETION-SHARED-INBOX-TRANSITION'; END IF;
 END IF;
 IF item.state='PENDING' THEN
  IF item.admission_operation_id IS NOT NULL OR item.safe_problem_code IS NOT NULL THEN RAISE EXCEPTION 'COMPLETION-SHARED-INBOX-PENDING'; END IF;
 ELSE
  IF item.state IS DISTINCT FROM d.disposition OR item.admission_operation_id IS DISTINCT FROM d.operation_id
   OR item.safe_problem_code IS DISTINCT FROM (CASE d.disposition WHEN 'QUARANTINED' THEN 'PC-OPS-9001' ELSE NULL END)
  THEN RAISE EXCEPTION 'COMPLETION-SHARED-INBOX-RESULT'; END IF;
 END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.check_notification_completion_cursor_effect(item control.notification_source_cursor,previous control.notification_source_cursor) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE d control.notification_completion_disposition%ROWTYPE;i control.notification_source_inbox%ROWTYPE;
BEGIN
 d:=openpc.check_notification_completion_shared_publication(item.last_event_id);
 SELECT * INTO STRICT i FROM control.notification_source_inbox WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id
  AND event_id=d.event_id AND subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1';
 IF d.disposition IS DISTINCT FROM 'ADMITTED' OR i.state IS DISTINCT FROM 'ADMITTED' OR i.admission_operation_id IS DISTINCT FROM d.operation_id
 OR item.participant_id IS DISTINCT FROM d.participant_id OR item.privacy_domain_id IS DISTINCT FROM d.privacy_domain_id
 OR item.subscription_id IS DISTINCT FROM i.subscription_id OR item.source IS DISTINCT FROM i.source OR item.partition IS DISTINCT FROM i.partition
 OR item.last_sequence IS DISTINCT FROM i.source_sequence OR item.last_data_digest IS DISTINCT FROM i.data_digest
 THEN RAISE EXCEPTION 'COMPLETION-SHARED-CURSOR-BINDING'; END IF;
 IF previous.participant_id IS NULL THEN
  IF item.revision IS DISTINCT FROM 1 THEN RAISE EXCEPTION 'COMPLETION-SHARED-CURSOR-INITIAL'; END IF;
 ELSE
  IF previous.last_sequence IS DISTINCT FROM 0 OR previous.last_event_id IS NOT NULL OR previous.last_data_digest IS NOT NULL OR previous.revision IS DISTINCT FROM 1
  OR item.revision IS DISTINCT FROM 2
  OR to_jsonb(previous)-ARRAY['last_sequence','last_event_id','last_data_digest','revision'] IS DISTINCT FROM to_jsonb(item)-ARRAY['last_sequence','last_event_id','last_data_digest','revision']
  THEN RAISE EXCEPTION 'COMPLETION-SHARED-CURSOR-TRANSITION'; END IF;
 END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.check_notification_completion_remediation_effect(item control.work_item) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE event uuid;d control.notification_completion_disposition%ROWTYPE;
BEGIN
 SELECT event_id INTO STRICT event FROM control.notification_completion_disposition WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND receipt_id=item.work_item_id;
 d:=openpc.check_notification_completion_shared_publication(event);
 IF item.participant_id IS DISTINCT FROM d.participant_id OR item.privacy_domain_id IS DISTINCT FROM d.privacy_domain_id
 OR item.row_version IS DISTINCT FROM 1 OR openpc.work_item_business_projection(item) IS DISTINCT FROM openpc.notification_completion_remediation_projection(d)
 THEN RAISE EXCEPTION 'COMPLETION-SHARED-REMEDIATION'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.complete_notification_completion_remediation() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE event uuid;
BEGIN
 SELECT event_id INTO STRICT event FROM control.notification_completion_disposition WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id AND receipt_id=NEW.work_item_id;
 PERFORM openpc.check_notification_completion_disposition_original(event);
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS notification_completion_remediation_complete ON control.work_item;
CREATE CONSTRAINT TRIGGER notification_completion_remediation_complete AFTER INSERT ON control.work_item
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
 WHEN (openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' OR (NEW.kind='REMEDIATION' AND openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-WORK_ITEMS_CREATE_RESOURCE-V1'))
 EXECUTE FUNCTION openpc.complete_notification_completion_remediation();
`;

const quote = (text) => `'${text.replaceAll("'", "''")}'`;
function functions(source) {
  return [
    ...source.matchAll(
      /CREATE OR REPLACE FUNCTION openpc\.(\w+)\(([^)]*)\)\s*RETURNS\s+([\w.]+)([\s\S]*?)AS \$\$([\s\S]*?)\$\$;/gu,
    ),
  ].map((m) => ({
    name: m[1],
    argumentNames: m[2].trim()
      ? m[2].split(',').map((argument) => argument.trim().split(/\s+/u)[0])
      : null,
    signature: `${m[1]}(${
      m[2].trim()
        ? m[2]
            .split(',')
            .map((a) => a.trim().split(/\s+/u).slice(1).join(' '))
            .join(',')
        : ''
    })`,
    returns: m[3],
    body: m[5],
    language: /LANGUAGE sql\b/u.test(m[4]) ? 'sql' : 'plpgsql',
    volatility: /\bIMMUTABLE\b/u.test(m[4]) ? 'i' : /\bSTABLE\b/u.test(m[4]) ? 's' : 'v',
  }));
}

const ownedSql =
  notificationCompletionDispositionGuardsSql +
  notificationCompletionDispositionPublicationSql +
  sharedEffectsSql;
const ownedFunctions = functions(ownedSql);
if (ownedFunctions.length < 20) throw new Error('Incomplete completion function declarations');
const authenticatedFunctions = [
  ...ownedFunctions,
  ...functions(notificationOccurrenceGuardsSql).filter(
    (f) => f.name === 'guard_notification_occurrence_truncate',
  ),
  ...functions(notificationOccurrencePublicationGuardsSql).filter((f) =>
    ['guard_notification_occurrence_effect', 'check_notification_occurrence_effect_pair'].includes(
      f.name,
    ),
  ),
  ...functions(workItemLifecycleGuardsSql),
  ...functions(workItemReceiptGuardsSql),
  ...functions(notificationCompletionAdmissionSql).filter(
    (f) => f.name === 'assert_notification_completion_admission_owner',
  ),
];
const functionChecks = authenticatedFunctions.map(
  (
    f,
  ) => `NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
 WHERE p.oid=to_regprocedure(${quote('openpc.' + f.signature)}) AND r.rolname='openpc_control_owner' AND l.lanname=${quote(f.language)}
 AND NOT p.prosecdef AND NOT p.proisstrict AND NOT p.proleakproof AND NOT p.proretset AND p.prokind='f' AND p.provariadic=0 AND p.pronargdefaults=0
 AND p.proargnames IS NOT DISTINCT FROM ${f.argumentNames ? `ARRAY[${f.argumentNames.map(quote).join(',')}]::text[]` : 'NULL::text[]'}
 AND p.provolatile=${quote(f.volatility)} AND p.prorettype=${quote(f.returns)}::regtype
 AND p.proconfig=ARRAY['search_path=pg_catalog'] AND p.prosrc=${quote(f.body)})`,
);

const tables = [
  'notification_completion_disposition_signer_installation',
  'notification_completion_source',
  'notification_completion_attempt',
  'notification_completion_disposition_signing',
  'notification_completion_disposition',
];
const roles = [
  'openpc_control_runtime',
  'openpc_control_worker',
  'openpc_control_reader',
  'openpc_control_platform_runtime',
];
const runtimeUpdates = {
  notification_completion_source: ['effective_limit'],
  notification_completion_attempt: ['attempt', 'attempt_bytes', 'attempt_digest'],
  notification_completion_disposition_signing: [
    'state',
    'dispatch_token',
    'dispatched_at_ms',
    'observation',
    'observation_bytes',
    'observation_digest',
  ],
  notification_source_inbox: ['state', 'safe_problem_code', 'admission_operation_id'],
  notification_source_cursor: ['last_sequence', 'last_event_id', 'last_data_digest', 'revision'],
};

// Registration and installed-owner checks follow below. This module is loaded
// after canonical shared occurrence, WorkItem and outcome owners and Identity
// 0099. It does not export tables or generate/reorder migrations itself.
const tableDefinitions = [
  notificationCompletionDispositionSigners,
  notificationCompletionSources,
  notificationCompletionAttempts,
  notificationCompletionDispositionSigning,
  notificationCompletionDispositions,
  notificationSourceInbox,
  notificationSourceCursors,
].map(getTableConfig);
const textArray = (values) => `ARRAY[${values.map(quote).join(',')}]::text[]`;
const keyNames = (key, relation) =>
  `(SELECT array_agg(a.attname::text ORDER BY k.n) FROM unnest(${key}) WITH ORDINALITY k(id,n) JOIN pg_attribute a ON a.attrelid=${relation} AND a.attnum=k.id)`;
const constraints = tableDefinitions.flatMap((table) => {
  const relation = quote(`control.${table.name}`);
  return [
    ...table.primaryKeys.map((key) => ({ name: key.getName(), type: 'p', columns: key.columns })),
    ...table.uniqueConstraints.map((key) => ({
      name: key.getName(),
      type: 'u',
      columns: key.columns,
    })),
    ...table.foreignKeys.map((key) => ({
      name: key.getName(),
      type: 'f',
      columns: key.reference().columns,
      foreign: key.reference(),
      onDelete: key.onDelete,
    })),
  ].map((key) => {
    const foreign = key.foreign;
    return `NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=${relation}::regclass AND c.conname=${quote(key.name.slice(0, 63))}
 AND c.contype=${quote(key.type)} AND c.convalidated
 AND ${keyNames('c.conkey', 'c.conrelid')}=${textArray(key.columns.map((c) => c.name))}
 ${
   foreign
     ? `AND c.confrelid=${quote('control.' + getTableConfig(foreign.foreignTable).name)}::regclass
 AND ${keyNames('c.confkey', 'c.confrelid')}=${textArray(foreign.foreignColumns.map((c) => c.name))}
 AND NOT c.condeferrable AND NOT c.condeferred AND c.confmatchtype='s' AND c.confupdtype='a' AND c.confdeltype=${quote(key.onDelete === 'restrict' ? 'r' : 'a')}`
     : `AND NOT c.condeferrable AND NOT c.condeferred`
 })`;
  });
});
// Whitespace normalization preserves all parentheses, operators and casts.
// It cannot conflate differently grouped Boolean expressions.
const normalize = (sql) => sql.replace(/\s+/gu, ' ').trim();
const expression = (sql) => `btrim(regexp_replace(${sql},'[[:space:]]+',' ','g'))`;
const subscriptions = [
  'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1',
  'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1',
  'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1',
];
const completionSubscription = 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1';
const pgArray = (values) => `ARRAY[${values.map((v) => quote(v) + '::text').join(', ')}]`;
// Exact PostgreSQL 18.6 deparser output from the owning Drizzle declarations.
// Keep operators, grouping and casts: presence alone does not pin semantics.
const checkExpressions = [
  [
    'notification_completion_attempt',
    'completion_attempt_bytes_ck',
    "(((octet_length(attempt_bytes) >= 1) AND (octet_length(attempt_bytes) <= 4096)) AND (attempt_digest = ('sha256:'::text || encode(sha256(attempt_bytes), 'hex'::text))))",
  ],
  [
    'notification_completion_attempt',
    'completion_attempt_number_ck',
    '((number >= (1)::numeric) AND (number <= (1000)::numeric))',
  ],
  [
    'notification_completion_disposition',
    'completion_disposition_bytes_ck',
    "(((octet_length(transition_bytes) >= 1) AND (octet_length(transition_bytes) <= 1048576)) AND (transition_digest = ('sha256:'::text || encode(sha256(transition_bytes), 'hex'::text))) AND ((octet_length(receipt_payload) >= 1) AND (octet_length(receipt_payload) <= 65536)) AND ((octet_length(cose_sign1) >= 65) AND (octet_length(cose_sign1) <= 131072)))",
  ],
  [
    'notification_completion_disposition',
    'completion_disposition_kind_ck',
    "(disposition = ANY (ARRAY['ADMITTED'::text, 'QUARANTINED'::text]))",
  ],
  [
    'notification_completion_disposition_signer_installation',
    'completion_signer_bytes_ck',
    "(((octet_length(trust_bytes) >= 1) AND (octet_length(trust_bytes) <= 65536)) AND (trust_digest = ('sha256:'::text || encode(sha256(trust_bytes), 'hex'::text))))",
  ],
  [
    'notification_completion_disposition_signer_installation',
    'completion_signer_state_ck',
    "(state = ANY (ARRAY['ACTIVE'::text, 'REVOKED'::text]))",
  ],
  [
    'notification_completion_disposition_signing',
    'completion_signing_bytes_ck',
    "(((octet_length(preparation_bytes) >= 1) AND (octet_length(preparation_bytes) <= 1048576)) AND (preparation_digest = ('sha256:'::text || encode(sha256(preparation_bytes), 'hex'::text))))",
  ],
  [
    'notification_completion_disposition_signing',
    'completion_signing_state_ck',
    "(((state = 'PREPARED'::text) AND (dispatch_token IS NULL) AND (dispatched_at_ms IS NULL) AND (observation IS NULL) AND (observation_bytes IS NULL) AND (observation_digest IS NULL)) OR ((state = 'DISPATCHED'::text) AND (dispatch_token ~ '^[0-9a-f]{64}$'::text) AND ((dispatched_at_ms >= (0)::numeric) AND (dispatched_at_ms <= ('9007199254740991'::bigint)::numeric)) AND (observation IS NULL) AND (observation_bytes IS NULL) AND (observation_digest IS NULL)) OR ((state = 'OBSERVED'::text) AND (dispatch_token ~ '^[0-9a-f]{64}$'::text) AND ((dispatched_at_ms >= (0)::numeric) AND (dispatched_at_ms <= ('9007199254740991'::bigint)::numeric)) AND (observation IS NOT NULL) AND ((octet_length(observation_bytes) >= 1) AND (octet_length(observation_bytes) <= 196608)) AND (observation_digest = ('sha256:'::text || encode(sha256(observation_bytes), 'hex'::text)))))",
  ],
  [
    'notification_completion_source',
    'completion_source_bytes_ck',
    "(((octet_length(source_bytes) >= 1) AND (octet_length(source_bytes) <= 524288)) AND (source_digest = ('sha256:'::text || encode(sha256(source_bytes), 'hex'::text))))",
  ],
  [
    'notification_completion_source',
    'completion_source_limit_ck',
    '((effective_limit >= (1)::numeric) AND (effective_limit <= (1000)::numeric))',
  ],
  [
    'notification_source_cursor',
    'notification_cursor_position_ck',
    "(((last_sequence = (0)::numeric) AND (last_event_id IS NULL) AND (last_data_digest IS NULL)) OR (((last_sequence >= (1)::numeric) AND (last_sequence <= '18446744073709551615'::numeric)) AND (last_event_id IS NOT NULL) AND (last_data_digest IS NOT NULL)))",
  ],
  [
    'notification_source_cursor',
    'notification_cursor_revision_ck',
    "((revision >= (1)::numeric) AND (revision <= '18446744073709551615'::numeric))",
  ],
  [
    'notification_source_cursor',
    'notification_cursor_source_ck',
    '(((octet_length(source) >= 1) AND (octet_length(source) <= 2048)) AND ((octet_length(partition) >= 1) AND (octet_length(partition) <= 256)))',
  ],
  [
    'notification_source_cursor',
    'notification_cursor_subscription_ck',
    "(subscription_id = ANY (ARRAY['SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1'::text, 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1'::text, 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'::text, 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'::text]))",
  ],
  [
    'notification_source_inbox',
    'notification_inbox_data_ck',
    "(data_digest ~ '^sha256:[0-9a-f]{64}$'::text)",
  ],
  [
    'notification_source_inbox',
    'notification_inbox_envelope_ck',
    "((octet_length(envelope) > 0) AND (envelope_digest = ('sha256:'::text || encode(sha256(envelope), 'hex'::text))))",
  ],
  [
    'notification_source_inbox',
    'notification_inbox_problem_ck',
    "(((state = 'QUARANTINED'::text) AND (safe_problem_code IS NOT NULL) AND (safe_problem_code ~ '^PC-[A-Z]+-[0-9]{4}$'::text)) OR ((state <> 'QUARANTINED'::text) AND (safe_problem_code IS NULL)))",
  ],
  [
    'notification_source_inbox',
    'notification_inbox_sequence_ck',
    "((source_sequence >= (1)::numeric) AND (source_sequence <= '18446744073709551615'::numeric))",
  ],
  [
    'notification_source_inbox',
    'notification_inbox_source_ck',
    '(((octet_length(source) >= 1) AND (octet_length(source) <= 2048)) AND ((octet_length(partition) >= 1) AND (octet_length(partition) <= 256)))',
  ],
  [
    'notification_source_inbox',
    'notification_inbox_state_ck',
    "((state = ANY (ARRAY['PENDING'::text, 'ADMITTED'::text, 'QUARANTINED'::text])) AND ((state = 'PENDING'::text) = (admission_operation_id IS NULL)))",
  ],
  [
    'notification_source_inbox',
    'notification_inbox_subscription_ck',
    "(subscription_id = ANY (ARRAY['SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1'::text, 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1'::text, 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'::text, 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'::text]))",
  ],
];
const declaredChecks = tableDefinitions
  .flatMap((table) => table.checks.map((check) => `${table.name}.${check.name}`))
  .sort();
const pinnedChecks = checkExpressions.map(([table, name]) => `${table}.${name}`).sort();
if (JSON.stringify(declaredChecks) !== JSON.stringify(pinnedChecks))
  throw new Error('Incomplete completion CHECK semantics');
const checkConstraints = checkExpressions.map(
  ([
    table,
    name,
    expected,
  ]) => `NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=${quote('control.' + table)}::regclass
 AND c.conname=${quote(name)} AND c.contype='c' AND c.convalidated AND NOT c.connoinherit
 AND ${expression('pg_get_expr(c.conbin,c.conrelid)')}=${quote(normalize(expected))})`,
);
const generatedExpressions = [
  [
    'occurrence_admission_operation_id',
    `CASE WHEN (subscription_id = ANY (${pgArray(subscriptions)})) THEN admission_operation_id ELSE NULL::uuid END`,
  ],
  [
    'completion_admission_operation_id',
    `CASE WHEN (subscription_id = '${completionSubscription}'::text) THEN admission_operation_id ELSE NULL::uuid END`,
  ],
];
const generatedChecks = generatedExpressions.map(
  ([
    column,
    expected,
  ]) => `NOT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE a.attrelid='control.notification_source_inbox'::regclass AND a.attname=${quote(column)} AND a.attgenerated='s' AND NOT a.attisdropped
 AND ${expression('pg_get_expr(d.adbin,d.adrelid)')}=${quote(normalize(expected))})`,
);
const columnChecks = tableDefinitions.flatMap((table) =>
  table.columns.map(
    (column) => `NOT EXISTS(SELECT 1 FROM pg_attribute a
 WHERE a.attrelid=${quote('control.' + table.name)}::regclass AND a.attname=${quote(column.name)} AND NOT a.attisdropped
 AND a.attnotnull=${column.notNull ? 'true' : 'false'} AND replace(format_type(a.atttypid,a.atttypmod),' ','')=${quote(column.getSQLType().replaceAll(' ', ''))})`,
  ),
);

const triggers = [
  ...tables.map((table) => [
    table,
    `${table}_guard`,
    table === 'notification_completion_disposition_signer_installation'
      ? 'guard_notification_completion_disposition_signer_installation'
      : {
          notification_completion_source: 'guard_notification_completion_source',
          notification_completion_attempt: 'guard_notification_completion_attempt',
          notification_completion_disposition_signing: 'guard_notification_completion_signing',
          notification_completion_disposition: 'guard_notification_completion_disposition',
        }[table],
    31,
    false,
  ]),
  ...tables.map((table) => [
    table,
    table === 'notification_completion_disposition_signer_installation'
      ? 'notification_completion_disposition_signer_truncate_guard'
      : `${table}_truncate`,
    table === 'notification_completion_disposition_signer_installation'
      ? 'guard_notification_completion_disposition_signer_truncate'
      : 'reject_notification_completion_truncate',
    34,
    false,
  ]),
  [
    'notification_completion_source',
    'notification_completion_source_first',
    'complete_notification_completion_source',
    5,
    true,
  ],
  [
    'notification_completion_disposition',
    'notification_completion_disposition_complete',
    'complete_notification_completion_disposition',
    5,
    true,
  ],
  ...['notification_source_inbox', 'notification_source_cursor'].flatMap((table) => [
    [table, `${table}_effect_guard`, 'guard_notification_occurrence_effect', 31, false],
    [table, `${table}_effect_pair`, 'check_notification_occurrence_effect_pair', 21, true],
    [table, `${table}_truncate_guard`, 'guard_notification_occurrence_truncate', 34, false],
  ]),
  ['work_item', 'work_item_lifecycle', 'enforce_work_item_lifecycle', 31, false],
  [
    'work_item',
    'work_item_effect_receipt',
    'check_work_item_effect_receipt',
    21,
    true,
    `(current_setting('openpc.action_intent_id'::text, true) = ANY (${pgArray(['ACT-WORK_ITEMS_CREATE_RESOURCE-V1', 'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1', 'ACT-OPERATIONS_UPDATE_CLAIM-V1', 'ACT-OPERATIONS_UPDATE_COMPLETE-V1'])}))`,
  ],
  [
    'work_item',
    'notification_completion_remediation_complete',
    'complete_notification_completion_remediation',
    5,
    true,
    `((openpc.current_action_intent_id() = 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'::text) OR ((new.kind = 'REMEDIATION'::control.work_item_kind) AND (openpc.current_action_intent_id() IS DISTINCT FROM 'ACT-WORK_ITEMS_CREATE_RESOURCE-V1'::text)))`,
  ],
];
const triggerChecks = triggers.map(
  ([
    table,
    name,
    fn,
    type,
    deferred,
    when,
  ]) => `NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=${quote('control.' + table)}::regclass
 AND t.tgname=${quote(name)} AND t.tgfoid=to_regprocedure(${quote('openpc.' + fn + '()')}) AND t.tgtype=${type}
 AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgnargs=0 AND octet_length(t.tgargs)=0 AND t.tgattr=''::int2vector
 AND t.tgdeferrable=${deferred ? 'true' : 'false'} AND t.tginitdeferred=${deferred ? 'true' : 'false'}
 AND ${when ? expression("split_part(split_part(pg_get_triggerdef(t.oid,false),' WHEN (',2),') EXECUTE FUNCTION ',1)") + '=' + quote(normalize(when)) : 't.tgqual IS NULL'})`,
);

const scopedTables = [...tables, 'notification_source_inbox', 'notification_source_cursor'];
const policyChecks = scopedTables.flatMap((table) =>
  [
    ['participant_isolation', true, 'openpc.matches_participant(participant_id)'],
    [
      'privacy_domain_isolation',
      false,
      '(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))',
    ],
  ].map(
    ([
      name,
      permissive,
      expr,
    ]) => `NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid=${quote('control.' + table)}::regclass
 AND p.polname=${quote(name)} AND p.polcmd='*' AND p.polpermissive=${permissive ? 'true' : 'false'}
 AND (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid=ANY(p.polroles))=ARRAY['openpc_control_reader','openpc_control_runtime','openpc_control_worker']::text[]
 AND pg_get_expr(p.polqual,p.polrelid)=${quote(expr)} AND pg_get_expr(p.polwithcheck,p.polrelid)=${quote(expr)})`,
  ),
);

const nonTriggerFunctions = ownedFunctions.filter((f) => f.returns !== 'trigger');
export const notificationCompletionDispositionRegistrationSql = `
${ownedSql}
${tables
  .map(
    (table) => `ALTER TABLE control.${table} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${table} FROM PUBLIC,${roles.join(',')};
GRANT SELECT ON control.${table} TO openpc_control_runtime;`,
  )
  .join('\n')}
GRANT INSERT,UPDATE ON control.notification_completion_disposition_signer_installation TO openpc_control_owner;
DROP POLICY IF EXISTS notification_completion_signer_installer ON control.notification_completion_disposition_signer_installation;
CREATE POLICY notification_completion_signer_installer ON control.notification_completion_disposition_signer_installation TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
GRANT INSERT ON ${tables
  .slice(1)
  .map((t) => 'control.' + t)
  .join(',')} TO openpc_control_runtime;
${Object.entries(runtimeUpdates)
  .map(
    ([table, columns]) =>
      `GRANT UPDATE(${columns.join(',')}) ON control.${table} TO openpc_control_runtime;`,
  )
  .join('\n')}
REVOKE ALL ON FUNCTION ${ownedFunctions.map((f) => 'openpc.' + f.signature).join(',')} FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ${nonTriggerFunctions.map((f) => 'openpc.' + f.signature).join(',')} TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.assert_notification_completion_disposition_shared_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF current_setting('row_security')<>'on' OR current_setting('session_replication_role')<>'origin'
 OR ${functionChecks.join('\n OR ')}
 OR ${triggerChecks.join('\n OR ')}
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-SHARED-OWNER'; END IF;
 PERFORM openpc.assert_notification_completion_admission_owner();
 IF ${constraints.concat(checkConstraints, generatedChecks, columnChecks, policyChecks).join('\n OR ')}
 OR EXISTS(SELECT 1 FROM unnest(${textArray([...scopedTables, 'work_item', 'outbox_event'])}) n(name)
  WHERE NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.oid=to_regclass('control.'||n.name)
   AND r.rolname='openpc_control_owner' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
   AND NOT c.relispartition AND NOT EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid)))
 OR EXISTS(SELECT 1 FROM unnest(${textArray(scopedTables)}) n(name) WHERE
  (SELECT count(*) FROM pg_policy WHERE polrelid=to_regclass('control.'||n.name))<>(CASE WHEN n.name='notification_completion_disposition_signer_installation' THEN 3 ELSE 2 END))
 OR NOT EXISTS(SELECT 1 FROM pg_policy p WHERE p.polrelid='control.notification_completion_disposition_signer_installation'::regclass
  AND p.polname='notification_completion_signer_installer' AND p.polcmd='*' AND p.polpermissive AND p.polroles=ARRAY['openpc_control_owner'::regrole::oid]
  AND pg_get_expr(p.polqual,p.polrelid)='(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))'
  AND pg_get_expr(p.polwithcheck,p.polrelid)='(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))')
 OR NOT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid WHERE i.indrelid='control.notification_completion_disposition_signer_installation'::regclass
  AND c.relname='completion_signer_current_uq' AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
  AND i.indnatts=3 AND i.indnkeyatts=3 AND i.indexprs IS NULL AND pg_get_expr(i.indpred,i.indrelid)='(state = ''ACTIVE''::text)'
  AND pg_get_indexdef(i.indexrelid,1,true)='participant_id' AND pg_get_indexdef(i.indexrelid,2,true)='privacy_domain_id'
  AND pg_get_indexdef(i.indexrelid,3,true)='worker_installation_digest')
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-SHARED-SCHEMA'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(${textArray(scopedTables)}) n(name),aclexplode(coalesce((SELECT relacl FROM pg_class WHERE oid=to_regclass('control.'||n.name)),acldefault('r',(SELECT relowner FROM pg_class WHERE oid=to_regclass('control.'||n.name))))) a WHERE a.grantee=0)
 OR EXISTS(SELECT 1 FROM unnest(${textArray(tables)}) n(name),unnest(${textArray(roles)}) r(name)
  WHERE has_table_privilege(r.name,'control.'||n.name,'DELETE,TRUNCATE,TRIGGER,REFERENCES')
   OR (r.name<>'openpc_control_runtime' AND (has_table_privilege(r.name,'control.'||n.name,'INSERT,UPDATE') OR has_any_column_privilege(r.name,'control.'||n.name,'INSERT,UPDATE'))))
 OR EXISTS(SELECT 1 FROM unnest(${textArray(tables)}) n(name) WHERE NOT has_table_privilege('openpc_control_runtime','control.'||n.name,'SELECT'))
 OR EXISTS(SELECT 1 FROM unnest(${textArray(tables.slice(1))}) n(name) WHERE NOT has_table_privilege('openpc_control_runtime','control.'||n.name,'INSERT'))
 ${Object.entries(runtimeUpdates)
   .map(
     ([table, columns]) =>
       `OR EXISTS(SELECT 1 FROM unnest(${textArray(columns)}) n(name) WHERE NOT has_column_privilege('openpc_control_runtime','control.${table}',n.name,'UPDATE'))`,
   )
   .join('\n ')}
 OR EXISTS(SELECT 1 FROM unnest(${textArray(nonTriggerFunctions.map((f) => 'openpc.' + f.signature))}) n(signature) WHERE NOT has_function_privilege('openpc_control_runtime',n.signature,'EXECUTE'))
 OR has_any_column_privilege('openpc_control_runtime','control.notification_completion_disposition_signer_installation','INSERT,UPDATE')
 OR has_any_column_privilege('openpc_control_runtime','control.notification_completion_disposition','UPDATE')
 ${Object.entries(runtimeUpdates)
   .map(
     ([
       table,
       columns,
     ]) => `OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid='control.${table}'::regclass AND a.attnum>0 AND NOT a.attisdropped
  AND a.attname<>ALL(${textArray(columns)}) AND has_column_privilege('openpc_control_runtime',a.attrelid,a.attnum,'UPDATE'))`,
   )
   .join('\n ')}
 OR EXISTS(SELECT 1 FROM unnest(${textArray(ownedFunctions.map((f) => 'openpc.' + f.signature))}) n(signature),
  aclexplode(coalesce((SELECT proacl FROM pg_proc WHERE oid=to_regprocedure(n.signature)),acldefault('f',(SELECT proowner FROM pg_proc WHERE oid=to_regprocedure(n.signature))))) a
  WHERE a.grantee=0 OR (a.is_grantable AND a.grantee<>'openpc_control_owner'::regrole) OR a.grantee NOT IN ('openpc_control_owner'::regrole,'openpc_control_runtime'::regrole))
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-SHARED-PRIVILEGES'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.assert_notification_completion_disposition_shared_owner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.assert_notification_completion_disposition_shared_owner() TO openpc_control_runtime;
SELECT openpc.assert_notification_completion_disposition_shared_owner();
`;
