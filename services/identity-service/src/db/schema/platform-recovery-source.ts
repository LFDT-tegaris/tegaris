import { sql, type SQL, type SQLWrapper } from 'drizzle-orm';
import { pgPolicy, PgDialect, getTableConfig, type PgTable } from 'drizzle-orm/pg-core';
import { controlOwnerRole } from './common.js';
import {
  platformRecoveryLeaseActions,
  platformRecoveryContinuationLeaseActions,
} from '../../domain/platform-recovery-lease.js';
import { discoveryCertificateRecoveryResumeActions } from '../../domain/discovery-certificate-recovery.js';

/** Keep the same private read predicate in its own native statement. Otherwise
 * PostgreSQL expands receiving-history RLS through every unrelated Root query.
 * The policy supplies the actual row; no caller-provided readiness is used. */
type HistoryOwnerTable =
  | 'mfa_challenge'
  | 'idempotency_record'
  | 'mutation_evidence'
  | 'outbox_event'
  | 'authority_envelope'
  | 'assignment'
  | 'identity_envelope_proposal'
  | 'mutation_candidate';
const historyOwnerDefinition = Symbol('platform-recovery-history-owner-definition');
type HistoryOwnerDefinition = {
  tableName: HistoryOwnerTable | 'approval_request';
  functionName: string;
  predicate: SQL;
  stable?: boolean;
};
type HistoryOwnerPolicy = ReturnType<typeof pgPolicy> & {
  [historyOwnerDefinition]?: HistoryOwnerDefinition;
};

/** Preserve the approval row's statement snapshot while keeping its two
 * recursive provenance reads out of the surrounding query plan. */
export function approvalHistoryOwnerLeafPolicy(complete: ReturnType<typeof pgPolicy>) {
  const names = new Map([
    [
      'root_expiry_pending_effect_source_read',
      'platform_history_approval_request_pending_effect_read',
    ],
    [
      'platform_prepare_approval_continuation_history_read',
      'platform_history_approval_request_case_read',
    ],
  ]);
  const functionName = names.get(complete.name);
  if (
    !functionName ||
    complete.for !== 'select' ||
    (complete.as !== undefined && complete.as !== 'permissive') ||
    complete.withCheck ||
    !complete.using ||
    !Array.isArray(complete.to) ||
    complete.to.length !== 1 ||
    complete.to[0] !== controlOwnerRole
  )
    throw new Error('Invalid approval history leaf');
  const leaf: HistoryOwnerPolicy = pgPolicy(complete.name, {
    as: complete.as,
    for: 'select',
    to: [controlOwnerRole],
    using: sql`openpc.${sql.raw(functionName)}(to_jsonb("approval_request"))`,
  });
  Object.defineProperty(leaf, historyOwnerDefinition, {
    value: Object.freeze({
      tableName: 'approval_request',
      functionName,
      predicate: complete.using,
      stable: true,
    }),
  });
  return leaf;
}

export function historyOwnerLeafPolicy(
  complete: ReturnType<typeof pgPolicy>,
  tableName: HistoryOwnerTable,
  rowEligible: SQL,
) {
  if (
    complete.for !== 'select' ||
    complete.withCheck ||
    !complete.using ||
    !Array.isArray(complete.to) ||
    complete.to.length !== 1 ||
    complete.to[0] !== controlOwnerRole ||
    ![
      'platform_prepare_approval_resume_history_read',
      'platform_prepare_approval_continuation_history_read',
      'platform_recovery_uneffected_effect_read',
      'root_expiry_admin_outbox_source_read',
      'root_expiry_admin_installation_receipt_read',
      'root_expiry_pending_preparation_outbox_source_read',
    ].includes(complete.name) ||
    (complete.name === 'root_expiry_pending_preparation_outbox_source_read' &&
      tableName !== 'outbox_event')
  )
    throw new Error('Invalid private Platform recovery history leaf');
  const suffix =
    complete.name === 'root_expiry_pending_preparation_outbox_source_read'
      ? 'pending_preparation'
      : complete.name === 'root_expiry_admin_outbox_source_read'
        ? 'root_source'
        : complete.name === 'root_expiry_admin_installation_receipt_read'
          ? 'root_installation'
          : complete.name === 'platform_prepare_approval_resume_history_read'
            ? 'resume'
            : complete.name === 'platform_recovery_uneffected_effect_read'
              ? 'uneffected'
              : 'case';
  const functionName = 'platform_history_' + tableName + '_' + suffix + '_read';
  const leaf: HistoryOwnerPolicy = pgPolicy(complete.name, {
    for: 'select',
    to: [controlOwnerRole],
    using: sql`case when (${rowEligible}) then openpc.${sql.raw(functionName)}(${sql.raw('to_jsonb("' + tableName + '")')}) else false end`,
  });
  Object.defineProperty(leaf, historyOwnerDefinition, {
    value: Object.freeze({ tableName, functionName, predicate: complete.using }),
  });
  return leaf;
}

/** Compile the owning schema's exact full predicate, rather than maintaining a
 * second authorization model. Builtin scalar preambles remain fail closed until
 * all table types exist and the owning security tail installs the complete body. */
export function platformRecoveryApprovalOwnerReadDefinitions(table: PgTable) {
  const config = getTableConfig(table);
  return config.policies.flatMap((policy) => {
    const definition = (policy as HistoryOwnerPolicy)[historyOwnerDefinition];
    if (!definition) return [];
    if (config.schema !== 'control' || config.name !== definition.tableName)
      throw new Error('Foreign history leaf row owner');
    const compiled = new PgDialect().sqlToQuery(definition.predicate);
    if (compiled.params.length) throw new Error('Unbound history leaf predicate parameters');
    const qualified = '"control"."' + config.name + '".',
      unqualified = '"' + config.name + '".';
    if (!compiled.sql.includes(qualified) && !compiled.sql.includes(unqualified))
      throw new Error('Missing actual history leaf row binding');
    const predicate = compiled.sql.replaceAll(qualified, 'r.').replaceAll(unqualified, 'r.');
    const header =
      'CREATE OR REPLACE FUNCTION openpc.' +
      definition.functionName +
      '(p_row jsonb)\nRETURNS boolean LANGUAGE plpgsql ' +
      (definition.stable ? 'STABLE' : 'VOLATILE') +
      ' SECURITY INVOKER SET search_path=pg_catalog,control SET row_security=on AS $$\n';
    const grants =
      'REVOKE ALL ON FUNCTION openpc.' +
      definition.functionName +
      '(jsonb) FROM PUBLIC;\nGRANT EXECUTE ON FUNCTION openpc.' +
      definition.functionName +
      '(jsonb) TO openpc_control_owner;\n';
    const preamble = header + 'BEGIN RETURN false; END $$;\n' + grants;
    // Reject an unrelated pending-effect row before planning its full history.
    // A matching binding still has to satisfy the complete owning predicate.
    const pendingEffect =
      definition.functionName === 'platform_history_approval_request_pending_effect_read';
    const pendingDeclarations = pendingEffect
      ? 'candidate_resource uuid; pending_document jsonb; binding_found boolean:=false;'
      : '';
    const pendingPrefilter = pendingEffect
      ? ` IF (r.subject_type='CONFIGURATION_CANDIDATE'
  AND openpc.matches_participant(r.participant_id) AND openpc.matches_privacy(r.privacy_domain_id)
  AND openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  AND current_setting('openpc.local_qa_runtime',true) IS NOT DISTINCT FROM '1') IS NOT TRUE THEN RETURN false; END IF;
 <<candidate_binding>>
 FOR candidate_resource IN SELECT c.resource_id FROM control.mutation_candidate c
  WHERE c.participant_id=r.participant_id AND c.privacy_domain_id=r.privacy_domain_id
   AND c.mutation_candidate_id=r.subject_id LOOP
  FOR pending_document IN SELECT pending.candidate FROM control.platform_scope_replacement pending
   WHERE pending.participant_id=r.participant_id AND pending.privacy_domain_id=r.privacy_domain_id
    AND pending.state='WITHDRAWING' AND pending.row_version=1 AND pending.superseded_by IS NULL
    AND num_nonnulls(pending.commit_operation_id,pending.commit_candidate_id,pending.commit_approval_id,pending.readiness_digest,pending.committed_at)=0 LOOP
   IF EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(pending_document->'administrators')='array'
       THEN pending_document->'administrators' ELSE '[]'::jsonb END) administrator
      WHERE candidate_resource::text=administrator->>'envelopeId') THEN
    binding_found:=true; EXIT candidate_binding;
   END IF;
  END LOOP;
 END LOOP;
 IF NOT binding_found THEN RETURN false; END IF;
`
      : '';
    // Avoid planning historical business joins when no eligible source exists.
    // A present source still passes through the complete owning predicate below.
    const uneffectedReceiptPrefilter =
      definition.functionName === 'platform_history_idempotency_record_uneffected_read'
        ? ` IF NOT EXISTS(SELECT 1 FROM control.platform_recovery_enrollment source
  WHERE source.participant_id=r.participant_id AND source.privacy_domain_id=r.privacy_domain_id
   AND source.source_purpose='ROOT_EXPIRY_RECOVERY' AND source.document->>'schemaVersion'='2'
   AND source.document->>'schema'='pc.identity.platform-recovery-enrollment'
   AND jsonb_typeof(source.document->'uneffectedPredecessor')='object'
   AND source.document#>>'{uneffectedPredecessor,schema}'='pc.identity.platform-expired-uneffected-recovery'
   AND source.document#>>'{uneffectedPredecessor,schemaVersion}'='1'
   AND source.state='ACTIVE' AND source.row_version=1
   AND source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
   AND source.valid_from<=clock_timestamp() AND source.valid_until>clock_timestamp())
 THEN RETURN false; END IF;
`
        : '';
    const body =
      header +
      'DECLARE r control.' +
      config.name +
      ';' +
      pendingDeclarations +
      "\nBEGIN\n IF p_row IS NULL OR jsonb_typeof(p_row)<>'object' THEN RETURN false; END IF;\n r:=jsonb_populate_record(NULL::control." +
      config.name +
      ',p_row);\n IF to_jsonb(r) IS DISTINCT FROM p_row THEN RETURN false; END IF;\n' +
      pendingPrefilter +
      uneffectedReceiptPrefilter +
      ' RETURN coalesce((' +
      predicate +
      '),false);\nEXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_datetime_format THEN RETURN false;\nEND $$;\n' +
      grants;
    return [
      {
        tableName: config.name,
        functionName: definition.functionName,
        predicate: definition.predicate,
        preamble,
        body,
      },
    ];
  });
}

/** Installation validation only. The uncommitted enrollment and all validation
 * share one transaction; a rejected source rolls back the provisional trust.
 * No application role, unrelated identity or mutation is admitted here. */
export function platformRecoveryInstallationSourcePolicies(
  participantId: SQLWrapper,
  identity: SQLWrapper,
  kind: 'principal' | 'credential' | 'assignment' | 'envelope' | 'role',
  lock = true,
) {
  const signer = sql`jsonb_build_array(enrollment.document->'recoveryPrincipal') || (enrollment.document->'custodians')`;
  const administrators = sql`case when enrollment.source_purpose in ('ROOT_EXPIRY_RECOVERY','ROOT_EXPIRY_RECOVERY_CONTINUATION','PENDING_ADMINISTRATION_EXPIRY_RECOVERY')
    then enrollment.document#>'{source,originalAdministrators}' else replacement.candidate->'administrators' end`;
  const match =
    kind === 'principal'
      ? sql`(exists(select 1 from jsonb_array_elements(${signer}) actor where actor->>'principalId'=${identity}::text)
          or exists(select 1 from jsonb_array_elements(${administrators}) actor where actor->>'principalId'=${identity}::text)
          or (enrollment.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
            and enrollment.document#>>'{certificateRecovery,workloadPrincipalId}'=${identity}::text))`
      : kind === 'credential'
        ? sql`(exists(select 1 from jsonb_array_elements(${signer}) actor where actor->>'credentialId'=${identity}::text)
          or (enrollment.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
            and (enrollment.document#>>'{certificateRecovery,predecessorCredentialId}'=${identity}::text
              or enrollment.document#>>'{certificateRecovery,successorCredentialId}'=${identity}::text)))`
        : sql`exists(select 1 from jsonb_array_elements(${administrators}) actor
            where actor->>${sql.raw(kind === 'assignment' ? "'assignmentId'" : kind === 'role' ? "'roleId'" : "'envelopeId'")}=${identity}::text)`;
  const actionContext =
    kind === 'role'
      ? sql`openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'`
      : sql`openpc.current_action_intent_id() in ('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')`;
  const discoveryActions = sql.join(
    discoveryCertificateRecoveryResumeActions.map((action) => sql`${sql.raw("'" + action + "'")}`),
    sql`, `,
  );
  const continuationActions = sql.join(
    platformRecoveryContinuationLeaseActions.map((action) => sql`${sql.raw("'" + action + "'")}`),
    sql`, `,
  );
  const expiryActions = sql.join(
    platformRecoveryContinuationLeaseActions.map((action) => sql`${sql.raw("'" + action + "'")}`),
    sql`, `,
  );
  const source = (context: SQL) => sql`openpc.matches_participant(${participantId})
    and exists(select 1 from control.platform_recovery_enrollment enrollment
      left join control.platform_scope_replacement replacement on replacement.replacement_id=enrollment.expired_replacement_id
        and replacement.participant_id=enrollment.participant_id and replacement.privacy_domain_id=enrollment.privacy_domain_id
        and replacement.state='COMMITTED'
      where enrollment.participant_id=${participantId} and openpc.matches_privacy(enrollment.privacy_domain_id)
        and ${context}
        and enrollment.state='ACTIVE' and enrollment.row_version=1
        and openpc.platform_recovery_installation_source_current(enrollment.enrollment_id)
        and enrollment.valid_from<=clock_timestamp() and enrollment.valid_until>clock_timestamp() and ${match})`;
  return [
    pgPolicy('platform_recovery_installation_source_read', {
      for: 'select',
      to: [controlOwnerRole],
      using: source(sql`(${actionContext}
        or (enrollment.document->>'schema'='pc.identity.discovery-certificate-recovery-enrollment'
          and enrollment.document->>'schemaVersion'='2'
          and openpc.current_action_intent_id() in (${discoveryActions}))
        or (enrollment.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' and enrollment.document->>'schemaVersion'='3'
          and enrollment.document->>'schema'='pc.identity.platform-recovery-enrollment'
          and enrollment.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
          and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
          and openpc.current_action_intent_id() in (${continuationActions}))
        or (enrollment.source_purpose='ROOT_EXPIRY_RECOVERY' and enrollment.document->>'schemaVersion'='2'
          and enrollment.document->>'schema'='pc.identity.platform-recovery-enrollment'
          and enrollment.document#>>'{uneffectedPredecessor,schema}'='pc.identity.platform-expired-uneffected-recovery'
          and enrollment.document#>>'{uneffectedPredecessor,schemaVersion}'='1'
          and enrollment.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
          and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
          and openpc.current_action_intent_id() in (${continuationActions}))
        or (enrollment.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and enrollment.document->>'schemaVersion'='4'
          and enrollment.document->>'schema'='pc.identity.platform-recovery-enrollment'
          and enrollment.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
          and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
          and openpc.current_action_intent_id() in (${expiryActions})))`),
    }),
    ...(lock
      ? [
          pgPolicy('platform_recovery_installation_source_lock', {
            for: 'update',
            to: [controlOwnerRole],
            using: source(actionContext),
            withCheck: sql`false`,
          }),
        ]
      : []),
  ];
}

/** Read-only historical witness, exact to a provisional schema3 installation.
 * It does not require or manufacture a live business lease. The Root comparison
 * is a leaf invoker statement: a Root lock may read these same witnesses. */
export function platformRecoveryContinuationSourcePolicy(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  match: SQL,
  name = 'platform_recovery_continuation_history_read',
) {
  return pgPolicy(name, {
    for: 'select',
    to: [controlOwnerRole],
    using: sql`openpc.matches_participant(${participantId}) and openpc.matches_privacy(${privacyDomainId})
      and exists(select 1 from control.platform_recovery_enrollment source
        where source.participant_id=${participantId} and source.privacy_domain_id=${privacyDomainId}
          and openpc.platform_recovery_continuation_root_matches(source.platform_context_id,source.participant_id,source.root_epoch,source.root_revision)
          and ((source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' and source.document->>'schemaVersion'='3')
            or (source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='4')
            or (source.source_purpose='ROOT_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='2'
              and jsonb_typeof(source.document->'uneffectedPredecessor')='object'
              and source.document#>>'{uneffectedPredecessor,schema}'='pc.identity.platform-expired-uneffected-recovery'
              and source.document#>>'{uneffectedPredecessor,schemaVersion}'='1'))
          and source.document->>'schema'='pc.identity.platform-recovery-enrollment' and source.state='ACTIVE' and source.row_version=1
          and source.document->>'assurance'='LOCAL_QA_VIRTUAL_AUTHENTICATOR'
          and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'
          and source.valid_from<=clock_timestamp() and source.valid_until>clock_timestamp()
          and openpc.current_action_intent_id() in (${sql.join(
            platformRecoveryContinuationLeaseActions.map((a) => sql`${sql.raw("'" + a + "'")}`),
            sql`, `,
          )})
          and (${match}))`,
  });
}

export function platformRecoveryContinuationHistoryPolicy(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  recoveryId: SQLWrapper,
) {
  return platformRecoveryContinuationSourcePolicy(
    participantId,
    privacyDomainId,
    sql`coalesce(source.document#>>'{source,continuation,recoveryId}',source.document#>>'{source,pendingExpiry,preparation,recoveryId}',source.document#>>'{uneffectedPredecessor,recoveryId}')=${recoveryId}::text`,
  );
}

/** Exact old partial-effect observation under installed expiry-recovery trust.
 * This permits no mutation or actor grant and remains readable after supersession. */
export function platformRecoveryPendingExpiryEffectPolicy(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  match: SQL,
) {
  const actions = sql.join(
    platformRecoveryLeaseActions.map((action) => sql`${sql.raw("'" + action + "'")}`),
    sql`, `,
  );
  return platformRecoveryContinuationSourcePolicy(
    participantId,
    privacyDomainId,
    sql`((source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='4')
        or (source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION' and source.document->>'schemaVersion'='3'
          and source.document#>>'{source,activatedHandoff,schemaVersion}'='1'))
      and (openpc.current_action_intent_id() in (${actions})
        or (openpc.current_action_intent_id()='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
          and not (source.document#>'{source}' ? 'activatedHandoff')
          and exists(select 1 from control.platform_recovery_case lease
            where lease.participant_id=source.participant_id and lease.privacy_domain_id=source.privacy_domain_id
              and lease.enrollment_id=source.enrollment_id
              and lease.enrollment_revision=source.row_version and lease.enrollment_digest=source.document_digest
              and lease.state='ACTIVE' and lease.valid_from<=clock_timestamp() and lease.valid_until>clock_timestamp()
              and lease.intent->>'schema'='pc.identity.platform-recovery-intent'
              and lease.intent ? 'approvalContinuation'
              and lease.intent->'pendingExpiry'=source.document#>'{source,pendingExpiry}'
              and lease.activation_operation_id is not null
              and lease.activation_evidence_digest=sha256(lease.activation_evidence_cbor)
              and octet_length(lease.activation_cose)>0
              and jsonb_typeof(lease.lease_bindings)='array' and jsonb_array_length(lease.lease_bindings)=2
)))
      and exists(select 1 from jsonb_array_elements(coalesce(source.document#>'{source,activatedHandoff,administrators}',source.document#>'{source,pendingExpiry,administrators}')) partial_effect
        where (${match}))`,
    'platform_recovery_pending_expiry_effect_read',
  );
}

/** Observe the exact predecessor targets before admitting an unused handoff.
 * This is owner-only metadata access, independent of the consuming absence check. */
export function platformRecoveryUneffectedEffectPolicy(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  match: SQL,
  rowEligible?: SQL,
  ownerTable?: HistoryOwnerTable,
) {
  const bounded = platformRecoveryContinuationSourcePolicy(
    participantId,
    privacyDomainId,
    sql`source.source_purpose='ROOT_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='2'
      and exists(select 1 from control.platform_recovery_case historical
        cross join lateral jsonb_array_elements(historical.intent#>'{preparation,administrators}') uneffected_administrator
        where historical.participant_id=source.participant_id and historical.privacy_domain_id=source.privacy_domain_id
          and historical.recovery_id::text=source.document#>>'{uneffectedPredecessor,recoveryId}'
          and historical.enrollment_id::text=source.document#>>'{uneffectedPredecessor,enrollmentId}'
          and historical.state='EXPIRED' and historical.valid_until<=source.valid_from
          and historical.intent_digest=sha256(convert_to(openpc.signing_canonical_json(historical.intent),'UTF8'))
          and 'sha256:'||encode(historical.intent_digest,'hex')=source.document#>>'{uneffectedPredecessor,intentDigest}'
          and historical.activation_operation_id::text=source.document#>>'{uneffectedPredecessor,activationOperationId}'
          and historical.activation_evidence_digest=sha256(historical.activation_evidence_cbor)
          and 'sha256:'||encode(historical.activation_evidence_digest,'hex')=source.document#>>'{uneffectedPredecessor,activationReceiptDigest}'
          and octet_length(historical.activation_cose)>0
          and historical.intent#>>'{preparation,replacementId}'=source.document#>>'{uneffectedPredecessor,replacementId}'
          and 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(historical.intent->'preparation'),'UTF8')),'hex')=source.document#>>'{uneffectedPredecessor,preparationDigest}'
          and (${match}))`,
    'platform_recovery_uneffected_effect_read',
  );
  if (
    ownerTable &&
    (!rowEligible ||
      ![
        'authority_envelope',
        'assignment',
        'identity_envelope_proposal',
        'mutation_candidate',
        'idempotency_record',
      ].includes(ownerTable))
  )
    throw new Error('Invalid private unused-handoff attempt reader');
  return ownerTable ? historyOwnerLeafPolicy(bounded, ownerTable, rowEligible!) : bounded;
}

/** A closed per-hop historical shape; the native owner authenticates every edge. */
export function platformRecoveryApprovalHistoryIntent(intent: SQLWrapper, recoveryId: SQLWrapper) {
  return sql`(not (${intent} ? 'approvalContinuation') or (
    ${intent}#>>'{approvalContinuation,schema}'='pc.identity.platform-prepare-approval-continuation'
    and ${intent}#>>'{approvalContinuation,schemaVersion}'='1'
    and ${intent}#>>'{approvalContinuation,recoveryId}'<>${recoveryId}::text
    and ${intent}#>>'{approvalContinuation,recoveryId}' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and ${intent}#>>'{approvalContinuation,candidateId}' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and ${intent}#>>'{approvalContinuation,approvalId}' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    and ${intent}#>>'{approvalContinuation,candidateDigest}'='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(${intent}->'preparation'),'UTF8')),'hex')
    and ${intent}#>>'{approvalContinuation,attempt}' ~ '^[1-9][0-9]{0,19}$'
  ))`;
}

/** Only the new signed source can read a different enrollment's closed case.
 * This exposes exact historical rows to the owner; it does not grant authority. */
export function platformRecoveryApprovalHistoryLink(fields: {
  enrollmentId: SQLWrapper;
  enrollmentRevision: SQLWrapper;
  enrollmentDigest: SQLWrapper;
  recoveryId: SQLWrapper;
  state: SQLWrapper;
  validUntil: SQLWrapper;
  intentDigest: SQLWrapper;
}) {
  return sql`((not (source.document#>'{source}' ? 'closedApproval')
    and ${fields.enrollmentId}=source.enrollment_id
    and ${fields.enrollmentRevision}=source.row_version and ${fields.enrollmentDigest}=source.document_digest
    and ${fields.state}='EXPIRED' and ${fields.validUntil}<=clock_timestamp())
   or (source.document#>>'{source,closedApproval,schema}'='pc.identity.closed-platform-approval-source'
    and source.document#>>'{source,closedApproval,schemaVersion}'='1'
    and ${fields.enrollmentId}::text=source.document#>>'{source,closedApproval,enrollmentId}'
    and ${fields.enrollmentId}<>source.enrollment_id
    and 'sha256:'||encode(${fields.enrollmentDigest},'hex')=source.document#>>'{source,closedApproval,enrollmentDigest}'
    and ${fields.recoveryId}::text=source.document#>>'{source,closedApproval,approval,recoveryId}'
    and 'sha256:'||encode(${fields.intentDigest},'hex')=source.document#>>'{source,closedApproval,approval,intentDigest}'
    and ${fields.state} in ('REVOKED','EXPIRED')
    and ${fields.state}=source.document#>>'{source,closedApproval,closure,state}'))`;
}

/** Exact historical preparation and its first prospective child. This is
 * read-only owner evidence; fresh custody and current authority are separate. */
export function platformRecoveryApprovalContinuationSourcePolicy(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  match: SQL,
  name = 'platform_prepare_approval_continuation_history_read',
  rowEligible?: SQL,
  ownerTable?: HistoryOwnerTable,
) {
  const complete = platformRecoveryContinuationSourcePolicy(
    participantId,
    privacyDomainId,
    sql`source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY'
      and source.document->>'schemaVersion'='4'
      and exists(select 1 from control.platform_recovery_case historical
        where historical.participant_id=source.participant_id
          and historical.privacy_domain_id=source.privacy_domain_id
          and ${platformRecoveryApprovalHistoryLink({
            enrollmentId: sql`historical.enrollment_id`,
            enrollmentRevision: sql`historical.enrollment_revision`,
            enrollmentDigest: sql`historical.enrollment_digest`,
            recoveryId: sql`historical.recovery_id`,
            state: sql`historical.state`,
            validUntil: sql`historical.valid_until`,
            intentDigest: sql`historical.intent_digest`,
          })}
          and historical.intent->'pendingExpiry'=source.document#>'{source,pendingExpiry}'
          and ${platformRecoveryApprovalHistoryIntent(sql`historical.intent`, sql`historical.recovery_id`)}
          and historical.intent_digest=sha256(convert_to(openpc.signing_canonical_json(historical.intent),'UTF8'))
          and historical.activation_operation_id is not null
          and historical.activation_evidence_digest=sha256(historical.activation_evidence_cbor)
          and octet_length(historical.activation_cose)>0
          and (${match}))`,
    name,
  );
  // CASE prevents an unrelated row from invoking the Source4/Root closure.
  // The full original private predicate still owns every eligible read.
  if (!rowEligible) return complete;
  const bounded = pgPolicy(name, {
    for: 'select',
    to: [controlOwnerRole],
    using: sql`case when (${rowEligible}) then (${complete.using!}) else false end`,
  });
  return ownerTable ? historyOwnerLeafPolicy(bounded, ownerTable, rowEligible) : bounded;
}

/** Exact immutable receiving-proof provenance for an expired resumed intent.
 * These owner SELECT policies authenticate stored links; they grant no lease. */
export function platformRecoveryApprovalResumeHistoryPolicy(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  match: SQL,
  rowEligible: SQL,
  ownerTable?: HistoryOwnerTable,
) {
  return platformRecoveryApprovalContinuationSourcePolicy(
    participantId,
    privacyDomainId,
    sql`exists(select 1 from control.mutation_candidate resume_candidate
      where resume_candidate.participant_id=historical.participant_id
        and resume_candidate.privacy_domain_id=historical.privacy_domain_id
        and resume_candidate.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE'
        and resume_candidate.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
        and resume_candidate.resource_type='participant' and resume_candidate.operation_class='UPDATE'
        and resume_candidate.expected_revision=0
        and resume_candidate.resource_id::text=historical.intent#>>'{preparation,replacementId}'
        and resume_candidate.candidate_document=historical.intent->'preparation'
        and resume_candidate.candidate_digest=sha256(convert_to(openpc.signing_canonical_json(resume_candidate.candidate_document),'UTF8'))
        and resume_candidate.maker_principal_id::text=historical.intent#>>'{preparation,administrators,0,principalId}'
        and resume_candidate.predecessor_candidate_id::text=historical.intent#>>'{approvalContinuation,candidateId}'
        and resume_candidate.predecessor_approval_id::text=historical.intent#>>'{approvalContinuation,approvalId}'
        and resume_candidate.idempotency_key=historical.intent#>>'{approvalContinuation,businessKey}'
        and resume_candidate.attempt=(historical.intent#>>'{approvalContinuation,attempt}')::numeric+1
        and resume_candidate.state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED')
        and resume_candidate.expires_at<=clock_timestamp() and resume_candidate.consumed_operation_id is null
        and resume_candidate.resume_operation_id is not null
        and resume_candidate.resume_request->>'command'='RESUME'
        and exists(select 1 from jsonb_array_elements(historical.lease_bindings) binding
          where binding->>'envelopeId'=resume_candidate.maker_authority_envelope_id::text
            and binding->>'assignmentId'=resume_candidate.maker_assignment_id::text
            and binding->>'principalId'=resume_candidate.maker_principal_id::text
            and binding->>'principalEpoch'=resume_candidate.maker_principal_epoch::text)
        and (${match}))`,
    'platform_prepare_approval_resume_history_read',
    rowEligible,
    ownerTable,
  );
}
