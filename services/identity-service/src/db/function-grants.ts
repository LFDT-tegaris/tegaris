/** Validate generated routine grants before writing a migration, then verify PostgreSQL's resolved signatures during migration. */
function splitList(value: string): string[] {
  let depth = 0;
  let start = 0;
  const result: string[] = [];
  for (let index = 0; index < value.length; index++) {
    if (value[index] === '(') depth++;
    if (value[index] === ')') depth--;
    if (depth < 0) throw new Error('Malformed function grant');
    if (value[index] === ',' && depth === 0) {
      result.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  if (depth !== 0) throw new Error('Malformed function grant');
  if (value.slice(start).trim()) result.push(value.slice(start).trim());
  return result;
}
const normalize = (value: string) =>
  value.replaceAll('"', '').replace(/\s+/gu, ' ').trim().toLowerCase();
const literal = (value: string) => `'${value.replaceAll("'", "''")}'`;
const intendedRoles: Record<string, readonly string[]> = {
  'openpc.platform_context_scoped_read_current(uuid,uuid)': [
    'openpc_control_owner',
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
    'openpc_control_reader',
    'openpc_control_worker',
  ],
  'openpc.platform_recovery_continuation_current(uuid,uuid,jsonb,jsonb)': [
    'openpc_control_owner',
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.require_platform_recovery_continuation_enrollment()': [],
  'openpc.platform_recovery_proposal_history_current(uuid,uuid,uuid,uuid)': [
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.platform_recovery_approval_resume_subject_visible(uuid,uuid,uuid,uuid,uuid)': [
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.assert_platform_recovery_approval_resume(control.mutation_candidate)': [
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.assert_handover_admission_candidate(control.mutation_candidate)': [
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.assert_discovery_preapproval_continuation(control.mutation_candidate)': [
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.guard_discovery_preapproval_target_claims()': ['openpc_control_owner'],
  'openpc.guard_discovery_preapproval_final()': [],
  'openpc.discovery_approval_resume_enrollments_compatible(uuid,uuid)': [
    'openpc_control_owner',
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.assert_discovery_approval_resume(control.mutation_candidate)': [
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.guard_discovery_approval_resume_target_claims()': ['openpc_control_owner'],
  'openpc.guard_discovery_approval_resume_final()': [],
  'openpc.guard_discovery_approval_resume_completed()': [],

  'openpc.workload_renewal_policy_projection(control.workload_renewal_policy)': [
    'openpc_control_runtime',
  ],
  'openpc.check_workload_renewal_policy_ancestors(control.workload_renewal_policy,control.audit_occurrence)':
    ['openpc_control_runtime'],
  'openpc.assert_workload_renewal_policy_receipt(control.audit_occurrence)': [
    'openpc_control_runtime',
  ],
  'openpc.revoke_identity_envelope_recovery_trust()': [
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.select_identity_envelope_recovery_trust()': [
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.admit_identity_envelope_recovery_trust(bytea,bytea)': [
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.check_identity_envelope_recovery_trust_admission(control.business_signing_key)': [
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
  ],
  'openpc.admit_notification_completion_phase(bytea,bytea,bytea)': ['openpc_control_runtime'],
  'openpc.require_notification_completion_disposition_authority(uuid,text)': [
    'openpc_control_runtime',
  ],
  'openpc.clear_notification_completion_phases()': ['openpc_control_runtime'],
  'openpc.notification_completion_phase_binding(uuid,text)': ['openpc_control_runtime'],
  'openpc.notification_completion_verified_receipt(uuid,text)': ['openpc_control_runtime'],
  'openpc.assert_notification_completion_admission_owner()': ['openpc_control_runtime'],
  'openpc.commit_fleet_fact_admission(bytea,bytea,bytea)': ['openpc_control_worker'],
  'openpc.commit_fleet_fact_admission_v2(bytea,bytea,bytea,text)': ['openpc_control_worker'],
  'openpc.begin_fleet_fact_delivery(bytea,bytea,bytea,text)': ['openpc_control_worker'],
  'openpc.fail_fleet_fact_delivery(bytea,bytea,bytea,text)': ['openpc_control_worker'],
  'openpc.require_fact_consumer_profile(text)': ['openpc_control_worker'],
  'openpc.notification_business_projection(control.notification)': ['openpc_control_runtime'],
  'openpc.assert_notification_receipt(control.audit_occurrence)': ['openpc_control_runtime'],
  'openpc.work_item_business_projection(control.work_item)': ['openpc_control_runtime'],
  'openpc.assert_work_item_receipt(control.audit_occurrence)': ['openpc_control_runtime'],
  'openpc.signing_canonical_json(jsonb)': [
    'openpc_control_runtime',
    'openpc_control_platform_runtime',
    'openpc_control_worker',
  ],
  'openpc.resolve_proved_oidc_identity(text,text,text)': ['openpc_identity_binding_resolver'],
  'openpc.check_signing_continuation_context(jsonb)': ['openpc_control_runtime'],
  'openpc.check_signing_continuation_snapshot(bytea,uuid,uuid,uuid,uuid,numeric,boolean)': [
    'openpc_control_runtime',
  ],
  'openpc.signing_operation_failure_preimage(uuid,text,uuid)': [
    'openpc_control_runtime',
    'openpc_control_worker',
  ],
};

/** PL/pgSQL scans the top-level THEN as the end of an IF condition; CASE expressions there need parentheses. */
export function verifyConditionCases(sql: string): void {
  for (const block of sql.matchAll(/\b(?:AS|DO)\s+\$(\w*)\$([\s\S]*?)\$\1\$/giu)) {
    const tokens =
      block[2]!.match(/'(?:''|[^'])*'|--[^\n]*|\/\*[\s\S]*?\*\/|[a-z_][a-z_0-9]*|[();]/giu) ?? [];
    let condition = false;
    let depth = 0;
    let prior = '';
    for (const raw of tokens) {
      if (raw.startsWith("'") || raw.startsWith('--') || raw.startsWith('/*')) continue;
      const token = raw.toUpperCase();
      if ((token === 'IF' && prior !== 'END') || token === 'ELSIF') {
        condition = true;
        depth = 0;
      } else if (condition) {
        if (token === '(') depth++;
        if (token === ')') depth--;
        if (token === 'CASE' && depth === 0)
          throw new Error('Unparenthesized CASE in generated IF condition');
        if (token === 'THEN' && depth === 0) condition = false;
      }
      prior = token;
    }
  }
}

function declaredFunctions(definitions: string): Set<string> {
  const declared = new Set<string>();
  for (const match of definitions.matchAll(
    /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w".]+)\s*\(([\s\S]*?)\)\s*RETURNS\b/giu,
  )) {
    const types = splitList(match[2]!).map((argument) => {
      const words = normalize(argument.replace(/\s+DEFAULT\s+[\s\S]*$/iu, '')).split(' ');
      if (['in', 'inout', 'variadic'].includes(words[0]!)) words.shift();
      // Generated owners always name parameters; argument-less routines have an empty list.
      if (words.length < 2) throw new Error(`Unnamed generated function argument: ${argument}`);
      return words.slice(1).join(' ');
    });
    declared.add(`${normalize(match[1]!)}(${types.join(',')})`);
  }
  return declared;
}

/** Generated DROP statements have explicit owned signatures. A historical
 * declaration no longer proves installation after its actual DROP. */
function functionDrops(definitions: string) {
  const events: { offset: number; kind: 'DROP'; signatures: string[] }[] = [];
  for (const match of definitions.matchAll(
    /^\s*DROP\s+FUNCTION\s+(?:IF\s+EXISTS\s+)?([^;]+);/gimu,
  )) {
    if (/\bCASCADE\s*$/iu.test(match[1]!)) throw new Error('Unsupported cascading function drop');
    const signatures = splitList(match[1]!.replace(/\s+RESTRICT\s*$/iu, '')).map((value) =>
      normalize(value).replace(/\s*([(),])\s*/gu, '$1'),
    );
    if (signatures.some((value) => !/^(?:openpc|control)\.[a-z_][a-z_0-9]*\([^;]*\)$/u.test(value)))
      throw new Error('Unsupported generated function drop signature');
    events.push({ offset: match.index, kind: 'DROP', signatures });
  }
  return events;
}
function installedFunctions(definitions: string): Set<string> {
  const events: { offset: number; kind: 'CREATE' | 'DROP'; signatures: string[] }[] =
    functionDrops(definitions);
  for (const match of definitions.matchAll(
    /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([\w".]+)\s*\(([\s\S]*?)\)\s*RETURNS\b/giu,
  ))
    events.push({
      offset: match.index,
      kind: 'CREATE',
      signatures: [...declaredFunctions(match[0])],
    });
  const installed = new Set<string>();
  for (const event of events.sort((left, right) => left.offset - right.offset))
    for (const signature of event.signatures)
      if (event.kind === 'CREATE') installed.add(signature);
      else installed.delete(signature);
  return installed;
}

/** Identity migrations share schemas with other owners. Replacing Identity
 * grants must not revoke a previously installed Control/Policy owner's grants. */
export function scopeFunctionRevocations(sql: string, priorDefinitions: string): string {
  return sql.replaceAll(
    'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM',
    (_reset, offset: number) => {
      const declared = [
        ...installedFunctions(priorDefinitions + '\n' + sql.slice(0, offset)),
      ].sort();
      if (declared.length === 0) throw new Error('No owned functions for privilege projection');
      return `REVOKE ALL ON FUNCTION ${declared.join(',')} FROM`;
    },
  );
}

/** Reproject only a previous complete owned reset in a verified unapplied
 * migration. Its DDL, late explicit revocations, grants and other bytes stay
 * intact. The caller must exclude applied files before persisting the result. */
export function repairFunctionRevocationOrder(sql: string, priorDefinitions: string): string {
  const full = [...declaredFunctions(priorDefinitions + '\n' + sql)].sort().join(',');
  const resetRoles = [
    'openpc_control_runtime',
    'openpc_control_worker',
    'openpc_control_platform_runtime',
    'openpc_control_reader',
    'openpc_control_maintenance',
    'openpc_backup_operator',
  ]
    .sort()
    .join(',');
  return sql.replaceAll(
    /REVOKE\s+ALL\s+ON\s+FUNCTION\s+([^;]+?)\s+FROM\s+([^;]+);/giu,
    (reset, signatures: string, grantees: string, offset: number) => {
      const roles = splitList(grantees).map(normalize).sort().join(',');
      const functions = splitList(signatures)
        .map((signature) => normalize(signature).replace(/\s*([(),])\s*/gu, '$1'))
        .sort()
        .join(',');
      if (functions !== full || (roles !== 'public' && roles !== resetRoles)) return reset;
      return scopeFunctionRevocations(
        `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA openpc, control FROM ${grantees};`,
        priorDefinitions + '\n' + sql.slice(0, offset),
      );
    },
  );
}

/** A generated owner may declare its narrow runtime grants beside its routine.
 * Preserve those declarations across the later shared privilege reset, copying
 * only grantees actually reset and leaving subsequent explicit revokes intact. */
export function restoreFunctionGrantsAfterReset(sql: string): string {
  const resetRoles = [
    'openpc_control_runtime',
    'openpc_control_worker',
    'openpc_control_platform_runtime',
    'openpc_control_reader',
    'openpc_control_maintenance',
    'openpc_backup_operator',
  ]
    .sort()
    .join(',');
  const marker = '-- BEGIN OPENPC GENERATED INLINE FUNCTION GRANTS';
  return sql.replaceAll(
    /REVOKE\s+ALL\s+ON\s+FUNCTION\s+([\s\S]*?)\s+FROM\s+([^;]+);/giu,
    (reset, signatures: string, grantees: string, offset: number) => {
      const roles = new Set(splitList(grantees).map(normalize));
      if (
        [...roles].sort().join(',') !== resetRoles ||
        sql.slice(offset + reset.length).startsWith('\n' + marker)
      )
        return reset;
      const resetFunctions = new Set(
        splitList(signatures).map((signature) =>
          normalize(signature).replace(/\s*([(),])\s*/gu, '$1'),
        ),
      );
      const effective = new Map<string, Set<string>>();
      const prefix = sql.slice(0, offset);
      const events: {
        offset: number;
        kind: 'GRANT' | 'REVOKE' | 'DROP';
        signatures: string[];
        roles: string[];
      }[] = functionDrops(prefix).map((event) => ({ ...event, roles: [] }));
      for (const event of prefix.matchAll(
        /\b(GRANT\s+EXECUTE|REVOKE\s+(?:ALL|EXECUTE))\s+ON\s+FUNCTION\s+([^;]+?)\s+(?:TO|FROM)\s+([^;]+);/giu,
      ))
        events.push({
          offset: event.index,
          kind: event[1]!.toUpperCase().startsWith('GRANT') ? 'GRANT' : 'REVOKE',
          signatures: splitList(event[2]!).map((item) =>
            normalize(item).replace(/\s*([(),])\s*/gu, '$1'),
          ),
          roles: splitList(event[3]!).map(normalize),
        });
      for (const event of events.sort((left, right) => left.offset - right.offset)) {
        for (const signature of event.signatures) {
          if (event.kind === 'DROP') {
            effective.delete(signature);
            continue;
          }
          const current = effective.get(signature) ?? new Set<string>();
          for (const role of event.roles)
            if (event.kind === 'GRANT') current.add(role);
            else current.delete(role);
          effective.set(signature, current);
        }
      }
      const grants: string[] = [];
      for (const [signature, current] of effective) {
        const retained = [...current].filter((role) => roles.has(role));
        if (resetFunctions.has(signature) && retained.length > 0)
          grants.push(`GRANT EXECUTE ON FUNCTION ${signature} TO ${retained.join(',')};`);
      }
      return grants.length === 0
        ? reset
        : `${reset}\n${marker}\n${grants.join('\n')}\n-- END OPENPC GENERATED INLINE FUNCTION GRANTS`;
    },
  );
}

export function verifyFunctionGrants(definitions: string, grants: string): string {
  const declared = installedFunctions(definitions);
  const expected = new Map<string, Set<string>>();
  const effective = new Map<string, Set<string>>();
  for (const event of grants.matchAll(
    /\b(GRANT\s+EXECUTE|REVOKE\s+(?:ALL|EXECUTE))\s+ON\s+FUNCTION\s+([\s\S]*?)\s+(?:TO|FROM)\s+([^;]+);/giu,
  )) {
    const grant = event[1]!.toUpperCase().startsWith('GRANT');
    const roles = splitList(event[3]!).map(normalize);
    for (const item of splitList(event[2]!)) {
      const signature = normalize(item).replace(/\s*([(),])\s*/gu, '$1');
      const current = effective.get(signature) ?? new Set<string>();
      for (const role of roles) {
        if (grant) current.add(role);
        else current.delete(role);
      }
      effective.set(signature, current);
    }
  }
  for (const match of grants.matchAll(
    /GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+([\s\S]*?)\s+TO\s+([^;]+);/giu,
  )) {
    const roles = splitList(match[2]!).map(normalize);
    for (const item of splitList(match[1]!)) {
      const signature = normalize(item).replace(/\s*([(),])\s*/gu, '$1');
      if (!declared.has(signature))
        throw new Error(`Function grant has no matching definition: ${signature}`);
      const existing = expected.get(signature) ?? new Set<string>();
      for (const role of roles) {
        if (!/^openpc_[a-z_]+$/u.test(role))
          throw new Error(`Unexpected function grantee: ${role}`);
        existing.add(role);
      }
      expected.set(signature, existing);
    }
  }
  for (const [signature, roles] of expected)
    for (const role of roles)
      if (!effective.get(signature)?.has(role))
        throw new Error(`Function grant revoked after declaration: ${signature} to ${role}`);
  for (const [signature, roles] of Object.entries(intendedRoles)) {
    if (
      declared.has(signature) &&
      [...(expected.get(signature) ?? [])].sort().join(',') !== [...roles].sort().join(',')
    )
      throw new Error(`Function grant role mismatch: ${signature}`);
  }
  const checks = [...expected].flatMap(([signature, roles]) =>
    [...roles].map((role) => `(${literal(signature)},${literal(role)})`),
  );
  if (checks.length === 0) throw new Error('Generated migration contains no function grants');
  return `DO $function_grant_acceptance$
DECLARE expected record; matched oid;
BEGIN
 FOR expected IN SELECT * FROM (VALUES ${checks.join(',\n')}) AS required(signature,grantee) LOOP
  matched:=to_regprocedure(expected.signature);
  IF matched IS NULL OR (SELECT count(*) FROM pg_catalog.pg_proc WHERE oid=matched)<>1
   OR NOT has_function_privilege(expected.grantee,matched,'EXECUTE') THEN
   RAISE EXCEPTION 'Generated function grant failed: % to %',expected.signature,expected.grantee;
  END IF;
 END LOOP;
END $function_grant_acceptance$;`;
}
