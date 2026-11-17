#!/bin/sh
set -eu

mode="${1:?migration mode required}"
schema_only=0
installation_only=0
roles_only=0
control_checks_reconciled=0
checks_only=0
if [ "$mode" = candidate_index-roles ]; then mode=candidate_index; roles_only=1; fi
if [ "$mode" = fact-roles ]; then mode=fact; roles_only=1; fi
if [ "$mode" = control-schema ]; then mode=control; schema_only=1; fi
if [ "$mode" = control-installation ]; then mode=control; installation_only=1; fi
if [ "$mode" = control-restore-checks ]; then mode=control; checks_only=1; fi
password="$(cat "/run/secrets/${mode}_pg_password")"
export PGPASSWORD="$password"

psql_base() {
  psql -X -q -v ON_ERROR_STOP=1 -h "${PGHOST:?}" -U "${PGUSER:?}" -d "${PGDATABASE:?}" "$@"
}

ensure_ledger() {
  psql_base -c 'CREATE SCHEMA IF NOT EXISTS openpc_local; CREATE TABLE IF NOT EXISTS openpc_local.migration(path text PRIMARY KEY, sha256 text NOT NULL CHECK (sha256 ~ '\''^[0-9a-f]{64}$'\''), applied_at timestamptz NOT NULL DEFAULT clock_timestamp());'
}

ledger_digest() {
  printf '%s\n' "SELECT sha256 FROM openpc_local.migration WHERE path=:'path';" |
    psql_base -At -v path="$1"
}

emit_ledger_insert() {
  printf '%s\n' \
    '' \
    'RESET ROLE;' \
    "INSERT INTO openpc_local.migration(path,sha256) VALUES (:'path',:'digest');"
}

apply_file() {
  path="$1"
  digest="$(sha256sum "$path" | cut -d ' ' -f 1)"
  prior="$(ledger_digest "$path")"
  if [ -n "$prior" ]; then
    [ "$prior" = "$digest" ] || { echo "migration digest drift: $path" >&2; exit 1; }
    return
  fi
  { cat "$path"; emit_ledger_insert; } |
    psql_base -1 -v path="$path" -v digest="$digest"
}

# pg_dump reparses BETWEEN into AND nodes. Restore only the eight historical
# CHECK declarations whose exact deparse guard distinguishes those parse trees.
# Allowed forms are derived exclusively from ledger-authenticated generated DDL;
# an observed database expression never creates an allowed form.
emit_control_check_restore() (
  check_root=/migrations/postgres/control-api
  for check_file in 0123_curved_firelord.sql 0156_notification_completion_shared.sql; do
    [ -f "$check_root/$check_file" ] && [ -r "$check_root/$check_file" ] || exit 1
    check_sum="$(sha256sum "$check_root/$check_file")" || exit 1
    check_digest="${check_sum%% *}"
    [ "${#check_digest}" = 64 ] || exit 1
    case "$check_digest" in *[!0-9a-f]*) exit 1 ;; esac
    check_recorded="$(ledger_digest "$check_root/$check_file")" || exit 1
    [ "$check_recorded" = "$check_digest" ] || {
      echo 'Control restore CHECK source/ledger mismatch' >&2; exit 1;
    }
    case "$check_file" in 0123_*) check_0123_digest=$check_digest ;; 0156_*) check_0156_digest=$check_digest ;; esac
  done
  cat <<'SQL' || exit 1
RESET ROLE;
SET LOCAL search_path=pg_catalog;
LOCK TABLE openpc_local.migration IN SHARE ROW EXCLUSIVE MODE;
CREATE TEMP TABLE openpc_restore_check_input(table_name text,name text,declaration text,columns text,path text,digest text,repair boolean DEFAULT false) ON COMMIT DROP;
COPY pg_temp.openpc_restore_check_input(table_name,name,declaration,columns,path,digest) FROM STDIN;
SQL
  while IFS='|' read -r check_table check_name check_file check_columns; do
    check_declaration="$(awk -v wanted="$check_name" '
      index($0,"CONSTRAINT \"" wanted "\" CHECK ") {
        if (started) exit 1;
        started=1; sub(/^.* CHECK /, "");
      }
      started {
        line=$0; opens=gsub(/\(/,"(",line); closes=gsub(/\)/,")",line);
        depth+=opens-closes; sub(/^[[:space:]]+/,"");
        if (depth==0) { sub(/,[[:space:]]*$/,""); printf "%s",$0; found=1; exit; }
        printf "%s ",$0;
      }
      END { if (!found) exit 1; }
    ' "$check_root/$check_file")" || exit 1
    [ -n "$check_declaration" ] && [ "${#check_declaration}" -le 8192 ] || exit 1
    # These closed historical declarations contain no COPY escaping characters.
    case "$check_declaration" in *'\'*|*"	"*) exit 1 ;; esac
    case "$check_file" in 0123_*) check_digest=$check_0123_digest ;; 0156_*) check_digest=$check_0156_digest ;; esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$check_table" "$check_name" "$check_declaration" "$check_columns" "$check_root/$check_file" "$check_digest" || exit 1
  done <<'CHECKS'
notification_completion_attempt|completion_attempt_bytes_ck|0156_notification_completion_shared.sql|attempt_bytes:bytea:yes,attempt_digest:text:yes
notification_completion_disposition|completion_disposition_bytes_ck|0156_notification_completion_shared.sql|transition_bytes:bytea:yes,transition_digest:text:yes,receipt_payload:bytea:yes,cose_sign1:bytea:yes
notification_completion_disposition_signer_installation|completion_signer_bytes_ck|0156_notification_completion_shared.sql|trust_bytes:bytea:yes,trust_digest:text:yes
notification_completion_disposition_signing|completion_signing_bytes_ck|0156_notification_completion_shared.sql|preparation_bytes:bytea:yes,preparation_digest:text:yes
notification_completion_source|completion_source_bytes_ck|0156_notification_completion_shared.sql|source_bytes:bytea:yes,source_digest:text:yes
notification_source_cursor|notification_cursor_position_ck|0123_curved_firelord.sql|last_sequence:numeric(20;0):yes,last_event_id:uuid:no,last_data_digest:text:no
notification_source_cursor|notification_cursor_source_ck|0123_curved_firelord.sql|source:text:yes,partition:text:yes
notification_source_inbox|notification_inbox_source_ck|0123_curved_firelord.sql|source:text:yes,partition:text:yes
CHECKS
  cat <<'SQL' || exit 1
\.
DO $$
DECLARE item record; column_profile text; wanted text; actual text; prior text; following text; variants text[]; iteration integer; stable boolean;
BEGIN
 IF current_user<>session_user OR NOT (SELECT rolsuper FROM pg_roles WHERE rolname=session_user)
 OR current_setting('row_security')<>'on' OR current_setting('session_replication_role')<>'origin'
 OR (SELECT count(*) FROM pg_temp.openpc_restore_check_input)<>8
 OR EXISTS(SELECT 1 FROM pg_temp.openpc_restore_check_input i LEFT JOIN openpc_local.migration m USING(path) WHERE m.sha256 IS DISTINCT FROM i.digest)
 THEN RAISE EXCEPTION 'CONTROL-RESTORE-CHECK-SOURCE'; END IF;
 FOR item IN SELECT DISTINCT table_name FROM pg_temp.openpc_restore_check_input ORDER BY table_name LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.oid=to_regclass('control.'||item.table_name)
   AND r.rolname='openpc_control_owner' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
   AND NOT c.relispartition AND NOT EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid))
  THEN RAISE EXCEPTION 'CONTROL-RESTORE-CHECK-TABLE'; END IF;
  EXECUTE format('LOCK TABLE ONLY control.%I IN ACCESS EXCLUSIVE MODE',item.table_name);
 END LOOP;
 FOR item IN SELECT * FROM pg_temp.openpc_restore_check_input ORDER BY table_name,name LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.oid=to_regclass('control.'||item.table_name) AND r.rolname='openpc_control_owner' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity AND NOT c.relispartition AND NOT EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid)) THEN RAISE EXCEPTION 'CONTROL-RESTORE-CHECK-TABLE'; END IF;
  FOREACH column_profile IN ARRAY string_to_array(item.columns,',') LOOP
   IF NOT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid WHERE a.attrelid=to_regclass('control.'||item.table_name)
    AND a.attname=split_part(column_profile,':',1) AND NOT a.attisdropped AND a.attnum>0
    AND t.typnamespace='pg_catalog'::regnamespace AND format_type(a.atttypid,a.atttypmod)=replace(split_part(column_profile,':',2),';',',')
    AND a.attnotnull=(split_part(column_profile,':',3)='yes') AND a.attgenerated='' AND a.attidentity=''
    AND a.attcollation=t.typcollation)
   THEN RAISE EXCEPTION 'CONTROL-RESTORE-CHECK-COLUMN'; END IF;
  END LOOP;
  SELECT btrim(regexp_replace(pg_get_expr(c.conbin,c.conrelid),'[[:space:]]+',' ','g')) INTO actual
   FROM pg_constraint c WHERE c.conrelid=to_regclass('control.'||item.table_name) AND c.conname=item.name
    AND c.contype='c' AND c.convalidated AND c.conenforced AND NOT c.connoinherit AND c.conislocal AND c.coninhcount=0;
  IF actual IS NULL THEN RAISE EXCEPTION 'CONTROL-RESTORE-CHECK-IDENTITY'; END IF;
  EXECUTE format('CREATE TEMP TABLE openpc_restore_check_reference (LIKE control.%I) ON COMMIT DROP',item.table_name);
  EXECUTE 'ALTER TABLE pg_temp.openpc_restore_check_reference ADD CONSTRAINT reference_ck CHECK '||replace(item.declaration,format('"control"."%s".',item.table_name),'');
  SELECT btrim(regexp_replace(pg_get_expr(conbin,conrelid),'[[:space:]]+',' ','g')) INTO wanted FROM pg_constraint WHERE conrelid='pg_temp.openpc_restore_check_reference'::regclass AND conname='reference_ck';
  variants:=ARRAY[wanted]; prior:=wanted; stable:=false;
  FOR iteration IN 1..4 LOOP
   IF prior IS NULL OR octet_length(prior)>8192 THEN RAISE EXCEPTION 'CONTROL-RESTORE-CHECK-PARSER'; END IF;
   ALTER TABLE pg_temp.openpc_restore_check_reference DROP CONSTRAINT reference_ck;
   EXECUTE 'ALTER TABLE pg_temp.openpc_restore_check_reference ADD CONSTRAINT reference_ck CHECK '||prior;
   SELECT btrim(regexp_replace(pg_get_expr(conbin,conrelid),'[[:space:]]+',' ','g')) INTO following FROM pg_constraint WHERE conrelid='pg_temp.openpc_restore_check_reference'::regclass AND conname='reference_ck';
   IF following=prior THEN stable:=true; EXIT; END IF;
   IF following=ANY(variants) THEN RAISE EXCEPTION 'CONTROL-RESTORE-CHECK-CYCLE'; END IF;
   variants:=array_append(variants,following); prior:=following;
  END LOOP;
  IF NOT stable OR array_length(variants,1)<>2 OR NOT actual=ANY(variants) THEN RAISE EXCEPTION 'CONTROL-RESTORE-CHECK-EXPRESSION'; END IF;
  UPDATE pg_temp.openpc_restore_check_input SET repair=(actual<>wanted) WHERE name=item.name AND table_name=item.table_name;
  DROP TABLE pg_temp.openpc_restore_check_reference;
 END LOOP;
 -- Every required prerequisite was validated before the first durable change.
 FOR item IN SELECT * FROM pg_temp.openpc_restore_check_input WHERE repair ORDER BY table_name,name LOOP
  EXECUTE format('ALTER TABLE control.%I DROP CONSTRAINT %I',item.table_name,item.name);
  EXECUTE format('ALTER TABLE control.%I ADD CONSTRAINT %I CHECK ',item.table_name,item.name)||item.declaration;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_temp.openpc_restore_check_input i JOIN pg_constraint c ON c.conrelid=to_regclass('control.'||i.table_name) AND c.conname=i.name WHERE NOT c.convalidated OR NOT c.conenforced OR c.connoinherit) THEN RAISE EXCEPTION 'CONTROL-RESTORE-CHECK-VALIDATION'; END IF;
END $$;
SET ROLE openpc_control_owner;
SQL
)

apply_owned_file() {
  path="$1"
  digest="$(sha256sum "$path" | cut -d ' ' -f 1)"
  prior="$(ledger_digest "$path")"
  if [ -n "$prior" ]; then
    [ "$prior" = "$digest" ] || { echo "migration digest drift: $path" >&2; exit 1; }
    return
  fi
  reconcile_checks=0
  case "$path" in
    /migrations/postgres/control-api/*)
      sequence="${path##*/}"; sequence="${sequence%%_*}"
      if [ "$sequence" -ge 157 ] && [ "$control_checks_reconciled" = 0 ]; then reconcile_checks=1; fi ;;
  esac
  if [ "$reconcile_checks" = 1 ]; then
    # Materialize the complete producer output before psql can commit. A failed
    # extraction must not be mistaken for a successful early EOF on a pipeline.
    restore_sql="$(mktemp)" || return 1
    (
      emit_control_check_restore || exit 1
      printf '%s\n' 'SET ROLE openpc_control_owner;' || exit 1
      cat "$path" || exit 1
      printf '%s\n' 'SELECT openpc.assert_notification_completion_disposition_shared_owner();' || exit 1
      emit_ledger_insert || exit 1
    ) > "$restore_sql" || { rm -f -- "$restore_sql"; return 1; }
    if psql_base -1 -v path="$path" -v digest="$digest" < "$restore_sql"; then
      rm -f -- "$restore_sql"
      control_checks_reconciled=1
    else
      restore_status=$?; rm -f -- "$restore_sql"; return "$restore_status"
    fi
  else
    {
      printf '%s\n' 'SET ROLE openpc_control_owner;'
      cat "$path"
      emit_ledger_insert
    } | psql_base -1 -v path="$path" -v digest="$digest"
  fi
}

restore_control_checks() (
  restore_sql="$(mktemp)" || exit 1
  trap 'rm -f -- "$restore_sql"' 0
  emit_control_check_restore > "$restore_sql" || exit 1
  printf '%s\n' 'SELECT openpc.assert_notification_completion_disposition_shared_owner();' >> "$restore_sql" || exit 1
  psql_base -1 < "$restore_sql"
)

# Identity 0100 installs the lifecycle introduced by Control 0156. Historical
# Control 0143-0155 assert the exact predecessor body. Install that immutable
# predecessor only inside the transaction that reaches 0156: no connection can
# observe a committed downgrade, and every original assertion still executes.
apply_control_shared_lifecycle_transition() (
  transition_root="$(mktemp -d)"
  trap 'rm -rf -- "$transition_root"' 0
  next_number=143
  pending=0
  applied_count=0
  : > "$transition_root/pending"
  : > "$transition_root/expected.sql"
  for transition_path in /migrations/postgres/control-api/014[3-9]_*.sql /migrations/postgres/control-api/015[0-6]_*.sql; do
    transition_name="${transition_path##*/}"
    printf '%s\n' "$transition_name" | grep -Eq '^[0-9]{4}_[a-z0-9_]+\.sql$' || exit 1
    [ -f "$transition_path" ] && [ "${transition_name%%_*}" = "$(printf '%04d' "$next_number")" ] || {
      echo 'incomplete Control 0143/0156 shared lifecycle transition' >&2; exit 1
    }
    next_number=$((next_number + 1))
    transition_digest="$(sha256sum "$transition_path" | cut -d ' ' -f 1)"
    transition_prior="$(ledger_digest "$transition_path")"
    printf "INSERT INTO pg_temp.openpc_lifecycle_migration_expected VALUES ('%s','%s','%s');\n" \
      "$transition_path" "$transition_digest" "$transition_prior" >> "$transition_root/expected.sql"
    if [ -n "$transition_prior" ]; then
      [ "$transition_prior" = "$transition_digest" ] && [ "$pending" = 0 ] || {
        echo 'drifted or non-prefix Control shared lifecycle transition' >&2; exit 1
      }
      applied_count=$((applied_count + 1))
    else
      pending=1
      printf '%s %s\n' "$transition_digest" "$transition_path" >> "$transition_root/pending"
    fi
  done
  [ "$next_number" = 157 ] || exit 1
  # Also check a fully applied group: an extra recorded filename is not a
  # recognized prefix, even if every known file is present and unchanged.
  recorded_count="$(psql_base -At -c "SELECT count(*) FROM openpc_local.migration WHERE path ~ '/control-api/(014[3-9]|015[0-6])_';")"
  [ "$recorded_count" = "$applied_count" ] || {
    echo 'unknown Control shared lifecycle migration history' >&2; exit 1
  }
  [ "$pending" = 1 ] || exit 0
  predecessor=/migrations/postgres/identity/0099_stiff_lockjaw.sql
  successor=/migrations/postgres/identity/0100_provider_qualification_resume.sql
  # Closed function boundaries from the authenticated generated migration, not a
  # second hand-maintained implementation or an assertion-derived allow-list.
  for lifecycle_source in "$predecessor" "$successor"; do
    lifecycle_digest="$(sha256sum "$lifecycle_source" | cut -d ' ' -f 1)"
    [ "$(ledger_digest "$lifecycle_source")" = "$lifecycle_digest" ] || {
      echo 'unverified shared lifecycle source' >&2; exit 1
    }
    printf "INSERT INTO pg_temp.openpc_lifecycle_migration_expected VALUES ('%s','%s','%s');\n" \
      "$lifecycle_source" "$lifecycle_digest" "$lifecycle_digest" >> "$transition_root/expected.sql"
    awk '
      /^CREATE OR REPLACE FUNCTION openpc.enforce_work_item_lifecycle\(\)$/ { found++; active=1 }
      active { print }
      active && /^END \$\$;$/ { active=0; ended++ }
      END { if (found != 1 || ended != 1 || active) exit 1 }
    ' "$lifecycle_source" > "$transition_root/${lifecycle_source##*/}"
    test "$(sed -n '2p' "$transition_root/${lifecycle_source##*/}")" = \
      'RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$'
  done
  old_body="$(printf '\n'; sed '1,2d;s/\$\$;$//' "$transition_root/${predecessor##*/}")"
  current_body="$(printf '\n'; sed '1,2d;s/\$\$;$//' "$transition_root/${successor##*/}")"
  {
    cat <<'SQL'
SELECT pg_advisory_xact_lock(hashtextextended('openpc.control.shared-lifecycle.0143-0156',0));
LOCK TABLE openpc_local.migration IN SHARE ROW EXCLUSIVE MODE;
CREATE TEMP TABLE openpc_lifecycle_migration_expected(path text PRIMARY KEY,digest text,prior text) ON COMMIT DROP;
SQL
    cat "$transition_root/expected.sql"
    cat <<'SQL'
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_temp.openpc_lifecycle_migration_expected e
  LEFT JOIN openpc_local.migration m USING(path) WHERE coalesce(m.sha256,'')<>e.prior)
 OR EXISTS(SELECT 1 FROM openpc_local.migration m WHERE m.path ~ '/control-api/(014[3-9]|015[0-6])_'
  AND NOT EXISTS(SELECT 1 FROM pg_temp.openpc_lifecycle_migration_expected e WHERE e.path=m.path))
 THEN RAISE EXCEPTION 'shared lifecycle migration history changed'; END IF;
END $$;
SET ROLE openpc_control_owner;
LOCK TABLE control.work_item,control.outbox_event,control.notification_delivery IN ACCESS EXCLUSIVE MODE;
SELECT set_config('openpc.migration.lifecycle_old',:'old_body',true) AS lifecycle_old,
 set_config('openpc.migration.lifecycle_current',:'current_body',true) AS lifecycle_current \gset
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
  JOIN pg_language l ON l.oid=p.prolang JOIN pg_trigger t ON t.tgfoid=p.oid
  WHERE p.oid='openpc.enforce_work_item_lifecycle()'::regprocedure
   AND r.rolname='openpc_control_owner' AND l.lanname='plpgsql' AND NOT p.prosecdef
   AND p.prorettype='trigger'::regtype AND p.pronargs=0 AND p.provolatile='v'
   AND p.proconfig=ARRAY['search_path=pg_catalog']
   AND p.prosrc IN (current_setting('openpc.migration.lifecycle_old'),current_setting('openpc.migration.lifecycle_current'))
   AND t.tgrelid='control.work_item'::regclass AND t.tgname='work_item_lifecycle' AND t.tgtype=31
   AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgnargs=0 AND t.tgqual IS NULL)
 THEN RAISE EXCEPTION 'unexpected installed shared lifecycle'; END IF;
END $$;
SQL
    cat "$transition_root/${predecessor##*/}"
  } > "$transition_root/transition.sql"
  while read -r transition_digest transition_path; do
    # Names come only from the closed numeric range above; digests are hex.
    printf "\\set path '%s'\n\\set digest '%s'\nSET ROLE openpc_control_owner;\n" \
      "$transition_path" "$transition_digest" >> "$transition_root/transition.sql"
    cat "$transition_path" >> "$transition_root/transition.sql"
    emit_ledger_insert >> "$transition_root/transition.sql"
  done < "$transition_root/pending"
  printf '%s\n' 'SET ROLE openpc_control_owner;' \
    'SELECT openpc.assert_notification_outcome_publication_shared_owners();' >> "$transition_root/transition.sql"
  cat >> "$transition_root/transition.sql" <<'SQL'
DO $$ BEGIN
 IF (SELECT prosrc FROM pg_proc WHERE oid='openpc.enforce_work_item_lifecycle()'::regprocedure)
  IS DISTINCT FROM current_setting('openpc.migration.lifecycle_current')
 THEN RAISE EXCEPTION 'shared lifecycle current restoration failed'; END IF;
END $$;
SQL
  psql_base -1 -v old_body="$old_body" -v current_body="$current_body" < "$transition_root/transition.sql"
)

apply_control_recreation_pair() {
  removal_path="$1"
  recreation_path="$2"
  removal_digest="$(sha256sum "$removal_path" | cut -d ' ' -f 1)"
  recreation_digest="$(sha256sum "$recreation_path" | cut -d ' ' -f 1)"
  removal_prior="$(ledger_digest "$removal_path")"
  recreation_prior="$(ledger_digest "$recreation_path")"
  if [ -n "$removal_prior" ] || [ -n "$recreation_prior" ]; then
    [ "$removal_prior" = "$removal_digest" ] &&
      [ "$recreation_prior" = "$recreation_digest" ] || {
        echo 'unsafe split or drifted control-api 0004/0005 transition' >&2
        exit 1
      }
    return
  fi
  {
    printf '%s\n' 'SET ROLE openpc_control_owner;'
    cat <<'SQL'
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM control.runtime_configuration_work) THEN
    RAISE EXCEPTION 'runtime_configuration_work must be reconciled before control-api 0004/0005';
  END IF;
END $$;
CREATE TEMP TABLE openpc_upgrade_abi_artifact ON COMMIT DROP AS TABLE control.abi_artifact;
CREATE TEMP TABLE openpc_upgrade_argument_rule_named_set_binding ON COMMIT DROP AS TABLE control.argument_rule_named_set_binding;
CREATE TEMP TABLE openpc_upgrade_typed_argument_rule_version ON COMMIT DROP AS TABLE control.typed_argument_rule_version;
CREATE TEMP TABLE openpc_upgrade_contract_method_policy ON COMMIT DROP AS TABLE control.contract_method_policy;
CREATE TEMP TABLE openpc_upgrade_logical_contract_asset ON COMMIT DROP AS TABLE control.logical_contract_asset;
CREATE TEMP TABLE openpc_upgrade_contract_runtime_binding ON COMMIT DROP AS TABLE control.contract_runtime_binding;
CREATE TEMP TABLE openpc_upgrade_typed_argument_rule ON COMMIT DROP AS TABLE control.typed_argument_rule;
SQL
    cat "$removal_path"
    cat "$recreation_path"
    cat <<'SQL'
INSERT INTO control.abi_artifact SELECT * FROM openpc_upgrade_abi_artifact;
INSERT INTO control.logical_contract_asset SELECT * FROM openpc_upgrade_logical_contract_asset;
INSERT INTO control.contract_runtime_binding SELECT * FROM openpc_upgrade_contract_runtime_binding;
INSERT INTO control.typed_argument_rule_version SELECT * FROM openpc_upgrade_typed_argument_rule_version;
INSERT INTO control.argument_rule_named_set_binding SELECT * FROM openpc_upgrade_argument_rule_named_set_binding;
INSERT INTO control.typed_argument_rule SELECT * FROM openpc_upgrade_typed_argument_rule;
INSERT INTO control.contract_method_policy SELECT * FROM openpc_upgrade_contract_method_policy;
RESET ROLE;
INSERT INTO openpc_local.migration(path,sha256)
VALUES (:'removal_path',:'removal_digest'),(:'recreation_path',:'recreation_digest');
SQL
  } | psql_base -1 \
    -v removal_path="$removal_path" -v removal_digest="$removal_digest" \
    -v recreation_path="$recreation_path" -v recreation_digest="$recreation_digest"
}

case "$mode" in
  control)
    if [ "$checks_only" = 1 ]; then restore_control_checks; exit 0; fi
    ensure_ledger
    # Identity 0129+ installs SQL policies over the withdrawal cohort introduced
    # by Control 0192. Earlier Identity creates the referenced replacement owner;
    # keep both immutable journals, but install their DDL in dependency order.
    printf 'OPENPC_INSTALL_PHASE|identity-base\n'
    for path in /migrations/postgres/identity/[0-9][0-9][0-9][0-9]_*.sql; do
      name="${path##*/}"
      if [ "${name%%_*}" -lt 129 ]; then apply_file "$path"; fi
    done
    for path in /migrations/postgres/policy/[0-9][0-9][0-9][0-9]_*.sql; do
      digest="$(sha256sum "$path" | cut -d ' ' -f 1)"
      prior="$(ledger_digest "$path")"
      if [ -n "$prior" ]; then
        [ "$prior" = "$digest" ] || { echo "migration digest drift: $path" >&2; exit 1; }
        continue
      fi
      {
        printf '%s\n' 'SET ROLE openpc_control_owner;'
        if [ "${path##*/}" = 0000_yummy_plazm.sql ]; then sed '1,2d' "$path"; else cat "$path"; fi
        emit_ledger_insert
      } | psql_base -1 -v path="$path" -v digest="$digest"
    done
    control_removal_path=
    control_recreation_path=
    control_discovery_succession_path=
    control_discovery_succession_updates=
    printf 'OPENPC_INSTALL_PHASE|control\n'
    for path in /migrations/postgres/control-api/[0-9][0-9][0-9][0-9]_*.sql; do
      case "${path##*/}" in
        0004_*) control_removal_path="$path" ;;
        0005_*) control_recreation_path="$path" ;;
      esac
    done
    [ -n "$control_removal_path" ] && [ -n "$control_recreation_path" ] || {
      echo 'control-api 0004/0005 transition files are required' >&2
      exit 1
    }
    for path in /migrations/postgres/control-api/[0-9][0-9][0-9][0-9]_*.sql; do
      case "${path##*/}" in
        0004_*) apply_control_recreation_pair "$control_removal_path" "$control_recreation_path" ;;
        0005_*) ;;
        0143_*) apply_control_shared_lifecycle_transition ;;
        014[4-9]_*|015[0-6]_*) ;;
        # This read-only successor owner references Identity 0132 recovery
        # tables and later Discovery issuance columns. Install it after the
        # Identity tail without changing either immutable migration journal.
        0197_*) control_discovery_succession_path="$path" ;;
        0198_smart_contract_discovery_integration.sql|0199_familiar_energizer.sql|0200_source_authentication_document_reuse.sql|0201_lush_black_widow.sql|0202_original_activation_worker_identity.sql|0203_demonic_celestials.sql|0204_expired_denial_hex_validation.sql|0205_expired_denial_issuance_ordinal.sql|0206_expired_denial_handover.sql|0207_expired_credential_denial_handover.sql|0208_public_operations_source_v1.sql)
          # The generated profile-binding tail preserves the Discovery owner
          # that depends on Identity 0132. Later generated tails retain that
          # dependency too; install them in their original order after Identity.
          # Keep source-verifier updates after the tails that replace that owner.
          control_discovery_succession_updates="$control_discovery_succession_updates $path" ;;
        *) apply_owned_file "$path" ;;
      esac
    done
    printf 'OPENPC_INSTALL_PHASE|identity-withdrawal-policies\n'
    for path in /migrations/postgres/identity/[0-9][0-9][0-9][0-9]_*.sql; do
      name="${path##*/}"
      if [ "${name%%_*}" -ge 129 ]; then apply_file "$path"; fi
    done
    [ -n "$control_discovery_succession_path" ] || {
      echo 'control-api 0197 discovery succession file is required' >&2
      exit 1
    }
    printf 'OPENPC_INSTALL_PHASE|control-discovery-succession\n'
    apply_owned_file "$control_discovery_succession_path"
    for path in $control_discovery_succession_updates; do apply_owned_file "$path"; done
    if [ "$control_checks_reconciled" = 0 ]; then restore_control_checks; fi
    # Read-only installation provenance for scoped predecessor compatibility.
    # Runtime logins cannot change migration history or cluster identity.
    psql_base -c 'GRANT USAGE ON SCHEMA openpc_local TO openpc_control_worker; GRANT SELECT ON openpc_local.migration TO openpc_control_worker; GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO openpc_control_worker;'
    # Populated predecessor acceptance needs its actual schema before today's
    # initial-trust role catalogue is installed by the ordinary control mode.
    [ "$schema_only" = 0 ] || exit 0
    runtime_password="$(cat /run/secrets/identity_runtime_db_password)"
    participant_runtime_password="$(cat /run/secrets/participant_runtime_db_password)"
    policy_runtime_password="$(cat /run/secrets/policy_runtime_db_password)"
    control_api_runtime_password="$(cat /run/secrets/control_api_runtime_db_password)"
    control_worker_runtime_password="$(cat /run/secrets/control_worker_runtime_db_password)"
    # A rooted native worker has a distinct installed login. This only binds its
    # existing host bridge keys; it never creates/enrolls a role or grants it SQL
    # privileges. Ordinary legacy bootstrap retains its existing default.
    native_worker_role="${OPENPC_CONTROL_WORKER_TRUST_ROLE:-openpc_local_control_worker}"
    if [ "$native_worker_role" != openpc_local_control_worker ]; then
      native_worker_installed="$(psql_base -At -v native_worker_role="$native_worker_role" <<'SQL'
SELECT count(*)=1 FROM control.runtime_artifact_source s JOIN pg_catalog.pg_roles r ON r.rolname=s.database_role
 WHERE s.database_role=:'native_worker_role' AND s.custody_root IS NOT NULL
 AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole
 AND NOT r.rolcreatedb AND NOT r.rolreplication
 AND pg_catalog.pg_has_role(r.oid,'openpc_control_worker','USAGE')
 AND NOT pg_catalog.pg_has_role(r.oid,'openpc_control_owner','MEMBER')
 AND NOT pg_catalog.pg_has_role(r.oid,'openpc_control_key_governor','MEMBER')
 AND NOT pg_catalog.pg_has_role(r.oid,'openpc_control_runtime','MEMBER');
SQL
)"
      [ "$native_worker_installed" = t ] || { echo 'native worker installation unavailable' >&2; exit 1; }
    fi
    if [ -f /run/secrets/fleet_fact_admission_key ]; then
      fleet_fact_key="$(cat /run/secrets/fleet_fact_admission_key)"
      printf '%s' "$fleet_fact_key" | grep -Eq '^[0-9a-f]{64}$' || { echo 'invalid Fleet Fact admission key' >&2; exit 1; }
      psql_base -v native_worker_role="$native_worker_role" -v fleet_fact_key="$fleet_fact_key" <<'SQL'
INSERT INTO control.fleet_fact_admission_key(database_role,verifier_secret)
VALUES(:'native_worker_role',decode(:'fleet_fact_key','hex')) ON CONFLICT(database_role) DO NOTHING;
SQL
      fleet_fact_key_matches="$(psql_base -At -v native_worker_role="$native_worker_role" -v fleet_fact_key="$fleet_fact_key" <<'SQL'
SELECT verifier_secret=decode(:'fleet_fact_key','hex') FROM control.fleet_fact_admission_key WHERE database_role=:'native_worker_role';
SQL
)"
      [ "$fleet_fact_key_matches" = t ] || { echo 'Fleet Fact admission key drift' >&2; exit 1; }
    fi
    if [ -f /run/secrets/runtime_target_disposition_key ]; then
      disposition_key="$(cat /run/secrets/runtime_target_disposition_key)"
      printf '%s' "$disposition_key" | grep -Eq '^[0-9a-f]{64}$' || { echo 'invalid target disposition key' >&2; exit 1; }
      psql_base -v native_worker_role="$native_worker_role" -v disposition_key="$disposition_key" <<'SQL'
INSERT INTO control.runtime_target_disposition_key(database_role,verifier_secret)
VALUES(:'native_worker_role',decode(:'disposition_key','hex')) ON CONFLICT(database_role) DO NOTHING;
SQL
      disposition_key_matches="$(psql_base -At -v native_worker_role="$native_worker_role" -v disposition_key="$disposition_key" <<'SQL'
SELECT verifier_secret=decode(:'disposition_key','hex') FROM control.runtime_target_disposition_key WHERE database_role=:'native_worker_role';
SQL
)"
      [ "$disposition_key_matches" = t ] || { echo 'target disposition key drift' >&2; exit 1; }
    fi
    # Distinct host-native completion bridge keys. Ordinary SQL roles never
    # read these; preserve exact installed trust on upgrade/recovery.
    for completion_host in identity control; do
      case "$completion_host" in
        identity) completion_role=openpc_identity_runtime ;;
        control) completion_role=openpc_configuration_runtime ;;
      esac
      completion_key_file="/run/secrets/notification_completion_${completion_host}_admission_key"
      if [ -f "$completion_key_file" ]; then
        completion_key="$(cat "$completion_key_file")"
        printf '%s' "$completion_key" | grep -Eq '^[0-9a-f]{64}$' || { echo 'invalid completion admission key' >&2; exit 1; }
        psql_base -v completion_role="$completion_role" -v completion_key="$completion_key" <<'SQL'
INSERT INTO control.notification_completion_admission_key(database_role,verifier_secret)
VALUES(:'completion_role',decode(:'completion_key','hex')) ON CONFLICT(database_role) DO NOTHING;
SQL
        completion_key_matches="$(psql_base -At -v completion_role="$completion_role" -v completion_key="$completion_key" <<'SQL'
SELECT verifier_secret=decode(:'completion_key','hex') FROM control.notification_completion_admission_key WHERE database_role=:'completion_role';
SQL
)"
        [ "$completion_key_matches" = t ] || { echo 'completion admission key drift' >&2; exit 1; }
        unset completion_key
      fi
    done
    source_control_password=''
    if [ -f /run/secrets/source_control_db_password ]; then
      source_control_password="$(cat /run/secrets/source_control_db_password)"
      case "$source_control_password" in ''|*[!0-9a-f]*) echo 'invalid source reader secret' >&2; exit 1;; esac
    fi
    psql_base -v initial_fixture="$((1 - installation_only))" <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_identity_runtime') THEN
    CREATE ROLE openpc_identity_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    GRANT openpc_control_runtime TO openpc_identity_runtime;
  END IF;
END \$\$;
ALTER ROLE openpc_identity_runtime PASSWORD '$runtime_password';
GRANT openpc_signing_continuation_issuer TO openpc_identity_runtime;
GRANT openpc_identity_binding_resolver TO openpc_identity_runtime WITH INHERIT FALSE, SET TRUE;
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_participant_runtime') THEN
    CREATE ROLE openpc_participant_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    GRANT openpc_control_runtime TO openpc_participant_runtime;
  END IF;
END \$\$;
ALTER ROLE openpc_participant_runtime PASSWORD '$participant_runtime_password';
GRANT openpc_control_platform_runtime TO openpc_participant_runtime;
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_configuration_runtime') THEN
    CREATE ROLE openpc_configuration_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    GRANT openpc_control_runtime TO openpc_configuration_runtime;
  END IF;
END \$\$;
ALTER ROLE openpc_configuration_runtime PASSWORD '$control_api_runtime_password';
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_runtime_source_legacy') THEN
    CREATE ROLE openpc_runtime_source_legacy NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    COMMENT ON ROLE openpc_runtime_source_legacy IS 'openpc:runtime-artifact-source:legacy-unproven:v1';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_local_control_worker') THEN
    CREATE ROLE openpc_local_control_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    GRANT openpc_control_worker TO openpc_local_control_worker;
    -- Initial host trust only. Existing unknown logins are never enrolled or
    -- downgraded by migrations, including after a per-database restore.
    GRANT openpc_runtime_source_legacy TO openpc_local_control_worker WITH ADMIN FALSE, INHERIT FALSE, SET FALSE;
  END IF;
END \$\$;
ALTER ROLE openpc_local_control_worker PASSWORD '$control_worker_runtime_password';
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_source_control_reader') THEN
    CREATE ROLE openpc_source_control_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    GRANT openpc_control_reader TO openpc_source_control_reader;
  END IF;
END \$\$;
ALTER ROLE openpc_source_control_reader PASSWORD '$source_control_password';
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_policy_runtime') THEN
    CREATE ROLE openpc_policy_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    GRANT openpc_control_runtime TO openpc_policy_runtime;
  END IF;
END \$\$;
ALTER ROLE openpc_policy_runtime PASSWORD '$policy_runtime_password';
-- A manual installation gets service logins and the action catalogue only.
-- Initial root/operator trust has a separate owner; migration is not enrollment.
\if :initial_fixture
INSERT INTO control.participant(participant_id,display_name,state,authority_epoch)
VALUES ('018f0000-0000-7000-8000-000000000101','OpenPC local participant','ACTIVE',1)
ON CONFLICT (participant_id) DO NOTHING;
INSERT INTO control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
VALUES ('018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000101','Local facts','PARTICIPANT_LOCAL','LOCAL_DEVELOPMENT','ACTIVE')
ON CONFLICT (privacy_domain_id) DO NOTHING;
UPDATE control.participant SET root_privacy_domain_id='018f0000-0000-7000-8000-000000000201'
WHERE participant_id='018f0000-0000-7000-8000-000000000101' AND root_privacy_domain_id IS NULL;
INSERT INTO control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
VALUES
 ('018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000101','PLATFORM_OPERATOR','Local operator','ACTIVE',1),
 ('018f0000-0000-7000-8000-000000000112','018f0000-0000-7000-8000-000000000101','USER','Local viewer','ACTIVE',1)
ON CONFLICT (principal_id) DO NOTHING;
DO \$human_identity_bootstrap\$ BEGIN
IF to_regclass('control.identity_subject') IS NOT NULL THEN
INSERT INTO control.identity_subject(identity_subject_id,created_at)
SELECT principal_id,created_at FROM control.principal
WHERE principal_id IN ('018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000112')
ON CONFLICT (identity_subject_id) DO NOTHING;
INSERT INTO control.participant_membership(membership_id,participant_id,identity_subject_id,created_at)
SELECT principal_id,participant_id,principal_id,created_at FROM control.principal
WHERE principal_id IN ('018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000112')
ON CONFLICT (membership_id) DO NOTHING;
END IF;
END \$human_identity_bootstrap\$;
\endif
INSERT INTO control.action_intent
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,
   step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-IDENTITY_UPDATE_STEP_UP-V1','identity','UPDATE','HIGH',false,false,true,'AUTHORIZED_ONLY','REDACTED','IDENTITY_MUTATION'),
 ('ACT-IDENTITY_CREATE_SESSION-V1','session','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','SESSION_MUTATION'),
 ('ACT-IDENTITY_DELETE_SESSION-V1','session','DELETE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','SESSION_MUTATION'),
 ('ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1','fact-artifacts','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_FACT_ARTIFACTS'),
 ('ACT-FACT_ARTIFACTS_READ_COLLECTION-V1','fact-artifacts','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_FACT_ARTIFACTS'),
 ('ACT-FACT_ARTIFACTS_READ_RESOURCE-V1','fact-artifacts','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','READ_FACT_ARTIFACTS'),
 ('ACT-PARTICIPANTS_CREATE_RESOURCE-V1','participant','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','IDENTITY_MUTATION'),
 ('ACT-PARTICIPANTS_READ_COLLECTION-V1','participant','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','IDENTITY_READ'),
 ('ACT-PARTICIPANTS_READ_RESOURCE-V1','participant','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','IDENTITY_READ'),
 ('ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1','participant','ACTIVATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','IDENTITY_MUTATION'),
 ('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','participant','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','IDENTITY_MUTATION'),
 ('ACT-PARTICIPANT_CREATE_MEMBER-V1','principal','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','IDENTITY_MUTATION'),
 ('ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1','policy-version','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','POLICY_MUTATION'),
 ('ACT-POLICY_VERSIONS_READ_COLLECTION-V1','policy-version','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','POLICY_READ'),
 ('ACT-POLICY_VERSIONS_READ_RESOURCE-V1','policy-version','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','POLICY_READ'),
 ('ACT-POLICY_CREATE_SIMULATION-V1','policy','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','POLICY_SIMULATION'),
 ('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','approval-requests','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','CREATE_APPROVAL_REQUESTS'),
 ('ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1','approval-requests','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_APPROVAL_REQUESTS'),
 ('ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1','approval-requests','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_APPROVAL_REQUESTS'),
 ('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1','approval-requests','UPDATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_APPROVAL_REQUESTS'),
 ('ACT-POLICY_APPROVE_REQUEST-V1','approval-request','APPROVE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','APPROVE_APPROVAL_REQUEST'),
 ('ACT-RELEASE_BUNDLES_CREATE_RESOURCE-V1','release-bundles','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CREATE_RELEASE_BUNDLE'),
 ('ACT-RELEASE_BUNDLES_READ_COLLECTION-V1','release-bundles','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_RELEASE_BUNDLE'),
 ('ACT-RELEASE_BUNDLES_READ_RESOURCE-V1','release-bundles','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','READ_RELEASE_BUNDLE'),
 ('ACT-RELEASE_BUNDLES_UPDATE_RESOURCE-V1','release-bundles','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','UPDATE_RELEASE_BUNDLE'),
 ('ACT-POLICY_ACTIVATE_PUBLISH-V1','release-bundle','ACTIVATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','PUBLISH_RELEASE_BUNDLE'),
 ('ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1','activation-occurrences','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CREATE_ACTIVATION_OCCURRENCE'),
 ('ACT-ACTIVATION_OCCURRENCES_READ_COLLECTION-V1','activation-occurrences','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_ACTIVATION_OCCURRENCE'),
 ('ACT-ACTIVATION_OCCURRENCES_READ_RESOURCE-V1','activation-occurrences','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','READ_ACTIVATION_OCCURRENCE'),
 ('ACT-ACTIVATION_OCCURRENCES_UPDATE_RESOURCE-V1','activation-occurrences','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','UPDATE_ACTIVATION_OCCURRENCE'),
 ('ACT-POLICY_ACTIVATE_RELEASE-V1','release','ACTIVATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','ACTIVATE_RELEASE'),
 ('ACT-FLEET_RECOVER_OCCURRENCE-V1','activation-occurrence','RECOVER','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','RECOVER_ACTIVATION_OCCURRENCE'),
 ('ACT-POLICY_ROLLBACK_RELEASE-V1','release','ROLLBACK','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','ROLLBACK_RELEASE'),
 ('ACT-POLICY_SETS_CREATE_RESOURCE-V1','policy-sets','CREATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','CREATE_POLICY_SETS'),
 ('ACT-POLICY_SETS_READ_COLLECTION-V1','policy-sets','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_POLICY_SETS'),
 ('ACT-POLICY_SETS_READ_RESOURCE-V1','policy-sets','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_POLICY_SETS'),
 ('ACT-NOTIFICATIONS_CREATE_RESOURCE-V1','notifications','CREATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','CREATE_NOTIFICATIONS'),
 ('ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1','notification','UPDATE','LOW',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_NOTIFICATION'),
 ('ACT-NOTIFICATIONS_READ_RESOURCE-V1','notifications','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_NOTIFICATIONS'),
 ('ACT-NOTIFICATIONS_READ_COLLECTION-V1','notifications','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_NOTIFICATIONS'),
 ('ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1','notification-endpoints','CREATE','HIGH',false,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','CREATE_NOTIFICATION_ENDPOINTS'),
 ('ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1','notification-endpoints','UPDATE','HIGH',false,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_NOTIFICATION_ENDPOINTS'),
 ('ACT-NOTIFICATION_UPDATE_VERIFY-V1','notification-endpoint','UPDATE','STANDARD',false,false,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_NOTIFICATION_ENDPOINT'),
 ('ACT-NOTIFICATION_ENDPOINTS_READ_RESOURCE-V1','notification-endpoints','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_NOTIFICATION_ENDPOINTS'),
 ('ACT-NOTIFICATION_ENDPOINTS_READ_COLLECTION-V1','notification-endpoints','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_NOTIFICATION_ENDPOINTS'),
 ('ACT-WORK_ITEMS_CREATE_RESOURCE-V1','work-items','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','CREATE_WORK_ITEMS'),
 ('ACT-WORK_ITEMS_READ_COLLECTION-V1','work-items','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_WORK_ITEMS'),
 ('ACT-WORK_ITEMS_READ_RESOURCE-V1','work-items','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_WORK_ITEMS'),
 ('ACT-WORK_ITEMS_UPDATE_RESOURCE-V1','work-items','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_WORK_ITEMS'),
 ('ACT-OPERATIONS_UPDATE_CLAIM-V1','work-item','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_WORK_ITEM'),
 ('ACT-OPERATIONS_UPDATE_COMPLETE-V1','work-item','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_WORK_ITEM'),
 ('ACT-POLICY_READ_EFFECTIVE_ACCESS-V1','policy','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','POLICY_EVALUATION'),
 ('ACT-MODULES_CREATE_RESOURCE-V1','modules','CREATE','HIGH',true,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','CREATE_MODULES'),
 ('ACT-MODULE_CREATE_INSTALL-V1','module','CREATE','HIGH',true,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','CREATE_MODULE'),
 ('ACT-MODULE_ACTIVATE_RESOURCE-V1','module','ACTIVATE','HIGH',true,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','ACTIVATE_MODULE'),
 ('ACT-MODULES_UPDATE_RESOURCE-V1','modules','UPDATE','HIGH',true,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','UPDATE_MODULES'),
 ('ACT-MODULES_READ_RESOURCE-V1','modules','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_MODULES'),
 ('ACT-MODULES_READ_COLLECTION-V1','modules','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_MODULES'),
 ('ACT-ABI_ARTIFACTS_CREATE_RESOURCE-V1','abi-artifact','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RUNTIME_CONFIGURATION_MUTATION'),
 ('ACT-ABI_ARTIFACTS_READ_RESOURCE-V1','abi-artifact','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RUNTIME_CONFIGURATION_READ'),
 ('ACT-LOGICAL_CONTRACT_ASSETS_CREATE_RESOURCE-V1','logical-contract-asset','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RUNTIME_CONFIGURATION_MUTATION'),
 ('ACT-LOGICAL_CONTRACT_ASSETS_READ_RESOURCE-V1','logical-contract-asset','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RUNTIME_CONFIGURATION_READ'),
 ('ACT-CONTRACT_RUNTIME_BINDINGS_CREATE_RESOURCE-V1','contract-runtime-binding','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RUNTIME_CONFIGURATION_MUTATION'),
 ('ACT-CONTRACT_RUNTIME_BINDINGS_READ_RESOURCE-V1','contract-runtime-binding','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RUNTIME_CONFIGURATION_READ'),
 ('ACT-TYPED_ARGUMENT_RULE_VERSIONS_CREATE_RESOURCE-V1','typed-argument-rule-version','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RUNTIME_CONFIGURATION_MUTATION'),
 ('ACT-TYPED_ARGUMENT_RULE_VERSIONS_READ_RESOURCE-V1','typed-argument-rule-version','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RUNTIME_CONFIGURATION_READ'),
 ('ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1','contract-method-policy','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RUNTIME_CONFIGURATION_MUTATION'),
 ('ACT-CONTRACT_METHOD_POLICIES_READ_RESOURCE-V1','contract-method-policy','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','RUNTIME_CONFIGURATION_READ'),
 ('ACT-RUNTIME_READ_RPC-V1','runtime-rpc','READ','LOW',false,false,false,'NONE','AUTHORIZED_MINIMAL','READ_RUNTIME_RPC'),
 ('ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1','provider-profiles','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CREATE_PROVIDER_PROFILES'),
 ('ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1','provider-profiles','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_PROVIDER_PROFILES'),
 ('ACT-PROVIDER_PROFILES_READ_RESOURCE-V1','provider-profiles','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_PROVIDER_PROFILES'),
 ('ACT-PROVIDER_PROFILES_READ_COLLECTION-V1','provider-profiles','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_PROVIDER_PROFILES'),
 ('ACT-PROVIDER_APPROVE_QUALIFICATION-V1','provider-profile','APPROVE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','APPROVE_PROVIDER_PROFILE'),
 ('ACT-PROVIDER_UPDATE_QUARANTINE-V1','provider-profile','UPDATE','HIGH',false,true,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_PROVIDER_PROFILE'),
 ('ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1','indexer-profiles','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','CREATE_INDEXER_PROFILES'),
 ('ACT-INDEXER_PROFILES_UPDATE_RESOURCE-V1','indexer-profiles','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_INDEXER_PROFILES'),
 ('ACT-INDEXER_PROFILES_READ_RESOURCE-V1','indexer-profiles','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_INDEXER_PROFILES'),
 ('ACT-INDEXER_PROFILES_READ_COLLECTION-V1','indexer-profiles','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_INDEXER_PROFILES'),
 ('ACT-INDEXER_APPROVE_PROFILE-V1','indexer-profile','APPROVE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','APPROVE_INDEXER_PROFILE'),
 ('ACT-PROJECTION_PLANS_CREATE_RESOURCE-V1','projection-plans','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','CREATE_PROJECTION_PLANS'),
 ('ACT-PROJECTION_PLANS_UPDATE_RESOURCE-V1','projection-plans','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_PROJECTION_PLANS'),
 ('ACT-PROJECTION_PLANS_READ_RESOURCE-V1','projection-plans','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_PROJECTION_PLANS'),
 ('ACT-PROJECTION_PLANS_READ_COLLECTION-V1','projection-plans','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_PROJECTION_PLANS'),
 ('ACT-INDEXER_RECOVER_PLAN-V1','projection-plan','RECOVER','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','RECOVER_PROJECTION_PLAN'),
 ('ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1','runtime-targets','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','CREATE_RUNTIME_TARGETS'),
 ('ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1','runtime-targets','UPDATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','UPDATE_RUNTIME_TARGETS'),
 ('ACT-RUNTIME_TARGETS_READ_RESOURCE-V1','runtime-targets','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_RUNTIME_TARGETS'),
 ('ACT-RUNTIME_TARGETS_READ_COLLECTION-V1','runtime-targets','READ','LOW',false,false,false,'FULL','AUTHORIZED_FULL','READ_RUNTIME_TARGETS'),
 ('ACT-OPERATIONS_READ_OPERATION-V1','operations','READ','LOW',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','READ_OPERATIONS'),
 ('ACT-RUNTIME_CONFIGURATION_GENERATIONS_CREATE_RESOURCE-V1','runtime-configuration-generation','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','STAGE_RUNTIME_CONFIGURATION'),
 ('ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1','runtime-configuration-generation','ACTIVATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','ACTIVATE_RUNTIME_CONFIGURATION')
ON CONFLICT (action_intent_id) DO UPDATE SET
  resource_type=excluded.resource_type,
  operation_class=excluded.operation_class,
  risk_class=excluded.risk_class,
  maker_checker_required=excluded.maker_checker_required,
  step_up_required=excluded.step_up_required,
  idempotency_required=excluded.idempotency_required,
  existence_disclosure=excluded.existence_disclosure,
  payload_disclosure=excluded.payload_disclosure,
  evidence_class=excluded.evidence_class;
\if :initial_fixture
INSERT INTO control.authority_envelope(
  authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
  authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,
  semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,
  risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
VALUES(
  '018f0000-0000-7000-8000-000000000121','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000111',
  '018f0000-0000-7000-8000-000000000112',1,1,'ACTIVE',clock_timestamp()-interval '1 hour',null,
  decode('a0','hex'),decode(repeat('a1',32),'hex'),decode('d28440a04040','hex'),
  array['018f0000-0000-7000-8000-000000000201']::text[],array[
    'ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1',
    'ACT-POLICY_SETS_CREATE_RESOURCE-V1','ACT-POLICY_SETS_READ_COLLECTION-V1','ACT-POLICY_SETS_READ_RESOURCE-V1',
    'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1','ACT-POLICY_VERSIONS_READ_COLLECTION-V1','ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
    'ACT-POLICY_CREATE_SIMULATION-V1','ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1','ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
    'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1',
    'ACT-WORK_ITEMS_CREATE_RESOURCE-V1','ACT-WORK_ITEMS_READ_COLLECTION-V1',
    'ACT-WORK_ITEMS_READ_RESOURCE-V1','ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
    'ACT-OPERATIONS_UPDATE_CLAIM-V1','ACT-OPERATIONS_UPDATE_COMPLETE-V1',
    'ACT-POLICY_ACTIVATE_RELEASE-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    'ACT-MODULES_CREATE_RESOURCE-V1','ACT-MODULES_READ_RESOURCE-V1','ACT-MODULES_READ_COLLECTION-V1',
    'ACT-MODULE_CREATE_INSTALL-V1','ACT-MODULE_ACTIVATE_RESOURCE-V1',
    'ACT-ABI_ARTIFACTS_CREATE_RESOURCE-V1','ACT-ABI_ARTIFACTS_READ_RESOURCE-V1',
    'ACT-LOGICAL_CONTRACT_ASSETS_CREATE_RESOURCE-V1','ACT-LOGICAL_CONTRACT_ASSETS_READ_RESOURCE-V1',
    'ACT-CONTRACT_RUNTIME_BINDINGS_CREATE_RESOURCE-V1','ACT-CONTRACT_RUNTIME_BINDINGS_READ_RESOURCE-V1',
    'ACT-TYPED_ARGUMENT_RULE_VERSIONS_CREATE_RESOURCE-V1','ACT-TYPED_ARGUMENT_RULE_VERSIONS_READ_RESOURCE-V1',
    'ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1','ACT-CONTRACT_METHOD_POLICIES_READ_RESOURCE-V1',
    'ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1','ACT-DEPLOYMENT_POLICIES_READ_RESOURCE-V1',
    'ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1','ACT-DEPLOYMENT_INTENTS_READ_RESOURCE-V1',
    'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1','ACT-DEPLOYMENT_SUBMISSIONS_READ_RESOURCE-V1',
    'ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1','ACT-NATIVE_VALUE_AUTHORIZATIONS_READ_RESOURCE-V1'
  ]::text[],array['*']::text[],array['LOW','STANDARD','HIGH']::text[],true,false,0)
ON CONFLICT (authority_envelope_id) DO NOTHING;

-- Local first trust for actor-facing contract reads. The workload assignment is
-- created through the Participant owner after its mTLS identity exists.
INSERT INTO control.authority_envelope(
  authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
  authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,
  semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,runtime_capability_ids,
  resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
VALUES(
  '018f0000-0000-7000-8000-000000000123','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000111',
  '018f0000-0000-7000-8000-000000000112',1,1,'ACTIVE',clock_timestamp()-interval '1 hour',null,
  decode('a0','hex'),decode(repeat('a5',32),'hex'),decode('d28440a04040','hex'),
  array['018f0000-0000-7000-8000-000000000201']::text[],array[]::text[],
  array['CALL_RESULT_DISCLOSURE']::text[],array['*']::text[],array['LOW']::text[],
  false,false,0)
ON CONFLICT (authority_envelope_id) DO NOTHING;
-- Separate initial source trust. This creates no role or workload assignment;
-- source access must be issued by the governed public Participant owners.
INSERT INTO control.authority_envelope(
  authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
  authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,
  semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,
  risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
VALUES(
  '018f0000-0000-7000-8000-000000000125','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000111',
  '018f0000-0000-7000-8000-000000000112',1,1,'ACTIVE',clock_timestamp()-interval '1 hour',null,
  decode('a0','hex'),decode(repeat('a6',32),'hex'),decode('d28440a04040','hex'),
  array['018f0000-0000-7000-8000-000000000201']::text[],array['ACT-RUNTIME_READ_RPC-V1','ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1']::text[],
  array['*']::text[],array['LOW','STANDARD']::text[],false,false,0)
ON CONFLICT (authority_envelope_id) DO UPDATE
SET action_intent_ids=excluded.action_intent_ids,risk_classes=excluded.risk_classes;
-- Explicit local Fact admission trust; retained unbound envelopes stay immutable.
INSERT INTO control.platform_context(platform_context_id,owner_participant_id,state,authority_epoch,row_version)
VALUES ('018f0000-0000-7000-8000-000000000135','018f0000-0000-7000-8000-000000000101','ACTIVE',1,1)
ON CONFLICT (platform_context_id) DO NOTHING;
INSERT INTO control.authority_envelope(
  authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
  authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,
  semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,
  risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,
  platform_context_id,platform_authority_epoch)
SELECT '018f0000-0000-7000-8000-000000000136',participant_id,principal_id,maker_principal_id,checker_principal_id,
  authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,
  decode(repeat('a7',32),'hex'),cose_sign1,privacy_domain_ids,
  array['ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1']::text[],resource_ids,
  array['STANDARD']::text[],false,false,0,'018f0000-0000-7000-8000-000000000135',1
FROM control.authority_envelope WHERE authority_envelope_id='018f0000-0000-7000-8000-000000000125'
ON CONFLICT (authority_envelope_id) DO NOTHING;
-- Separate local Explorer trust. Keep existing roles and grants immutable;
-- the journey must create the operator assignment through public governance.
INSERT INTO control.authority_envelope(
  authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
  authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,
  semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,
  risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,
  platform_context_id,platform_authority_epoch)
SELECT '018f0000-0000-7000-8000-000000000139',participant_id,principal_id,maker_principal_id,checker_principal_id,
  authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,
  decode(repeat('a9',32),'hex'),cose_sign1,privacy_domain_ids,
  array['ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1','ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1',
    'ACT-PRIVACY_EXPLORER_PROFILES_READ_RESOURCE-V1','ACT-PRIVACY_EXPLORER_READ_PROJECTION-V1',
    'ACT-PRIVACY_EXPLORER_READ_OCCURRENCE-V1']::text[],resource_ids,
  array['LOW','STANDARD','HIGH']::text[],true,false,0,platform_context_id,platform_authority_epoch
FROM control.authority_envelope WHERE authority_envelope_id='018f0000-0000-7000-8000-000000000136'
ON CONFLICT (authority_envelope_id) DO NOTHING;
INSERT INTO control.authority_role
 (authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
SELECT '018f0000-0000-7000-8000-000000000805',participant_id,
 'urn:openpc:role:018f0000-0000-7000-8000-000000000805','Local Explorer operator',action_intent_ids,
 'BOOTSTRAP','018f0000-0000-7000-8000-000000000111'
FROM control.authority_envelope WHERE authority_envelope_id='018f0000-0000-7000-8000-000000000139'
ON CONFLICT (participant_id,role_id) DO NOTHING;
-- End local Explorer initial trust.
UPDATE control.authority_envelope
SET action_intent_ids=array(
  SELECT DISTINCT value FROM unnest(action_intent_ids || ARRAY[
    'ACT-RUNTIME_READ_RPC-V1',
    'ACT-IDENTITY_UPDATE_STEP_UP-V1',
    'ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1',
    'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',
    'ACT-FACT_ARTIFACTS_READ_COLLECTION-V1','ACT-FACT_ARTIFACTS_READ_RESOURCE-V1',
    'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1','ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
    'ACT-PARTICIPANTS_CREATE_RESOURCE-V1','ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
    'ACT-PARTICIPANTS_READ_COLLECTION-V1','ACT-PARTICIPANTS_READ_RESOURCE-V1',
    'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-PARTICIPANT_CREATE_MEMBER-V1',
    'ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1','ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1',
    'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1','ACT-PROVIDER_PROFILES_READ_COLLECTION-V1',
    'ACT-PROVIDER_APPROVE_QUALIFICATION-V1','ACT-PROVIDER_UPDATE_QUARANTINE-V1',
    'ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1','ACT-INDEXER_PROFILES_UPDATE_RESOURCE-V1',
    'ACT-INDEXER_PROFILES_READ_RESOURCE-V1','ACT-INDEXER_PROFILES_READ_COLLECTION-V1',
    'ACT-INDEXER_APPROVE_PROFILE-V1','ACT-PROJECTION_PLANS_CREATE_RESOURCE-V1',
    'ACT-PROJECTION_PLANS_UPDATE_RESOURCE-V1','ACT-PROJECTION_PLANS_READ_RESOURCE-V1',
    'ACT-PROJECTION_PLANS_READ_COLLECTION-V1','ACT-INDEXER_RECOVER_PLAN-V1',
    'ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1','ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',
    'ACT-RUNTIME_TARGETS_READ_RESOURCE-V1','ACT-RUNTIME_TARGETS_READ_COLLECTION-V1',
    'ACT-OPERATIONS_READ_OPERATION-V1',
    'ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1','ACT-CIGL_SETTINGS_READ_RESOURCE-V1',
    'ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1','ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1',
    'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1','ACT-CIGL_ANALYSES_READ_RESOURCE-V1',
    'ACT-CIGL_GRANTS_CREATE_RESOURCE-V1','ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1',
    'ACT-CIGL_GRANTS_READ_RESOURCE-V1','ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1',
    'ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1','ACT-SIGNING_KEY_ROTATIONS_READ_COLLECTION-V1',
    'ACT-SIGNING_KEY_ROTATIONS_READ_RESOURCE-V1','ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',
    'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1','ACT-SIGNING_KEYS_READ_COLLECTION-V1',
    'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1','ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1',
    'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1','ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
    'ACT-POLICY_APPROVE_REQUEST-V1',
    'ACT-RELEASE_BUNDLES_CREATE_RESOURCE-V1','ACT-RELEASE_BUNDLES_READ_COLLECTION-V1',
    'ACT-RELEASE_BUNDLES_READ_RESOURCE-V1','ACT-RELEASE_BUNDLES_UPDATE_RESOURCE-V1',
    'ACT-POLICY_ACTIVATE_PUBLISH-V1',
    'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1',
    'ACT-ACTIVATION_OCCURRENCES_READ_COLLECTION-V1',
    'ACT-ACTIVATION_OCCURRENCES_READ_RESOURCE-V1',
    'ACT-ACTIVATION_OCCURRENCES_UPDATE_RESOURCE-V1',
    'ACT-POLICY_ACTIVATE_RELEASE-V1','ACT-FLEET_RECOVER_OCCURRENCE-V1',
    'ACT-POLICY_ROLLBACK_RELEASE-V1',
    'ACT-WORK_ITEMS_CREATE_RESOURCE-V1','ACT-WORK_ITEMS_READ_COLLECTION-V1',
    'ACT-WORK_ITEMS_READ_RESOURCE-V1','ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
    'ACT-OPERATIONS_UPDATE_CLAIM-V1','ACT-OPERATIONS_UPDATE_COMPLETE-V1',
    'ACT-RUNTIME_CONFIGURATION_GENERATIONS_CREATE_RESOURCE-V1',
    'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',
    'ACT-MODULE_CREATE_INSTALL-V1','ACT-MODULE_ACTIVATE_RESOURCE-V1'
  ]::text[]) AS value ORDER BY value)
WHERE authority_envelope_id='018f0000-0000-7000-8000-000000000121';
-- Materialize the administrative role named by the local initial-trust assignment.
-- Evidence catalogue reads are initial trust only. Keep a retained governance
-- role immutable; these two read capabilities have their own narrow assignment.
INSERT INTO control.authority_role
 (authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
VALUES
 ('018f0000-0000-7000-8000-000000000806','018f0000-0000-7000-8000-000000000101',
  'urn:openpc:role:018f0000-0000-7000-8000-000000000806','Local evidence catalogue reader',
  array['ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1','ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1']::text[],
  'BOOTSTRAP','018f0000-0000-7000-8000-000000000111')
ON CONFLICT (participant_id,role_id) DO NOTHING;
INSERT INTO control.assignment(
  assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
  scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,
  action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
  onward_delegation_depth,role_id)
VALUES(
  '018f0000-0000-7000-8000-000000000128','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000121',1,
  decode(repeat('a8',32),'hex'),tstzrange(clock_timestamp()-interval '1 hour',null,'[)'),
  'ACTIVE','018f0000-0000-7000-8000-000000000111',
  array['018f0000-0000-7000-8000-000000000201']::text[],
  array['ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1','ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1']::text[],
  array['*']::text[],array['LOW']::text[],false,false,0,
  'urn:openpc:role:018f0000-0000-7000-8000-000000000806')
ON CONFLICT (assignment_id) DO NOTHING;
INSERT INTO control.authority_role
 (authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
SELECT '018f0000-0000-7000-8000-000000000801',participant_id,
 'urn:openpc:role:018f0000-0000-7000-8000-000000000801','Local governance operator',action_intent_ids,
 'BOOTSTRAP','018f0000-0000-7000-8000-000000000111'
FROM control.authority_envelope WHERE authority_envelope_id='018f0000-0000-7000-8000-000000000121'
ON CONFLICT (participant_id,role_id) DO NOTHING;
-- Fact artifact reads are local first trust used by the authenticated Workbench.
-- Keep the retained governance role immutable and issue the two read actions
-- through their own role and assignment under the existing trusted envelope.
INSERT INTO control.authority_role
 (authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
VALUES
 ('018f0000-0000-7000-8000-000000000802','018f0000-0000-7000-8000-000000000101',
  'urn:openpc:role:018f0000-0000-7000-8000-000000000802','Local Fact artifact reader',
  array['ACT-FACT_ARTIFACTS_READ_COLLECTION-V1','ACT-FACT_ARTIFACTS_READ_RESOURCE-V1']::text[],
  'BOOTSTRAP','018f0000-0000-7000-8000-000000000111')
ON CONFLICT (participant_id,role_id) DO NOTHING;
INSERT INTO control.assignment(
  assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
  scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,
  action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
  onward_delegation_depth,role_id)
VALUES(
  '018f0000-0000-7000-8000-000000000127','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000121',1,
  decode(repeat('a7',32),'hex'),tstzrange(clock_timestamp()-interval '1 hour',null,'[)'),
  'ACTIVE','018f0000-0000-7000-8000-000000000111',
  array['018f0000-0000-7000-8000-000000000201']::text[],
  array['ACT-FACT_ARTIFACTS_READ_COLLECTION-V1','ACT-FACT_ARTIFACTS_READ_RESOURCE-V1']::text[],
  array['*']::text[],array['LOW']::text[],false,false,0,
  'urn:openpc:role:018f0000-0000-7000-8000-000000000802')
ON CONFLICT (assignment_id) DO NOTHING;
INSERT INTO control.assignment(
  assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
  scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,
  action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
  onward_delegation_depth,role_id)
SELECT
  '018f0000-0000-7000-8000-000000000122','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000121',1,
  decode(repeat('a2',32),'hex'),tstzrange(clock_timestamp()-interval '1 hour',null,'[)'),
  'ACTIVE','018f0000-0000-7000-8000-000000000111',
  array['018f0000-0000-7000-8000-000000000201']::text[],array[
    'ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1',
    'ACT-POLICY_SETS_CREATE_RESOURCE-V1','ACT-POLICY_SETS_READ_COLLECTION-V1','ACT-POLICY_SETS_READ_RESOURCE-V1',
    'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1','ACT-POLICY_VERSIONS_READ_COLLECTION-V1','ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
    'ACT-POLICY_CREATE_SIMULATION-V1','ACT-POLICY_APPROVE_REQUEST-V1',
    'ACT-POLICY_ACTIVATE_RELEASE-V1','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    'ACT-MODULES_CREATE_RESOURCE-V1','ACT-MODULES_READ_RESOURCE-V1','ACT-MODULES_READ_COLLECTION-V1',
    'ACT-MODULE_CREATE_INSTALL-V1','ACT-MODULE_ACTIVATE_RESOURCE-V1',
    'ACT-ABI_ARTIFACTS_CREATE_RESOURCE-V1','ACT-ABI_ARTIFACTS_READ_RESOURCE-V1',
    'ACT-LOGICAL_CONTRACT_ASSETS_CREATE_RESOURCE-V1','ACT-LOGICAL_CONTRACT_ASSETS_READ_RESOURCE-V1',
    'ACT-CONTRACT_RUNTIME_BINDINGS_CREATE_RESOURCE-V1','ACT-CONTRACT_RUNTIME_BINDINGS_READ_RESOURCE-V1',
    'ACT-TYPED_ARGUMENT_RULE_VERSIONS_CREATE_RESOURCE-V1','ACT-TYPED_ARGUMENT_RULE_VERSIONS_READ_RESOURCE-V1',
    'ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1','ACT-CONTRACT_METHOD_POLICIES_READ_RESOURCE-V1',
    'ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1','ACT-DEPLOYMENT_POLICIES_READ_RESOURCE-V1',
    'ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1','ACT-DEPLOYMENT_INTENTS_READ_RESOURCE-V1',
    'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1','ACT-DEPLOYMENT_SUBMISSIONS_READ_RESOURCE-V1',
    'ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1','ACT-NATIVE_VALUE_AUTHORIZATIONS_READ_RESOURCE-V1'
  ]::text[],array['*']::text[],array['LOW','STANDARD','HIGH']::text[],true,false,0,'urn:openpc:role:018f0000-0000-7000-8000-000000000801'
WHERE NOT EXISTS (SELECT FROM control.assignment WHERE assignment_id='018f0000-0000-7000-8000-000000000122')
ON CONFLICT (assignment_id) DO NOTHING;
UPDATE control.assignment
-- Retained roles are immutable. Refresh only capabilities already in that
-- bootstrap role; new workload roles still use the public issuance owner.
SET action_intent_ids=ARRAY(SELECT capability FROM control.authority_envelope envelope,
  unnest(envelope.action_intent_ids) capability
  WHERE envelope.authority_envelope_id='018f0000-0000-7000-8000-000000000121'
    -- Dedicated read assignments remain the sole authority path on both a
    -- fresh store and a retained store with an older immutable governance role.
    AND capability<>ALL(ARRAY['ACT-FACT_ARTIFACTS_READ_COLLECTION-V1','ACT-FACT_ARTIFACTS_READ_RESOURCE-V1',
      'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1','ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1']::text[])
    AND EXISTS(SELECT FROM control.authority_role role
      WHERE role.participant_id=control.assignment.participant_id
        AND role.role_id=control.assignment.role_id AND role.state='ACTIVE'
        AND capability=ANY(role.action_intent_ids)))
WHERE assignment_id='018f0000-0000-7000-8000-000000000122' AND state='ACTIVE';
INSERT INTO control.authority_envelope(
  authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
  authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,
  semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,
  risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
SELECT
  '018f0000-0000-7000-8000-000000000131','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000112','018f0000-0000-7000-8000-000000000111',
  '018f0000-0000-7000-8000-000000000112',1,1,'ACTIVE',clock_timestamp()-interval '1 hour',null,
  decode('a0','hex'),decode(repeat('a3',32),'hex'),decode('d28440a04040','hex'),
  array['018f0000-0000-7000-8000-000000000201']::text[],
  -- The checker must hold the target mutation as well as approval authority.
  -- Initial trust only: never rewrite a retained grant or historical approval.
  action_intent_ids || array[
    'ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1',
    'ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1'
  ]::text[],
  array['*']::text[],array['LOW','STANDARD','HIGH']::text[],true,true,0
FROM control.authority_envelope
WHERE authority_envelope_id='018f0000-0000-7000-8000-000000000121'
ON CONFLICT (authority_envelope_id) DO NOTHING;
INSERT INTO control.assignment(
  assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
  scope_digest,valid_during,state,created_by_principal_id,privacy_domain_ids,
  action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
  onward_delegation_depth)
SELECT
  '018f0000-0000-7000-8000-000000000132','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000112','018f0000-0000-7000-8000-000000000131',1,
  decode(repeat('a4',32),'hex'),tstzrange(clock_timestamp()-interval '1 hour',null,'[)'),
  'ACTIVE','018f0000-0000-7000-8000-000000000111',privacy_domain_ids,
  action_intent_ids,resource_ids,risk_classes,true,true,0
FROM control.authority_envelope
WHERE authority_envelope_id='018f0000-0000-7000-8000-000000000131'
ON CONFLICT (assignment_id) DO NOTHING;
\endif
SQL
    ;;
  fact)
    if [ "$roles_only" = 1 ]; then
      # Prepare only an isolated empty restore target. Original schema, data,
      # verifier secrets and migration ledger must come from its exact archive.
      # Keep the check and role changes in one transaction so rejection cannot
      # leave a partially installed role catalogue.
      runtime_password="$(cat /run/secrets/fact_runtime_db_password)"
      reader_password="$(cat /run/secrets/policy_fact_db_password)"
      [ -n "$runtime_password" ] && [ -n "$reader_password" ] || {
        echo 'fact restore runtime secret is empty' >&2; exit 1;
      }
      OPENPC_FACT_RESTORE_PASSWORD="$runtime_password" \
      OPENPC_POLICY_FACT_RESTORE_PASSWORD="$reader_password" psql_base -1 <<'SQL'
DO $restore$ BEGIN
 IF current_database()<>'openpc_facts'
   OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema')
   OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND nspname NOT IN ('public','information_schema'))
   OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')
   OR EXISTS(SELECT 1 FROM pg_database WHERE datname NOT IN ('postgres','template0','template1','openpc_facts'))
 THEN RAISE EXCEPTION 'fact roles-only restore target must be empty openpc_facts'; END IF;
END $restore$;
-- These names and attributes are owned by SQLx Fact migrations 0001/0002.
-- Existing roles are not repaired or granted new authority by restore setup.
CREATE ROLE openpc_facts_lifecycle_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_facts_capability_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_fact_bridge_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_candidate_index_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_policy_fact_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_fact_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_policy_fact_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\getenv runtime_password OPENPC_FACT_RESTORE_PASSWORD
\getenv reader_password OPENPC_POLICY_FACT_RESTORE_PASSWORD
ALTER ROLE openpc_fact_runtime PASSWORD :'runtime_password';
ALTER ROLE openpc_policy_fact_runtime PASSWORD :'reader_password';
GRANT openpc_fact_bridge_writer TO openpc_fact_runtime;
GRANT openpc_policy_fact_reader TO openpc_policy_fact_runtime;
GRANT CONNECT ON DATABASE openpc_facts TO openpc_fact_runtime,openpc_policy_fact_runtime;
SQL
      exit 0
    fi
    ensure_ledger
    apply_file /migrations/postgres/common-primitives.sql
    for path in /migrations/postgres/facts/[0-9][0-9][0-9][0-9]_*.sql; do apply_file "$path"; done
    capability_secret="$(cat /run/secrets/fact_capability_secret)"
    psql_base -v capability_secret="$capability_secret" <<'SQL'
INSERT INTO facts.mutation_capability_secret(secret_version,verifier_secret)
VALUES (1,decode(:'capability_secret','hex')) ON CONFLICT (secret_version) DO NOTHING;
SQL
    installed="$(psql_base -At -c 'SELECT encode(verifier_secret,'\''hex'\'') FROM facts.mutation_capability_secret WHERE secret_version=1')"
    [ "$installed" = "$capability_secret" ] || { echo "fact capability secret drift" >&2; exit 1; }
    runtime_password="$(cat /run/secrets/fact_runtime_db_password)"
    reader_password="$(cat /run/secrets/policy_fact_db_password)"
    psql_base <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_fact_runtime') THEN
    CREATE ROLE openpc_fact_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_policy_fact_runtime') THEN
    CREATE ROLE openpc_policy_fact_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END \$\$;
ALTER ROLE openpc_fact_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$runtime_password';
GRANT openpc_fact_bridge_writer TO openpc_fact_runtime;
GRANT CONNECT ON DATABASE openpc_facts TO openpc_fact_runtime;
ALTER ROLE openpc_policy_fact_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$reader_password';
GRANT openpc_policy_fact_reader TO openpc_policy_fact_runtime;
GRANT CONNECT ON DATABASE openpc_facts TO openpc_policy_fact_runtime;
SQL
    ;;
  candidate_index)
    if [ "$roles_only" = 0 ]; then
      ensure_ledger
    else
      # Restore preparation only. Never touch a populated source or silently
      # migrate/seed a target whose original archive has not been restored yet.
      psql_base <<'SQL'
DO $restore$ BEGIN
 IF current_database()<>'openpc_candidate_index'
   OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema')
   OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND nspname NOT IN ('public','information_schema'))
   OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')
   OR EXISTS(SELECT 1 FROM pg_database WHERE datname NOT IN ('postgres','template0','template1','openpc_candidate_index'))
 THEN RAISE EXCEPTION 'candidate roles-only restore target must be empty openpc_candidate_index'; END IF;
END $restore$;
SQL
    fi
    psql_base <<'SQL'
DO $roles$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_candidate_index') THEN CREATE ROLE openpc_candidate_index NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_candidate_index_owner') THEN CREATE ROLE openpc_candidate_index_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_indexer_manager') THEN CREATE ROLE openpc_indexer_manager NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_indexer_writer') THEN CREATE ROLE openpc_indexer_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_fact_bridge_reader') THEN CREATE ROLE openpc_fact_bridge_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_candidate_index_reader') THEN CREATE ROLE openpc_candidate_index_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_candidate_index_maintenance') THEN CREATE ROLE openpc_candidate_index_maintenance NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='openpc_backup_operator') THEN CREATE ROLE openpc_backup_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF;
END $roles$;
GRANT openpc_candidate_index_owner TO openpc_candidate_index;
ALTER DATABASE openpc_candidate_index OWNER TO openpc_candidate_index_owner;
SQL
    if [ "$roles_only" = 0 ]; then
      for path in /migrations/postgres/candidate-index/[0-9][0-9][0-9][0-9]_*.sql; do
        digest="$(sha256sum "$path" | cut -d ' ' -f 1)"
        prior="$(ledger_digest "$path")"
        if [ -n "$prior" ]; then
          [ "$prior" = "$digest" ] || { echo "migration digest drift: $path" >&2; exit 1; }
          continue
        fi
        commit_count="$(awk '$0 == "COMMIT;" { count += 1 } END { print count + 0 }' "$path")"
        [ "$commit_count" = 1 ] || {
          echo "candidate-index migration must contain exactly one transaction commit: $path" >&2
          exit 1
        }
        awk -v ledger_insert="INSERT INTO openpc_local.migration(path,sha256) VALUES (:'path',:'digest');" '
          $0 == "COMMIT;" { print "RESET ROLE;"; print ledger_insert }
          { print }
        ' "$path" | (
          cd "$(dirname "$path")"
          psql_base \
            -v "openpc_migration_checksum=sha256:$digest" \
            -v openpc_migration_profile=MIG-GREENFIELD-V1 \
            -v path="$path" -v digest="$digest"
        )
      done
    fi
    # A runtime identity is enabled only when its own installation secret is
    # supplied. The manager, candidate writer, Fact Bridge and archive readers retain
    # independent credentials and the migration's exact least privileges.
    for runtime_identity in indexer_manager indexer_writer fact_bridge_reader candidate_index_reader; do
      secret_file="/run/secrets/${runtime_identity}_db_password"
      if [ -f "$secret_file" ]; then
        runtime_password="$(cat "$secret_file")"
        [ -n "$runtime_password" ] || { echo "candidate runtime secret is empty" >&2; exit 1; }
        OPENPC_CANDIDATE_RUNTIME_PASSWORD="$runtime_password" psql_base -v "runtime_role=openpc_$runtime_identity" <<'SQL'
\getenv runtime_password OPENPC_CANDIDATE_RUNTIME_PASSWORD
ALTER ROLE :"runtime_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'runtime_password';
GRANT CONNECT ON DATABASE openpc_candidate_index TO :"runtime_role";
SQL
      fi
    done
    [ "$roles_only" = 0 ] || exit 0
    # A distinct host verifier key admits candidate retirement. Fact capability
    # material is never reused across these target stores. Missing installation
    # material leaves the owner inactive; a supplied replacement cannot silently
    # change immutable trust in a populated database.
    if [ -f /run/secrets/candidate_retirement_capability_secret ]; then
      candidate_capability_secret="$(cat /run/secrets/candidate_retirement_capability_secret)"
      printf '%s' "$candidate_capability_secret" | grep -Eq '^[0-9a-f]{64}$' || {
        echo 'invalid candidate retirement capability secret' >&2; exit 1;
      }
      psql_base -v capability_secret="$candidate_capability_secret" <<'SQL'
INSERT INTO candidate.retirement_capability_secret(secret_version,verifier_secret)
VALUES(1,decode(:'capability_secret','hex')) ON CONFLICT(secret_version) DO NOTHING;
SQL
      installed="$(psql_base -At -v capability_secret="$candidate_capability_secret" <<'SQL'
SELECT verifier_secret=decode(:'capability_secret','hex') FROM candidate.retirement_capability_secret WHERE secret_version=1;
SQL
)"
      [ "$installed" = t ] || { echo 'candidate retirement capability secret drift' >&2; exit 1; }
    fi
    ;;
  *) echo "unknown migration mode" >&2; exit 1 ;;
esac
