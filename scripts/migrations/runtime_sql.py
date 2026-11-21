"""Emit psql-only transaction entrypoints for the standard PostgreSQL image."""
import hashlib
import json
import re


def emit(base,record,catalog,query,helpers,normalize,quote,lineage,wire,restore_wire):
    (base/'catalog.sql').write_text(query)
    (base/'catalog-helpers.sql').write_text(helpers)
    (base/'normalize.sql').write_text(normalize)
    query=query.replace('SET search_path=pg_catalog;','').strip().rstrip(';')
    legacy=json.loads((base/'legacy-package.json').read_text())
    expected={('/'+path):item['sha256'] for path,item in legacy['files'].items()
              if re.fullmatch(r'migrations/postgres/(identity|control-api|policy)/[0-9]{4}_[a-z_0-9-]+\.sql',path)}
    profiles=quote(json.dumps(record['catalog_profiles']))+'::jsonb'
    accepted=','.join(quote(p['wire_catalog_sha256']) for p in record['catalog_profiles'].values())
    verify=f"""\\ir catalog-helpers.sql
\\ir normalize.sql
SET search_path=pg_catalog;
DO $verify$ DECLARE actual text; BEGIN
 IF current_setting('server_version_num')<>'180006' OR current_database()<>'openpc_control'
 THEN RAISE EXCEPTION 'Verification requires PostgreSQL 18.6 and database openpc_control'; END IF;
 SELECT encode(sha256(convert_to(pg_temp.tegaris_catalog_canonical(j)::text,'UTF8')),'hex')
 INTO actual FROM ({query}) x(j);
 IF actual NOT IN ({accepted}) THEN RAISE EXCEPTION 'BASELINE-CATALOG-MISMATCH: %',actual; END IF;
 IF to_regclass('openpc_local.baseline_lineage') IS NOT NULL THEN
  IF (SELECT count(*) FROM openpc_local.baseline_lineage)<>1 OR NOT EXISTS(
   SELECT FROM openpc_local.baseline_lineage l JOIN jsonb_each({profiles}) profile ON profile.key=l.catalog_profile
   WHERE baseline_id={quote(record['baseline_id'])}
   AND source_commit={quote(record['source_commit'])}
   AND sql_sha256={quote(record['files']['control.sql'])}
   AND l.catalog_sha256=profile.value->>'catalog_sha256' AND actual=profile.value->>'wire_catalog_sha256'
   AND l.origin IN ('FRESH','LEGACY_HANDOFF'))
  THEN RAISE EXCEPTION 'BASELINE-LINEAGE-MISMATCH'; END IF;
  IF EXISTS(SELECT FROM openpc_local.baseline_lineage WHERE origin='FRESH') THEN
   IF EXISTS(SELECT FROM openpc_local.baseline_lineage WHERE catalog_profile<>'canonical')
   THEN RAISE EXCEPTION 'Fresh baseline has an unexpected catalogue profile'; END IF;
   IF EXISTS(SELECT FROM openpc_local.migration) THEN RAISE EXCEPTION 'Fresh baseline has unexpected legacy ledger entries'; END IF;
  ELSIF (SELECT jsonb_object_agg(path,sha256) FROM openpc_local.migration) IS DISTINCT FROM {quote(json.dumps(expected))}::jsonb
  THEN RAISE EXCEPTION 'Legacy handoff ledger drift'; END IF;
 END IF;
 IF EXISTS(SELECT FROM jsonb_array_elements({quote((base/'seeds.json').read_text())}::jsonb->'control.action_intent') e
  WHERE NOT EXISTS(SELECT FROM control.action_intent t WHERE to_jsonb(t)-'registered_at'=e))
 THEN RAISE EXCEPTION 'BASELINE-SEED-MISMATCH'; END IF;
END $verify$;
"""
    (base/'verify.sql').write_text(verify)
    guard="""SET LOCAL lock_timeout='5s';
DO $lock$ BEGIN
 IF current_setting('server_version_num')<>'180006' THEN RAISE EXCEPTION 'PostgreSQL 18.6 required'; END IF;
 IF current_database()<>'openpc_control' THEN RAISE EXCEPTION 'This baseline requires database openpc_control'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('tegaris-control-baseline-v1',0)) THEN RAISE EXCEPTION 'Another baseline migrator is active'; END IF;
END $lock$;
"""
    empty="""DO $empty$ BEGIN
 IF EXISTS(SELECT FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname !~ '^pg_')
 OR EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')
 OR EXISTS(SELECT FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')
 THEN RAISE EXCEPTION 'Baseline requires an empty database; use verified legacy upgrade/handoff'; END IF;
END $empty$;
"""
    role_signature={k:catalog[k] for k in ['roles','memberships']}
    role_guard=f"""DO $roles$ DECLARE actual jsonb; BEGIN
 IF EXISTS(SELECT FROM pg_roles WHERE oid<>10 AND starts_with(rolname,'openpc_')) THEN
 SELECT jsonb_build_object('roles',j->'roles','memberships',j->'memberships') INTO actual FROM ({query}) x(j);
 IF actual IS DISTINCT FROM {quote(json.dumps(role_signature))}::jsonb THEN RAISE EXCEPTION 'Existing cluster roles differ from validated baseline'; END IF;
 END IF; END $roles$;
"""
    (base/'install.sql').write_text('\\set ON_ERROR_STOP on\n\\set baseline_origin FRESH\nBEGIN;\n\\ir catalog-helpers.sql\n'+guard+empty+role_guard+'\n\\ir control.sql\n\\ir verify.sql\n'+lineage(record)+'\n\\ir verify.sql\nCOMMIT;\n')
    # pg_restore does not restore an extension's original owner. Provision the
    # pinned extension under its authenticated owner in an empty target, then
    # exclude only its CREATE EXTENSION TOC entry from the incoming archive.
    prepare='\\set ON_ERROR_STOP on\nBEGIN;\n\\ir catalog-helpers.sql\n'+guard+empty+role_guard+'\n\\ir roles.sql\n'
    prepare+='ALTER DATABASE openpc_control OWNER TO openpc_control_owner;\nSET ROLE openpc_control_owner;\nCREATE EXTENSION pgcrypto WITH SCHEMA public VERSION \'1.4\';\nRESET ROLE;\n\\ir database-acls.sql\nCOMMIT;\n'
    (base/'prepare-restore.sql').write_text(prepare)
    handoff=f"""LOCK TABLE openpc_local.migration IN SHARE ROW EXCLUSIVE MODE;
DO $ledger$ BEGIN
 IF (SELECT jsonb_object_agg(path,sha256) FROM openpc_local.migration) IS DISTINCT FROM {quote(json.dumps(expected))}::jsonb
 THEN RAISE EXCEPTION 'Legacy ledger is incomplete, modified or unrecognized; use verified compatibility package'; END IF;
END $ledger$;
"""
    (base/'handoff.sql').write_text('\\set ON_ERROR_STOP on\n\\set baseline_origin LEGACY_HANDOFF\nBEGIN;\n'+guard+'\n\\ir verify.sql\n'+handoff+lineage(record)+'\n\\ir verify.sql\nCOMMIT;\n')
    restore=f"""\\set ON_ERROR_STOP on
BEGIN;
{guard}
\\ir normalize.sql
\\ir catalog-helpers.sql
SET search_path=pg_catalog;
DO $restore$ DECLARE actual text; expected jsonb; BEGIN
 IF to_regclass('openpc_local.baseline_lineage') IS NULL THEN RAISE EXCEPTION 'Restore requires verified baseline lineage'; END IF;
 SELECT profile.value INTO expected FROM openpc_local.baseline_lineage l
 JOIN jsonb_each({profiles}) profile ON profile.key=l.catalog_profile
 WHERE baseline_id={quote(record['baseline_id'])} AND source_commit={quote(record['source_commit'])}
 AND sql_sha256={quote(record['files']['control.sql'])} AND l.catalog_sha256=profile.value->>'catalog_sha256';
 IF expected IS NULL OR (SELECT count(*) FROM openpc_local.baseline_lineage)<>1
 THEN RAISE EXCEPTION 'Restore requires verified baseline lineage'; END IF;
 SELECT encode(sha256(convert_to(pg_temp.tegaris_catalog_canonical(j)::text,'UTF8')),'hex') INTO actual FROM ({query}) x(j);
 IF actual<>expected->>'wire_catalog_sha256' AND actual<>expected->>'restore_wire_catalog_sha256'
 THEN RAISE EXCEPTION 'Unrecognized restore catalogue; no repair permitted'; END IF;
END $restore$;
SELECT encode(sha256(convert_to(pg_temp.tegaris_catalog_canonical(j)::text,'UTF8')),'hex') NOT IN ({accepted}) AS needs_restore FROM ({query}) x(j) \\gset
\\if :needs_restore
\\ir repairs.sql
\\endif
\\ir verify.sql
COMMIT;
"""
    (base/'restore.sql').write_text(restore)
    for name in ['catalog.sql','catalog-helpers.sql','normalize.sql','verify.sql','install.sql','handoff.sql','restore.sql','prepare-restore.sql']:
        record['files'][name]=hashlib.sha256((base/name).read_bytes()).hexdigest()
    record['wire_catalog_sha256']=wire
    record['restore_wire_catalog_sha256']=restore_wire
