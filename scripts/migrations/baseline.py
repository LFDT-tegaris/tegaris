#!/usr/bin/env python3
"""Explicit offline baseline build, verification and current-legacy handoff.

Connections use ordinary PG* variables. The proof driver supplies only its own
Unix socket. No automatic downloads, server starts, role password copies or
rewriting of historical migration ledger entries.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from source_repairs import extract as source_repairs, parser_variant
from runtime_sql import emit as emit_runtime
from catalog_profiles import private_policy_trigger

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'migrations/postgres/baseline-v1'
CATALOG = Path(__file__).with_name('catalog.sql')
HELPERS = Path(__file__).with_name('catalog-helpers.sql')
SOURCE = 'db5e64b566712e5213424db5e166775d9a15a7be'
BASELINE = 'tegaris-control-db5e64b-v1'


def sql(value, *, check=True):
    p = subprocess.run(['psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1'],
                       input=value, text=True, capture_output=True)
    if check and p.returncode:
        raise RuntimeError(p.stderr[-12000:])
    return p


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def ident(value):
    return '"' + value.replace('"','""') + '"'


def canonical(value):
    # ACL array order is not semantic and pg_dump may reorder its entries.
    if isinstance(value,list):
        return [canonical(v) for v in value]
    if isinstance(value,dict):
        return {k:canonical(v) for k,v in value.items()}
    if isinstance(value,str) and value.startswith('{') and value.endswith('}') and '=' in value and '/' in value:
        entries=[]
        for entry in value[1:-1].split(','):
            grantee,rights=entry.split('=',1); permissions,grantor=rights.rsplit('/',1)
            entries.append(grantee+'='+''.join(sorted(re.findall(r'[A-Za-z]\*?',permissions)))+'/'+grantor)
        return '{'+','.join(sorted(entries))+'}'
    return value


def serialized(value):
    return json.dumps(canonical(value),sort_keys=True,separators=(',',':'))


def fingerprint(value):
    return hashlib.sha256(serialized(value).encode()).hexdigest()


def snapshot():
    return canonical(json.loads(sql(HELPERS.read_text()+'\n'+CATALOG.read_text()).stdout))


def cleaned_dump(args):
    p=subprocess.run(['pg_dump','--no-password',*args],capture_output=True,text=True,check=True)
    return '\n'.join(line for line in p.stdout.splitlines()
                     if not line.startswith(('\\restrict ','\\unrestrict ','-- Dumped from','-- Dumped by')))+'\n'


def roles_sql(catalog):
    out=["SELECT rolname AS bootstrap_role FROM pg_roles WHERE oid=10 \\gset"]
    for row in catalog['roles']:
        name,sup,inherit,create_role,create_db,login,replicate,bypass,limit,until,config,comment=row
        if until is not None or config is not None:
            raise ValueError('Baseline cannot copy role-specific expirations or settings')
        flags=['SUPERUSER' if sup else 'NOSUPERUSER','INHERIT' if inherit else 'NOINHERIT',
               'CREATEROLE' if create_role else 'NOCREATEROLE','CREATEDB' if create_db else 'NOCREATEDB',
               'LOGIN' if login else 'NOLOGIN','REPLICATION' if replicate else 'NOREPLICATION',
               'BYPASSRLS' if bypass else 'NOBYPASSRLS','CONNECTION LIMIT '+str(limit)]
        statement='CREATE ROLE '+ident(name)+' WITH '+' '.join(flags)
        out.append('DO $roles$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='+quote(name)+') THEN EXECUTE '+quote(statement)+'; END IF; END $roles$;')
        if comment is not None:
            out.append('COMMENT ON ROLE '+ident(name)+' IS '+quote(comment)+';')
    for role,member,grantor,admin,inherit,can_set in catalog['memberships'] or []:
        role=':"bootstrap_role"' if role=='@bootstrap' else ident(role)
        member=':"bootstrap_role"' if member=='@bootstrap' else ident(member)
        grantor=':"bootstrap_role"' if grantor=='@bootstrap' else ident(grantor)
        out.append(f'GRANT {role} TO {member} WITH ADMIN {str(admin).upper()}, INHERIT {str(inherit).upper()}, SET {str(can_set).upper()} GRANTED BY {grantor};')
    return '\n'.join(out)+'\n'


def build(seed_tables,legacy_root=None):
    if seed_tables != ['control.action_intent']:
        raise ValueError('The complete public action-intent catalogue is required')
    if sql('SELECT current_database()').stdout.strip()!='openpc_control':
        raise ValueError('This baseline requires database openpc_control')
    version=int(sql('SHOW server_version_num').stdout)
    if version != 180006:
        raise ValueError('Build reference must use PostgreSQL 18.6')
    if sql("SELECT to_regclass('openpc_local.baseline_lineage') IS NOT NULL").stdout.strip()=='t':
        raise ValueError('A baseline cannot be built from another baseline')
    catalog=snapshot()
    text=roles_sql(catalog)
    database,owner,_=catalog['database_acl']
    text+='ALTER DATABASE '+ident(database)+' OWNER TO '+ident(owner)+';\n'
    for name,version,schema,owner in catalog['extensions'] or []:
        if name=='plpgsql':continue
        if name!='pgcrypto' or schema!='public':raise ValueError('Unsupported extension in reference')
        database=sql('SELECT current_database()').stdout.strip()
        text+=f'GRANT CREATE ON DATABASE {ident(database)} TO {ident(owner)};\nGRANT USAGE,CREATE ON SCHEMA public TO {ident(owner)};\nSET ROLE {ident(owner)};\nCREATE EXTENSION {ident(name)} WITH SCHEMA public VERSION {quote(version)};\nRESET ROLE;\nREVOKE CREATE ON DATABASE {ident(database)} FROM {ident(owner)};\nREVOKE ALL ON SCHEMA public FROM {ident(owner)};\n'
    schema=cleaned_dump(['--schema-only','--schema=control','--schema=openpc','--schema=public'])
    bootstrap=sql('SELECT rolname FROM pg_roles WHERE oid=10').stdout.strip()
    schema=re.sub(r'(?m)^(ALTER [^\n]+ OWNER TO )'+re.escape(ident(bootstrap))+r';$',r'\1:"bootstrap_role";',schema)
    schema=re.sub(r'(?m)^(ALTER [^\n]+ OWNER TO )'+re.escape(bootstrap)+r';$',r'\1:"bootstrap_role";',schema)
    text+='\n'.join('CREATE SCHEMA IF NOT EXISTS public;' if line=='CREATE SCHEMA public;' else line for line in schema.splitlines())+'\n'
    for table in seed_tables:
        if table != 'control.action_intent':
            raise ValueError('Only the public action-intent catalogue is an approved seed source')
        text+=cleaned_dump(['--data-only','--inserts','--table='+table])
    repairs,provenance=source_repairs(legacy_root or ROOT,catalog,sql,BASE/'legacy-package.json')
    text+='\n-- Exact source forms retained for audited PostgreSQL parser differences.\n'+repairs
    # Database and modified built-in function ACLs are outside schema-only dumps.
    db_acl=json.loads(sql("SELECT jsonb_agg(jsonb_build_array(CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,a.privilege_type,a.is_grantable) ORDER BY a.grantee,a.privilege_type) FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d'::\"char\",d.datdba))) a WHERE d.datname=current_database()").stdout)
    database=sql('SELECT current_database()').stdout.strip()
    database_permissions=''
    for role in sorted({row[0] for row in db_acl}|{'PUBLIC'}):
        database_permissions+='REVOKE ALL ON DATABASE '+ident(database)+' FROM '+('PUBLIC' if role=='PUBLIC' else ident(role))+';\n'
    for role,privilege,grantable in db_acl:
        if privilege not in ('CREATE','CONNECT','TEMPORARY'):raise ValueError('Unknown database privilege')
        database_permissions+='GRANT '+privilege+' ON DATABASE '+ident(database)+' TO '+('PUBLIC' if role=='PUBLIC' else ident(role))+(' WITH GRANT OPTION' if grantable else '')+';\n'
    text+=database_permissions
    text+=sql("SELECT 'GRANT EXECUTE ON FUNCTION '||p.oid::regprocedure::text||' TO '||quote_ident(r.rolname)||CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END||';' FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles r ON r.oid=a.grantee WHERE n.nspname='pg_catalog' AND r.rolname LIKE 'openpc\\_%' ESCAPE '\\' ORDER BY p.oid::regprocedure::text,r.rolname").stdout
    BASE.mkdir(parents=True,exist_ok=True)
    (BASE/'control.sql').write_text(text)
    (BASE/'catalog.json').write_text(json.dumps(catalog,sort_keys=True,indent=2)+'\n')
    seeds={table:json.loads(sql('SELECT jsonb_agg(to_jsonb(t)-\'registered_at\' ORDER BY action_intent_id) FROM '+table+' t').stdout)
           for table in seed_tables}
    (BASE/'seeds.json').write_text(json.dumps(seeds,sort_keys=True,indent=2)+'\n')
    (BASE/'source-provenance.json').write_text(json.dumps(provenance,sort_keys=True,indent=2)+'\n')
    (BASE/'repairs.sql').write_text(repairs)
    (BASE/'roles.sql').write_text(roles_sql(catalog))
    (BASE/'database-acls.sql').write_text(database_permissions)
    variant,restore_profile=parser_variant(catalog,sql)
    (BASE/'restore-profile.json').write_text(json.dumps(restore_profile,sort_keys=True,indent=2)+'\n')
    record={'format':1,'baseline_id':BASELINE,'source_commit':SOURCE,'postgres_version':180006,
            'catalog_sha256':fingerprint(catalog),'seed_tables':seed_tables,
            'files':{name:hashlib.sha256((BASE/name).read_bytes()).hexdigest() for name in ['control.sql','catalog.json','seeds.json','source-provenance.json','repairs.sql','roles.sql','database-acls.sql','restore-profile.json']}}
    wire=sql("SELECT encode(sha256(convert_to("+quote(serialized(catalog))+"::jsonb::text,'UTF8')),'hex')").stdout.strip()
    restore_wire=sql("SELECT encode(sha256(convert_to("+quote(serialized(variant))+"::jsonb::text,'UTF8')),'hex')").stdout.strip()
    record['catalog_profiles']={}
    for name,source,restored in [('canonical',catalog,variant),('legacy_private_policy_trigger',private_policy_trigger(catalog),private_policy_trigger(variant))]:
        record['catalog_profiles'][name]={
            'catalog_sha256':fingerprint(source),
            'wire_catalog_sha256':sql("SELECT encode(sha256(convert_to("+quote(serialized(source))+"::jsonb::text,'UTF8')),'hex')").stdout.strip(),
            'restore_wire_catalog_sha256':sql("SELECT encode(sha256(convert_to("+quote(serialized(restored))+"::jsonb::text,'UTF8')),'hex')").stdout.strip()}
    emit_runtime(BASE,record,catalog,CATALOG.read_text(),HELPERS.read_text(),Path(__file__).with_name('normalize.sql').read_text(),quote,lineage,wire,restore_wire)
    (BASE/'baseline.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
    names=sorted([*record['files'],'baseline.json','legacy-package.json'])
    (BASE/'CHECKSUMS').write_text(''.join(hashlib.sha256((BASE/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in names))
    return record


def assets():
    record=json.loads((BASE/'baseline.json').read_text())
    if record['format']!=1 or record['baseline_id']!=BASELINE or record['source_commit']!=SOURCE:
        raise ValueError('Unsupported baseline identity')
    for name,expected in record['files'].items():
        if name not in ('control.sql','catalog.json','seeds.json','source-provenance.json','catalog.sql','catalog-helpers.sql','normalize.sql','verify.sql','install.sql','handoff.sql','repairs.sql','roles.sql','database-acls.sql','restore-profile.json','restore.sql','prepare-restore.sql') or hashlib.sha256((BASE/name).read_bytes()).hexdigest()!=expected:
            raise ValueError('Baseline asset checksum mismatch')
    return record


def verify():
    record=assets()
    subprocess.run(['psql','-X','-q','-v','ON_ERROR_STOP=1','-f',str(BASE/'verify.sql')],check=True)
    return record


def lineage(record):
    return f"""
RESET ROLE;
CREATE SCHEMA IF NOT EXISTS openpc_local;
REVOKE ALL ON SCHEMA openpc_local FROM PUBLIC;
CREATE TABLE IF NOT EXISTS openpc_local.migration(path text PRIMARY KEY,sha256 text NOT NULL CHECK(sha256 ~ '^[0-9a-f]{{64}}$'),applied_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS openpc_local.baseline_lineage(
 baseline_id text PRIMARY KEY,source_commit text NOT NULL,sql_sha256 text NOT NULL,
 catalog_sha256 text NOT NULL,catalog_profile text NOT NULL,origin text NOT NULL CHECK(origin IN ('FRESH','LEGACY_HANDOFF')),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON openpc_local.migration,openpc_local.baseline_lineage FROM PUBLIC;
INSERT INTO openpc_local.baseline_lineage(baseline_id,source_commit,sql_sha256,catalog_sha256,catalog_profile,origin)
 SELECT {quote(BASELINE)},{quote(SOURCE)},{quote(record['files']['control.sql'])},profile.value->>'catalog_sha256',profile.key,:'baseline_origin'
 FROM ({CATALOG.read_text().replace('SET search_path=pg_catalog;','').strip().rstrip(';')}) x(j)
 CROSS JOIN jsonb_each({quote(json.dumps(record['catalog_profiles']))}::jsonb) profile
 WHERE profile.value->>'wire_catalog_sha256'=encode(sha256(convert_to(pg_temp.tegaris_catalog_canonical(j)::text,'UTF8')),'hex');
GRANT USAGE ON SCHEMA openpc_local TO openpc_control_worker;
GRANT SELECT ON openpc_local.migration,openpc_local.baseline_lineage TO openpc_control_worker;
"""


def install(handoff=False):
    record=assets()
    if sql('SELECT current_database()').stdout.strip()!='openpc_control':
        raise ValueError('This baseline requires database openpc_control')
    if int(sql('SHOW server_version_num').stdout)!=180006:
        raise ValueError('This baseline is validated only for PostgreSQL 18.6')
    present=sql("SELECT to_regclass('openpc_local.baseline_lineage') IS NOT NULL").stdout.strip()=='t'
    entrypoint='verify.sql' if present else 'handoff.sql' if handoff else 'install.sql'
    subprocess.run(['psql','-X','-q','-v','ON_ERROR_STOP=1','-f',str(BASE/entrypoint)],check=True)
    return {**record,'result':'ALREADY_CURRENT' if present else 'LEGACY_HANDOFF' if handoff else 'FRESH'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['build','verify','install','handoff'])
    p.add_argument('--seed-table',action='append',default=[])
    p.add_argument('--legacy-root',type=Path)
    a=p.parse_args()
    result=build(a.seed_table or ['control.action_intent'],a.legacy_root) if a.command=='build' else install(a.command=='handoff') if a.command in ('install','handoff') else verify()
    print(json.dumps({k:result[k] for k in ['baseline_id','catalog_sha256','result'] if k in result}))


if __name__=='__main__':
    main()
