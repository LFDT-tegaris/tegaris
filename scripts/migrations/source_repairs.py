"""Retain exact source forms for PostgreSQL deparse/reparse differences.

These CHECKs and policies are closed, audited source identities. This
does not normalize away expression differences or infer allowed SQL from a live
database. Every source byte is authenticated against the legacy manifest.
"""
import hashlib
import json
from pathlib import Path
import re

CHECKS=[('action_intent','action_intent_operation_ck'),('action_intent','action_intent_risk_ck'),
        ('authority_role','authority_role_origin_ck'),('authority_role','authority_role_state_ck'),
        ('idempotency_record','idempotency_catalog_operation_ck'),('mutation_evidence','mutation_evidence_catalog_operation_ck')]
CHECKS += [('notification_completion_attempt','completion_attempt_bytes_ck'),
 ('notification_completion_disposition','completion_disposition_bytes_ck'),
 ('notification_completion_disposition_signer_installation','completion_signer_bytes_ck'),
 ('notification_completion_disposition_signing','completion_signing_bytes_ck'),
 ('notification_completion_source','completion_source_bytes_ck'),
 ('notification_source_cursor','notification_cursor_position_ck'),
 ('notification_source_cursor','notification_cursor_source_ck'),
 ('notification_source_inbox','notification_inbox_source_ck')]
CHECKS += [tuple(value) for value in json.loads(Path(__file__).with_name('extra-source-checks.json').read_text())]
POLICIES=[('mutation_candidate','platform_recovery_pending_expiry_effect_read'),
          ('root_expiry_recovery_case','root_expiry_admin_receipt_prerequisite_read'),
          ('root_expiry_recovery_enrollment','root_expiry_admin_receipt_prerequisite_read'),
          ('root_expiry_recovery_scope','root_expiry_admin_receipt_prerequisite_read'),
          ('root_expiry_recovery_scope','root_expiry_scope_read')]


def boundary(text,start,balanced=False):
    quote=None;depth=0;i=start
    while i<len(text):
        c=text[i]
        if quote:
            if c==quote:
                if i+1<len(text) and text[i+1]==quote:i+=2;continue
                quote=None
        elif c in "'\"":quote=c
        elif balanced:
            if c=='(':depth+=1
            elif c==')':
                depth-=1
                if depth==0:return i+1
        elif c==';':return i+1
        i+=1
    raise ValueError('Unterminated audited source expression')


def extract(root,catalog,evaluate,manifest_path):
    root=Path(root); manifest=json.loads(Path(manifest_path).read_text())
    found={};provenance=[];out=[];failures={};rejected_checks=set();rejected_policies=set()
    expected_checks={tuple(row[1:3]):row[-2:] for row in catalog['constraints'] if row[0]=='control'}
    expected_policies={tuple(row[1:3]):row for row in catalog['policies'] if row[0]=='control'}
    for path,item in sorted(manifest['files'].items(),reverse=True):
        if not re.fullmatch(r'migrations/postgres/(identity|control-api|policy)/[^/]+\.sql',path):continue
        text=(root/path).read_text()
        for table,name in CHECKS:
            if (table,name) in found:continue
            matches=list(re.finditer(r'CONSTRAINT\s+(?:"'+name+r'"|'+name+r')\s+CHECK\s*',text))
            if not matches:continue
            if hashlib.sha256((root/path).read_bytes()).hexdigest()!=item['sha256']:raise ValueError('Source CHECK digest mismatch')
            for match in reversed(matches):
                end=boundary(text,match.end(),True);expression=text[match.end():end]
                candidate=(table,name,expression)
                if candidate in rejected_checks:continue
                compiled_expression=expression.replace('"control"."'+table+'".','"pg_temp"."'+table+'".').replace('control.'+table+'.','pg_temp.'+table+'.')
                proof=f'SET search_path=pg_catalog; CREATE TEMP TABLE "{table}" (LIKE control."{table}"); ALTER TABLE pg_temp."{table}" ADD CONSTRAINT "{name}" CHECK {compiled_expression}; SELECT jsonb_build_array(pg_get_expr(conbin,conrelid),pg_get_constraintdef(oid,true)) FROM pg_constraint WHERE conrelid=\'pg_temp."{table}"\'::regclass AND conname=\'{name}\';'
                result=evaluate(proof,check=False)
                if result.returncode or json.loads(result.stdout)!=expected_checks[(table,name)]:
                    rejected_checks.add(candidate);failures[name]=(result.stderr or result.stdout)[:500];continue
                out.append(f'ALTER TABLE control."{table}" DROP CONSTRAINT "{name}";\nALTER TABLE control."{table}" ADD CONSTRAINT "{name}" CHECK {expression};')
                found[(table,name)]=True;provenance.append({'object':table+'.'+name,'source':path,'source_sha256':item['sha256']})
                break
        if len(found)==len(CHECKS):break
    if len(found)!=len(CHECKS):raise ValueError('Missing audited source CHECK: '+str({name:failures.get(name) for table,name in CHECKS if (table,name) not in found}))
    policy_sources={}
    for path,item in sorted(manifest['files'].items(),reverse=True):
        if not re.fullmatch(r'migrations/postgres/(identity|control-api|policy)/[^/]+\.sql',path):continue
        text=(root/path).read_text()
        for table,name in POLICIES:
            if (table,name) in policy_sources:continue
            pattern=r'(CREATE|ALTER) POLICY\s+(?:"'+name+r'"|'+name+r')\s+ON\s+("?control"?\."?'+table+r'"?)(?=\s|$)'
            matches=list(re.finditer(pattern,text))
            if not matches:continue
            if hashlib.sha256((root/path).read_bytes()).hexdigest()!=item['sha256']:raise ValueError('Source policy digest mismatch')
            expected=expected_policies[(table,name)]
            for match in reversed(matches):
                start=match.start();end=boundary(text,start);statement=text[start:end]
                candidate=(table,name,statement)
                if candidate in rejected_policies:continue
                relative_start=match.start(2)-start;relative_end=match.end(2)-start
                compiled=statement[:relative_start]+'pg_temp."'+table+'"'+statement[relative_end:]
                compiled=compiled.replace('"control"."'+table+'".','"pg_temp"."'+table+'".').replace('control.'+table+'.','pg_temp.'+table+'.')
                initial='' if match[1]=='CREATE' else f'CREATE POLICY "{name}" ON pg_temp."{table}" TO '+','.join('"'+role+'"' for role in expected[5])+' USING(true);'
                proof=f'SET search_path=pg_catalog; CREATE TEMP TABLE "{table}" (LIKE control."{table}"); '+initial+compiled+f" SELECT jsonb_build_array((SELECT array_agg(CASE WHEN u=0 THEN 'public' ELSE pg_get_userbyid(u) END ORDER BY CASE WHEN u=0 THEN 'public' ELSE pg_get_userbyid(u) END) FROM unnest(polroles) u),pg_get_expr(polqual,polrelid),pg_get_expr(polwithcheck,polrelid)) FROM pg_policy WHERE polrelid='pg_temp.\"{table}\"'::regclass AND polname='{name}';"
                result=evaluate(proof,check=False)
                if result.returncode:
                    rejected_policies.add(candidate);failures[(table,name)]=result.stderr[:1500];continue
                try:actual=json.loads(result.stdout)
                except json.JSONDecodeError:continue
                if actual!=expected[5:]:
                    rejected_policies.add(candidate);failures[(table,name)]=str(actual)[:1500];continue
                prefix=f'DROP POLICY "{name}" ON control."{table}";\n' if match[1]=='CREATE' else ''
                policy_sources[(table,name)]=(prefix+statement,path,item['sha256'])
                break
        if len(policy_sources)==len(POLICIES):break
    for table,name in POLICIES:
        if (table,name) not in policy_sources:raise ValueError('Missing audited policy: '+table+'.'+name+' '+str(failures.get((table,name))))
        statement,path,digest=policy_sources[(table,name)]
        out.append(statement)
        provenance.append({'object':table+'.'+name,'source':path,'source_sha256':digest})
    return '\n'.join(out)+'\n',provenance


def parser_variant(catalog,evaluate):
    """Derive a dump/reparse profile independently in temporary objects.

    Observed backup contents never define an accepted expression or privilege.
    Only one parser pass of the authenticated reference catalogue is accepted.
    """
    variant=json.loads(json.dumps(catalog));profile=[]
    for row in variant['constraints']:
        schema,table,name=row[:3]
        if schema!='control' or (table,name) not in CHECKS:continue
        # pg_dump 18.6 uses the non-pretty deparser. Pretty output can produce
        # a different Boolean parse tree on input, so model its exact call.
        statement=evaluate(f"SELECT pg_get_constraintdef(oid,false) FROM pg_constraint WHERE conrelid='control.\"{table}\"'::regclass AND conname='{name}';").stdout.strip()
        statement=statement.replace('"control"."'+table+'".','"pg_temp"."'+table+'".').replace('control.'+table+'.','pg_temp.'+table+'.')
        proof=f'SET search_path=pg_catalog; CREATE TEMP TABLE "{table}" (LIKE control."{table}"); ALTER TABLE pg_temp."{table}" ADD CONSTRAINT "{name}" {statement}; SELECT jsonb_build_array(pg_get_expr(conbin,conrelid),pg_get_constraintdef(oid,true)) FROM pg_constraint WHERE conrelid=\'pg_temp."{table}"\'::regclass AND conname=\'{name}\';'
        row[-2:]=json.loads(evaluate(proof).stdout)
        profile.append({'object':table+'.'+name,'kind':'CHECK','parsed':row[-2:]})
    for row in variant['policies']:
        schema,table,name=row[:3]
        if schema!='control' or (table,name) not in POLICIES:continue
        expressions=[]
        for label,expression in zip(['USING','WITH CHECK'],row[-2:]):
            if expression is not None:
                expression=expression.replace('"control"."'+table+'".','"pg_temp"."'+table+'".').replace('control.'+table+'.','pg_temp.'+table+'.')
                expressions.append(label+' ('+expression+')')
        proof=f'SET search_path=pg_catalog; CREATE TEMP TABLE "{table}" (LIKE control."{table}"); CREATE POLICY "{name}" ON pg_temp."{table}" '+ ' '.join(expressions)+f"; SELECT jsonb_build_array(pg_get_expr(polqual,polrelid),pg_get_expr(polwithcheck,polrelid)) FROM pg_policy WHERE polrelid='pg_temp.\"{table}\"'::regclass AND polname='{name}';"
        row[-2:]=json.loads(evaluate(proof).stdout)
        profile.append({'object':table+'.'+name,'kind':'POLICY','parsed':row[-2:]})
    return variant,profile
