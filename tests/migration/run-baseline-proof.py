#!/usr/bin/env python3
"""Native PostgreSQL 18.6 proof. All clusters are newly owned, Unix-socket only.

Requires matching pgcrypto binaries. Does not use Docker, a running PostgreSQL,
PGSERVICE, a user database, a TCP listener, or any repository deployment secrets.
Keeps logs and synthetic backups under --work-dir; stops only its own clusters.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'scripts/migrations'))
import compatibility
from runtime_role_proof import RuntimeRoleProof


class Proof:
    def __init__(self,args):
        self.bin=args.pg_bin.resolve();self.root=args.work_dir.resolve()
        self.resume=args.resume
        if self.resume:
            owner=json.loads((self.root/'owner.json').read_text())
            assert owner['source']==compatibility.SOURCE and self.root.stat().st_uid==os.getuid()
            compatibility.verify(args.archive)
            self.started=[];self.results=json.loads((self.root/'results.json').read_text());self.started_at=time.monotonic()
            self.offset=self.results[-1]['elapsed_seconds'] if self.results else 0
            return
        self.root.mkdir(mode=0o700,parents=True,exist_ok=False)
        if len(str(self.root/'sock').encode())>80:raise ValueError('Use a shorter test work directory')
        (self.root/'owner.json').write_text(json.dumps({'source':compatibility.SOURCE,'pid':os.getpid()}))
        self.started=[];self.results=[];self.started_at=time.monotonic();self.offset=0
        (self.root/'sock').mkdir();(self.root/'shim').mkdir();(self.root/'secrets').mkdir()
        compatibility.verify(args.archive,destination=self.root/'legacy')
        (self.root/'candidate').symlink_to(REPO,target_is_directory=True)
        for name in ['control_pg_password','identity_runtime_db_password','participant_runtime_db_password',
                     'policy_runtime_db_password','control_api_runtime_db_password','control_worker_runtime_db_password']:
            (self.root/'secrets'/name).write_text('0123456789abcdef0123456789abcdef')
        shim='''#!/usr/bin/env python3
import os,sys,subprocess
root=os.environ['TG_LEGACY_ROOT'];args=[];variable=False
for a in sys.argv[1:]:
 args.append(a.replace(root,'/migrations/postgres') if variable else a)
 variable=a=='-v'
data=sys.stdin.buffer.read().replace(root.encode(),b'/migrations/postgres')
sys.exit(subprocess.run([os.environ['TG_PSQL'],*args],input=data).returncode)
'''
        (self.root/'shim/psql').write_text(shim);(self.root/'shim/psql').chmod(0o700)
        for label,source in [('legacy',self.root/'legacy/deploy/compose/local/migrate.sh'),('candidate',REPO/'deploy/compose/local/migrate.sh')]:
            target=self.root/(label+'-runner');target.mkdir()
            migration_root=self.root/('legacy' if label=='legacy' else 'candidate')/'migrations/postgres'
            text=source.read_text().replace('/migrations/postgres',str(migration_root)).replace('/run/secrets',str(self.root/'secrets'))
            (target/'migrate.sh').write_text(text)

    def mark(self,label):
        self.results.append({'check':label,'status':'PASS','elapsed_seconds':round(self.offset+time.monotonic()-self.started_at,3)})
        print('PASS',label,flush=True)
        (self.root/'results.json').write_text(json.dumps(self.results,indent=2)+'\n')

    def env(self,index,db='openpc_control',shim=False):
        env={k:v for k,v in os.environ.items() if not k.startswith(('PG','OPENPC_','TG_'))}
        env.update(PGHOST=str(self.root/'sock'),PGPORT=str(65430+index),PGUSER='openpc_control' if index in (2,5) else 'postgres',PGDATABASE=db,
                   TG_PSQL=str(self.bin/'psql'),TG_LEGACY_ROOT=str(self.root/'legacy/migrations/postgres'),
                   OPENPC_MIGRATIONS_ROOT=str(self.root/'candidate/migrations/postgres'),
                   PATH=(str(self.root/'shim')+':' if shim else '')+str(self.bin)+':'+env['PATH'])
        return env

    def run(self,args,index,*,input=None,ok=True,label='command',shim=False,db='openpc_control'):
        p=subprocess.run([str(x) for x in args],input=input,text=True,capture_output=True,env=self.env(index,db,shim))
        with (self.root/'commands.log').open('a') as log:
            log.write(f'\n--- {label} [{p.returncode}] ---\n'+p.stdout+p.stderr)
        if ok and p.returncode:raise RuntimeError(label+'\n'+p.stderr[-5000:])
        return p

    def sql(self,text,index,*,ok=True,db='openpc_control'):
        return self.run([self.bin/'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1'],index,input=text,ok=ok,label='SQL',db=db)

    def file(self,path,index,ok=True):
        return self.run([self.bin/'psql','-X','-q','-v','ON_ERROR_STOP=1','-f',path],index,ok=ok,label=Path(path).name)

    def cluster(self,index):
        data=self.root/f'cluster-{index}'
        if not data.exists():
            self.run([self.bin/'initdb','-D',data,'-U','openpc_control' if index in (2,5) else 'postgres','-A','trust','--no-locale','-E','UTF8'],index,label='initdb')
        self.run([self.bin/'pg_ctl','-D',data,'-l',self.root/f'cluster-{index}.log','-o',
                  f"-k {self.root/'sock'} -p {65430+index} -c listen_addresses='' -c shared_buffers=128MB -c max_connections=20 -c max_locks_per_transaction=1024",'-w','start'],index,label='start owned cluster')
        self.started.append(index)
        assert self.sql('SHOW data_directory',index,db='postgres').stdout.strip()==str(data)
        assert self.sql('SHOW server_version_num',index,db='postgres').stdout.strip()=='180006'
        if self.sql("SELECT 1 FROM pg_database WHERE datname='openpc_control'",index,db='postgres').stdout.strip()!='1':
            self.sql('CREATE DATABASE openpc_control',index,db='postgres')

    def migrate(self,label,index,mode='control-installation',ok=True):
        return self.run(['sh',self.root/(label+'-runner/migrate.sh'),mode],index,ok=ok,label=label+' '+mode,shim=True)

    def data_hash(self,index):
        tables=json.loads(self.sql("SELECT jsonb_agg(quote_ident(n.nspname)||'.'||quote_ident(c.relname) ORDER BY c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='control' AND c.relkind='r'",index).stdout)
        queries=[]
        for table in tables:
            queries.append("SELECT '"+table.replace("'","''")+"' AS name, coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) AS payload FROM "+table+' t')
        # One statement gives every table the same MVCC snapshot and avoids
        # hundreds of separate client connections for each data comparison.
        value=json.loads(self.sql('SELECT jsonb_object_agg(name,payload) FROM ('+' UNION ALL '.join(queries)+') data',index).stdout)
        return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def run_proof(self):
        base=REPO/'migrations/postgres/baseline-v1'
        if self.resume:
            self.cluster(1);self.cluster(2)
        else:
            self.mark('compatibility archive and every member checksum verified')
            self.cluster(1)
            self.migrate('legacy',1)
            self.file(base/'verify.sql',1)
            self.mark('complete legacy manual installation matches baseline catalogue and seed data')
            self.cluster(2)
            self.migrate('candidate',2,'control-schema')
            self.file(base/'verify.sql',2)
            self.mark('ordinary schema entrypoint installs compact baseline')
            self.migrate('candidate',2)
            before=self.data_hash(2)
            self.migrate('candidate',2)
            assert self.data_hash(2)==before
            self.mark('manual role setup and repeat run preserve all application rows')
            assert self.sql('SELECT count(*) FROM openpc_local.migration',2).stdout.strip()=='0'
            self.mark('fresh baseline never fabricates historical migration receipts')
            self.migrate('legacy',1,'control')
            before=self.data_hash(1)
            ledger=self.sql('SELECT jsonb_object_agg(path,sha256) FROM openpc_local.migration',1).stdout
            self.sql("UPDATE openpc_local.migration SET sha256=repeat('0',64) WHERE path=(SELECT min(path) FROM openpc_local.migration)",1)
            p=self.migrate('candidate',1,ok=False)
            assert p.returncode and 'ledger' in p.stderr.lower()
            assert self.sql("SELECT to_regclass('openpc_local.baseline_lineage') IS NULL",1).stdout.strip()=='t'
            self.mark('altered legacy checksum rejected before handoff metadata is created')
            entry=json.loads(ledger);path=min(entry)
            self.sql("UPDATE openpc_local.migration SET sha256='"+entry[path]+"' WHERE path='"+path+"'",1)
            self.migrate('candidate',1)
            assert self.data_hash(1)==before
            assert self.sql('SELECT jsonb_object_agg(path,sha256) FROM openpc_local.migration',1).stdout==ledger
            self.mark('populated current handoff preserves every application row and all legacy ledger entries')
            self.migrate('candidate',1)
            assert self.data_hash(1)==before
            self.mark('handoff replay is idempotent')
        self.cluster(3)
        for index in [1,2]:
            target=3 if index==1 else 5
            if target==5:self.cluster(5)
            archive=self.root/f'backup-{index}.dump'
            self.run([self.bin/'pg_dump','--format=custom','--create','--file',archive],index,label='backup synthetic fixture')
            if self.resume:
                self.sql('DROP DATABASE openpc_control WITH (FORCE)',target,db='postgres')
                self.sql('CREATE DATABASE openpc_control',target,db='postgres')
            with archive.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
            self.run(['python3',REPO/'scripts/migrations/restore.py','--archive',archive,'--sha256',digest],target,label='qualified restore to empty owned target')
            self.file(base/'verify.sql',target)
            assert self.data_hash(target)==self.data_hash(index)
            self.mark(('legacy handoff' if index==1 else 'fresh baseline')+' backup restores with exact catalogue and data')
        self.cluster(6)
        self.sql("CREATE SCHEMA openpc_local; CREATE TABLE openpc_local.migration(path text PRIMARY KEY,sha256 text NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp());",6)
        for lane,maximum in [('identity',15),('policy',7),('control-api',3)]:
            for path in sorted((self.root/'legacy/migrations/postgres'/lane).glob('*.sql')):
                if int(path.name[:4])>maximum:continue
                source=path.read_text()
                if lane=='policy' and path.name.startswith('0000_'):source='\n'.join(source.splitlines()[2:])
                prefix='SET ROLE openpc_control_owner;\n' if lane in ('policy','control-api') else ''
                self.sql('BEGIN;\n'+prefix+source+'\nCOMMIT;',6)
                logical='/migrations/postgres/'+lane+'/'+path.name
                digest=hashlib.sha256(path.read_bytes()).hexdigest()
                self.sql("INSERT INTO openpc_local.migration(path,sha256) VALUES('"+logical+"','"+digest+"');",6)
        self.sql("""INSERT INTO control.participant(participant_id,display_name,state,authority_epoch)
VALUES ('018f0000-0000-7000-8000-000000000101','Preserved predecessor participant','ACTIVE',1);
INSERT INTO control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
VALUES ('018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000101','Preserved predecessor domain','PARTICIPANT_LOCAL','LOCAL_DEVELOPMENT','ACTIVE');
UPDATE control.participant SET root_privacy_domain_id='018f0000-0000-7000-8000-000000000201' WHERE participant_id='018f0000-0000-7000-8000-000000000101';""",6)
        before=self.data_hash(6)
        assert self.migrate('candidate',6,'control-schema',ok=False).returncode
        assert self.data_hash(6)==before
        self.mark('older populated prefix rejected by baseline until explicit compatibility upgrade')
        self.migrate('legacy',6)
        assert self.sql("SELECT display_name||'|'||authority_epoch FROM control.participant WHERE participant_id='018f0000-0000-7000-8000-000000000101'",6).stdout.strip()=='Preserved predecessor participant|1'
        assert self.sql("SELECT domain_name FROM control.privacy_domain WHERE privacy_domain_id='018f0000-0000-7000-8000-000000000201'",6).stdout.strip()=='Preserved predecessor domain'
        before=self.data_hash(6);self.migrate('candidate',6)
        assert self.data_hash(6)==before
        assert self.sql("SELECT catalog_profile FROM openpc_local.baseline_lineage",6).stdout.strip()=='legacy_private_policy_trigger'
        assert self.sql("SELECT NOT EXISTS(SELECT FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE p.oid='openpc.reject_policy_immutable_mutation()'::regprocedure AND a.grantee=0)",6).stdout.strip()=='t'
        self.mark('verified compatibility package upgrades populated predecessor and hands off without data loss')
        self.cluster(7)
        archive=self.root/'backup-6.dump'
        self.run([self.bin/'pg_dump','--format=custom','--create','--file',archive],6,label='backup private-policy predecessor')
        with archive.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        self.run(['python3',REPO/'scripts/migrations/restore.py','--archive',archive,'--sha256',digest],7,label='restore private-policy predecessor')
        assert self.data_hash(7)==self.data_hash(6)
        self.file(base/'verify.sql',7)
        assert self.sql('SELECT catalog_profile FROM openpc_local.baseline_lineage',7).stdout.strip()=='legacy_private_policy_trigger'
        self.mark('older private-policy profile backup restores without broadening function privileges')
        self.cluster(4)
        self.sql('CREATE TABLE public.keep_me(value text); INSERT INTO public.keep_me VALUES(\'preserved\');',4)
        assert self.migrate('candidate',4,'control-schema',ok=False).returncode
        assert self.sql('SELECT value FROM public.keep_me',4).stdout.strip()=='preserved'
        assert self.sql("SELECT to_regnamespace('control') IS NULL",4).stdout.strip()=='t'
        self.mark('nonempty unknown database rejected without changing its data')
        self.sql('DROP TABLE public.keep_me; CREATE ROLE openpc_control_owner LOGIN;',4)
        assert self.migrate('candidate',4,'control-schema',ok=False).returncode
        assert self.sql("SELECT rolcanlogin FROM pg_roles WHERE rolname='openpc_control_owner'",4).stdout.strip()=='t'
        assert self.sql("SELECT to_regnamespace('control') IS NULL",4).stdout.strip()=='t'
        self.mark('unknown cluster role privileges rejected without reconciliation')
        self.sql('DROP ROLE openpc_control_owner;',4)
        holder=subprocess.Popen([str(self.bin/'psql'),'-X','-q','-A','-t','-v','ON_ERROR_STOP=1'],
                                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env(4))
        holder.stdin.write("BEGIN; SELECT pg_advisory_xact_lock(hashtextextended('tegaris-control-baseline-v1',0));\n\\echo READY\n");holder.stdin.flush()
        for line in holder.stdout:
            if line.strip()=='READY':break
        try:
            blocked=self.migrate('candidate',4,'control-schema',ok=False)
            assert blocked.returncode and 'Another baseline migrator' in blocked.stderr
            assert self.sql("SELECT to_regnamespace('control') IS NULL",4).stdout.strip()=='t'
        finally:
            holder.stdin.write('ROLLBACK;\n\\q\n');holder.stdin.close();holder.stdout.read();holder.wait()
        self.mark('concurrent baseline migrator rejected before schema changes')
        bad=self.root/'failed-install';bad.mkdir()
        for p in base.iterdir():
            if p.is_file():(bad/p.name).write_bytes(p.read_bytes())
        with (bad/'control.sql').open('a') as f:f.write('\nCREATE TABLE public.atomic_probe(value int); SELECT 1/0;\n')
        assert self.file(bad/'install.sql',4,ok=False).returncode
        assert self.sql("SELECT to_regnamespace('control') IS NULL AND to_regclass('public.atomic_probe') IS NULL",4).stdout.strip()=='t'
        assert self.sql("SELECT count(*) FROM pg_roles WHERE starts_with(rolname,'openpc_')",4).stdout.strip()=='0'
        self.mark('injected SQL failure rolls back schema, metadata and newly created roles')
        self.migrate('candidate',2,'control')
        self.sql("INSERT INTO control.participant(participant_id,display_name,state,authority_epoch) VALUES('018f0000-0000-7000-8000-000000009999','Other proof participant','ACTIVE',1);",2)
        for participant in ['018f0000-0000-7000-8000-000000000101','018f0000-0000-7000-8000-000000009999']:
            visible=self.sql("BEGIN; SET ROLE openpc_control_runtime; SELECT set_config('openpc.participant_id','"+participant+"',true); SELECT jsonb_agg(participant_id ORDER BY participant_id) FROM control.participant; ROLLBACK;",2).stdout.splitlines()[-1]
            assert json.loads(visible)==[participant]
        absent=self.sql('BEGIN; SET ROLE openpc_control_runtime; SELECT count(*) FROM control.participant; ROLLBACK;',2,ok=False)
        assert absent.returncode or absent.stdout.strip()=='0'
        denied=self.sql("BEGIN; SET ROLE openpc_control_reader; UPDATE control.participant SET display_name='forbidden'; ROLLBACK;",2,ok=False)
        assert denied.returncode
        self.mark('actual scoped reads isolate participants and unscoped/read-only operations are denied')
        for index,change,undo in [(2,'REVOKE','GRANT'),(6,'GRANT','REVOKE')]:
            def privilege(verb):
                return verb+' EXECUTE ON FUNCTION openpc.reject_policy_immutable_mutation() '+('TO' if verb=='GRANT' else 'FROM')+' PUBLIC'
            self.sql(privilege(change),index)
            altered=self.migrate('candidate',index,ok=False)
            assert altered.returncode and 'LINEAGE' in altered.stderr
            self.sql(privilege(undo),index)
            self.file(base/'verify.sql',index)
        self.mark('catalogue profiles are pinned and permission changes between recognized profiles are rejected')
        for index in [1,2]:
            self.sql("ALTER TABLE control.participant DISABLE ROW LEVEL SECURITY",index)
            p=self.migrate('candidate',index,ok=False)
            assert p.returncode and 'CATALOG' in p.stderr
            self.sql("ALTER TABLE control.participant ENABLE ROW LEVEL SECURITY",index)
            self.file(base/'verify.sql',index)
        self.mark('RLS weakening is detected on both installation lineages')

    def close(self):
        for index in reversed(self.started):
            data=self.root/f'cluster-{index}'
            if self.sql('SHOW data_directory',index,db='postgres',ok=False).stdout.strip()==str(data):
                self.run([self.bin/'pg_ctl','-D',data,'-w','stop','-m','fast'],index,ok=False,label='stop owned cluster')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pg-bin',type=Path,required=True);p.add_argument('--archive',type=Path,required=True)
    p.add_argument('--work-dir',type=Path,required=True)
    p.add_argument('--resume',action='store_true',help='Resume only a proof directory previously created by this runner')
    p.add_argument('--inspect-restore',action='store_true',help='Read the catalogue from the owned restore fixture for diagnostics')
    p.add_argument('--inspect-cluster',type=int,choices=range(1,8),default=3)
    args=p.parse_args();proof=Proof(args)
    try:
        if args.inspect_restore:
            if not args.resume:raise ValueError('Diagnostics require a previously owned proof')
            proof.cluster(args.inspect_cluster)
            base=REPO/'migrations/postgres/baseline-v1'
            actual=json.loads(proof.sql((base/'catalog-helpers.sql').read_text()+'\n'+(base/'catalog.sql').read_text(),args.inspect_cluster).stdout)
            (proof.root/f'cluster-{args.inspect_cluster}-catalog.json').write_text(json.dumps(actual,indent=2,sort_keys=True)+'\n')
            expected=json.loads((base/'catalog.json').read_text())
            print('Catalogue fields requiring investigation:',[k for k in expected if expected[k]!=actual[k]],flush=True)
        else:
            proof.run_proof()
            RuntimeRoleProof(proof).run()
    finally:proof.close()
    print(json.dumps({'passed':len(proof.results),'evidence':str(proof.root),'seconds':round(time.monotonic()-proof.started_at,2)}))


if __name__=='__main__':main()
