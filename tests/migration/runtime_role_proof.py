"""Runtime-role migration contract probes on the proof driver's owned clusters.

These synthetic bindings exercise SQL role contracts, not custody enrollment,
retained files or the full demo. The Linux compact-checkout runtime gate must
exercise the actual Rust installer and application journeys separately.
"""
import copy
import hashlib
import json
import base64
from pathlib import Path


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def identifier(value):
    return '"' + value.replace('"', '""') + '"'


class RuntimeRoleProof:
    def __init__(self, proof):
        self.proof = proof
        self.base = Path(__file__).resolve().parents[2] / 'migrations/postgres/baseline-v1'

    def fixture(self, index, archive=False, *, participant='018f0000-0000-7000-8000-000000000101', privacy=None):
        privacy = privacy or '018f0000-0000-7000-8000-00000000720' + ('2' if archive else '1')
        source = json.dumps(['openpc:runtime-source-scope:v1', participant, privacy], separators=(',', ':'))
        suffix = base64.urlsafe_b64encode(hashlib.sha256(source.encode()).digest()).decode().rstrip('=')
        scope = 'openpc_rs_scope_' + suffix
        login = 'openpc_rs_login_' + suffix
        root = {'generation_id': '018f0000-0000-7000-8000-000000000301',
                'journal_binding': 'a' * 64, 'retained_root_binding': 'b' * 64,
                'consumer_profile': 'openpc:local-runtime-source-consumers:v' + ('2' if archive else '1')}
        if archive:
            root['database'] = json.loads(self.proof.sql("SELECT jsonb_build_object('system_identifier',s.system_identifier::text,'database_oid',d.oid::text) FROM pg_control_system() s,pg_database d WHERE d.datname=current_database()", index).stdout)
        binding = {'version': 1, 'installation': {'participant_id': participant,
                   'privacy_domain_id': privacy, 'source_owner_id': '018f0000-0000-7000-8000-000000000401',
                   'source_file_binding': 'd' * 64}, 'root': root, 'database_role': login,
                   'source_public_key': list(bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')),
                   'commit_key_digest': 'c' * 64}
        statements = [f'CREATE ROLE {identifier(scope)} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                      f'CREATE ROLE {identifier(login)} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                      f'GRANT openpc_control_worker TO {identifier(login)}',
                      f'GRANT {identifier(scope)} TO {identifier(login)} WITH ADMIN FALSE, INHERIT FALSE, SET FALSE']
        if archive:
            archive_login = 'openpc_ra_login_' + suffix
            binding['archive_custody'] = {'database_role': archive_login, 'stream_id': 'synthetic-native-archive', 'keys': {'synthetic-key': 'e' * 64}}
            profile = {'installation': binding['installation'], 'root': root, 'archive': binding['archive_custody']}
            statements.extend([f'CREATE ROLE {identifier(archive_login)} LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                               f'GRANT openpc_control_worker TO {identifier(archive_login)}',
                               self.comment(archive_login, profile)])
        statements.append(self.comment(scope, binding))
        self.proof.sql('BEGIN;\n' + ';\n'.join(statements) + ';\nCOMMIT;', index)
        return scope, login, binding

    @staticmethod
    def comment(role, profile):
        return f'COMMENT ON ROLE {identifier(role)} IS {literal(json.dumps(profile, separators=(",", ":")))}'

    def state(self, index):
        return self.proof.sql("""SELECT jsonb_build_object(
 'roles',(SELECT jsonb_agg(jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil,rolconfig,shobj_description(oid,'pg_authid')) ORDER BY rolname) FROM pg_roles WHERE starts_with(rolname,'openpc_')),
 'memberships',(SELECT jsonb_agg(jsonb_build_array(pg_get_userbyid(roleid),pg_get_userbyid(member),pg_get_userbyid(grantor),admin_option,inherit_option,set_option) ORDER BY roleid,member,grantor) FROM pg_auth_members),
 'lineage',(SELECT jsonb_agg(to_jsonb(l)) FROM openpc_local.baseline_lineage l),
 'ledger',(SELECT jsonb_agg(to_jsonb(l) ORDER BY path) FROM openpc_local.migration l))""", index).stdout

    def rejects(self, index, label, change, error='BASELINE-RUNTIME-ROLE-MISMATCH'):
        before = self.state(index)
        result = self.proof.sql('BEGIN;\n' + change + ';\n\\ir ' + literal(str(self.base / 'verify.sql')) + '\nROLLBACK;', index, ok=False)
        assert result.returncode and error in result.stderr, (label, result.stderr[-2000:])
        assert self.state(index) == before, label + ': rejected transaction changed roles or lineage'
        self.proof.mark('runtime role guard rejects ' + label)

    def source_row(self, index, binding):
        installation = binding['installation']
        participant = installation['participant_id']; privacy = installation['privacy_domain_id']
        # Preserve the actual genesis guard: new participant/domain and the
        # source row are born in one transaction. Never rewrite an existing
        # participant or disable a trigger to manufacture an enrolled source.
        self.proof.sql(f"""BEGIN;
 INSERT INTO control.participant(participant_id,display_name,state,authority_epoch)
 VALUES ({literal(participant)},'Synthetic role-contract participant','ACTIVE',1);
 INSERT INTO control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
 VALUES ({literal(privacy)},{literal(participant)},'Synthetic role-contract domain','PARTICIPANT_LOCAL','LOCAL_DEVELOPMENT','ACTIVE');
 UPDATE control.participant SET root_privacy_domain_id={literal(privacy)} WHERE participant_id={literal(participant)};
 INSERT INTO control.runtime_artifact_source(participant_id,privacy_domain_id,source_owner_id,source_file_binding,source_public_key,database_role,installation_reference,custody_root)
 VALUES ({literal(participant)},{literal(privacy)},{literal(installation['source_owner_id'])},decode({literal(installation['source_file_binding'])},'hex'),decode({literal(bytes(binding['source_public_key']).hex())},'hex'),{literal(binding['database_role'])},{literal('native-source-root:' + binding['root']['generation_id'])},{literal(json.dumps(binding['root']))}::jsonb);
 COMMIT;""", index)

    def run(self):
        p = self.proof
        scope, login, binding = self.fixture(2)
        qscope = identifier(scope); qlogin = identifier(login)
        assert login == 'openpc_rs_login_MKKiERMDsgOMN-RH8MIkV68t_AtuGWZCx26uBYoE4c8'
        before = self.state(2); data = p.data_hash(2)
        for mode in ['control-schema', 'control-installation', 'control']:
            p.migrate('candidate', 2, mode)
        assert self.state(2) == before and p.data_hash(2) == data
        p.mark('runtime-source roles survive actual schema, installation and bootstrap reruns unchanged')
        archive_scope, archive_source, archive_binding = self.fixture(2, archive=True)
        archive_login = archive_binding['archive_custody']['database_role']
        p.file(self.base / 'verify.sql', 2)
        before = self.state(2)
        p.migrate('candidate', 2)
        assert self.state(2) == before and p.data_hash(2) == data
        p.mark('materialization and archive roles pass repeat migration without changing roles, bindings, lineage or data')
        for index in [1, 6]:
            self.fixture(index)
            before = self.state(index); data_before = p.data_hash(index)
            p.migrate('candidate', index)
            assert self.state(index) == before and p.data_hash(index) == data_before
        p.mark('both authenticated legacy privilege profiles retain runtime roles during handoff replay')
        for attribute in ['SUPERUSER', 'BYPASSRLS', 'CREATEROLE', 'CREATEDB', 'REPLICATION', 'NOINHERIT', 'NOLOGIN', 'CONNECTION LIMIT 1', "VALID UNTIL '2099-01-01'"]:
            self.rejects(2, 'source ' + attribute, f'ALTER ROLE {qlogin} {attribute}')
        self.rejects(2, 'login-capable scope marker', f'ALTER ROLE {qscope} LOGIN')
        self.rejects(2, 'role settings', f"ALTER ROLE {qlogin} SET search_path=public")
        self.rejects(2, 'database-specific role settings', f"ALTER ROLE {qlogin} IN DATABASE openpc_control SET search_path=public")
        self.rejects(2, 'direct table grant', f'GRANT SELECT ON control.participant TO {qlogin}')
        self.rejects(2, 'direct database grant', f'GRANT CONNECT ON DATABASE openpc_control TO {qlogin}')
        self.rejects(2, 'direct schema grant', f'GRANT USAGE ON SCHEMA control TO {qlogin}')
        self.rejects(2, 'off-schema ownership', f'CREATE SCHEMA role_probe; CREATE TABLE role_probe.owned(id int); ALTER TABLE role_probe.owned OWNER TO {qlogin}')
        self.rejects(2, 'off-schema RLS policy dependency', f'CREATE SCHEMA role_probe; CREATE TABLE role_probe.protected(id int); CREATE POLICY unexpected ON role_probe.protected TO {qlogin} USING(true)')
        self.rejects(2, 'static owner membership', f'GRANT openpc_control_owner TO {qlogin}')
        self.rejects(2, 'worker admin option', f'GRANT openpc_control_worker TO {qlogin} WITH ADMIN TRUE')
        self.rejects(2, 'worker SET option removal', f'GRANT openpc_control_worker TO {qlogin} WITH SET FALSE')
        self.rejects(2, 'scope SET option', f'GRANT {qscope} TO {qlogin} WITH SET TRUE')
        self.rejects(2, 'scope INHERIT option', f'GRANT {qscope} TO {qlogin} WITH INHERIT TRUE')
        self.rejects(2, 'scope ADMIN option', f'GRANT {qscope} TO {qlogin} WITH ADMIN TRUE')
        self.rejects(2, 'missing worker membership', f'REVOKE openpc_control_worker FROM {qlogin}')
        self.rejects(2, 'missing scope membership', f'REVOKE {qscope} FROM {qlogin}')
        self.rejects(2, 'cross-scope membership', f'GRANT {qscope} TO {identifier(archive_source)} WITH ADMIN FALSE, INHERIT FALSE, SET FALSE')
        self.rejects(2, 'source login delegated to another consumer', f'GRANT {qlogin} TO openpc_control_reader')
        self.rejects(2, 'orphan marker', f'DROP ROLE {qlogin}')
        self.rejects(2, 'missing marker', f'DROP ROLE {qscope}')
        self.rejects(2, 'missing archive', f'DROP ROLE {identifier(archive_login)}')
        self.rejects(2, 'malformed reserved role name', 'CREATE ROLE openpc_rs_login_unqualified')
        self.rejects(2, 'unrecognized openpc role', 'CREATE ROLE openpc_unknown_consumer', 'BASELINE-CATALOG-MISMATCH')
        self.rejects(2, 'malformed scope JSON', f"COMMENT ON ROLE {qscope} IS 'not-json'")
        for label, mutate in [
            ('wrong scope identity', lambda b: b['installation'].update(privacy_domain_id=binding['installation']['participant_id'])),
            ('wrong login identity', lambda b: b.update(database_role=archive_source)),
            ('missing digest', lambda b: b.pop('commit_key_digest')),
            ('null scope version', lambda b: b.update(version=None)),
            ('unexpected binding field', lambda b: b.update(unqualified=True)),
            ('wrong public key width', lambda b: b.update(source_public_key=[2] * 32)),
            ('uncompressed public key', lambda b: b['source_public_key'].__setitem__(0, 4)),
        ]:
            changed = copy.deepcopy(binding); mutate(changed)
            self.rejects(2, label, self.comment(scope, changed))
        changed = copy.deepcopy(archive_binding); changed['root']['database']['database_oid'] = '1'
        self.rejects(2, 'materialization restored to a different database', self.comment(archive_scope, changed))
        self.rejects(2, 'archive profile differs', self.comment(archive_login, {'installation': archive_binding['installation']}))
        self.rejects(2, 'unexpected login comment', self.comment(login, {'unqualified': True}))
        self.rejects(2, 'static RLS drift with runtime roles present', 'ALTER TABLE control.participant DISABLE ROW LEVEL SECURITY', 'BASELINE-CATALOG-MISMATCH')
        # A persisted invalid grant must stay invalid after failed ordinary
        # migration. Only the fixture itself removes it for subsequent checks.
        p.sql(f'ALTER ROLE {qlogin} BYPASSRLS', 2)
        before = self.state(2); data_before = p.data_hash(2)
        rejected = p.migrate('candidate', 2, ok=False)
        assert rejected.returncode and 'BASELINE-RUNTIME-ROLE-MISMATCH' in rejected.stderr
        assert self.state(2) == before and p.data_hash(2) == data_before
        p.sql(f'ALTER ROLE {qlogin} NOBYPASSRLS', 2)
        p.file(self.base / 'verify.sql', 2)
        p.mark('failed ordinary migration neither reconciles role privileges nor changes application data')
        for target in ['openpc_control_owner', scope]:
            result = p.sql(f'SET SESSION AUTHORIZATION {qlogin}; SET ROLE {identifier(target)};', 2, ok=False)
            assert result.returncode and 'permission denied' in result.stderr
        p.mark('source login cannot SET owner or scope-marker identity')
        self.recovery()

    def recovery(self):
        p = self.proof
        # A real per-database backup/restore retains existing cluster roles. The
        # v1 binding has no materialization database-OID pin; v2 mismatch was
        # rejected above. Host custody and consumer startup remain separate.
        _, _, binding = self.fixture(1, participant='018f0000-0000-7000-8000-000000000901', privacy='018f0000-0000-7000-8000-000000007203')
        self.source_row(1, binding)
        p.file(self.base / 'verify.sql', 1)
        before = self.state(1); data_before = p.data_hash(1)
        backup = p.root / 'runtime-role-control.dump'
        p.run([p.bin / 'pg_dump', '--format=custom', '--create', '--file', backup], 1)
        digest = hashlib.sha256(backup.read_bytes()).hexdigest()
        p.sql('DROP DATABASE openpc_control WITH (FORCE)', 1, db='postgres')
        p.sql('CREATE DATABASE openpc_control', 1, db='postgres')
        restore = Path(__file__).resolve().parents[2] / 'scripts/migrations/restore.py'
        p.run(['python3', restore, '--archive', backup, '--sha256', digest], 1)
        assert self.state(1) == before and p.data_hash(1) == data_before
        p.mark('same-cluster v1 database restore preserves source rows, role bindings, lineage and application data')
        rejected = p.run(['python3', restore, '--archive', backup, '--sha256', digest], 4, ok=False)
        assert rejected.returncode and 'source binding roles are missing' in rejected.stderr
        assert p.sql("SELECT count(*) FROM pg_roles WHERE starts_with(rolname,'openpc_rs_') OR starts_with(rolname,'openpc_ra_')", 4).stdout.strip() == '0'
        p.mark('source-bearing restore without original cluster bindings is rejected without fabricating roles')
        # Reuse only this owned rejected-restore target. The frozen catalogue
        # must not depend on the target database's text sort order.
        p.sql('DROP DATABASE openpc_control WITH (FORCE)', 4, db='postgres')
        p.sql("CREATE DATABASE openpc_control TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER libc LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8'", 4, db='postgres')
        p.migrate('candidate', 4, 'control-installation')
        p.file(self.base / 'verify.sql', 4)
        before = self.state(4); data_before = p.data_hash(4)
        p.migrate('candidate', 4, 'control-installation')
        assert self.state(4) == before and p.data_hash(4) == data_before
        assert p.sql("SELECT catalog_profile FROM openpc_local.baseline_lineage", 4).stdout.strip() == 'canonical'
        p.mark('English UTF-8 locale installs and repeats with the original catalogue and permission fingerprints')
        for change, undo in [
            ('ALTER TABLE control.participant DISABLE ROW LEVEL SECURITY', 'ALTER TABLE control.participant ENABLE ROW LEVEL SECURITY'),
            ('ALTER ROLE openpc_control_reader BYPASSRLS', 'ALTER ROLE openpc_control_reader NOBYPASSRLS'),
        ]:
            p.sql(change, 4)
            rejected = p.migrate('candidate', 4, 'control-schema', ok=False)
            assert rejected.returncode and 'BASELINE-CATALOG-MISMATCH' in rejected.stderr
            assert p.data_hash(4) == data_before
            p.sql(undo, 4)
            p.file(self.base / 'verify.sql', 4)
        p.mark('English UTF-8 locale still rejects RLS and role-privilege drift without changing application data')
