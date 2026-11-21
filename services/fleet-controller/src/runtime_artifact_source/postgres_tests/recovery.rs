//! Actual same-cluster per-database backup/restore inside the existing isolated
//! PostgreSQL runner. Globals and host files are deliberately outside the dump.
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process::{Command, Output},
};

// Same-database component fixture only: preserve its original database OID,
// extension owner and public schema. Production empty-target recovery remains
// scripts/migrations/restore.py. Every command below is inside an owned runner.
const COMPACT_RESTORE: &str = r#"
set -eu
backup=$1
case "$backup" in */openpc-source-before-install-*.dump) ;; *) exit 78 ;; esac
test -f "$backup" && test ! -L "$backup"
psql -Xq -v ON_ERROR_STOP=1 -U postgres -d openpc_control -f "/migrations/postgres/baseline-v1/verify.sql"
toc=$(mktemp)
trap 'rm -f -- "$toc"' EXIT HUP INT TERM
pg_restore --list "$backup" | awk '
 /^[0-9]+; [0-9]+ [0-9]+ EXTENSION - pgcrypto( |$)/ {extension++; next}
 /^[0-9]+; [0-9]+ [0-9]+ SCHEMA - public( |$)/ {schema++; next}
 {print}
 END {if (extension!=1 || schema>1) exit 78}
' > "$toc"
pg_restore --clean --if-exists --exit-on-error --single-transaction --username=postgres --dbname=openpc_control --use-list "$toc" "$backup"
PGHOST=127.0.0.1 PGUSER=postgres PGDATABASE=openpc_control sh /local/migrate.sh control-restore-checks
"#;

pub(super) struct ControlBackup {
    container: String,
    owner: PathBuf,
    file: String,
}

impl ControlBackup {
    pub(super) fn capture() -> Self {
        let container = std::env::var("OPENPC_RUNTIME_SOURCE_RECOVERY_CONTAINER").unwrap();
        let owner = PathBuf::from(std::env::var("OPENPC_RUNTIME_SOURCE_RECOVERY_OWNER").unwrap());
        let scratch = PathBuf::from(std::env::var("OPENPC_LOCAL_RUNTIME_TMP_ROOT").unwrap());
        assert!(container.starts_with("openpc-participant-readback-"));
        assert!(
            owner
                .canonicalize()
                .unwrap()
                .starts_with(scratch.canonicalize().unwrap())
        );
        let backup = Self {
            container,
            owner,
            file: format!(
                "/tmp/openpc-source-before-install-{}.dump",
                uuid::Uuid::now_v7()
            ),
        };
        backup.execute(&[
            "pg_dump",
            "--username=postgres",
            "--dbname=openpc_control",
            "--format=custom",
            "--file",
            &backup.file,
        ]);
        backup
    }

    pub(super) fn restore(&self) {
        // The caller has closed all database pools and native owners. This
        // restores only this disposable database, with its original ownership.
        if self.compact() {
            self.execute(&[
                "sh",
                "-c",
                COMPACT_RESTORE,
                "restore-owned-control",
                &self.file,
            ]);
            return;
        }
        self.execute(&[
            "pg_restore",
            "--clean",
            "--if-exists",
            "--exit-on-error",
            "--single-transaction",
            "--username=postgres",
            "--dbname=openpc_control",
            &self.file,
        ]);
    }

    pub(super) fn reapply_bootstrap(&self) {
        let arguments = [
            "env",
            "PGHOST=127.0.0.1",
            "PGUSER=postgres",
            "PGDATABASE=openpc_control",
            "sh",
            "/local/migrate.sh",
            "control",
        ];
        if !self.compact() {
            self.execute(&arguments);
            return;
        }
        // This call follows deliberate loss of the scope marker and legacy
        // membership. The compact verifier must refuse to reenroll the damaged
        // cluster, including leaving passwords, bindings and source rows alone.
        let before = self.state_digest();
        let result = self.output(&arguments);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("BASELINE-RUNTIME-ROLE-MISMATCH"));
        assert_eq!(self.state_digest(), before);
    }

    fn compact(&self) -> bool {
        self.run(&["test", "-f", "/migrations/postgres/baseline-v1/install.sql"])
    }

    fn state_digest(&self) -> Vec<u8> {
        let result = self.output(&[
            "psql",
            "-XqAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-U",
            "postgres",
            "-d",
            "openpc_control",
            "-c",
            "select encode(sha256(convert_to(jsonb_build_object('roles',(select jsonb_agg(to_jsonb(r) order by oid) from pg_authid r),'memberships',(select jsonb_agg(to_jsonb(m) order by oid) from pg_auth_members m),'sources',(select jsonb_agg(to_jsonb(s) order by source_owner_id) from control.runtime_artifact_source s),'lineage',(select jsonb_agg(to_jsonb(l) order by baseline_id) from openpc_local.baseline_lineage l))::text,'UTF8')),'hex')",
        ]);
        assert!(result.status.success());
        assert_eq!(result.stdout.len(), 65);
        result.stdout
    }

    pub(super) fn install_worker_bridges(&self, role: &str) {
        self.execute(&[
            "env",
            "PGHOST=127.0.0.1",
            "PGUSER=postgres",
            "PGDATABASE=openpc_control",
            &format!("OPENPC_CONTROL_WORKER_TRUST_ROLE={role}"),
            "sh",
            "/local/migrate.sh",
            "control",
        ]);
    }

    pub(super) fn reject_unknown_worker_bridges(&self) {
        assert!(!self.run(&[
            "env",
            "PGHOST=127.0.0.1",
            "PGUSER=postgres",
            "PGDATABASE=openpc_control",
            "OPENPC_CONTROL_WORKER_TRUST_ROLE=openpc_unknown_source_worker",
            "sh",
            "/local/migrate.sh",
            "control",
        ]));
    }

    #[track_caller]
    fn execute(&self, arguments: &[&str]) {
        let result = self.output(arguments);
        if !result.status.success() {
            // Retain raw diagnostics privately in the owned fixture only. The
            // existing bounded reporter emits redacted error classes to CI.
            let path = self
                .owner
                .join(format!("custody-command-{}.log", uuid::Uuid::now_v7()));
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap()
                .write_all(&result.stderr)
                .unwrap();
            let report = Command::new("python3")
                .arg(
                    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join("../../scripts/migrations/report-failure.py"),
                )
                .arg(path)
                .output()
                .unwrap();
            if report.status.success() {
                eprint!("{}", String::from_utf8_lossy(&report.stdout));
            }
        }
        assert!(
            result.status.success(),
            "isolated database recovery or host registration failed ({})",
            arguments[0]
        );
    }

    fn run(&self, arguments: &[&str]) -> bool {
        self.output(arguments).status.success()
    }

    fn output(&self, arguments: &[&str]) -> Output {
        let owner = Command::new("docker")
            .args([
                "inspect",
                "--format",
                "{{index .Config.Labels \"io.openpc.test-owner\"}}",
                &self.container,
            ])
            .output()
            .unwrap();
        assert!(
            owner.status.success(),
            "could not verify recovery fixture ownership"
        );
        assert_eq!(
            String::from_utf8(owner.stdout).unwrap().trim(),
            self.owner.to_str().unwrap()
        );
        let result = Command::new("docker")
            .args(["exec", &self.container])
            .args(arguments)
            .output()
            .unwrap();
        if !result.status.success() {
            // Emit only closed diagnostic classes, never command arguments,
            // database rows, role comments, credentials or raw stderr.
            let stderr = String::from_utf8_lossy(&result.stderr);
            for class in ["BASELINE-CATALOG-MISMATCH", "BASELINE-RUNTIME-ROLE-MISMATCH"] {
                if stderr.contains(class) {
                    eprintln!("ISOLATED_CUSTODY_DATABASE_ERROR|class={class}");
                }
            }
        }
        result
    }
}
