//! Actual same-cluster per-database backup/restore inside the existing isolated
//! PostgreSQL runner. Globals and host files are deliberately outside the dump.
use std::{path::PathBuf, process::Command};

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
        self.execute(&[
            "env",
            "PGHOST=127.0.0.1",
            "PGUSER=postgres",
            "PGDATABASE=openpc_control",
            "sh",
            "/local/migrate.sh",
            "control",
        ]);
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

    fn execute(&self, arguments: &[&str]) {
        assert!(
            self.run(arguments),
            "isolated database recovery or host registration failed"
        );
    }

    fn run(&self, arguments: &[&str]) -> bool {
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
        result.status.success()
    }
}
