"""Exercise the real convenience CLI with isolated command doubles, never Docker."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("policy-testing.sh").resolve()


class PolicyTestingCLI(unittest.TestCase):
    def setUp(self):
        parent = os.environ.get("OPENPC_TEST_TMP_ROOT")
        if parent:
            Path(parent).mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="policy-cli-", dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repository"
        operations = self.repo / "scripts/operations"
        operations.mkdir(parents=True)
        shutil.copyfile(SCRIPT, operations / SCRIPT.name)
        maintenance = self.repo / "scripts/maintenance"
        maintenance.mkdir()
        shutil.copyfile(SCRIPT.parent.parent / "maintenance/server-capacity.sh",
                        maintenance / "server-capacity.sh")
        (maintenance / "project-toolchain.sh").write_text(
            "openpc_use_project_toolchain() { return 0; }\n"
        )
        (maintenance / "run-bounded.sh").write_text(
            """#!/usr/bin/env bash
set -eu
python3 - "$@" <<'PY'
import json, os, sys
from pathlib import Path
fixture = Path(os.environ['OPENPC_LOCAL_RUNTIME_TMP_ROOT']) / 'container-input.json'
fixture.write_text('{}')
with open(os.environ['FAKE_CALLS'], 'a') as out:
    out.write(json.dumps({'args': sys.argv[1:], 'env': {
        k: v for k, v in os.environ.items()
        if k.startswith('OPENPC_LOCAL_RUNTIME_') or k in ('OPENPC_SERVER_CAPACITY', 'CARGO_BUILD_JOBS', 'OPENPC_QA_PUBLIC_ORIGIN', 'OPENPC_EVALUATION_UI')
    }}) + '\\n')
PY
printf 'simulated bounded command output\\n'
exit "${FAKE_RUN_EXIT:-0}"
"""
        )
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, content in {
            "git": 'if [[ "$*" == *--git-common-dir* ]]; then printf "%s/.git\\n" "$FAKE_REPO"; else printf "%s\\n" "$FAKE_REPO"; fi',
            "node": 'printf "%s\\n" "${FAKE_KEEPER_KIB:-0}"',
            "rustup": "exit 0",
            "systemctl": "exit 0",
            "systemd-run": "exit 0",
            "docker": """if [[ $1 == context ]]; then
  printf '%s\\n' "${FAKE_DOCKER_ENDPOINT:-unix:///var/run/docker.sock}"
else
  exit 0
fi""",
        }.items():
            path = self.bin / name
            path.write_text("#!/usr/bin/env bash\nset -eu\n" + content + "\n")
            path.chmod(0o700)
        self.calls = self.root / "calls.jsonl"
        self.data = self.root / "private data"
        self.env = {
            k: v for k, v in os.environ.items()
            if not k.startswith("OPENPC_") and k != "DOCKER_HOST"
        }
        self.env.update(
            PATH=f"{self.bin}:{os.environ['PATH']}",
            FAKE_REPO=str(self.repo),
            FAKE_CALLS=str(self.calls),
        )

    def invoke(self, command, *options, **overrides):
        return subprocess.run(
            ["bash", str(self.repo / "scripts/operations" / SCRIPT.name),
             command, *options, "--data-dir", str(self.data)],
            env={**self.env, **overrides}, capture_output=True, text=True, timeout=15,
        )

    def recorded(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_check_creates_no_state_and_starts_no_workload(self):
        result = self.invoke("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.data.exists())
        self.assertFalse(self.calls.exists())

    def test_qa_requires_opt_in_and_uses_standard_runtime_target_without_browser_or_new_keeper(self):
        denied = self.invoke("qa-start")
        self.assertEqual(denied.returncode, 64)
        self.assertFalse(self.calls.exists())
        result = self.invoke("qa-start", "--local-qa-fixture", FAKE_KEEPER_KIB="2949120")
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.recorded()[0]
        self.assertEqual(call["args"][:4], ["--profile", "runtime-target", "--external-memory-gib", "11.813"])
        self.assertNotIn("--memory-gib", call["args"])
        self.assertEqual(call["env"]["OPENPC_LOCAL_RUNTIME_QA_FIXTURE"], "1")
        self.assertNotIn("OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY", call["env"])

    def test_current_console_is_selected_for_new_build_run_and_qa_workspaces(self):
        for action, options in (("build", ()), ("run", ()), ("qa-start", ("--local-qa-fixture",))):
            with self.subTest(action=action):
                result = self.invoke(action, *options)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.recorded()[-1]["env"]["OPENPC_EVALUATION_UI"], "1")

    def test_explicit_console_selection_is_preserved(self):
        for value in ("0", "1"):
            for action, options in (("build", ()), ("run", ()), ("qa-start", ("--local-qa-fixture",))):
                with self.subTest(value=value, action=action):
                    result = self.invoke(action, *options, OPENPC_EVALUATION_UI=value)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.recorded()[-1]["env"]["OPENPC_EVALUATION_UI"], value)

    def test_invalid_console_selection_fails_before_allocating(self):
        for value in ("", "true", "2", "01", "native", "1 "):
            with self.subTest(value=value):
                result = self.invoke("run", OPENPC_EVALUATION_UI=value)
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertIn("OPENPC_EVALUATION_UI must be 0 or 1.", result.stderr)
                self.assertFalse(self.data.exists())
                self.assertFalse(self.calls.exists())

    def test_public_origin_reaches_only_explicit_qa_start(self):
        result = self.invoke("qa-start", "--local-qa-fixture",
                             OPENPC_QA_PUBLIC_ORIGIN="https://demo.example.org")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.recorded()[0]["env"]["OPENPC_QA_PUBLIC_ORIGIN"],
                         "https://demo.example.org")

    def test_public_origin_is_rejected_for_other_commands_before_allocation(self):
        for action in ("check", "install", "build", "run", "qa-status", "qa-stop"):
            result = self.invoke(action, OPENPC_QA_PUBLIC_ORIGIN="https://demo.example.org")
            self.assertEqual(result.returncode, 64, (action, result.stderr))
            self.assertFalse(self.data.exists())
            self.assertFalse(self.calls.exists())

    def test_existing_qa_root_resumes_original_lifecycle_without_reseeding(self):
        runtime = self.data / "runtime"
        runtime.mkdir(parents=True, mode=0o700)
        self.data.chmod(0o700)
        (runtime / "qa-root").write_text("/original/private/qa-root\n")
        result = self.invoke("qa-start", "--local-qa-fixture")
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.recorded()[0]
        self.assertEqual(call["args"][-4:], ["node", "tests/integration/local-runtime/qa-sandbox.mjs", "start", str(runtime)])
        self.assertNotIn("OPENPC_LOCAL_RUNTIME_QA_FIXTURE", call["env"])

    def test_qa_stop_preserves_the_runtime_target_resource_envelope(self):
        result = self.invoke("qa-stop", FAKE_KEEPER_KIB="2949120")
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.recorded()[0]
        self.assertEqual(call["args"][:4], ["--profile", "runtime-target", "--external-memory-gib", "11.813"])
        self.assertEqual(call["args"][-2:], ["stop", str(self.data / "runtime")])

    def test_run_selects_bounded_policy_journey_and_private_retention(self):
        result = self.invoke("run", FAKE_KEEPER_KIB="1048576")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.recorded()
        self.assertEqual(len(calls), 1)
        args = calls[0]["args"]
        self.assertEqual(args[:4], ["--profile", "runtime-target", "--external-memory-gib", "10.313"])
        self.assertIn("--memory-gib", args)
        self.assertEqual(args[-3:], ["--", "bash", "tests/integration/local-runtime/run-compose-e2e.sh"])
        env = calls[0]["env"]
        self.assertEqual(env["OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY"], "1")
        self.assertEqual(env["OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT"], "1")
        self.assertEqual(env["OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE"], "1")
        self.assertEqual(self.data.stat().st_mode & 0o777, 0o700)
        runtime = self.data / "runtime"
        self.assertEqual(runtime.stat().st_mode & 0o777, 0o700)
        self.assertEqual((runtime / "container-input.json").stat().st_mode & 0o777, 0o644)
        logs = list((self.data / "logs").glob("*.log"))
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].stat().st_mode & 0o777, 0o600)
        self.assertIn("simulated bounded command output", logs[0].read_text())

    def invoke_console_e2e(self, *options, **overrides):
        package = json.loads((SCRIPT.parents[2] / "apps/admin-web/package.json").read_text())
        console = self.repo / "apps/admin-web"
        console.mkdir(parents=True, exist_ok=True)
        return subprocess.run(
            ["bash", "-c", package["scripts"]["test:e2e"] + ' "$@"',
             "console-e2e", *options, "--data-dir", str(self.data)],
            cwd=console, env={**self.env, **overrides},
            capture_output=True, text=True, timeout=15,
        )

    def test_console_e2e_runs_real_cli_from_package_directory_with_private_data_path(self):
        result = self.invoke_console_e2e()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.recorded()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["args"][-3:],
                         ["--", "bash", "tests/integration/local-runtime/run-compose-e2e.sh"])
        self.assertEqual(calls[0]["env"]["OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY"], "1")
        self.assertEqual(calls[0]["env"]["OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE"], "1")
        self.assertEqual(self.data.stat().st_mode & 0o777, 0o700)
        self.assertTrue(list((self.data / "logs").glob("*.log")))

    def test_console_e2e_preserves_failed_journey_status(self):
        result = self.invoke_console_e2e(FAKE_RUN_EXIT="37")
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertNotIn("Policy journey passed", result.stdout)

    def test_console_e2e_rejects_unknown_options_before_allocating(self):
        result = self.invoke_console_e2e("--unknown-option")
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertFalse(self.data.exists())
        self.assertFalse(self.calls.exists())

    def test_console_e2e_rejects_inherited_scenario_before_allocating(self):
        result = self.invoke_console_e2e(OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY="1")
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertFalse(self.data.exists())
        self.assertFalse(self.calls.exists())

    def test_build_does_not_select_runtime_acceptance(self):
        result = self.invoke("build")
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.recorded()[0]
        self.assertEqual(call["args"][1], "image-build")
        self.assertEqual(call["env"]["OPENPC_LOCAL_RUNTIME_BUILD_ONLY"], "1")
        self.assertNotIn("OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY", call["env"])

    def test_failed_runtime_survives_logging_without_success_message(self):
        result = self.invoke("run", FAKE_RUN_EXIT="37")
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertNotIn("Policy journey passed", result.stdout)
        self.assertEqual(len(list((self.data / "logs").glob("*.log"))), 1)

    def test_server_capacity_reaches_build_and_runtime_without_changing_the_journey(self):
        for action in ("build", "run"):
            result = self.invoke(action, OPENPC_SERVER_CAPACITY="1")
            self.assertEqual(result.returncode, 0, result.stderr)
            call = self.recorded()[-1]
            self.assertEqual(call["args"][2:4], ["--external-memory-gib", "40.000"])
            self.assertEqual(call["env"]["CARGO_BUILD_JOBS"], "8")
            self.assertEqual(call["env"]["OPENPC_SERVER_CAPACITY"], "1")
            self.assertEqual(call["env"]["OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY"], "1")
            if action == "run":
                self.assertEqual(call["args"][6:8], ["--memory-gib", "12"])
                self.assertEqual(call["env"]["OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE"], "1")

    def test_server_capacity_does_not_reconfigure_retained_qa(self):
        for action in ("qa-start", "qa-status", "qa-stop"):
            options = ("--local-qa-fixture",) if action == "qa-start" else ()
            result = self.invoke(action, *options, OPENPC_SERVER_CAPACITY="1")
            self.assertEqual(result.returncode, 64, result.stderr)
            self.assertFalse(self.data.exists())
            self.assertFalse(self.calls.exists())

    def test_invalid_server_capacity_fails_before_allocation(self):
        result = self.invoke("build", OPENPC_SERVER_CAPACITY="yes")
        self.assertEqual(result.returncode, 64, result.stderr)
        self.assertFalse(self.data.exists())
        self.assertFalse(self.calls.exists())

    def test_failed_install_stops_before_later_dependency_steps(self):
        result = self.invoke("install", FAKE_RUN_EXIT="23")
        self.assertEqual(result.returncode, 23, result.stderr)
        calls = self.recorded()
        self.assertEqual(len(calls), 1)
        self.assertIn("--frozen-lockfile", calls[0]["args"])
        self.assertIn("--ignore-scripts", calls[0]["args"])
        self.assertNotIn("Dependencies installed", result.stdout)

    def test_successful_install_keeps_locked_dependency_and_browser_steps(self):
        result = self.invoke("install")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.recorded()
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1]["args"][-3:], ["cargo", "fetch", "--locked"])
        self.assertEqual(calls[2]["args"][-4:], ["exec", "playwright", "install", "chromium"])

    def test_inherited_fault_selection_fails_before_allocating(self):
        result = self.invoke("run", OPENPC_CANDIDATE_CONTROL_RESTORE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.data.exists())
        self.assertFalse(self.calls.exists())

    def test_unsafe_storage_and_remote_docker_do_not_start_workloads(self):
        target = self.root / "other"
        target.mkdir()
        self.data.symlink_to(target, target_is_directory=True)
        result = self.invoke("run")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(target.iterdir()), [])
        self.data.unlink()
        result = self.invoke("run", FAKE_DOCKER_ENDPOINT="ssh://different-host")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.data.exists())
        self.assertFalse(self.calls.exists())

    def test_invalid_keeper_inventory_is_not_treated_as_zero(self):
        result = self.invoke("run", FAKE_KEEPER_KIB="unknown")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
