"""Resource admission and builder identity regressions; no Docker allocation."""

import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
SETTINGS = ROOT / "scripts/maintenance/server-capacity.sh"
IMAGES = ROOT / "scripts/maintenance/local-runtime-images.sh"


class ServerCapacity(unittest.TestCase):
    def shell(self, script, **env):
        return subprocess.run(["bash", "-euc", script], cwd=ROOT,
                              env={**os.environ, **env}, capture_output=True,
                              text=True, timeout=10)

    @unittest.skipUnless(os.environ.get("OPENPC_TEST_SERVER_SCOPE") == "1",
                         "requires the dedicated Linux server and systemd")
    def test_live_scope_and_smaller_nested_runtime_admission(self):
        result = self.shell('''
retained=$(node tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs reservation)
external=$(awk -v retained="$retained" 'BEGIN {printf "%.3f", 40 + int((retained*1000+1048575)/1048576)/1000}')
bash scripts/maintenance/run-bounded.sh --profile runtime-target --external-memory-gib "$external" -- bash -euc '
cg=$(cut -d: -f3 /proc/self/cgroup)
test "$(cat "/sys/fs/cgroup$cg/memory.max")" = 12884901888
read -r quota period < "/sys/fs/cgroup$cg/cpu.max"
test "$((quota * 100 / period))" = 1400
test "$CARGO_BUILD_JOBS" = 8
source scripts/maintenance/local-runtime-images.sh
openpc_builder_owned=1
openpc_stop_owned_builder
test "$OPENPC_ADMITTED_PHASE_EXTERNAL_MEMORY_KIB" = 12582912
bash scripts/maintenance/run-bounded.sh --profile runtime-target --memory-gib 3 --external-memory-gib 9.313 --reuse -- true
bash scripts/maintenance/run-bounded.sh --profile runtime-target --reuse -- true
bash scripts/maintenance/run-project.sh -- true
'
''', OPENPC_SERVER_CAPACITY="1", CARGO_BUILD_JOBS="8")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_floor_changes_only_after_verified_builder_stop(self):
        for state, expected in (("false", 0), ("true", 96)):
            result = self.shell(f"""
source "{IMAGES}"
openpc_builder_owned=1
export OPENPC_EXECUTION_PROFILE=runtime-target OPENPC_ADMITTED_PHASE_EXTERNAL_MEMORY_KIB=41943040
openpc_verify_owned_builder() {{ return 0; }}
openpc_report_container_memory() {{ return 0; }}
docker() {{
  if [[ $1 == buildx && $2 == stop ]]; then return 0
  elif [[ $1 == inspect ]]; then echo {state}
  else return 99; fi
}}
status=0
openpc_stop_owned_builder || status=$?
if [[ $status == 0 ]]; then
  test "$OPENPC_ADMITTED_PHASE_EXTERNAL_MEMORY_KIB" = 12582912
else
  test "$OPENPC_ADMITTED_PHASE_EXTERNAL_MEMORY_KIB" = 41943040
fi
exit "$status"
""", OPENPC_SERVER_CAPACITY="1")
            self.assertEqual(result.returncode, expected, result.stderr)

    def test_capacity_boundaries_preserve_os_headroom(self):
        gib = 1048576
        for total, available, cpus, host, external, expected in (
            (63*gib, 57*gib, 16, 16*gib, 40*gib, 0),
            (63*gib, 57*gib-1, 16, 16*gib, 40*gib, 75),
            (60*gib-1, 59*gib, 16, 16*gib, 40*gib, 75),
            (63*gib, 59*gib, 15, 16*gib, 40*gib, 75),
            (63*gib, 62*gib, 16, 17*gib, 40*gib, 75),
        ):
            result = self.shell(f'source "{SETTINGS}"; openpc_admit_server_capacity '
                                f'{total} {available} {cpus} {host} {external}')
            self.assertEqual(result.returncode, expected, result.stderr)

    def test_database_limits_require_server_runtime_admission(self):
        for flag, budget, expected, limits in (
            ('0', '0', 0, '1g 2g 0.75'),
            ('1', str(12*1048576), 0, '4g 4g 2'),
            ('1', str(12*1048576-1), 75, ''),
            ('1', 'invalid', 64, ''),
            ('invalid', str(40*1048576), 64, ''),
        ):
            result = self.shell(f'''source "{SETTINGS}"
openpc_runtime_database_capacity
printf '%s %s %s' "$OPENPC_LOCAL_CONTROL_PG_MEMORY" "$OPENPC_LOCAL_CONTROL_PG_SWAP" "$OPENPC_LOCAL_CONTROL_PG_CPUS"
''', OPENPC_SERVER_CAPACITY=flag, OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB=budget)
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertEqual(result.stdout, limits)

    def test_invalid_settings_reject_before_workload(self):
        runner = ROOT / "scripts/maintenance/run-bounded.sh"
        for flag, jobs, options in (
            ("yes", "2", ""), ("0", "3", ""), ("1", "9", ""),
            ("1", "8", "--cpu-percent 1500"),
            ("1", "8", "--memory-gib 17 --external-memory-gib 40"),
            ("1", "8", "--profile image-build --external-memory-gib 8"),
        ):
            result = self.shell(f'bash "{runner}" {options} -- echo FORBIDDEN',
                                OPENPC_SERVER_CAPACITY=flag, CARGO_BUILD_JOBS=jobs)
            self.assertEqual(result.returncode, 64, result.stderr)
            self.assertNotIn("FORBIDDEN", result.stdout)

    def test_builder_limits_and_identity_are_verified_for_both_profiles(self):
        image = "moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
        for flag, memory, quota in (("0", 8*1024**3, 200000), ("1", 40*1024**3, 1400000)):
            original = {
                "Config": {"Image": image, "Env": ["OPENPC_BUILDER_OWNER=openpc-r1-local-runtime-v1"]},
                "HostConfig": {"Memory": memory, "MemorySwap": memory, "CpuPeriod": 100000, "CpuQuota": quota},
                "Mounts": [{"Type": "volume", "Name": "buildx_buildkit_openpc-r1-local-v1-node_state", "Destination": "/var/lib/buildkit"}],
            }
            for mutation in ("valid", "memory", "quota", "owner", "volume"):
                config = json.loads(json.dumps(original))
                if mutation == "memory": config["HostConfig"]["Memory"] = 0
                if mutation == "quota": config["HostConfig"]["CpuQuota"] = 0
                if mutation == "owner": config["Config"]["Env"] = []
                if mutation == "volume": config["Mounts"][0]["Name"] = "unrelated"
                result = self.shell(f'''source "{IMAGES}"
docker() {{
  if [[ $1 == buildx && $2 == inspect ]]; then printf 'Driver: docker-container\\n'
  elif [[ $1 == inspect ]]; then printf '%s' "$BUILDER_FIXTURE"
  else return 99; fi
}}
openpc_verify_owned_builder
''', OPENPC_SERVER_CAPACITY=flag, BUILDER_FIXTURE=json.dumps([config]))
                self.assertEqual(result.returncode, 0 if mutation == "valid" else 96,
                                 f"{flag}/{mutation}: {result.stderr}")


if __name__ == "__main__":
    unittest.main()
