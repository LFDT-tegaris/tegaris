import copy
import hashlib
import json
import pathlib
import subprocess
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
OVERLAY = ROOT / "deploy/kustomize/overlays/i09-local-readiness"
IMAGE = "otel/opentelemetry-collector-contrib:0.159.0@sha256:1f2c54a30e713fac6b3ae77a1ec84010c2007e29ced8ec666214fc2f6739c1cc"


def render():
    raw = subprocess.check_output(
        ["kubectl", "kustomize", str(OVERLAY), "--load-restrictor", "LoadRestrictionsNone"],
        text=True,
    )
    return raw, [item for item in yaml.safe_load_all(raw) if item]


def validate(objects):
    kinds = [item["kind"] for item in objects]
    required = {"Namespace", "ServiceAccount", "Deployment", "Service", "ConfigMap", "NetworkPolicy"}
    if not required.issubset(kinds):
        raise ValueError("incomplete I09 Kubernetes object set")
    if "Secret" in kinds:
        raise ValueError("Kubernetes secret bytes are forbidden")
    deployment = next(item for item in objects if item["kind"] == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    security = container["securityContext"]
    pod_security = pod["securityContext"]
    if container["image"] != IMAGE or "@sha256:" not in container["image"]:
        raise ValueError("image is not the exact platform digest")
    if pod.get("automountServiceAccountToken") is not False or any(
        pod.get(field) is not False for field in ("hostIPC", "hostNetwork", "hostPID")
    ):
        raise ValueError("pod identity or host namespace is overprivileged")
    if not pod_security.get("runAsNonRoot") or pod_security.get("seccompProfile", {}).get("type") != "RuntimeDefault":
        raise ValueError("pod security context is incomplete")
    if (
        security.get("allowPrivilegeEscalation") is not False
        or security.get("privileged") is not False
        or security.get("readOnlyRootFilesystem") is not True
        or security.get("capabilities", {}).get("drop") != ["ALL"]
    ):
        raise ValueError("container security context is incomplete")
    for dimension in ("cpu", "memory", "ephemeral-storage"):
        if dimension not in container["resources"]["requests"] or dimension not in container["resources"]["limits"]:
            raise ValueError(f"unbounded resource {dimension}")
    if {probe for probe in ("startupProbe", "readinessProbe", "livenessProbe") if probe in container} != {
        "startupProbe", "readinessProbe", "livenessProbe"
    }:
        raise ValueError("independent probes are incomplete")
    service = next(item for item in objects if item["kind"] == "Service")
    if any(port["port"] == 13133 for port in service["spec"]["ports"]):
        raise ValueError("collector health endpoint is publicly serviced")
    policies = [item for item in objects if item["kind"] == "NetworkPolicy"]
    if not any(set(item["spec"].get("policyTypes", [])) == {"Ingress", "Egress"} for item in policies):
        raise ValueError("default deny is absent")
    if any(item["kind"] in {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"} for item in objects):
        raise ValueError("collector must have no Kubernetes API permission")
    return deployment


class I09KubernetesOciTest(unittest.TestCase):
    def test_exact_render_and_local_oci_identity(self):
        raw, objects = render()
        validate(objects)
        self.assertNotIn("OPENPC_INPUT_", raw)
        self.assertNotIn("DU-SUBQUERY", raw)
        inspect = json.loads(subprocess.check_output(["docker", "image", "inspect", IMAGE]))[0]
        self.assertEqual(inspect["Architecture"], "amd64")
        self.assertIn("sha256:1f2c54a30e713fac6b3ae77a1ec84010c2007e29ced8ec666214fc2f6739c1cc", inspect["RepoDigests"][0])
        self.assertEqual(len(hashlib.sha256(raw.encode()).hexdigest()), 64)

    def test_field_isolated_security_mutations_reject(self):
        _, objects = render()
        deployment = next(item for item in objects if item["kind"] == "Deployment")
        mutations = []
        for path, value in [
            (("spec", "template", "spec", "hostNetwork"), True),
            (("spec", "template", "spec", "containers", 0, "image"), "otel:latest"),
            (("spec", "template", "spec", "containers", 0, "securityContext", "privileged"), True),
            (("spec", "template", "spec", "containers", 0, "securityContext", "readOnlyRootFilesystem"), False),
        ]:
            candidate = copy.deepcopy(objects)
            mutated = next(item for item in candidate if item["kind"] == "Deployment")
            owner = mutated
            for key in path[:-1]:
                owner = owner[key]
            owner[path[-1]] = value
            mutations.append(candidate)
        for candidate in mutations:
            with self.assertRaises(ValueError):
                validate(candidate)


if __name__ == "__main__":
    unittest.main()
