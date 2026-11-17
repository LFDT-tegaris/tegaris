"""Read-only build input selection for the existing bounded Compose runner."""

import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tomllib


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], timeout=30)


def within(path, parent):
    return path == parent or parent in path.parents


def context_excluded(root, path):
    # Interpret only unambiguous exclusions from the actual Docker owner.
    # Unknown patterns/re-inclusions cause extra work, never stale images.
    patterns = (root / ".dockerignore").read_text().splitlines()
    if any(line.strip().startswith("!") for line in patterns):
        return False
    for raw in patterns:
        pattern = raw.strip()
        if not pattern or pattern.startswith("#"):
            continue
        if pattern.startswith("**/"):
            basename = pattern[3:]
            if not any(char in basename for char in "?[/"):
                if basename.startswith("*.") and "*" not in basename[1:]:
                    if path.name.endswith(basename[1:]):
                        return True
                elif "*" not in basename and basename in path.parts:
                    return True
        elif not any(char in pattern for char in "*?["):
            if within(path, Path(pattern)):
                return True
    return False


def docker_inputs(root, dockerfile, source=None):
    """Return conservative local COPY inputs; unknown context use selects all."""
    if source is None:
        source = (root / dockerfile).read_text()
    if (root / f"{dockerfile}.dockerignore").exists():
        raise ValueError("Dockerfile-specific ignore requires conservative selection")
    inputs = [Path(dockerfile), Path(".dockerignore")]
    targets = []
    stages = set()
    for line in re.sub(r"\\\s*\n", " ", source).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        instruction, _, body = line.partition(" ")
        if instruction.upper() == "FROM":
            parts = shlex.split(body)
            if not parts or parts[0].startswith("--") or not (parts[0] == "scratch" or parts[0] in stages or re.search(r"@sha256:[a-f0-9]{64}$", parts[0])):
                raise ValueError("unpinned base image requires conservative selection")
            if len(parts) == 3 and parts[1].upper() == "AS":
                stages.add(parts[2])
        if instruction.upper() == "RUN":
            if any(not mount.startswith("type=cache,") for mount in re.findall(r"--mount=(\S+)", body)):
                raise ValueError("additional build context requires conservative selection")
            if "cargo build" in body:
                packages = re.findall(r"(?:^|\s)(?:-p|--package)\s+([a-z0-9_-]+)", body)
                if not packages:
                    raise ValueError("unknown Cargo target requires conservative selection")
                targets.extend(packages)
        if instruction.upper() not in ("COPY", "ADD"):
            continue
        if instruction.upper() == "ADD":
            raise ValueError("ADD requires conservative selection")
        tokens = shlex.split(body)
        from_stage = next((token[7:] for token in tokens if token.startswith("--from=")), None)
        if from_stage is not None:
            if from_stage not in stages:
                raise ValueError("external COPY requires conservative selection")
            continue
        while tokens and tokens[0].startswith("--"):
            if not tokens[0].startswith(("--chown=", "--chmod=")):
                raise ValueError("unsupported COPY option")
            tokens.pop(0)
        if body.lstrip().startswith("["):
            tokens = json.loads(body)
        elif "[" in body:
            raise ValueError("COPY with options and JSON requires conservative selection")
        if len(tokens) < 2:
            raise ValueError("invalid COPY")
        for token in tokens[:-1]:
            if any(char in token for char in "$*?[\\"):
                raise ValueError("dynamic COPY requires conservative selection")
            path = Path(token)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("COPY outside repository")
            inputs.append(path)
    return inputs, targets


def cargo_closure(root, targets):
    packages = {}
    for path in (*root.glob("crates/*/Cargo.toml"), *root.glob("services/*/Cargo.toml")):
        document = tomllib.loads(path.read_text())
        packages[document["package"]["name"]] = (path, document)
    workspace = tomllib.loads((root / "Cargo.toml").read_text()).get("workspace", {})
    pending, seen = list(targets), set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        path, document = packages[name]
        scopes = [document, *document.get("target", {}).values()]
        for scope in scopes:
            for kind in ("dependencies", "build-dependencies", "dev-dependencies"):
                for key, value in scope.get(kind, {}).items():
                    if not isinstance(value, dict):
                        continue
                    parent = path.parent
                    if value.get("workspace"):
                        value = workspace.get("dependencies", {}).get(key, {})
                        parent = root
                    if isinstance(value, dict) and "path" in value:
                        dependency = (parent / value["path"] / "Cargo.toml").resolve()
                        if not within(dependency, root):
                            raise ValueError("Cargo dependency outside repository")
                        pending.append(tomllib.loads(dependency.read_text())["package"]["name"])
    return {packages[name][0].parent.relative_to(root) for name in seen}


def validate_cargo_inputs(root, inputs, targets):
    # --locked resolves the whole workspace, not just the selected target.
    # Omitting an unrelated member changes the canonical lockfile's package set.
    workspace = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]
    excluded = {root / path for path in workspace.get("exclude", [])}
    for pattern in workspace["members"]:
        for member in root.glob(pattern):
            manifest = member / "Cargo.toml"
            if member in excluded or not manifest.is_file():
                continue
            if not any(within(manifest.relative_to(root), source) for source in inputs):
                raise ValueError(f"Docker locked workspace omits member: {member.relative_to(root)}")
    for dependency in cargo_closure(root, targets):
        if not any(within(dependency, source) for source in inputs):
            raise ValueError(f"Docker inputs omit Cargo dependency: {dependency}")
    # Every copied workspace member participates in Cargo manifest loading,
    # including dev dependencies, even if the selected binary does not use it.
    copied = []
    for manifest in (*root.glob("crates/*/Cargo.toml"), *root.glob("services/*/Cargo.toml")):
        if any(within(manifest.relative_to(root), source) for source in inputs):
            copied.append(tomllib.loads(manifest.read_text())["package"]["name"])
    for dependency in cargo_closure(root, copied):
        if not any(within(dependency, source) for source in inputs):
            raise ValueError(f"Docker workspace omits Cargo dependency: {dependency}")


def selected_services(root, services, changed):
    selected = []
    for name, build in services.items():
        context = Path(build["context"])
        if context.resolve() != root or build.get("additional_contexts"):
            return list(services)
        try:
            inputs, targets = docker_inputs(root, build["dockerfile"])
        except (ValueError, OSError):
            return list(services)
        if targets:
            validate_cargo_inputs(root, inputs, targets)
        relevant = [path for path in changed if path == Path(build["dockerfile"]) or not context_excluded(root, path)]
        if any(any(within(path, source) or within(source, path) for source in inputs) for path in relevant):
            selected.append(name)
    return selected


def validate_refresh_build_inputs(root, path, before, after):
    """Permit only context narrowing, never changes to execution or admission."""
    if path == ".dockerignore":
        if after.splitlines() != before.replace("**/AGENTS.md\n", "**/AGENTS.md\n**/Dockerfile\n", 1).splitlines():
            raise ValueError("unreviewed Docker ignore refresh")
        return
    removed = set(before.splitlines()) - set(after.splitlines())
    if not removed or any(not re.fullmatch(r"COPY (services/[a-z0-9-]+/) \1", line) for line in removed):
        raise ValueError("refresh may only omit unused Cargo source directories")
    if [line for line in before.splitlines() if line not in removed] != after.splitlines():
        raise ValueError("Docker executable or configuration changed")
    inputs, targets = docker_inputs(root, path, after)
    if not targets:
        raise ValueError("context narrowing requires a verified Cargo owner")
    validate_cargo_inputs(root, inputs, targets)


def main():
    root = Path(sys.argv[1]).resolve()
    revision = sys.argv[2]
    names = sys.argv[3:]
    if (revision != '--validate' and not re.fullmatch(r"[0-9a-f]{40}", revision)) or not names:
        raise ValueError("full predecessor and services required")
    compose = json.load(sys.stdin)["services"]
    builds = {name: compose[name]["build"] for name in names}
    if revision == '--validate':
        for build in builds.values():
            inputs, targets = docker_inputs(root, build["dockerfile"])
            if targets:
                validate_cargo_inputs(root, inputs, targets)
        return
    changed = set(git(root, "diff", "--name-only", "--no-renames", "-z", revision).split(b"\0"))
    changed.update(git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0"))
    paths = [Path(path.decode()) for path in changed if path]
    # A changed build invocation/configuration may alter inputs outside COPY.
    conservative = any(str(path).startswith(("deploy/compose/", "scripts/maintenance/")) for path in paths)
    selected = selected_services(root, builds, paths)
    if conservative:
        selected = names
    for name in selected:
        print(name)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        print("OPENPC_BUILD_INPUTS|FAIL|invalid-source-or-dependency-closure", file=sys.stderr)
        raise SystemExit(96)
