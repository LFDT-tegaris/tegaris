#!/usr/bin/env python3
import json
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def identity(locator: str) -> tuple[str, str]:
    locator = locator.strip("'")
    match = re.match(r"^(.+?)@([0-9][^()]*)", locator)
    if not match:
        raise ValueError(f"unrecognized pnpm snapshot locator: {locator}")
    return match.group(1), match.group(2)


def bom_ref(name: str, version: str) -> str:
    from urllib.parse import quote

    return f"pkg:npm/{quote(name, safe='')}@{version}"


lock = yaml.safe_load((ROOT / "pnpm-lock.yaml").read_text())
snapshots = lock.get("snapshots", {})
nodes: dict[str, set[str]] = {}
for locator in snapshots:
    name, version = identity(locator)
    nodes.setdefault(bom_ref(name, version), set())
for locator, record in snapshots.items():
    source_name, source_version = identity(locator)
    source = bom_ref(source_name, source_version)
    for collection in ("dependencies", "optionalDependencies"):
        for name, selected in (record.get(collection) or {}).items():
            version = selected.get("version") if isinstance(selected, dict) else str(selected)
            version = version.split("(", 1)[0]
            target = bom_ref(name, version)
            if target in nodes:
                nodes[source].add(target)
output = [
    {"ref": reference, "dependsOn": sorted(dependencies)}
    for reference, dependencies in sorted(nodes.items())
]
print(json.dumps(output, separators=(",", ":")))
