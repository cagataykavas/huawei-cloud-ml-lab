"""Fail CI when CCE manifests lose required security or availability controls."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from cloud_lab.manifest_contract import validate_contract


def load_manifest(path: Path) -> Mapping[str, Any]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, Mapping):
        raise ValueError(f"{path} must contain a YAML mapping")
    return loaded


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate the CCE manifest contract")
    parser.add_argument("--deployment", type=Path, default=Path("deploy/cce-deployment.yaml"))
    parser.add_argument("--hpa", type=Path, default=Path("deploy/cce-hpa.yaml"))
    parser.add_argument("--pdb", type=Path, default=Path("deploy/cce-pdb.yaml"))
    args = parser.parse_args()
    validate_contract(
        load_manifest(args.deployment),
        load_manifest(args.hpa),
        load_manifest(args.pdb),
    )
    print("CCE manifest contract validated")


if __name__ == "__main__":
    main()
