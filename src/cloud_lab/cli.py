"""Validate configuration and emit a deterministic deployment plan."""

from __future__ import annotations

import argparse
import json

from .config import DeploymentConfig
from .planner import build_plan


def main() -> None:
    parser = argparse.ArgumentParser(description="Huawei Cloud ML deployment planner")
    parser.add_argument("config")
    parser.add_argument("--allow-policy-errors", action="store_true")
    values = parser.parse_args()
    plan = build_plan(DeploymentConfig.from_json(values.config))
    print(json.dumps(plan, indent=2, sort_keys=True))
    if not plan["deployable"] and not values.allow_policy_errors:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
