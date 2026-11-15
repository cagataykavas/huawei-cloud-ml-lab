"""CLI for reproducible SLO burn-rate evidence evaluation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .slo import evaluate_slo


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Evaluate request telemetry against SLO burn rates"
    )
    parser.add_argument("evidence", help="JSON request-bucket evidence")
    values = parser.parse_args()
    try:
        with Path(values.evidence).open(encoding="utf-8") as stream:
            evidence = json.load(stream)
        report = evaluate_slo(evidence)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(
            json.dumps({"status": "invalid", "error": str(error)}, sort_keys=True),
            file=sys.stderr,
        )
        raise SystemExit(2) from error

    print(json.dumps(report, indent=2, sort_keys=True))
    if report["status"] == "alert":
        raise SystemExit(3)
    if report["status"] == "insufficient_traffic":
        raise SystemExit(4)


if __name__ == "__main__":
    main()
