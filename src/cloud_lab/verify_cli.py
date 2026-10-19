"""Command-line model artifact verification."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from .config import DeploymentConfig
from .model_integrity import DEFAULT_MAX_BYTES, ArtifactAccessError, verify_model_artifact


def run(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a downloaded model against its approved deployment digest"
    )
    parser.add_argument("config", help="deployment configuration JSON")
    parser.add_argument("artifact", help="downloaded local model file")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    values = parser.parse_args(arguments)

    try:
        config = DeploymentConfig.from_json(values.config)
        result = verify_model_artifact(config, values.artifact, max_bytes=values.max_bytes)
    except (ArtifactAccessError, OSError, ValueError) as error:
        print(
            json.dumps(
                {
                    "schema_version": "model-artifact-verification/v1",
                    "verified": False,
                    "error": type(error).__name__,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 3

    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.verified else 2


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
