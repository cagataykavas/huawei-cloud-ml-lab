"""Fail CI when Kubernetes manifests lose required security or availability controls."""

from __future__ import annotations

from pathlib import Path

import yaml


def main() -> None:
    deployment = yaml.safe_load(Path("deploy/cce-deployment.yaml").read_text(encoding="utf-8"))
    pod_spec = deployment["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]
    assert pod_spec["securityContext"]["runAsNonRoot"] is True
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["resources"]["requests"]
    assert container["resources"]["limits"]
    assert container["readinessProbe"] and container["livenessProbe"]

    hpa = yaml.safe_load(Path("deploy/cce-hpa.yaml").read_text(encoding="utf-8"))
    assert hpa["spec"]["minReplicas"] >= 3
    assert hpa["spec"]["maxReplicas"] > hpa["spec"]["minReplicas"]
    print("CCE manifests validated")


if __name__ == "__main__":
    main()
