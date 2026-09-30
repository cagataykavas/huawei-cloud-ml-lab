# CCE release-contract audit

The deployment planner and Kubernetes validators answer different questions. The planner approves
intended model, encryption and capacity settings; a manifest validator checks general YAML posture.
Neither alone proves that the rendered CCE workload still carries the approved values.

`huawei-release-audit` closes that gap before credentials or a cluster are involved:

```bash
huawei-release-audit \
  --config configs/prod.json \
  --deployment deploy/cce-deployment.yaml \
  --hpa deploy/cce-hpa.yaml \
  --allowed-registry swr.example.com/ml/ \
  --output artifacts/release-contract.json
```

The gate binds the approved model URI, model digest, KMS key, replica envelope, Deployment identity,
HPA target and security posture. It also requires an immutable container digest from an explicit SWR
prefix and a zero-unavailable rolling update. Duplicate keys, malformed structures and documents over
the byte budget fail before a policy decision is made.

Exit codes are stable: `0` accepted, `2` malformed or operational evidence, and `3` valid evidence
rejected by policy. The report contains source hashes and reason codes, not raw manifests or secrets.

## Trust boundary

This is a pre-deployment artifact audit. It does not prove that CCE admitted the exact manifests, that
the SWR digest is signed or vulnerability-free, or that OBS/KMS/IAM resources exist. A production
release should follow it with provider-side signature verification, server-side apply, admission
receipt capture and live-state reconciliation keyed by the same evidence digest.
