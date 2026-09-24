# Database restore rehearsal audit

Retention settings prove that backups are scheduled; they do not prove that a
backup can be restored within the service's recovery objectives. This audit
turns evidence from an isolated GaussDB/RDS restore rehearsal into a
deterministic deployment or operations gate.

## Evidence contract

The producer records provider timestamps, the source and isolated restore
instances, validation counts, network/encryption posture, cleanup outcome and
content manifests:

```json
{
  "schema_version": 1,
  "drill_id": "drill-2026-09-24",
  "backup_id": "backup-prod-0042",
  "source_instance_id": "gaussdb-prod",
  "restore_instance_id": "gaussdb-restore-drill",
  "region": "tr-west-1",
  "backup_completed_at": "2026-09-24T08:00:00Z",
  "recovery_point_at": "2026-09-24T09:45:00Z",
  "restore_started_at": "2026-09-24T10:00:00Z",
  "restore_ready_at": "2026-09-24T10:12:00Z",
  "validation_completed_at": "2026-09-24T10:20:00Z",
  "cleanup_completed_at": "2026-09-24T10:25:00Z",
  "source_manifest": {
    "row_count": 150000,
    "schema_sha256": "<64 lowercase hex characters>",
    "data_sha256": "<64 lowercase hex characters>"
  },
  "restored_manifest": {
    "row_count": 150000,
    "schema_sha256": "<matching SHA-256>",
    "data_sha256": "<matching SHA-256>"
  },
  "validation_queries_total": 5,
  "validation_queries_passed": 5,
  "private_network": true,
  "kms_key_id": "kms-prod-key",
  "cleanup_succeeded": true
}
```

Timestamps must be timezone-aware and chronologically consistent. Digests,
counts and booleans are validated strictly; duplicate JSON fields and oversized
artifacts fail closed.

```bash
python -m cloud_lab.restore_audit restore-drill.json \
  --output artifacts/restore-audit.json
```

Exit `0` means accepted, `2` means well-formed evidence violated policy, and
`3` means the evidence or policy was invalid.

## Release gates

The audit measures:

- RPO: restore start minus the backup recovery point;
- RTO: restore start through validation completion;
- provider backup age at restore start;
- restore-ready and validation durations;
- schema, data and row-count manifest equality;
- validation-query completion;
- source/restore instance isolation;
- private-network, KMS and cleanup evidence.

Every violation has a stable reason code. The JSON report includes the active
policy and a canonical SHA-256 digest of the normalized artifact, but no
database contents.

## Trust boundary and limitations

The gate trusts the evidence producer. Production evidence should come from a
restricted drill workflow using provider APIs, signed logs and immutable
storage; a caller-supplied boolean does not prove that networking, encryption
or cleanup actually occurred.

Full-data digests can be expensive and may require a stable canonical export.
Sample digests provide weaker evidence. Row counts and hashes do not establish
transactional consistency, application-level correctness, user permissions or
successful secret rotation. KMS-key presence does not prove restore-time key
availability.

A same-region rehearsal does not prove regional disaster recovery. Point-in-
time recovery, replica promotion and cross-region copies need separate drills.
RPO is measured against the declared provider recovery point, not the last
business transaction. Thresholds must follow the service's documented SLO and
be calibrated with realistic data volume.
