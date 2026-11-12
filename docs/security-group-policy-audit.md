# Security-group policy audit

The deployment planner says the CCE inference tier belongs in a private VPC,
but a boolean configuration cannot prove that the deployed security group still
matches a reviewed network contract. `cloud_lab.network_audit` evaluates a
normalized provider snapshot before deployment or promotion.

## Contract

The snapshot identifies the exact security group, provider revision, capture
time, and bounded allow rules. Each rule has one source or destination:

- a canonical IPv4/IPv6 CIDR; or
- a constrained peer security-group identifier.

The policy declares reviewed allowances using the same direction, protocol,
port, and remote identity fields. CIDR rules may be narrower than their
allowance, but broader rules fail closed. Required allowances also prove that
critical paths such as API Gateway ingress or database egress were not removed.

```python
report = audit_security_group(snapshot, policy, evaluated_at=now)
if not report.accepted:
    raise RuntimeError(report.to_dict())
```

The audit rejects:

- rules outside the allowlist;
- missing required paths;
- mismatched security-group identities;
- stale or implausibly future-dated snapshots;
- malformed protocols, port ranges, CIDRs, identifiers, and schemas;
- duplicate or excessive rules; and
- global CIDR allowances unless the policy sets `permit_global=true`.

The report is deterministic for fixed evidence and evaluation time. Its
SHA-256 digest binds the normalized snapshot and reviewed policy while sorting
rules and allowances by identity, so source ordering does not change the
commitment.

## Trust boundaries

- This module audits normalized evidence; it does not call Huawei Cloud or
  authenticate the snapshot producer.
- Security-group allow rules are only one layer. Route tables, NACLs, ELB/API
  Gateway policies, Kubernetes NetworkPolicy, DNS, NAT, and service-side
  authorization can still change reachability.
- `permit_global=true` records an explicit exception; it does not make public
  exposure safe.
- Fresh evidence can become stale immediately after evaluation. Production
  admission should bind the accepted digest to the exact deployment revision.

The next increment should add a read-only adapter for signed provider exports
and cross-bind the accepted digest to the CCE release contract.
