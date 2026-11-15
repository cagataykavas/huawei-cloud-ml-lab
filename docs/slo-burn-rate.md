# Multi-window SLO burn-rate gate

`huawei-slo-evaluate` turns fixed-width request telemetry buckets into a reproducible incident
decision. It evaluates paired short and long windows so one noisy bucket cannot page on its own:

| Policy | Short window | Long window | Burn threshold |
|---|---:|---:|---:|
| fast | 5 minutes | 1 hour | 14.4x |
| slow | 30 minutes | 6 hours | 6x |

The evidence JSON contains exactly `service`, `objective`, `as_of`, `bucket_seconds`,
`minimum_requests`, and `buckets`. Each bucket contains an interval `end`, `requests`, and `errors`.
The evaluator requires six hours of ordered, contiguous coverage ending at `as_of`; gaps, duplicate
intervals, naive timestamps, extra fields, and error counts above request counts fail closed.

```bash
huawei-slo-evaluate cloud-eye-request-buckets.json > slo-report.json
```

Exit codes are stable for release and incident automation: `0` is healthy, `2` is invalid evidence,
`3` is an alert, and `4` means traffic is below the configured minimum. The report retains the
request counts, error counts, error rates, and burn rates used for each decision.

## Operational boundary

This evaluator consumes already aggregated counts. It does not query Cloud Eye, authenticate a
metric export, distinguish application errors from dependency errors, or send notifications. A
production adapter should pin the metric namespace and dimensions, preserve the provider query and
response hashes, and pass only closed time buckets into this gate. The objective and minimum traffic
must be selected from an owned service-level policy rather than copied from the example tests.
