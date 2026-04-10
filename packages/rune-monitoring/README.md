# rune-monitoring

Health checks, metric collection, threshold alerting, SLA tracking, and system status for the RUNE governance ecosystem.

## Overview

`rune-monitoring` is the **observation layer** of RUNE's active-defense stack. Where `rune-detection` senses attacks and `rune-shield` defends against them, `rune-monitoring` continuously observes *system health* — liveness, readiness, performance, availability — and produces the signals that feed dashboards, incident runbooks, and capacity planning.

Every event speaks in `rune-security`'s `SecuritySeverity` vocabulary so monitoring flows naturally into security dashboards and incident management.

## Modules

| Module | Purpose |
|--------|---------|
| `health` | `HealthCheck`, `HealthStatus`, `HealthCheckRunner`, `HealthSummary` |
| `metric` | `MetricRegistry`, `MonitoringMetric`, percentile/rate/trend |
| `threshold` | `ThresholdRule`, `ThresholdEngine`, built-in rule templates |
| `sla` | `Sla`, `SlaTarget` (Uptime/Latency/ErrorRate/Throughput/ResponseTime/Custom), `SlaTracker`, templates |
| `uptime` | `UptimeTracker`, availability %, MTBF |
| `status` | `SystemStatus`, `OverallStatus`, `StatusAggregator`, `StatusPage` (text + JSON) |
| `policy` | `MonitoringPolicy`, `AlertChannel`, `MonitoringPolicySet`, production templates |
| `collector` | `MetricSource`, `CollectorEngine` — push-based sample drain |
| `audit` | `MonitoringAuditLog` with 11 event types and filters |
| `error` | `MonitoringError` with 11 typed variants |

## Health Checks

| HealthCheckType | Meaning |
|-----------------|---------|
| `Liveness`      | Is the process alive? |
| `Readiness`     | Can the process serve traffic? |
| `Dependency`    | Is an external dependency reachable? |
| `Performance`   | Are performance SLOs being met? |
| `Storage`       | Is storage writable with headroom? |
| `Memory`        | Is memory usage within bounds? |
| `Custom(name)`  | Anything else |

`HealthCheckRunner::summary()` rolls up per-check results into a worst-case `HealthStatus` plus counts for `healthy`, `degraded`, `unhealthy`, `unknown`, and `critical_failures` (unhealthy checks marked `.critical()`). A run is **operational** iff overall is Healthy/Degraded *and* `critical_failures == 0`.

## Metrics

`MetricRegistry` is a pure in-memory time-series store keyed by metric id:

- `record(id, value, ts)` — rejects NaN/±∞ and unknown metrics
- `latest`, `count`, `sum`, `average`, `max`, `min`
- `percentile(id, p)` — linear-interpolated across the sorted sample set
- `rate(id)` — samples/sec across the first→last timestamp window (requires ≥ 2 samples)
- `trend(id)` — first-half avg vs second-half avg with a 5% stability band; `lower_is_better` metrics flip the improving/degrading direction (Timer/Histogram default to lower-is-better)

## Threshold Alerting

Rules combine a metric id, a `ThresholdCondition`, a severity, and an enabled flag. `ThresholdEngine::evaluate(&registry, now)` returns *transitions* only (newly-firing or newly-resolved), so the engine can be polled repeatedly without duplicate events.

| Condition | Description |
|-----------|-------------|
| `Above { value }` / `Below { value }` | Latest sample strictly above/below |
| `OutsideRange { lo, hi }` | Latest sample outside the inclusive range |
| `RateAbove { value }` | Samples/sec above |
| `PercentileAbove { percentile, value }` | p(k) above |
| `AverageAbove { value }` / `AverageBelow { value }` | Running average above/below |

Built-in templates: `high_error_rate`, `high_latency` (p95), `low_availability`, `high_memory`, `queue_depth`.

## SLA Tracking

An `Sla` binds an `SlaTarget` to a metric; `SlaTracker::evaluate` returns `SlaStatus` with a tri-state: **Meeting**, **AtRisk** (close to target), **Breached**. Every breach also produces an `SlaViolation` record. Built-ins: `five_nines`, `four_nines`, `three_nines`, `fast_api` (p95 ≤ 100ms), `standard_api` (p95 ≤ 500ms).

## System Status

`StatusAggregator::aggregate(health, uptime, thresholds, slas, now)` computes an `OverallStatus` as the worst of:
- health rollup (Healthy→Operational, Degraded→Degraded, Unhealthy→PartialOutage, Unknown→Degraded)
- critical health failures → MajorOutage
- any `UptimeTracker` component in Down state → MajorOutage
- any active threshold alerts or breached SLAs → Degraded

`StatusPage::render_text` / `render_json` emits a human-readable or machine-readable snapshot with per-component availability %.

## Four-Pillar Alignment

- **Security Baked In**: Default production policy has medium severity floor, log alerts, and 15/30s intervals out of the box. Every health check, metric collection, threshold transition, SLA breach, and component state change lands in `MonitoringAuditLog` automatically.
- **Assumed Breach**: Availability and MTBF are computed from observed state transitions, so a silent dependency degradation is still quantifiable. Status page aggregates across independent signals — a healthy-looking health check plus a down `UptimeTracker` component still produces MajorOutage.
- **Zero Trust Throughout**: `HealthCheckRunner::record` rejects results for unregistered checks; `MetricRegistry::record` rejects unknown metrics and non-finite values; `CollectorEngine::submit` rejects unknown sources; thresholds require explicit rule+metric binding.
- **No Single Points of Failure**: Four independent subsystems (health, uptime, thresholds, SLAs) feed the status aggregator; the overall status is the worst of any of them, so a bug or blind spot in one detector cannot mask a problem visible to another.

## Usage

```rust
use rune_monitoring::*;
use rune_security::SecuritySeverity;

// 1. Register health checks.
let mut health = HealthCheckRunner::new();
health.register(HealthCheck::new("db", "Database", HealthCheckType::Dependency, "db").critical());
health.record(HealthCheckResult::healthy(HealthCheckId::new("db"), 1_700_000_000)).unwrap();

// 2. Register and record metrics.
let mut metrics = MetricRegistry::new();
metrics.register(MonitoringMetric::new("api_lat", "API Latency", MonitoringMetricType::Timer, "ms"));
for v in [12.0, 15.0, 18.0, 22.0] { metrics.record("api_lat", v, 1_700_000_000).unwrap(); }

// 3. Threshold alerting.
let mut thresholds = ThresholdEngine::new();
thresholds.add_rule(high_latency("api_lat", 100.0));
let transitions = thresholds.evaluate(&metrics, 1_700_000_000);
for alert in transitions {
    println!("{} {} @ {}", alert.status, alert.rule_id, alert.fired_at);
}

// 4. SLA tracking.
let mut slas = SlaTracker::new();
slas.register(fast_api("api_lat"));
let _ = slas.evaluate(&metrics, 1_700_000_000);

// 5. Uptime.
let mut uptime = UptimeTracker::new();
uptime.register("api", 1_700_000_000);

// 6. Aggregated status.
let system = StatusAggregator::aggregate(
    &health.summary(),
    &uptime,
    &thresholds,
    &slas,
    1_700_000_000,
);
println!("{}", StatusPage::render_text(&system));
assert_eq!(system.overall, OverallStatus::Operational);
```

## Tests

96 tests across all modules, covering:
- Health status ordering (Healthy < Unknown < Degraded < Unhealthy), severity mapping, critical-failure operational gating
- Metric record validation (NaN/±∞ rejection, unknown metric rejection), percentile with single/many samples, rate with insufficient data, trend improving/degrading/stable/insufficient with lower-is-better flip
- All seven `ThresholdCondition` variants, transition-only evaluation (no duplicate firing), rule disable and removal, built-in templates
- All six `SlaTarget` variants with meeting/at-risk/breached tri-state, violation trail, count aggregation, all five templates
- Uptime state machine (up/down/maintenance), availability with in-flight transitions, MTBF with and without failures, overall availability arithmetic mean
- Status aggregation worst-case rollup, all-maintenance downgrade, alphabetical component ordering, text and JSON rendering
- Policy severity floor, disabled policies never notify, `for_target` with `AllServices`, production and high-availability templates
- Collector push/drain with unknown metrics counted as errors, disabled sources skipped, multi-source merge
- Audit log filters: threshold, SLA, health, by severity, since, all 11 event-type displays
