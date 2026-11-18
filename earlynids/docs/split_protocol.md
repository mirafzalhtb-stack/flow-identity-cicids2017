# Split Protocol (v4.1)

Implementation: `src/datasets/splits.py`, CLI `scripts.make_splits`. Partitions: `train`, `val` (model selection), `calib` (calibration and stopping-parameter fitting), `test` (final evaluation only), and `excluded` (embargo, unplanned captures, excluded hosts).

## Common guarantees (all strategies)
* The unit is the flow (`flow_uid`). Duplicate `flow_uid` aborts the split.
* Only `trusted` flows (unique label match + valid early prefix) are assigned.
* Every prefix derived from a flow inherits its partition. Use `check_prefix_assignment` when prefix tables are built (Phase 2).
* Manifests are immutable: a non-empty output directory is refused (exit 5). They contain the full config, seed, input fingerprint (full SHA-256), assignment-file SHA-256, gate-report reference, per-partition counts by binary label and family, a leakage report, explicit `guarantees`, and warnings.

## Strategies
| Strategy | What is enforced | What is NOT enforced |
|---|---|---|
| **A `capture`** | Whole captures (days) in one partition | Temporal order inside a partition. Attack-type coverage (CIC-IDS2017 attacks differ by day, which must be disclosed) |
| **B `chronological`** | Global time order. Contiguous blocks. Flows crossing a boundary are excluded, and with `embargo_s` > 0 so are flows starting within ±embargo | Host separation. Ties at a boundary when `embargo_s` = 0 |
| **C `initiator`** | No initiator IP in two partitions (deterministic hash) | **Responders (servers, victims) appear in several partitions. This is not host-disjoint** |
| **C′ `host_components`** | No host (initiator or responder) in two partitions, except `exclude_hosts`, which are listed in the manifest | Feasibility: raises `InfeasibleSplitError` if one connected component exceeds `max_component_fraction`. CIC-IDS2017 traffic to shared servers and gateways will very likely make strict host-disjointness infeasible without excluding them. **Not verified on real data** |
| **D `hybrid`** | Per capture: whole assignment, or time windows (`until_fraction` of the capture's own span, or `until_utc`) with embargo at internal cuts. Captures not in the plan are excluded | Host separation |

## Leakage report (diagnostic)
Per partition pair: flow overlap (must be 0), initiator overlap, any-endpoint overlap, shared captures, time overlap within shared captures; time ranges; `chronological_order_ok`. Overlaps that the chosen strategy does not promise to remove are reported, not hidden.

## Recommended configuration for CIC-IDS2017 (to be decided after the real label audit)
Primary: `hybrid`, e.g. Monday–Wednesday → train, Thursday split in time → val / calib, Friday → test, with 60 s embargo. Check the family coverage table in the manifest. Families absent from training are evaluated as "unseen". Secondary: `chronological` and `host_components` (if feasible) as robustness analyses. The final choice is recorded in `experiment_protocol.md` before freezing.

## Example
```yaml
splits:
  strategy: hybrid
  embargo_s: 60
  hybrid_plan:
    monday: train
    tuesday: train
    wednesday: train
    thursday: [{until_fraction: 0.5, partition: val}, {until_fraction: 0.75, partition: calib}, {partition: test}]
    friday: test
```
