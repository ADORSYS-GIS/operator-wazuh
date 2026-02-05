# to-fix

Date: 2026-02-05
Cluster: docker-desktop (M2/arm64)
Namespace under test: `wazuh-test`
Deploy sources: `examples/ca`, `examples/simple-stack`, `examples/security`, `examples/backups`

## Implemented and now working

- CRDs apply cleanly (`kubectl apply -f manifests/crds`).
- Operator RBAC covers newly used resources (no more `forbidden` for `wazuhlisteners` / `wazuhconfigs` in current logs).
- `wazuh-indexer-config` cronjob is healthy and recurring:
  - latest jobs complete (`Complete 1/1`)
  - `securityadmin.sh` succeeds (`Done with success`).
- Indexer and Dashboard are running and reachable via their services.

## Remaining issues (not working)

## 1) Wazuh Manager container crashes on both master and worker (blocking)

- Symptom:
  - `wazuh-manager-master-0` and `wazuh-manager-worker-0` are `1/2` with `CrashLoopBackOff`.
- Evidence (manager container logs):
  - `wazuh-remoted: CRITICAL: Remoted connection is not configured.`
  - `wazuh-remoted: Configuration error. Exiting`
- Current generated config:
  - `ConfigMap/wazuh-manager-master-config` and `ConfigMap/wazuh-manager-worker-config` contain a very minimal `ossec.conf` with only `<cluster>` and `<indexer>` blocks.
- Likely root cause:
  - The generated `ossec.conf` is missing required manager/remoted sections for this image startup path.
- Fix direction:
  - Generate a complete manager-safe `ossec.conf` baseline and merge cluster/indexer/listener/rule/decoder overlays instead of replacing config with a minimal file.

## 2) Manager startup script noise and config assumptions (non-blocking but high noise)

- Observed on both manager pods:
  - many `Read-only file system` warnings from `chown`
  - `sed: cannot rename ... Device or resource busy`
  - `wazuh-keystore ... Error reading from stdin.`
- Impact:
  - These are noisy and may hide real failures; primary blocker is still `wazuh-remoted` config error.
- Fix direction:
  - Align mounted paths and init behavior with image expectations, or disable unsupported init operations when using read-only mounted config files.

## 3) Listener behavior not yet validated against multi-worker selectors (coverage gap)

- Current test deployment (`examples/*`) does not create `WazuhListener` objects, so listener attach/create behavior was not exercised in this run.
- Need targeted test:
  - create listeners selecting multiple managers/workers
  - verify ports are reflected in managed services as intended.

## Current workload status snapshot

- Running:
  - `wazuh-indexer-0` (`1/1`)
  - `wazuh-dashboard-*` (`2/2`)
  - `wazuh-indexer-config-cronjob-*` jobs complete successfully.
- Not healthy:
  - `wazuh-manager-master-0` (`1/2`, CrashLoopBackOff)
  - `wazuh-manager-worker-0` (`1/2`, CrashLoopBackOff)
