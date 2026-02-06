# to-fix

Date: 2026-02-06
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
- Wazuh Managers no longer crash on startup:
  - Baseline `<remote>` (1514/tcp secure) and `<auth>` (1515) are present in generated `ossec.conf`.
  - Cluster placeholders now match the image init expectations and the cluster key is injected via `WAZUH_CLUSTER_KEY`.
  - Config files are mounted via `/wazuh-config-mount/...` so init scripts can copy + `sed -i` the real `/var/ossec/etc/ossec.conf`.
  - Default `local_decoder.xml` and `local_rules.xml` are valid minimal files (no more `wazuh-testrule` config errors).
- Dashboard Wazuh plugin no longer logs `Invalid URL`:
  - default generated `WAZUH_API_URL` is now host-only (`https://<manager-service>`) instead of embedding `:55000`.
- Manager `ossec.conf` now includes `<indexer><ssl>...</ssl></indexer>` with mounted cert paths:
  - `/var/ossec/etc/certs/ca.crt`
  - `/var/ossec/etc/certs/tls.crt`
  - `/var/ossec/etc/certs/tls.key`
  - after manager restart, the previous indexer TLS handshake bursts stopped during re-check window.
- `WazuhListener` attach mode works end-to-end for dynamic ports:
  - `examples/dynamic-ports/listener.yaml` creates a listener that patches `Service/wazuh-manager` ports.
  - Listener entries are appended to `ossec.conf` and the manager StatefulSets expose the corresponding container ports.

## Remaining issues (not working)

## 1) Startup noise (non-blocking)

- Managers still log a large number of `chown: ... Read-only file system` lines for serviceaccount and `/wazuh-config-mount/*` paths because those are Kubernetes-projected/configmap/secret volumes.
- This is noisy but does not block startup anymore; if we want it cleaner, we would need to adjust the image init behavior (not owned by the operator) or add an init wrapper to skip those ownership operations.

## 2) Missing list files warnings (non-blocking)

- `wazuh-analysisd` warns that several list files are not present (for example `etc/lists/audit-keys`, `etc/lists/malicious-ioc/*`, `etc/lists/amazon/aws-eventnames`).
- This does not prevent pods from becoming ready, but related built-in rules are ignored.

## 3) Listener create-mode selectors (coverage gap)

- `Attach` mode (cluster-wide) is validated.
- `Create` mode (per-selector dedicated Service(s), including `headless: true`) is not yet validated in this test run.

## Current workload status snapshot

- Running:
  - `wazuh-indexer-0` (`1/1`)
  - `wazuh-dashboard-*` (`2/2`)
  - `wazuh-manager-master-0` (`2/2`)
  - `wazuh-manager-worker-0` (`2/2`)
  - `wazuh-indexer-config-cronjob-*` jobs complete successfully.
