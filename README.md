# Kubernetes CrashGuard Operator

A lightweight Kubernetes operator that **detects CrashLoopBackOff pods, alerts Slack with the root cause and logs, and auto-rolls-back bad deployments** to their last working revision.

Built with [Kopf](https://kopf.readthedocs.io/) (Kubernetes Operator Pythonic Framework). Under 300 lines of Python. No Prometheus required.

---

## Why

When a pod enters `CrashLoopBackOff`, Kubernetes handles the restarts correctly — but it doesn't tell your team. Services can sit broken for 30+ minutes before anyone notices. CrashGuard closes that gap: it detects the crash within seconds, posts the actual error to Slack, and (optionally) rolls the deployment back to the previous working version if the crash persists.

---

## Features

- **Fast detection** — event-driven, catches `CrashLoopBackOff` within seconds of it appearing.
- **Root-cause alerts** — Slack message includes the termination reason, exit code (translated to plain English), and the last log lines from the crashed container.
- **Conditional auto-rollback** — reverts the Deployment to its previous revision (`kubectl rollout undo`) if the crash persists past a configurable threshold.
- **Namespace opt-in via CRD** — the operator only acts on namespaces that have a `CrashLoopPolicy` applied. No policy, no monitoring.
- **Per-namespace settings** — each namespace sets its own threshold, rollback toggle, and required revision history.
- **Safety guards** — minimum revision history before rollback, a 1-hour rollback cooldown to prevent thrashing, a per-deployment skip annotation, and a startup grace period to avoid alert floods on restart.
- **Read-only on pods** — never patches or places finalizers on your pods; only patches Deployments when rolling back.

---

## How It Works

```
pod status changes
      │
      ▼
operator receives event (kopf)
      │
      ├─ namespace has a CrashLoopPolicy?  ── no ──▶ ignore
      │            │ yes
      ▼            ▼
   is the container in CrashLoopBackOff?  ── no ──▶ reset crash clock
      │ yes
      ▼
   send Slack alert (reason + exit code + last logs)
      │
      ▼
   crashing longer than thresholdMinutes AND autoRollback enabled
   AND deployment has >= minRevisionsForRollback revisions?
      │ yes
      ▼
   roll back to previous revision  ──▶  Slack: "rolling back" + "rolled back"
```

The operator is purely event-driven — it consumes near-zero resources when the cluster is healthy and only does work when a pod status actually changes.

---

## Install

```bash
# 1. Install the CRD (cluster-wide, teaches Kubernetes about CrashLoopPolicy)
kubectl apply -f manifests/crd.yaml

# 2. Deploy the operator (namespace, RBAC, deployment)
kubectl apply -f manifests/operator.yaml

# 3. Create the Slack webhook secret
kubectl -n crashguard create secret generic crashguard-secrets \
  --from-literal=SLACK_WEBHOOK_URL='https://hooks.slack.com/services/XXX/YYY/ZZZ'

kubectl -n crashguard rollout restart deployment crashguard
kubectl -n crashguard logs -f deploy/crashguard
```

---

## Enabling a Namespace

The operator does nothing until you opt a namespace in with a `CrashLoopPolicy`:

```yaml
apiVersion: crashguard.io/v1alpha1
kind: CrashLoopPolicy
metadata:
  name: policy
  namespace: payment-gateway
spec:
  thresholdMinutes: 5        # roll back after 5 min of crashlooping
  autoRollback: true         # set false for alert-only
  minRevisionsForRollback: 3 # require current + 2 previous revisions
```

```bash
kubectl apply -f my-policy.yaml

# see which namespaces are monitored
kubectl get clp --all-namespaces

# stop monitoring a namespace (takes effect within 60s, no restart)
kubectl delete clp policy -n payment-gateway
```

### Policy fields

| Field | Default | Description |
|-------|---------|-------------|
| `thresholdMinutes` | `10` | Minutes of CrashLoopBackOff before rollback is triggered. |
| `autoRollback` | `true` | Whether to roll back automatically. `false` = alert only. |
| `minRevisionsForRollback` | `3` | Revision history required before a rollback is allowed (current + N−1 previous). |

---

## Configuration (operator defaults)

Set as env vars on the operator Deployment. These are the fallback defaults used when a `CrashLoopPolicy` doesn't specify them.

| Env var | Default | Description |
|---------|---------|-------------|
| `SLACK_WEBHOOK_URL` | — | Slack incoming webhook (required for alerts). |
| `CRASH_THRESHOLD_MINUTES` | `10` | Default minutes before rollback. |
| `AUTO_ROLLBACK` | `true` | Default rollback behavior. |
| `MIN_REVISIONS_FOR_ROLLBACK` | `3` | Default revision history requirement. |
| `LOG_TAIL_LINES` | `15` | Log lines included in the alert. |
| `STARTUP_GRACE_SECONDS` | `120` | Silence period after startup, to avoid alert floods on the initial scan. |
| `ALERT_COOLDOWN_SECONDS` | `900` | Minimum seconds between repeat alerts for the same deployment. |

---

## Per-Deployment Annotation

Exempt a single deployment from auto-rollback (still alerts):

```bash
kubectl -n my-namespace annotate deployment my-app crashguard.io/skip=true
```

Useful for GitOps-managed deployments (e.g. ArgoCD) where a rollback would be overwritten on the next sync.

---

## Example Alerts

**Crash detected:**

```
🚨 CrashLoopBackOff detected
Pod: payment-gateway/payment-service-7d9f8b-xk2p
Deployment: payment-service
Container: payment-service   Restarts: 12
Reason: Error (exit code 1 — application error)
Last crashed at: 2024-06-10T03:14:22Z
Last logs:
  Error: Cannot connect to database
  Connection refused: postgres:5432

Auto-rollback in 5 min if still crashing.
```

**Rollback executed:**

```
↩️ Auto-rollback executed
Deployment: payment-gateway/payment-service
Revision: 8 → 7
Restored image: registry.../payment-service:sha-a1b2c3d4
Rollback completed successfully.
```

---

## Testing

```bash
# enable a test namespace
kubectl apply -f - <<EOF
apiVersion: crashguard.io/v1alpha1
kind: CrashLoopPolicy
metadata:
  name: policy
  namespace: default
spec:
  thresholdMinutes: 2
  autoRollback: false
  minRevisionsForRollback: 3
EOF

# trigger a crash
kubectl -n default create deployment crashtest \
  --image=busybox -- /bin/sh -c "echo 'simulated failure'; exit 1"

# you should get a Slack alert within ~1 minute, then clean up
kubectl -n default delete deployment crashtest
```

---

## Local Development

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export SLACK_WEBHOOK_URL='https://hooks.slack.com/services/...'
kubectl apply -f manifests/crd.yaml      # CRD must exist even for local runs

kopf run operator/main.py --all-namespaces --verbose
```

Kopf uses your local kubeconfig automatically when run outside the cluster.

---

## Roadmap

- **Committer attribution** — identify who pushed the code running in the crashed pod (via image SHA tag → GitHub API).
- **Per-namespace alert routing** — different Slack channels per team.
- **PagerDuty / OpsGenie** webhooks for high-severity crashes.

---

## License

MIT
