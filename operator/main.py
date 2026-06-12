"""
CrashGuard v3.0 — cluster-wide CrashLoopBackOff detection, Slack alerts with
reason + logs, conditional auto-rollback, and per-namespace policy via CRD.

Config resolution per namespace (highest priority first):
  1. CrashLoopPolicy object in that namespace (CRD, optional)
  2. Operator env vars (defaults)

Rollback rule: only if the Deployment has at least min_revisions revisions in
history (default 3 = current + 2 previous). Target = immediately previous
revision. Less history -> alert only.

Slack flow per incident:
  1. :rotating_light: CrashLoopBackOff detected (reason + logs)
  2. :hourglass_flowing_sand: Rolling back now
  3. :leftwards_arrow_with_hook: Auto-rollback executed

- Event-driven, read-only on pods (no finalizers, no patches on pods).
- Watches ALL namespaces (kopf --all-namespaces), minus EXCLUDED_NAMESPACES.

Env (global defaults):
  SLACK_WEBHOOK_URL            Slack incoming webhook
  EXCLUDED_NAMESPACES          comma-separated, wildcards ok (e.g. cilium-test-*)
  CRASH_THRESHOLD_MINUTES      minutes of crashloop before rollback (default 10)
  AUTO_ROLLBACK                "true"/"false" (default true)
  MIN_REVISIONS_FOR_ROLLBACK   revisions required to allow rollback (default 3)
  LOG_TAIL_LINES               log lines in the alert (default 15)

Per-Deployment annotation:
  crashguard.io/skip: "true"   -> alert only, never roll back this deployment
"""

import os
import re
import time
import fnmatch
import logging

import kopf
import requests
import kubernetes
from kubernetes.client import ApiClient

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("crashguard")

# ---------------------------------------------------------------------------
# Global defaults (overridable per namespace via CrashLoopPolicy)
# ---------------------------------------------------------------------------

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
LOG_TAIL_LINES = int(os.environ.get("LOG_TAIL_LINES", "15"))
THRESHOLD_MINUTES = float(os.environ.get("CRASH_THRESHOLD_MINUTES", "10"))
AUTO_ROLLBACK = os.environ.get("AUTO_ROLLBACK", "true").lower() == "true"
MIN_REVISIONS_FOR_ROLLBACK = int(os.environ.get("MIN_REVISIONS_FOR_ROLLBACK", "3"))

EXCLUDED_NAMESPACES = [
    p.strip()
    for p in os.environ.get(
        "EXCLUDED_NAMESPACES",
        "kube-system,kube-public,kube-node-lease",
    ).split(",")
    if p.strip()
]

ANN_SKIP = "crashguard.io/skip"
ANN_ROLLED_BACK = "crashguard.io/rolled-back-at"
ROLLBACK_COOLDOWN_SECONDS = 3600   # never roll the same deployment twice within 1h
ALERT_COOLDOWN_SECONDS = 900       # 1 alert per DEPLOYMENT per 15 min
POLICY_CACHE_TTL = 60              # seconds to cache CrashLoopPolicy lookups

# ---------------------------------------------------------------------------
# Kubernetes clients
# ---------------------------------------------------------------------------

if os.environ.get("KUBERNETES_SERVICE_HOST"):
    kubernetes.config.load_incluster_config()
else:
    kubernetes.config.load_kube_config()

core_v1 = kubernetes.client.CoreV1Api()
apps_v1 = kubernetes.client.AppsV1Api()
custom_api = kubernetes.client.CustomObjectsApi()
api_client = ApiClient()

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

crash_tracker = {}   # {(ns, pod): first_seen_ts}
alerted = {}         # {alert_key: last_alert_ts}
_policy_cache = {}   # {ns: (policy_dict, fetched_at)}

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

EXIT_CODE_MEANINGS = {
    0:   "clean exit — process finished and was restarted (check logs/config)",
    1:   "application error (uncaught exception / generic failure)",
    2:   "shell misuse / bad arguments",
    126: "command found but not executable (permissions?)",
    127: "command not found (wrong entrypoint/CMD or missing binary)",
    134: "SIGABRT — process aborted itself",
    137: "SIGKILL — usually OOMKilled (memory limit) or force-killed",
    139: "SIGSEGV — segmentation fault (native crash)",
    143: "SIGTERM — terminated (shutdown signal)",
    255: "exit status out of range / container runtime error",
}


def namespace_excluded(namespace: str) -> bool:
    return any(fnmatch.fnmatch(namespace, pattern) for pattern in EXCLUDED_NAMESPACES)


# ---------------------------------------------------------------------------
# Per-namespace policy (CrashLoopPolicy CRD, optional)
# ---------------------------------------------------------------------------

def get_policy(namespace: str) -> dict:
    """Settings for a namespace: its CrashLoopPolicy if one exists, else env defaults."""
    now = time.time()
    cached = _policy_cache.get(namespace)
    if cached and now - cached[1] < POLICY_CACHE_TTL:
        return cached[0]

    spec = {}
    try:
        items = custom_api.list_namespaced_custom_object(
            group="crashguard.io", version="v1alpha1",
            namespace=namespace, plural="crashlooppolicies",
        ).get("items", [])
        if items:
            spec = items[0].get("spec", {}) or {}
            if len(items) > 1:
                log.warning("Multiple CrashLoopPolicies in %s — using '%s'",
                            namespace, items[0]["metadata"]["name"])
    except kubernetes.client.exceptions.ApiException:
        pass  # CRD not installed / no permission -> env defaults

    policy = {
        "threshold_minutes": float(spec.get("thresholdMinutes", THRESHOLD_MINUTES)),
        "auto_rollback": bool(spec.get("autoRollback", AUTO_ROLLBACK)),
        "min_revisions": int(spec.get("minRevisionsForRollback",
                                      MIN_REVISIONS_FOR_ROLLBACK)),
    }
    _policy_cache[namespace] = (policy, now)
    return policy


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

def send_slack(text: str):
    if not SLACK_WEBHOOK_URL:
        log.warning("SLACK_WEBHOOK_URL not set — would have sent:\n%s", text)
        return
    try:
        requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=10)
    except requests.RequestException as e:
        log.error("Slack post failed: %s", e)


def once_per_cooldown(key, cooldown=ALERT_COOLDOWN_SECONDS) -> bool:
    now = time.time()
    if now - alerted.get(key, 0) > cooldown:
        alerted[key] = now
        return True
    return False


# ---------------------------------------------------------------------------
# Crash info helpers
# ---------------------------------------------------------------------------

def get_crash_reason(cs: dict) -> dict:
    terminated = (cs.get("lastState") or {}).get("terminated") or {}
    exit_code = terminated.get("exitCode")
    return {
        "reason": terminated.get("reason", "Unknown"),
        "exit_code": exit_code,
        "exit_meaning": EXIT_CODE_MEANINGS.get(exit_code, "unknown exit code"),
        "finished_at": terminated.get("finishedAt", "?"),
    }


def get_last_logs(namespace: str, pod: str, container: str) -> str:
    for previous in (True, False):
        try:
            resp = core_v1.read_namespaced_pod_log(
                name=pod, namespace=namespace, container=container,
                previous=previous, tail_lines=LOG_TAIL_LINES,
                _preload_content=False,
            )
            text = resp.data.decode("utf-8", errors="replace")
            return ANSI_RE.sub("", text).strip()
        except kubernetes.client.exceptions.ApiException:
            continue
    return "(could not fetch logs)"


# ---------------------------------------------------------------------------
# Ownership: pod -> ReplicaSet -> Deployment
# ---------------------------------------------------------------------------

def find_owning_deployment(namespace: str, pod_name: str):
    try:
        pod = core_v1.read_namespaced_pod(pod_name, namespace)
    except kubernetes.client.exceptions.ApiException:
        return None
    for owner in pod.metadata.owner_references or []:
        if owner.kind == "ReplicaSet":
            try:
                rs = apps_v1.read_namespaced_replica_set(owner.name, namespace)
            except kubernetes.client.exceptions.ApiException:
                return None
            for rs_owner in rs.metadata.owner_references or []:
                if rs_owner.kind == "Deployment":
                    return rs_owner.name
    return None


# ---------------------------------------------------------------------------
# Conditional rollback
# ---------------------------------------------------------------------------

def get_previous_replicaset(namespace: str, deploy_name: str, min_revisions: int):
    """Return (current_rev, prev_rev, prev_rs) if the deployment has at least
    `min_revisions` revisions in history. Otherwise None -> no rollback."""
    owned = []
    for rs in apps_v1.list_namespaced_replica_set(namespace).items:
        for o in rs.metadata.owner_references or []:
            if o.kind == "Deployment" and o.name == deploy_name:
                rev = int((rs.metadata.annotations or {}).get(
                    "deployment.kubernetes.io/revision", "0"))
                owned.append((rev, rs))
    owned.sort(key=lambda t: t[0])

    if len(owned) < min_revisions:
        return None

    return owned[-1][0], owned[-2][0], owned[-2][1]


def rollback_deployment(namespace: str, deploy_name: str, policy: dict) -> bool:
    deploy = apps_v1.read_namespaced_deployment(deploy_name, namespace)
    anns = deploy.metadata.annotations or {}

    if anns.get(ANN_SKIP) == "true":
        log.info("Skip annotation set on %s/%s — not rolling back", namespace, deploy_name)
        return False

    if ANN_ROLLED_BACK in anns:
        try:
            if time.time() - float(anns[ANN_ROLLED_BACK]) < ROLLBACK_COOLDOWN_SECONDS:
                log.info("%s/%s already rolled back within cooldown", namespace, deploy_name)
                return False
        except ValueError:
            pass

    prev = get_previous_replicaset(namespace, deploy_name, policy["min_revisions"])
    if prev is None:
        log.info("%s/%s has fewer than %s revisions — leaving it alone",
                 namespace, deploy_name, policy["min_revisions"])
        return False

    current_rev, prev_rev, prev_rs = prev
    prev_images = ", ".join(c.image for c in prev_rs.spec.template.spec.containers)

    # --- announce BEFORE doing it ------------------------------------------
    log.info("Rolling back %s/%s now (rev %s -> %s)...",
             namespace, deploy_name, current_rev, prev_rev)
    send_slack(
        f":hourglass_flowing_sand: *Rolling back now*\n"
        f"*Deployment:* `{namespace}/{deploy_name}`\n"
        f"CrashLoopBackOff persisted for {policy['threshold_minutes']:.0f}+ minutes — "
        f"reverting revision {current_rev} → {prev_rev} "
        f"(image: `{prev_images}`)."
    )

    # --- do it ----------------------------------------------------------------
    template = api_client.sanitize_for_serialization(prev_rs.spec.template)
    template.get("metadata", {}).get("labels", {}).pop("pod-template-hash", None)

    patch = {
        "metadata": {"annotations": {ANN_ROLLED_BACK: str(time.time())}},
        "spec": {"template": template},
    }
    apps_v1.patch_namespaced_deployment(deploy_name, namespace, patch)

    log.info("ROLLED BACK %s/%s: revision %s -> %s", namespace, deploy_name,
             current_rev, prev_rev)
    send_slack(
        f":leftwards_arrow_with_hook: *Auto-rollback executed*\n"
        f"*Deployment:* `{namespace}/{deploy_name}`\n"
        f"*Revision:* {current_rev} → {prev_rev}\n"
        f"*Restored image:* `{prev_images}`\n"
        f"_Rollback completed successfully._"
    )
    return True


# ---------------------------------------------------------------------------
# Main handler — event-driven, fires on every pod status change
# ---------------------------------------------------------------------------

@kopf.on.event("v1", "pods")
def check_pod(namespace, name, status, event, **_):
    if namespace_excluded(namespace):
        return

    if event.get("type") == "DELETED":
        crash_tracker.pop((namespace, name), None)
        return

    container_statuses = (status or {}).get("containerStatuses") or []

    for cs in container_statuses:
        waiting = (cs.get("state") or {}).get("waiting") or {}
        if waiting.get("reason") != "CrashLoopBackOff":
            crash_tracker.pop((namespace, name), None)
            continue

        key = (namespace, name)
        now = time.time()
        first_seen = crash_tracker.setdefault(key, now)
        minutes = (now - first_seen) / 60.0

        policy = get_policy(namespace)
        deploy_name = find_owning_deployment(namespace, name)
        container = cs.get("name", "?")
        restarts = cs.get("restartCount", 0)

        # Rollback only possible per this namespace's policy + enough history
        can_rollback = (
            policy["auto_rollback"]
            and deploy_name is not None
            and get_previous_replicaset(
                namespace, deploy_name, policy["min_revisions"]) is not None
        )

        # --- alert: deduped per DEPLOYMENT ----------------------------------
        if once_per_cooldown((namespace, deploy_name or name)):
            why = get_crash_reason(cs)
            logs = get_last_logs(namespace, name, container)
            log.info("CrashLoopBackOff: %s/%s deploy=%s restarts=%s reason=%s exit=%s",
                     namespace, name, deploy_name, restarts,
                     why["reason"], why["exit_code"])
            rollback_note = ""
            if can_rollback:
                remaining = max(policy["threshold_minutes"] - minutes, 0)
                rollback_note = (f"\n_Auto-rollback in {remaining:.0f} min "
                                 f"if still crashing._")
            send_slack(
                f":rotating_light: *CrashLoopBackOff detected*\n"
                f"*Pod:* `{namespace}/{name}`\n"
                f"*Deployment:* `{deploy_name or 'none (standalone pod)'}`\n"
                f"*Container:* `{container}`   *Restarts:* {restarts}\n"
                f"*Reason:* `{why['reason']}` (exit code {why['exit_code']} — "
                f"{why['exit_meaning']})\n"
                f"*Last crashed at:* {why['finished_at']}\n"
                f"*Last logs:*\n```{logs[-2500:] or '(no log output)'}```"
                f"{rollback_note}"
            )

        # --- rollback after this namespace's threshold ------------------------
        if can_rollback and minutes >= policy["threshold_minutes"]:
            try:
                if rollback_deployment(namespace, deploy_name, policy):
                    crash_tracker.pop(key, None)
            except Exception as e:
                log.exception("Rollback failed for %s/%s", namespace, deploy_name)
                send_slack(f":x: Rollback FAILED for `{namespace}/{deploy_name}`: {e}")


@kopf.on.startup()
def startup(settings: kopf.OperatorSettings, **_):
    settings.posting.enabled = False
    log.info("CrashGuard v3.0 started — defaults: threshold=%s min, auto_rollback=%s, "
             "min_revisions=%s, excluded=%s (per-namespace CrashLoopPolicy overrides "
             "supported)",
             THRESHOLD_MINUTES, AUTO_ROLLBACK, MIN_REVISIONS_FOR_ROLLBACK,
             EXCLUDED_NAMESPACES)