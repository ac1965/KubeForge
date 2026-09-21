#!/usr/bin/env python3
"""Pod Security 監査: privileged / host namespace 共有 / root 実行などを検出する。

Usage: pod_security_audit.py <json_out> <md_out>
"""
import sys

from kube import get, write_json, write_markdown

# 単体では見逃されがちだが、privileged と同等にホスト脱出を許すケーパビリティ。
HOST_ESCAPE_CAPABILITIES = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT", "SYS_CHROOT"}

# CNI/CSI などクラスタ運用上 privileged + hostPath が正当に必要な system namespace。
# ブレイクアウト・チェーン検出はここを除外し、想定外の Namespace に絞って出す
# (network_audit.py の EXEMPT_NAMESPACES と同じ方針)。
EXEMPT_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "tigera-operator", "calico-system"}


def _has_host_escape_capability(security_context: dict) -> bool:
    if security_context.get("privileged"):
        return True
    caps = (security_context.get("capabilities", {}) or {}).get("add", [])
    return bool(HOST_ESCAPE_CAPABILITIES & set(caps))


def find_breakout_chains(pods: list[dict]) -> list[dict]:
    """個別フラグの列挙ではなく、コンテナからノードを実際に乗っ取れる組み合わせを検出する。

    - privileged/特権capability + hostPath マウント: コンテナ内からホストの
      ファイルシステムに直接読み書きでき、chroot でノード root と同等になる。
    - privileged/特権capability + hostPID: nsenter でホストの PID namespace
      (PID 1 等) に侵入してノードを乗っ取れる。
    """
    chains = []
    for pod in pods:
        spec = pod["spec"]
        namespace = pod["metadata"]["namespace"]
        name = pod["metadata"]["name"]
        if namespace in EXEMPT_NAMESPACES:
            continue

        host_path_volumes = {
            v["name"]: v["hostPath"].get("path")
            for v in spec.get("volumes", []) or []
            if "hostPath" in v
        }
        host_pid = bool(spec.get("hostPID"))

        for container in spec.get("containers", []) or []:
            sc = container.get("securityContext", {}) or {}
            cname = container["name"]
            if not _has_host_escape_capability(sc):
                continue

            for vm in container.get("volumeMounts", []) or []:
                host_path = host_path_volumes.get(vm.get("name"))
                if host_path is None:
                    continue
                chains.append({
                    "namespace": namespace,
                    "pod": name,
                    "container": cname,
                    "chain": "privileged/特権capability + hostPath マウント",
                    "detail": (
                        f"hostPath '{host_path}' がコンテナ内 '{vm.get('mountPath')}' にマウントされており、"
                        "ノードのファイルシステムに直接読み書きできます (例: chroot でノード root と同等の操作)。"
                    ),
                })

            if host_pid:
                chains.append({
                    "namespace": namespace,
                    "pod": name,
                    "container": cname,
                    "chain": "privileged/特権capability + hostPID",
                    "detail": (
                        "hostPID でホストの PID namespace を共有しており、nsenter でホスト上のプロセス "
                        "(PID 1 等) に侵入してノードを乗っ取れます "
                        "(例: nsenter --target 1 --mount --net --pid -- sh)。"
                    ),
                })

    return chains


def audit_pod(pod: dict) -> list[str]:
    issues = []
    spec = pod["spec"]
    name = pod["metadata"]["name"]
    namespace = pod["metadata"]["namespace"]

    if spec.get("hostNetwork"):
        issues.append("hostNetwork=true")
    if spec.get("hostPID"):
        issues.append("hostPID=true")
    if spec.get("hostIPC"):
        issues.append("hostIPC=true")

    pod_sc = spec.get("securityContext", {})
    if not pod_sc.get("runAsNonRoot"):
        issues.append("runAsNonRoot not enforced")

    for container in spec.get("containers", []):
        sc = container.get("securityContext", {}) or {}
        cname = container["name"]
        if sc.get("privileged"):
            issues.append(f"container/{cname}: privileged=true")
        caps = (sc.get("capabilities", {}) or {}).get("add", [])
        if caps:
            issues.append(f"container/{cname}: added capabilities {caps}")
        if sc.get("runAsUser") == 0:
            issues.append(f"container/{cname}: runAsUser=0 (root)")
        if not container.get("resources", {}).get("limits"):
            issues.append(f"container/{cname}: no resource limits")

    for volume in spec.get("volumes", []):
        if "hostPath" in volume:
            issues.append(f"hostPath volume: {volume['hostPath'].get('path')}")

    return [f"{namespace}/{name}: {i}" for i in issues]


def main() -> None:
    json_out, md_out = sys.argv[1], sys.argv[2]

    pods = get("pods", all_namespaces=True)["items"]
    all_issues = []
    for pod in pods:
        all_issues.extend(audit_pod(pod))

    breakout_chains = find_breakout_chains(pods)

    write_json(json_out, {"findings": all_issues, "breakout_chains": breakout_chains})

    lines = ["# Pod Security Audit", "", f"検出件数: {len(all_issues)}", ""]
    if not all_issues:
        lines.append("問題は検出されませんでした。")
    lines.extend(f"- {issue}" for issue in all_issues)

    lines += [
        "",
        "## コンテナブレイクアウト・チェーン (ノード乗っ取りに直結する組み合わせ)",
        "",
        f"検出件数: {len(breakout_chains)}",
        "",
    ]
    if not breakout_chains:
        lines.append("問題は検出されませんでした。")
    for c in breakout_chains:
        lines.append(
            f"- **{c['namespace']}/{c['pod']} (container/{c['container']})**: {c['chain']} — {c['detail']}"
        )
    write_markdown(md_out, lines)
    print(f"Pod Security audit: {len(all_issues)} findings, {len(breakout_chains)} breakout chain(s)")


if __name__ == "__main__":
    main()
