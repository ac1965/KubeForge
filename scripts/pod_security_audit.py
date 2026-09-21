#!/usr/bin/env python3
"""Pod Security 監査: privileged / host namespace 共有 / root 実行などを検出する。

Usage: pod_security_audit.py <json_out> <md_out>
"""
import sys

from kube import get, write_json, write_markdown


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

    write_json(json_out, {"findings": all_issues})

    lines = ["# Pod Security Audit", "", f"検出件数: {len(all_issues)}", ""]
    if not all_issues:
        lines.append("問題は検出されませんでした。")
    lines.extend(f"- {issue}" for issue in all_issues)
    write_markdown(md_out, lines)
    print(f"Pod Security audit: {len(all_issues)} findings")


if __name__ == "__main__":
    main()
