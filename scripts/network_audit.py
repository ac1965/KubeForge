#!/usr/bin/env python3
"""ネットワーク監査: NetworkPolicy が存在しない Namespace を検出する。

Usage: network_audit.py <json_out> <md_out>
"""
import sys

from kube import get, write_json, write_markdown

EXEMPT_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "tigera-operator", "calico-system"}


def main() -> None:
    json_out, md_out = sys.argv[1], sys.argv[2]

    namespaces = [ns["metadata"]["name"] for ns in get("namespaces")["items"]]
    policies = get("networkpolicies", all_namespaces=True)["items"]

    covered = {p["metadata"]["namespace"] for p in policies}
    uncovered = sorted(set(namespaces) - covered - EXEMPT_NAMESPACES)

    write_json(json_out, {
        "namespaces": namespaces,
        "namespaces_with_networkpolicy": sorted(covered),
        "namespaces_without_networkpolicy": uncovered,
    })

    lines = [
        "# Network Audit",
        "",
        f"NetworkPolicy が存在しない Namespace: {len(uncovered)} 件",
        "",
    ]
    if not uncovered:
        lines.append("すべての対象 Namespace に NetworkPolicy が存在します。")
    lines.extend(f"- {ns}: NetworkPolicy なし（Pod 間通信が無制限）" for ns in uncovered)
    write_markdown(md_out, lines)
    print(f"Network audit: {len(uncovered)} namespaces without NetworkPolicy")


if __name__ == "__main__":
    main()
