#!/usr/bin/env python3
"""ネットワーク監査: NetworkPolicy が存在しない Namespace を検出する。

Usage: network_audit.py <json_out> <md_out>
"""
import sys

from kube import get, write_json, write_markdown

EXEMPT_NAMESPACES = {
    "kube-system", "kube-public", "kube-node-lease", "tigera-operator", "calico-system", "calico-apiserver",
}


def find_permissive_rules(policies: list[dict]) -> list[dict]:
    """NetworkPolicy は「存在する」だけでは不十分。ルールに from/to (送信元/宛先の
    絞り込み) が無いと、その方向は実質的に全許可になり、Namespace に NetworkPolicy が
    「ある」という表面的な安心感とは裏腹に何も守っていない (default-deny のつもりが
    そうなっていない、典型的な誤設定)。
    """
    findings = []
    for policy in policies:
        namespace = policy["metadata"]["namespace"]
        name = policy["metadata"]["name"]
        if namespace in EXEMPT_NAMESPACES:
            continue
        spec = policy.get("spec", {})
        policy_types = spec.get("policyTypes", [])

        if "Ingress" in policy_types:
            for rule in spec.get("ingress", []) or []:
                if "from" not in rule:
                    findings.append({
                        "namespace": namespace,
                        "policy": name,
                        "direction": "Ingress",
                        "detail": "from が指定されていないルールがあり、任意の送信元からの通信を許可しています",
                    })

        if "Egress" in policy_types:
            for rule in spec.get("egress", []) or []:
                if "to" not in rule:
                    findings.append({
                        "namespace": namespace,
                        "policy": name,
                        "direction": "Egress",
                        "detail": "to が指定されていないルールがあり、任意の宛先への通信を許可しています",
                    })

    return findings


def find_hostnetwork_bypass(pods: list[dict], covered_namespaces: set) -> list[dict]:
    """hostNetwork=true の Pod は Pod ネットワークを経由しないため、その Namespace に
    NetworkPolicy があっても効果が及ばない (NetworkPolicy は Pod のネットワーク
    namespace 単位で適用される仕組みのため)。「NetworkPolicy があるから安全」という
    判断を無効化する組み合わせとして検出する。
    """
    findings = []
    for pod in pods:
        namespace = pod["metadata"]["namespace"]
        name = pod["metadata"]["name"]
        if namespace in EXEMPT_NAMESPACES:
            continue
        if pod["spec"].get("hostNetwork"):
            has_policy = namespace in covered_namespaces
            findings.append({
                "namespace": namespace,
                "pod": name,
                "has_networkpolicy": has_policy,
                "detail": (
                    f"NetworkPolicy が存在するにもかかわらず適用されません (hostNetwork の Pod には効果がありません)"
                    if has_policy
                    else "NetworkPolicy も存在せず、ホストのネットワークに直接露出しています"
                ),
            })
    return findings


def main() -> None:
    json_out, md_out = sys.argv[1], sys.argv[2]

    namespaces = [ns["metadata"]["name"] for ns in get("namespaces")["items"]]
    policies = get("networkpolicies", all_namespaces=True)["items"]
    pods = get("pods", all_namespaces=True)["items"]

    covered = {p["metadata"]["namespace"] for p in policies}
    uncovered = sorted(set(namespaces) - covered - EXEMPT_NAMESPACES)

    permissive_rules = find_permissive_rules(policies)
    hostnetwork_bypass = find_hostnetwork_bypass(pods, covered)

    write_json(json_out, {
        "namespaces": namespaces,
        "namespaces_with_networkpolicy": sorted(covered),
        "namespaces_without_networkpolicy": uncovered,
        "permissive_rules": permissive_rules,
        "hostnetwork_bypass": hostnetwork_bypass,
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

    lines += [
        "",
        "## 実効性のない NetworkPolicy ルール (存在するが制限になっていない)",
        "",
        f"検出件数: {len(permissive_rules)}",
        "",
    ]
    if not permissive_rules:
        lines.append("問題は検出されませんでした。")
    for f in permissive_rules:
        lines.append(f"- **{f['namespace']}/{f['policy']}** ({f['direction']}): {f['detail']}")

    lines += [
        "",
        "## hostNetwork による NetworkPolicy バイパス",
        "",
        f"検出件数: {len(hostnetwork_bypass)}",
        "",
    ]
    if not hostnetwork_bypass:
        lines.append("問題は検出されませんでした。")
    for f in hostnetwork_bypass:
        lines.append(f"- **{f['namespace']}/{f['pod']}**: {f['detail']}")

    write_markdown(md_out, lines)
    print(
        f"Network audit: {len(uncovered)} namespaces without NetworkPolicy, "
        f"{len(permissive_rules)} permissive rule(s), {len(hostnetwork_bypass)} hostNetwork bypass(es)"
    )


if __name__ == "__main__":
    main()
