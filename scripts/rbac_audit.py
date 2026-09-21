#!/usr/bin/env python3
"""RBAC 監査: 過剰な権限を持つ ClusterRole/Role・ClusterRoleBinding/RoleBinding を検出する。

Usage: rbac_audit.py <json_out> <md_out>
"""
import sys

from kube import get, write_json, write_markdown

SENSITIVE_CLUSTER_ROLES = {"cluster-admin"}


def is_wildcard_rule(rule: dict) -> bool:
    return "*" in rule.get("apiGroups", []) or "*" in rule.get("resources", []) or "*" in rule.get("verbs", [])


def audit_roles(items: list[dict], kind: str) -> list[dict]:
    findings = []
    for role in items:
        name = role["metadata"]["name"]
        namespace = role["metadata"].get("namespace")
        wildcard_rules = [r for r in role.get("rules", []) if is_wildcard_rule(r)]
        if wildcard_rules:
            findings.append({
                "kind": kind,
                "name": name,
                "namespace": namespace,
                "issue": "wildcard-permissions",
                "rules": wildcard_rules,
            })
    return findings


def audit_bindings(items: list[dict], kind: str) -> list[dict]:
    findings = []
    for binding in items:
        name = binding["metadata"]["name"]
        namespace = binding["metadata"].get("namespace")
        role_ref = binding.get("roleRef", {})
        if role_ref.get("name") in SENSITIVE_CLUSTER_ROLES:
            findings.append({
                "kind": kind,
                "name": name,
                "namespace": namespace,
                "issue": f"bound-to-{role_ref.get('name')}",
                "subjects": binding.get("subjects", []),
            })
    return findings


def main() -> None:
    json_out, md_out = sys.argv[1], sys.argv[2]

    cluster_roles = get("clusterroles")["items"]
    roles = get("roles", all_namespaces=True)["items"]
    cluster_role_bindings = get("clusterrolebindings")["items"]
    role_bindings = get("rolebindings", all_namespaces=True)["items"]

    findings = (
        audit_roles(cluster_roles, "ClusterRole")
        + audit_roles(roles, "Role")
        + audit_bindings(cluster_role_bindings, "ClusterRoleBinding")
        + audit_bindings(role_bindings, "RoleBinding")
    )

    write_json(json_out, {"findings": findings})

    lines = ["# RBAC Audit", "", f"検出件数: {len(findings)}", ""]
    if not findings:
        lines.append("問題は検出されませんでした。")
    for f in findings:
        scope = f["namespace"] or "cluster-scoped"
        lines.append(f"- **{f['kind']}/{f['name']}** ({scope}): {f['issue']}")
    write_markdown(md_out, lines)
    print(f"RBAC audit: {len(findings)} findings")


if __name__ == "__main__":
    main()
