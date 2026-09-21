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


def covers_serviceaccount_token_creation(rule: dict) -> bool:
    """`kubectl create token <sa>` (serviceaccounts/token の create) を許可する rule か。"""
    api_groups = rule.get("apiGroups", [])
    resources = rule.get("resources", [])
    verbs = rule.get("verbs", [])
    api_ok = "*" in api_groups or "" in api_groups
    resource_ok = "*" in resources or "serviceaccounts/token" in resources
    verb_ok = "*" in verbs or "create" in verbs
    return api_ok and resource_ok and verb_ok


def build_role_rules_index(cluster_roles: list[dict], roles: list[dict]) -> dict:
    index = {}
    for cr in cluster_roles:
        index[("ClusterRole", None, cr["metadata"]["name"])] = cr.get("rules", [])
    for r in roles:
        index[("Role", r["metadata"]["namespace"], r["metadata"]["name"])] = r.get("rules", [])
    return index


def collect_privileged_service_accounts(cluster_role_bindings: list[dict], role_bindings: list[dict]) -> set:
    """SENSITIVE_CLUSTER_ROLES (cluster-admin 等) にバインドされている ServiceAccount の (namespace, name) 集合。"""
    privileged = set()
    for binding in cluster_role_bindings + role_bindings:
        if binding.get("roleRef", {}).get("name") not in SENSITIVE_CLUSTER_ROLES:
            continue
        for subject in binding.get("subjects", []) or []:
            if subject.get("kind") == "ServiceAccount":
                privileged.add((subject.get("namespace"), subject.get("name")))
    return privileged


def find_token_escalation_paths(
    cluster_role_bindings: list[dict],
    role_bindings: list[dict],
    role_rules_index: dict,
    privileged_sas: set,
) -> list[dict]:
    """2024年以降実際に悪用される手口: あるトークンさえあれば同じ namespace 内の
    cluster-admin 付き ServiceAccount のトークンを `kubectl create token` で
    発行できてしまう経路 (RoleBinding は namespace スコープに見えるが、
    serviceaccounts/token への create 権限があれば実質的に権限昇格になる)。
    """
    findings = []

    def resource_name_lists_for(rules: list[dict]) -> list[list[str]]:
        return [rule.get("resourceNames", []) for rule in rules if covers_serviceaccount_token_creation(rule)]

    def escalation_capable_subjects(subjects: list[dict], target_ns: str, target_sa: str) -> list[dict]:
        # Kubernetes 組み込みの Group/User (system:masters, kubeadm:cluster-admins,
        # system:kube-controller-manager 等) は既に強い権限を持つ制御プレーンの
        # 識別子であり、「ワークロードが乗っ取られてトークンを奪う」シナリオの
        # 対象外なので ServiceAccount subject のみを対象にする。
        # また、なりすます先の SA 自身や、既に privileged な SA からの自己昇格も除外する。
        return [
            s
            for s in (subjects or [])
            if s.get("kind") == "ServiceAccount"
            and not (s.get("namespace") == target_ns and s.get("name") == target_sa)
            and (s.get("namespace"), s.get("name")) not in privileged_sas
        ]

    # ClusterRoleBinding は全 namespace に対して有効。
    for binding in cluster_role_bindings:
        role_ref = binding.get("roleRef", {})
        rules = role_rules_index.get(("ClusterRole", None, role_ref.get("name")), [])
        name_lists = resource_name_lists_for(rules)
        if not name_lists:
            continue
        for ns, sa_name in privileged_sas:
            subjects = escalation_capable_subjects(binding.get("subjects"), ns, sa_name)
            if not subjects:
                continue
            if any(not names or sa_name in names for names in name_lists):
                findings.append({
                    "target_namespace": ns,
                    "target_service_account": sa_name,
                    "via": f"ClusterRoleBinding/{binding['metadata']['name']}",
                    "subjects": subjects,
                })

    # RoleBinding はそれ自身の namespace 内でのみ有効。
    for binding in role_bindings:
        namespace = binding["metadata"]["namespace"]
        role_ref = binding.get("roleRef", {})
        key = (
            ("ClusterRole", None, role_ref.get("name"))
            if role_ref.get("kind") == "ClusterRole"
            else ("Role", namespace, role_ref.get("name"))
        )
        rules = role_rules_index.get(key, [])
        name_lists = resource_name_lists_for(rules)
        if not name_lists:
            continue
        for ns, sa_name in privileged_sas:
            if ns != namespace:
                continue
            subjects = escalation_capable_subjects(binding.get("subjects"), ns, sa_name)
            if not subjects:
                continue
            if any(not names or sa_name in names for names in name_lists):
                findings.append({
                    "target_namespace": ns,
                    "target_service_account": sa_name,
                    "via": f"RoleBinding/{binding['metadata']['name']}",
                    "subjects": subjects,
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

    role_rules_index = build_role_rules_index(cluster_roles, roles)
    privileged_sas = collect_privileged_service_accounts(cluster_role_bindings, role_bindings)
    escalation_findings = find_token_escalation_paths(
        cluster_role_bindings, role_bindings, role_rules_index, privileged_sas
    )

    write_json(json_out, {"findings": findings, "token_escalation_paths": escalation_findings})

    lines = ["# RBAC Audit", "", f"検出件数: {len(findings)}", ""]
    if not findings:
        lines.append("問題は検出されませんでした。")
    for f in findings:
        scope = f["namespace"] or "cluster-scoped"
        lines.append(f"- **{f['kind']}/{f['name']}** ({scope}): {f['issue']}")

    lines += [
        "",
        "## Token 昇格パス (ServiceAccount トークンなりすましによる権限昇格)",
        "",
        f"検出件数: {len(escalation_findings)}",
        "",
    ]
    if not escalation_findings:
        lines.append("問題は検出されませんでした。")
    for f in escalation_findings:
        subjects_desc = ", ".join(
            f"{s.get('kind')}:{s.get('namespace', '-')}/{s.get('name')}" for s in f["subjects"]
        )
        lines.append(
            f"- **{f['via']}** により `{subjects_desc}` は、namespace `{f['target_namespace']}` の "
            f"cluster-admin 権限 ServiceAccount `{f['target_service_account']}` のトークンを発行でき、"
            f"実質的に cluster-admin へ権限昇格できます"
        )
    write_markdown(md_out, lines)
    print(f"RBAC audit: {len(findings)} findings, {len(escalation_findings)} token escalation path(s)")


if __name__ == "__main__":
    main()
