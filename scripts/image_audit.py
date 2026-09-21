#!/usr/bin/env python3
"""イメージ脆弱性チェーン監査: Trivy のスキャン結果単体ではなく、
「既知の重大脆弱性を持つイメージ」×「その Pod が持つノード脱出手段
(privileged/hostPath/hostNetwork 等)」を突き合わせて検出する。

rbac_audit.py / pod_security_audit.py / network_audit.py と同じ設計思想:
個別の所見 (このイメージには CVE がある / この Pod は privileged だ) を
別々に眺めるだけでは、それらが組み合わさった時の実際の危険度が見えない。

Usage: image_audit.py <json_out> <md_out>
"""
import json
import subprocess
import sys

from kube import get, write_json, write_markdown

# CNI/CSI などクラスタ運用上 privileged が正当に必要な system namespace。
# pod_security_audit.py / network_audit.py と同じ方針で除外する。
EXEMPT_NAMESPACES = {
    "kube-system", "kube-public", "kube-node-lease", "tigera-operator", "calico-system", "calico-apiserver",
}

HOST_ESCAPE_CAPABILITIES = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "SYS_BOOT", "SYS_CHROOT"}
SEVERITIES_OF_INTEREST = {"CRITICAL", "HIGH"}


def scan_image(image: str) -> tuple[dict, bool]:
    """(scan結果, スキャン成功したか) を返す。

    trivy がイメージを解決できない場合 (ローカルのみに存在しレジストリに
    push されていないイメージなど) は非ゼロ終了・JSON 出力なしで失敗する。
    これを「脆弱性 0 件」と区別せずに握りつぶすと、スキャンできていない
    ことに気づけないまま「安全」という誤った結論になってしまう。
    """
    result = subprocess.run(
        ["trivy", "image", "--quiet", "--format", "json", image],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return {}, False
    try:
        return json.loads(result.stdout), True
    except json.JSONDecodeError:
        return {}, False


def count_severities(scan: dict) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0}
    for result in scan.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = vuln.get("Severity")
            if severity in counts:
                counts[severity] += 1
    return counts


def pod_escape_factors(pod: dict, container: dict) -> list[str]:
    """この container がノード脱出手段を持っているかを列挙する
    (pod_security_audit.py の breakout chain 判定と同じ条件)。"""
    spec = pod["spec"]
    factors = []
    if spec.get("hostNetwork"):
        factors.append("hostNetwork")
    if spec.get("hostPID"):
        factors.append("hostPID")

    sc = container.get("securityContext", {}) or {}
    if sc.get("privileged"):
        factors.append("privileged")
    else:
        caps = (sc.get("capabilities", {}) or {}).get("add", [])
        escape_caps = HOST_ESCAPE_CAPABILITIES & set(caps)
        if escape_caps:
            factors.append(f"capabilities {sorted(escape_caps)}")

    host_path_volumes = {v["name"] for v in spec.get("volumes", []) or [] if "hostPath" in v}
    if any(vm.get("name") in host_path_volumes for vm in container.get("volumeMounts", []) or []):
        factors.append("hostPath マウント")

    return factors


def find_image_chains(pods: list[dict]) -> tuple[list[dict], list[dict]]:
    """(chains, scan_failures) を返す。scan_failures はスキャンし忘れではなく、
    トリアージが必要な「未確認」の脱出可能 Pod として明示的に報告する。"""
    chains = []
    scan_failures = []
    scan_cache: dict[str, tuple[dict, bool]] = {}

    for pod in pods:
        namespace = pod["metadata"]["namespace"]
        if namespace in EXEMPT_NAMESPACES:
            continue
        name = pod["metadata"]["name"]

        for container in pod["spec"].get("containers", []) or []:
            escape_factors = pod_escape_factors(pod, container)
            if not escape_factors:
                continue

            image = container["image"]
            if image not in scan_cache:
                scan_result, ok = scan_image(image)
                scan_cache[image] = (count_severities(scan_result) if ok else {}, ok)
            counts, ok = scan_cache[image]

            if not ok:
                scan_failures.append({
                    "namespace": namespace,
                    "pod": name,
                    "container": container["name"],
                    "image": image,
                    "escape_factors": escape_factors,
                    "detail": (
                        "Trivy がこのイメージをスキャンできませんでした (レジストリに存在しない "
                        "ローカル限定イメージである可能性があります)。ノード脱出手段を持つ Pod のため、"
                        "手動でイメージの脆弱性を確認してください。"
                    ),
                })
                continue

            if counts["CRITICAL"] == 0 and counts["HIGH"] == 0:
                continue

            chains.append({
                "namespace": namespace,
                "pod": name,
                "container": container["name"],
                "image": image,
                "critical": counts["CRITICAL"],
                "high": counts["HIGH"],
                "escape_factors": escape_factors,
                "detail": (
                    f"イメージに CRITICAL {counts['CRITICAL']} 件 / HIGH {counts['HIGH']} 件の既知脆弱性があり、"
                    f"かつ {', '.join(escape_factors)} によりノード脱出手段も持っています。"
                    "イメージ脆弱性のリモート悪用がそのままノード侵害に直結します。"
                ),
            })

    return chains, scan_failures


def main() -> None:
    json_out, md_out = sys.argv[1], sys.argv[2]

    pods = get("pods", all_namespaces=True)["items"]
    chains, scan_failures = find_image_chains(pods)

    write_json(json_out, {"image_breakout_chains": chains, "scan_failures": scan_failures})

    lines = [
        "# Image Vulnerability Chain Audit",
        "",
        f"検出件数: {len(chains)}",
        "",
    ]
    if not chains:
        lines.append("問題は検出されませんでした。")
    for c in chains:
        lines.append(
            f"- **{c['namespace']}/{c['pod']} (container/{c['container']}, image {c['image']})**: {c['detail']}"
        )

    lines += [
        "",
        "## スキャン失敗 (未確認のまま残っているノード脱出可能 Pod)",
        "",
        f"検出件数: {len(scan_failures)}",
        "",
    ]
    if not scan_failures:
        lines.append("問題は検出されませんでした。")
    for f in scan_failures:
        lines.append(
            f"- **{f['namespace']}/{f['pod']} (container/{f['container']}, image {f['image']})**: {f['detail']}"
        )

    write_markdown(md_out, lines)
    print(f"Image audit: {len(chains)} chain(s) found, {len(scan_failures)} scan failure(s)")


if __name__ == "__main__":
    main()
