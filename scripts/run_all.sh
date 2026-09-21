#!/usr/bin/env bash
# 全診断スクリプトを実行し、reports/<timestamp>/ に結果を保存する。
# 診断コンテナ内 (kubectl が対象クラスタに到達可能な状態) で実行すること。
set -euo pipefail
cd "$(dirname "$0")/.."

TS=$(date +%Y%m%d-%H%M%S)
OUT="reports/${TS}"
mkdir -p "$OUT/trivy"

echo "[*] RBAC audit"
python3 scripts/rbac_audit.py "$OUT/rbac_audit.json" "$OUT/rbac_audit.md"

echo "[*] Pod Security audit"
python3 scripts/pod_security_audit.py "$OUT/pod_security_audit.json" "$OUT/pod_security_audit.md"

echo "[*] Network audit"
python3 scripts/network_audit.py "$OUT/network_audit.json" "$OUT/network_audit.md"

echo "[*] CIS Benchmark (kube-bench)"
kubectl delete job kube-bench --ignore-not-found=true >/dev/null 2>&1 || true
kubectl apply -f manifests/audits/kube-bench-job.yaml >/dev/null
kubectl wait --for=condition=complete job/kube-bench --timeout=120s >/dev/null 2>&1 || true
kubectl logs job/kube-bench > "$OUT/kube_bench.log" 2>&1 \
  || echo "    ! failed to retrieve kube-bench logs (job may still be running/pending)"
FAIL_COUNT=$(grep -c '^\[FAIL\]' "$OUT/kube_bench.log" 2>/dev/null || true)
FAIL_COUNT=${FAIL_COUNT:-0}
{
  echo "# CIS Benchmark (kube-bench)"
  echo ""
  echo "検出件数 (FAIL): ${FAIL_COUNT}"
  echo ""
  grep '^\[FAIL\]' "$OUT/kube_bench.log" 2>/dev/null | sed 's/^/- /' || true
} > "$OUT/kube_bench.md"
echo "    kube-bench: ${FAIL_COUNT} FAIL"

echo "[*] Image vulnerability scan (trivy)"
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' \
  | sort -u \
  | while read -r image; do
      [ -z "$image" ] && continue
      safe=$(echo "$image" | tr '/:' '__')
      echo "    - $image"
      trivy image --quiet --format json --output "$OUT/trivy/${safe}.json" "$image" \
        || echo "      ! trivy failed for $image"
    done

echo "[*] Image vulnerability chain audit"
python3 scripts/image_audit.py "$OUT/image_audit.json" "$OUT/image_audit.md"

cat "$OUT"/*.md > "$OUT/summary.md"
echo "[*] Done: $OUT"
