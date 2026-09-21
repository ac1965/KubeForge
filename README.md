# KubeForge

Kubernetes のセキュリティ診断（RBAC・Pod Security・NetworkPolicy・コンテナイメージ）に特化した、
Arch Linux ベースの診断コンテナ + kind ラボ環境。詳しい設計方針は [AGENTS.md](AGENTS.md) を参照。

診断コンテナは amd64 / arm64 (Apple Silicon 含む) の両方をネイティブビルド対応
(エミュレーション不要)。詳細は [docker/Dockerfile](docker/Dockerfile) を参照。

## 前提

- Docker Desktop（Apple Silicon / Intel 両対応）
- [kind](https://kind.sigs.k8s.io/)（`brew install kind`）
- kubectl（ホスト側。診断コンテナ内にも同梱）

## クイックスタート

```bash
# 1. 診断コンテナをビルド
make build

# 2. kind クラスタを作成し、NetworkPolicy 対応の Calico を導入
make cluster-up

# 3. 意図的に脆弱なラボ環境と、比較用の安全な構成例をデプロイ
make lab-deploy
make policies-deploy

# 4. 診断コンテナから RBAC / Pod Security / Network / kube-bench / イメージ脆弱性を監査
make audit

# 後片付け
make cluster-down
```

`make audit` の結果は `reports/<timestamp>/` 配下に JSON と Markdown で出力される
(`summary.md` が全体のまとめ)。

`scripts/` と `manifests/audits/` は `docker/Dockerfile` の `COPY` でイメージに
焼き込まれる（実行時にマウントはしない）ため、これらを編集したら
`make audit` / `make shell` の前に **`make build` を再実行**すること。

## その他のコマンド

```bash
# kube-bench だけを素早く単体実行したいとき
make kube-bench

# 診断コンテナに対話シェルで入り、kubectl/trivy/nmap 等を手動で試す
make shell

# ローカルの生成物 (reports/, kind の内部 kubeconfig) を削除
make clean
```

## ディレクトリ構成

```text
KubeForge/
├── AGENTS.md                 # 設計方針・エージェント向けガイド
├── Makefile                  # ビルド/クラスタ/診断の一連の操作
├── docker/Dockerfile         # Arch Linux 診断コンテナ (kubectl, trivy, kube-bench, nmap, python, go)
├── kind/
│   ├── kind-config.yaml      # 3ノード kind クラスタ（デフォルト CNI 無効化、CIS Benchmark 是正パッチ込み）
│   └── calico/               # NetworkPolicy 対応 CNI (Calico) の導入設定
├── manifests/
│   ├── vulnerable-lab/       # 意図的に脆弱な RBAC / Pod 設定（検出対象）
│   ├── policies/             # Pod Security Standards + NetworkPolicy の良い例
│   └── audits/               # kube-bench 実行用 Job
├── scripts/                  # RBAC / Pod Security / Network 監査スクリプト (Python)
└── reports/                  # 診断結果の出力先（gitignore 対象、.gitkeep のみ管理）
```

## 診断内容

| カテゴリ | スクリプト | 検出内容 |
| --- | --- | --- |
| RBAC | `scripts/rbac_audit.py` | `cluster-admin` バインド、ワイルドカード権限の Role/ClusterRole |
| Pod Security | `scripts/pod_security_audit.py` | privileged、hostNetwork/PID/IPC、root 実行、hostPath マウント、limits 未設定 |
| ネットワーク | `scripts/network_audit.py` | NetworkPolicy が存在しない Namespace |
| ノード設定 | `manifests/audits/kube-bench-job.yaml`（`run_all.sh` から自動実行） | CIS Kubernetes Benchmark |
| イメージ | `scripts/run_all.sh` 内の Trivy 呼び出し | クラスタ上で稼働中イメージの既知脆弱性 |

kube-bench の FAIL のうち、apiserver/controller-manager/scheduler の起動フラグで
是正できるもの(profiling 無効化、監査ログ設定、ServiceAccount トークン長期化の禁止)は
`kind/kind-config.yaml` の `kubeadmConfigPatches` で対応済み（FAIL 12件 → 4件）。
残る4件はファイル権限/所有者系（kind ノードコンテナの使い捨てファイルシステムに起因し
是正不可）と、`--kubelet-certificate-authority`（有効化すると kind の自己署名
kubelet 証明書の IP SANs 不足により `kubectl logs`/`exec` が失敗するため意図的に対象外）。

## 注意事項

- `manifests/vulnerable-lab/` は**意図的に脆弱**な構成です。この Namespace 以外や、
  第三者が管理する実クラスタに対して同様の設定・診断コマンドを実行しないでください。
- 詳細な利用範囲・エージェント向けの作業ルールは [AGENTS.md](AGENTS.md) を参照してください。
