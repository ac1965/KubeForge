# AGENTS.md

このファイルは、KubeForge リポジトリで作業する AI エージェント（Claude Code など）向けのガイドです。

## プロジェクト概要

**KubeForge** は、Kubernetes クラスタのセキュリティ診断（構成ミス・権限設定・ネットワーク分離・コンテナセキュリティの検証）に特化した、Arch Linux ベースの Docker 環境です。単なるツール寄せ集めのペネトレーションテスト用イメージではなく、Kubernetes 特有の攻撃面（RBAC、Pod Security、NetworkPolicy、コンテナ/イメージ）を体系的に検証できるラボ環境として設計します。

対象読者: 認可されたセキュリティ診断・CTF・学習目的でこの環境を使う人。**実運用クラスタへの適用は、必ず正当な権限と許可がある場合に限る。**

## アーキテクチャ

```text
macOS (Apple Silicon)
└─ Docker Desktop
   └─ Kubernetes Lab
      ├─ Arch Pentest Container（診断コンテナ）
      │   ├─ kubectl
      │   ├─ kube-bench
      │   ├─ Trivy
      │   ├─ Nmap
      │   └─ Python / Go
      │        │  Kubernetes API 経由でアクセス
      │        ▼
      └─ Kubernetes Cluster（kind 上に構築）
          ├─ Control Plane
          ├─ Worker Nodes
          └─ Test Namespaces（RBAC / NetworkPolicy 検証用）
```

設計上のポイント:

- 診断コンテナとクラスタを分離し、Kubernetes API へのアクセス権限を限定する
- RBAC・NetworkPolicy を実際に検証できる構成にする（NetworkPolicy はリソースを作るだけでは機能せず、対応する CNI が必要）
- 脆弱な設定をあえて再現するテスト用 Namespace を用意する
- 診断結果は JSON / Markdown で保存する

## 採用構成（決定事項）

以下の組み合わせを初期構成として採用する。

| 項目 | 採用 |
| --- | --- |
| ① クラスタ | A. kind（Docker 上に構築） |
| ② 診断対象 | A. 自分で構築した脆弱な Kubernetes ラボ（再現可能なラボを最優先） |
| ③ ディストリビューション方向性 | D. Kubernetes ペンテスター向け独自ディストリビューション（Arch Linux ベース） |

まず再現可能な脆弱ラボを構築し、RBAC・Pod Security・NetworkPolicy の検証をそれぞれ分離して実施できる状態にしてから、実運用クラスタへの適用を検討する。

## 技術スタック

| 機能 | 採用候補 |
| --- | --- |
| 診断 OS | Arch Linux |
| クラスタ | kind |
| CLI | kubectl |
| イメージ診断 | Trivy |
| Kubernetes 設定監査 | kube-bench |
| RBAC 確認 | kubectl / 専用スクリプト |
| ネットワーク | NetworkPolicy 対応 CNI |
| ポリシー | Pod Security Admission |
| 出力 | JSON / Markdown |

## 検証するセキュリティ項目

### A. RBAC
- 過剰な権限を持つ ServiceAccount
- 不要な ClusterRoleBinding
- `*` による過度な権限付与
- Namespace 間の権限分離

### B. Pod Security
- privileged コンテナ
- hostNetwork / hostPID / hostIPC
- root 実行
- Linux capabilities
- Seccomp 設定
- Pod Security Standards の 3 レベル（Privileged / Baseline / Restricted）に基づく評価

### C. ネットワーク
- Namespace 間通信
- 不要な Ingress / Egress
- NetworkPolicy の有無
- 外部接続の制御

### D. コンテナ・イメージ
- 脆弱性を含むイメージ（Trivy）
- root 実行
- 不要な Linux capabilities
- イメージの出所・タグ管理

## リポジトリ構成

```text
KubeForge/
├── AGENTS.md
├── README.md                 # クイックスタート
├── Makefile                  # build / cluster-up / lab-deploy / audit などの操作
├── docker/Dockerfile         # Arch Linux 診断コンテナ (kubectl, trivy, kube-bench, nmap, python, go)
│                             # amd64/arm64 ともネイティブビルド対応（マルチステージ、後述）
├── kind/
│   ├── kind-config.yaml      # kind クラスタ設定（3ノード、デフォルト CNI 無効化）
│   └── calico/               # NetworkPolicy 対応 CNI (Calico) の導入設定
├── manifests/
│   ├── vulnerable-lab/       # 意図的に脆弱な構成を再現する Namespace/マニフェスト
│   ├── policies/             # NetworkPolicy, Pod Security 設定例（比較用の安全な構成）
│   └── audits/               # kube-bench 実行用 Job
├── scripts/                  # RBAC / Pod Security / Network / Image 監査スクリプト（Python、攻撃チェーン検出込み）
└── reports/                  # 診断結果の出力先（JSON/Markdown、gitignore 対象）
```

詳細な使い方は [README.md](README.md) を参照。

## 診断コンテナのマルチアーキテクチャ対応

`docker/Dockerfile` はマルチステージ構成で amd64 / arm64 双方をネイティブビルドする
（`docker build`、buildx とも `--platform` 指定なしでホストのアーキテクチャに
合わせてビルドされる）。

- amd64: 公式の `archlinux:latest`（Docker Hub, `docker.io/library/archlinux`）をそのまま使用。
- arm64: 公式 archlinux イメージは amd64 のみ提供のため、Arch Linux ARM
  (ALARM, archlinuxarm.org — Arch Linux の姉妹プロジェクトで ARM 移植版) の
  rootfs (`http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz`)
  を取得して `FROM scratch` に展開したものを使用。ALARM は独自の pacman 署名鍵を
  持つため `pacman-key --init && pacman-key --populate archlinuxarm` を実行してから
  パッケージを導入する。

Apple Silicon 上で QEMU エミュレーションを避けてネイティブ arm64 ビルドにするための
選択であり、`menci/archlinuxarm` のような非公式イメージより ALARM 公式配布物を
優先している（セキュリティ診断ツールというプロジェクトの性質上、サプライチェーンの
出所をできるだけ公式なものに揃えるため）。

## 攻撃チェーン検出の設計方針

`scripts/` 配下の4つの監査スクリプト（RBAC / Pod Security / Network / Image）は、
いずれも「個別の所見を並べるだけ」で終わらせず、**単体では見過ごされがちな所見同士
が組み合わさると実際に悪用できてしまう経路（攻撃チェーン）** を検出する関数を持つ。
これは単なる網羅性向上ではなく、実際に kind クラスタ上で手動 PoC を行った上で
「この組み合わせは本当に悪用できる」と確認してから実装した検出ロジックである。

| スクリプト | チェーン検出関数 | 検出するチェーン |
| --- | --- | --- |
| `rbac_audit.py` | `find_token_escalation_paths` | ある namespace 内で `serviceaccounts/token` の create 権限を持つ ServiceAccount が、同じ namespace 内の cluster-admin 付き ServiceAccount へ `kubectl create token` でなりすませる（RoleBinding は namespace スコープに見えるが実質的に無意味化する） |
| `pod_security_audit.py` | `find_breakout_chains` | privileged/特権 capability + hostPath マウント（ホストのファイルシステムに直接アクセス）、または + hostPID（`/proc/1/root` 経由でホストプロセスへ侵入）によるノード乗っ取り |
| `network_audit.py` | `find_permissive_rules` / `find_hostnetwork_bypass` | NetworkPolicy が存在してもルールに `from`/`to` が無ければ実質全許可、hostNetwork の Pod は NetworkPolicy の適用対象外（namespace に NetworkPolicy があっても効かない） |
| `image_audit.py` | `find_image_chains` | Trivy が検出した CRITICAL/HIGH 脆弱性を持つイメージが、`pod_security_audit.py` と同じ判定基準でノード脱出手段（privileged/hostPath/hostNetwork 等）も持つ Pod で稼働している |

**繰り返し踏んだ落とし穴**: これらのチェーン検出は `kube-system` / `calico-system` /
`calico-apiserver` / `tigera-operator` といった system namespace の正当な
DaemonSet（CNI/CSI 等）や、`system:masters` のような組み込みの Group/User を
誤検出しやすい（privileged + hostPath は CNI にとって正当な構成であり、
`system:masters` は最初から cluster-admin なので「昇格」ではない）。
このセッションで RBAC・Pod Security・Network の3つとも同じノイズに一度は
引っかかった。**新しいチェーン検出を追加するときは、最初から `EXEMPT_NAMESPACES`
（各スクリプトで定義済み）での除外、および RBAC の場合は subject を
`kind: ServiceAccount` に絞る、といったフィルタを組み込むこと。**

**検証手順**: 新しいチェーン検出を追加する際は次の3段階を踏む。
1. `manifests/vulnerable-lab/` の実際の構成を模したモックデータで単体テスト
   （検出されるべきケースと、されるべきでないケース＝false positive 候補の両方）
2. kind クラスタを実際に構築し、対象マニフェストをデプロイしてスクリプトを
   ライブ実行し、期待件数と一致するか確認
3. 可能であれば `kubectl exec` / `kubectl create token` / 別 namespace からの
   `curl` などで実際に攻撃を成立させ、検出が机上の空論でないことを実証する

## エージェントへの指示

- **対象範囲の遵守**: このリポジトリのツール・スクリプトは、`manifests/vulnerable-lab/` 配下など明示的にラボ用と分かる Kubernetes クラスタ、または利用者が管理者権限を持つ kind クラスタに対してのみ実行する。実運用クラスタや第三者が管理するクラスタへの診断コマンド実行は、利用者から明確な許可を得るまで行わない。
- **破壊的操作の回避**: `kubectl delete`、RBAC の変更、NetworkPolicy の削除など状態を変更する操作は、診断（読み取り専用）ではなく環境構築の一部である場合のみ行い、事前に何を変更するか利用者に説明する。
- **診断ツールの追加**: 新しいツールを Docker イメージに追加する場合は、Arch Linux の `pacman`/AUR で入手可能なものを優先する。
- **結果の保存**: 診断スクリプトの出力は `reports/` 配下に JSON または Markdown で保存する形を基本とする。
- **コミットメッセージ・コード内コメント**: 既存の慣習がない限り、日本語で簡潔に記述する。
