# AGENTS.md

このファイルは、KubeForge リポジトリで作業する AI エージェント（Claude Code など）向けのガイドです。

## プロジェクト概要

**KubeForge** は、意図的に脆弱な Kubernetes クラスタ（RBAC・Pod Security・
NetworkPolicy の設定ミスを再現）を `kind` 上に**再現可能な形で構築するためだけ**
の、スコープを絞ったラボ環境です。

以前は Arch Linux ベースの診断コンテナ（kubectl/trivy/kube-bench/nmap 同梱）と、
RBAC/Pod Security/Network/イメージの多面的監査スクリプト・攻撃チェーン検出・
HTML ダッシュボード生成を同梱していましたが、**それらはロジックごと
[PownForge](https://github.com/ac1965/PownForge) リポジトリへ移植し、このリポジトリ
からは削除しました**（`kubernetes`/`kubernetes-audit`/`kube-bench` プラグイン、
`attack-session report --format html`。詳細は PownForge の `docs/handbook.md`
§6「プラグイン」・§13「証跡とレポート」参照）。このリポジトリに新しい診断・
監査・可視化ロジックを追加しないこと — その種の変更は PownForge 側で行う。

対象読者: 認可されたセキュリティ診断・CTF・学習目的でこの環境を使う人。**実運用クラスタへの適用は、必ず正当な権限と許可がある場合に限る。**

## アーキテクチャ

```text
macOS (Apple Silicon)
└─ Docker Desktop
   ├─ Kubernetes Lab (kind上に構築)
   │   ├─ Control Plane
   │   ├─ Worker Nodes
   │   └─ Test Namespaces (RBAC / NetworkPolicy 検証用)
   │
   └─ PownForge (別リポジトリ、pownforge-lab / kind の両Dockerネットワークに
       接続したコンテナ) が Kubernetes API 経由で診断・監査・可視化を行う
```

設計上のポイント:

- クラスタの「構築」と「診断」を別リポジトリに分離し、それぞれの責務を
  はっきりさせる (KubeForge = ラボ構築、PownForge = 診断・監査・可視化)
- RBAC・NetworkPolicy を実際に検証できる構成にする（NetworkPolicy はリソースを作るだけでは機能せず、対応する CNI が必要）
- 脆弱な設定をあえて再現するテスト用 Namespace を用意する

## 採用構成（決定事項）

以下の組み合わせを初期構成として採用する。

| 項目 | 採用 |
| --- | --- |
| ① クラスタ | A. kind（Docker 上に構築） |
| ② 診断対象 | A. 自分で構築した脆弱な Kubernetes ラボ（再現可能なラボを最優先） |

まず再現可能な脆弱ラボを構築し、RBAC・Pod Security・NetworkPolicy の検証を
それぞれ分離して実施できる状態にする。診断・監査自体は PownForge 側で行う。

## 技術スタック

| 機能 | 採用候補 |
| --- | --- |
| クラスタ | kind |
| CLI | kubectl |
| ネットワーク | NetworkPolicy 対応 CNI (Calico) |
| ポリシー | Pod Security Admission |

## このラボが再現する設定ミスのカテゴリ

`manifests/vulnerable-lab/`・`manifests/policies/` が再現/対比する、PownForge
側の `kubernetes`/`kubernetes-audit` プラグインが検出対象とするカテゴリ。

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
- Pod Security Standards の 3 レベル（Privileged / Baseline / Restricted）

### C. ネットワーク
- Namespace 間通信
- 不要な Ingress / Egress
- NetworkPolicy の有無

### D. コンテナ・イメージ
- 脆弱性を含むイメージ（PownForge の `kubernetes`/`kubernetes-audit` プラグインが Trivy 経由で検出）
- root 実行
- 不要な Linux capabilities

## リポジトリ構成

```text
KubeForge/
├── AGENTS.md
├── README.md                 # クイックスタート
├── Makefile                  # cluster-up / cluster-down / lab-deploy / policies-deploy / clean
├── kind/
│   ├── kind-config.yaml      # kind クラスタ設定（3ノード、デフォルト CNI 無効化、CIS Benchmark 是正パッチ込み）
│   └── calico/               # NetworkPolicy 対応 CNI (Calico) の導入設定
└── manifests/
    ├── vulnerable-lab/       # 意図的に脆弱な Namespace/マニフェスト（PownForge の診断対象）
    └── policies/             # Pod Security Standards + NetworkPolicy の良い例（比較用）
```

詳細な使い方は [README.md](README.md) を参照。

## Hardening 施策の効果測定について

`kind/kind-config.yaml` の `kubeadmConfigPatches` で apiserver/controller-manager/
scheduler の起動フラグを変更し、クラスタを作り直すところまではこのリポジトリの
責務。変更前後で kube-bench の PASS/FAIL/WARN 件数がどう変わったかを**測定する**
のは PownForge 側の `kube-bench` プラグイン(`pownforge scan kube-bench --target
<name>` を2回実行して比較する)の責務。

## 攻撃チェーン検出・HTML ダッシュボードについて

RBAC トークン昇格・Pod Security ブレイクアウト・NetworkPolicy バイパス・
イメージ脆弱性×ノード脱出手段の組み合わせを検出する「攻撃チェーン検出」と、
それをトポロジー図付きで可視化する HTML ダッシュボードは、いずれも
PownForge の `kubernetes-audit` プラグイン(`src/pownforge/plugins/
kubernetes_audit.py`)と `reporting/kubernetes_dashboard.py`
(`attack-session report --format html` から自動描画)に移植済み。
このリポジトリには実装を置かない。設計上の教訓（system namespace の
誤検出対策など）も含め、PownForge の `docs/handbook.md` を参照すること。

## コミットメッセージ規約

- 日本語で記述する。
- `type(scope): 要約` の Conventional Commits 風の 1 行目にする
  （例: `feat(kind): kind-config.yamlにCISベンチマーク是正パッチを追加`、
  `fix(kind): calico rollout の CRD 競合状態を修正`、
  `docs(agents): スコープの変更を反映`、
  `chore(gitignore): __pycache__ を除外`）。
  - `type` は `feat`（機能追加）/ `fix`（不具合修正）/ `docs`（ドキュメント）/
    `chore`（雑務・設定変更）/ `refactor` などから選ぶ。
  - `scope` はディレクトリ名や機能名（`kind`, `manifests`, `agents` など）を使う。
- 本文（任意）は `- ` の箇条書きで変更点を列挙する。詳細な経緯や検証結果を
  書く場合もこの形式に合わせる。

## エージェントへの指示

- **対象範囲の遵守**: このリポジトリのツール・マニフェストは、`manifests/vulnerable-lab/` 配下など明示的にラボ用と分かる Kubernetes クラスタ、または利用者が管理者権限を持つ kind クラスタに対してのみ実行する。実運用クラスタや第三者が管理するクラスタへのコマンド実行は、利用者から明確な許可を得るまで行わない。
- **破壊的操作の回避**: `kubectl delete`、RBAC の変更、NetworkPolicy の削除など状態を変更する操作は、環境構築の一部である場合のみ行い、事前に何を変更するか利用者に説明する。
- **スコープを広げない**: 診断スクリプト・監査ロジック・HTML ダッシュボード生成・診断用コンテナイメージなど、「ラボ構築」を超える機能をこのリポジトリに追加しない。それらは PownForge リポジトリ側の役割。
- **コミットメッセージ・コード内コメント**: コミットメッセージは上記「コミットメッセージ規約」に従う。コード内コメントは既存の慣習がない限り、日本語で簡潔に記述する。
