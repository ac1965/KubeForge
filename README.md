# KubeForge

意図的に脆弱な Kubernetes クラスタ（RBAC・Pod Security・NetworkPolicy の設定ミスを
再現）を、`kind` 上に一発で・何度でも再現可能な形で構築するためのラボ環境。
詳しい設計方針は [AGENTS.md](AGENTS.md) を参照。

**このリポジトリの役割は「再現可能な脆弱 Kubernetes ラボの構築」のみです。**
診断（RBAC/Pod Security/Network/イメージの多面的セキュリティ監査）・
CIS Kubernetes Benchmark（kube-bench）による Hardening 施策の効果測定・
攻撃チェーンの可視化（トポロジー図付き HTML ダッシュボード）は、
[PownForge](https://github.com/ac1965/PownForge) リポジトリ側の
`kubernetes`/`kubernetes-audit`/`kube-bench` プラグインと
`attack-session report --format html` が担当する（詳細は PownForge の
`docs/handbook.md` §6「プラグイン」・§13「証跡とレポート」参照）。
以前このリポジトリに同梱していた診断コンテナ・監査スクリプト・
ダッシュボード生成は、ロジックごと PownForge 側へ移植済み。

## できること

- **再現可能な脆弱 Kubernetes ラボの構築**: `kind` + Calico で 3 ノードクラスタを
  一発で立て、`manifests/vulnerable-lab/`（意図的に脆弱な RBAC・Pod・NetworkPolicy 設定）と
  `manifests/policies/`（Pod Security Standards + NetworkPolicy の良い例）を
  並べてデプロイし、Before/After を比較できる。
- **Hardening 効果測定用のクラスタ構成**: `kind/kind-config.yaml` の
  `kubeadmConfigPatches` で apiserver/controller-manager/scheduler のフラグを
  変更したクラスタを作り直せる（本リポジトリでは kube-bench の FAIL 12件→4件まで
  是正済み。効果の測定自体は PownForge 側の `kube-bench` プラグインで行う）。
- **PownForge からの到達性**: `make cluster-up` が生成する
  `kind/kubeconfig-internal.yaml`（`server` が Docker ネットワーク上のコンテナ名、
  例: `kubeforge-lab-control-plane:6443`）を使うと、`pownforge-lab` ネットワーク
  (`--internal`) 上の PownForge コンテナからでもこのクラスタに直接到達できる。

## 活用シーン

- **学習・研修**: RBAC のワイルドカード権限や privileged コンテナなど、
  典型的な Kubernetes の設定ミスをハンズオンで再現し、PownForge の診断ツールが
  どう検出するか実際に手を動かして確認する。
- **診断ワークフローのリハーサル**: 実運用クラスタに診断をかける前に、
  このラボで PownForge の `kubernetes-audit`/`kube-bench` プラグインの挙動を
  安全に試す。
- **Hardening 施策の検証**: kubeadm の起動フラグや NetworkPolicy 変更が
  CIS Benchmark や監査結果にどう効くかを、使い捨てクラスタで気軽に試行錯誤する。
- **CTF・セキュリティ研究**: 権限昇格（wildcard RBAC → cluster-admin）や
  コンテナブレイクアウト（privileged + hostPath）などの攻撃プリミティブを
  再現可能な環境で練習する。
- **チームのオンボーディング教材**: 脆弱な構成と安全な構成を並べて見せることで、
  Pod Security Standards や NetworkPolicy の必要性を具体例で説明する。

実運用クラスタや第三者管理のクラスタへの適用範囲については
[AGENTS.md](AGENTS.md) のルールに従うこと。

## 前提

- Docker Desktop（Apple Silicon / Intel 両対応）
- [kind](https://kind.sigs.k8s.io/)（`brew install kind`）
- kubectl（ホスト側）

## クイックスタート

```bash
# 1. kind クラスタを作成し、NetworkPolicy 対応の Calico を導入
make cluster-up

# 2. 意図的に脆弱なラボ環境と、比較用の安全な構成例をデプロイ
make lab-deploy
make policies-deploy

# 後片付け
make cluster-down
```

診断・監査・ダッシュボード生成は PownForge リポジトリ側から行う。例:

```bash
# PownForge リポジトリ側 (docs/handbook.md §7「ラボネットワーク」参照)
kind get kubeconfig --internal --name kubeforge-lab \
  > ../PownForge/config/kubeforge-lab.kubeconfig
cd ../PownForge
pownforge target add kubeforge-lab --address kind-kubeforge-lab \
  --kind host --type kubernetes \
  --allowed-plugins kubernetes,kubernetes-audit,kube-bench

docker compose run --rm \
  -e KUBECONFIG=/app/config/kubeforge-lab.kubeconfig \
  pownforge scan kubernetes-audit --target kubeforge-lab \
  --option namespaces=vulnerable-lab
```

## その他のコマンド

```bash
# ローカルの生成物 (kind の内部 kubeconfig) を削除
make clean
```

## ディレクトリ構成

```text
KubeForge/
├── AGENTS.md                 # 設計方針・エージェント向けガイド
├── Makefile                  # クラスタの起動/停止/ラボデプロイのみ
├── kind/
│   ├── kind-config.yaml      # 3ノード kind クラスタ（デフォルト CNI 無効化、CIS Benchmark 是正パッチ込み）
│   └── calico/               # NetworkPolicy 対応 CNI (Calico) の導入設定
└── manifests/
    ├── vulnerable-lab/       # 意図的に脆弱な RBAC / Pod / NetworkPolicy 設定（検出対象）
    └── policies/             # Pod Security Standards + NetworkPolicy の良い例
```

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
