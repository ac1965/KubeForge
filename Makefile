CLUSTER_NAME := kubeforge-lab
CALICO_VERSION := v3.28.0
KUBECONFIG_INTERNAL := kind/kubeconfig-internal.yaml

.PHONY: cluster-up cluster-down lab-deploy policies-deploy clean

## kind クラスタを作成し、NetworkPolicy 対応のため Calico を導入する
cluster-up:
	kind create cluster --name $(CLUSTER_NAME) --config kind/kind-config.yaml
	# tigera-operator の CRD (installations.operator.tigera.io) は
	# last-applied-configuration 注釈の上限を超えるため --server-side を使う。
	kubectl apply --server-side --force-conflicts \
		-f https://raw.githubusercontent.com/projectcalico/calico/$(CALICO_VERSION)/manifests/tigera-operator.yaml
	# CRD (Installation 等) が API サーバーの discovery に反映されるまで待ってから
	# custom-resources.yaml を適用する (反映前に適用すると "no matches for kind"
	# エラーで失敗する競合状態がある)。
	kubectl wait --for=condition=Established --timeout=60s crd/installations.operator.tigera.io
	kubectl apply -f kind/calico/custom-resources.yaml
	# calico-system namespace と Deployment は tigera-operator が Installation を
	# reconcile した後に作成するため、rollout status の前に存在確認を待つ。
	kubectl wait --for=create namespace/calico-system --timeout=120s
	kubectl wait --for=create -n calico-system deployment/calico-kube-controllers --timeout=120s
	kubectl -n calico-system rollout status deployment/calico-kube-controllers --timeout=180s
	# PownForge の kubernetes/kubernetes-audit/kube-bench プラグインが
	# pownforge-lab ネットワーク経由でこのクラスタに到達するための内部向け
	# kubeconfig (server が Docker ネットワーク上のコンテナ名になる)。
	# 診断・監査・可視化は PownForge リポジトリ側で行う (README 参照)。
	kind get kubeconfig --name $(CLUSTER_NAME) --internal > $(KUBECONFIG_INTERNAL)

## kind クラスタを削除する
cluster-down:
	kind delete cluster --name $(CLUSTER_NAME)
	rm -f $(KUBECONFIG_INTERNAL)

## 意図的に脆弱なラボ環境をデプロイする
lab-deploy:
	kubectl apply -f manifests/vulnerable-lab/

## 比較用の安全な構成例 (Pod Security Standards + NetworkPolicy) をデプロイする
policies-deploy:
	kubectl apply -f manifests/policies/

## ローカルの生成物を削除する
clean:
	rm -f kind/kubeconfig-internal.yaml
