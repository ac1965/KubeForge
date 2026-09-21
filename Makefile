IMAGE_NAME := kubeforge-toolbox
CLUSTER_NAME := kubeforge-lab
CALICO_VERSION := v3.28.0
KUBECONFIG_INTERNAL := kind/kubeconfig-internal.yaml

.PHONY: build cluster-up cluster-down lab-deploy policies-deploy audit kube-bench shell clean

## Arch Linux 診断コンテナをビルドする
build:
	docker build -t $(IMAGE_NAME) -f docker/Dockerfile .

## kind クラスタを作成し、NetworkPolicy 対応のため Calico を導入する
cluster-up:
	kind create cluster --name $(CLUSTER_NAME) --config kind/kind-config.yaml
	# tigera-operator の CRD (installations.operator.tigera.io) は
	# last-applied-configuration 注釈の上限を超えるため --server-side を使う。
	kubectl apply --server-side --force-conflicts \
		-f https://raw.githubusercontent.com/projectcalico/calico/$(CALICO_VERSION)/manifests/tigera-operator.yaml
	kubectl apply -f kind/calico/custom-resources.yaml
	kubectl -n calico-system rollout status deployment/calico-kube-controllers --timeout=180s
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

## kube-bench (CIS Benchmark) を control-plane ノード上の Job として実行する
kube-bench:
	kubectl apply -f manifests/audits/kube-bench-job.yaml
	kubectl wait --for=condition=complete job/kube-bench --timeout=120s
	kubectl logs job/kube-bench

## 診断コンテナを kind クラスタの Docker ネットワークに接続して全監査を実行する
audit:
	docker run --rm \
		--network kind \
		-v $(PWD)/$(KUBECONFIG_INTERNAL):/home/forger/.kube/config:ro \
		-v $(PWD)/reports:/workspace/reports \
		$(IMAGE_NAME) -c "bash scripts/run_all.sh"

## 診断コンテナに対話シェルで入る（手動でツールを試す用）
shell:
	docker run --rm -it \
		--network kind \
		-v $(PWD)/$(KUBECONFIG_INTERNAL):/home/forger/.kube/config:ro \
		-v $(PWD)/reports:/workspace/reports \
		$(IMAGE_NAME)

## ローカルの生成物を削除する
clean:
	rm -rf reports/*/ kind/kubeconfig-internal.yaml
