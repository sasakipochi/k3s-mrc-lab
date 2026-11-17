# MRC ラボ (k3s) — 開発用。使うだけなら kubectl apply -k で公開イメージを入れる (README)
#   make            … イメージをビルドしてローカルレジストリに push、namespace mrc-lab に fabric と監視を導入
#   make console-ui … 操作盤を http://127.0.0.1:8089/ で開けるよう port-forward (Ctrl-C で終了)
#   make status     … 状態表示 / make down … namespace ごと削除
export KUBECONFIG ?= $(HOME)/.kube/config
NS        := mrc-lab
REGISTRY  ?= localhost:5000
VERSION   := 0.1.2
IMAGE     := $(REGISTRY)/mrc-fabric:$(VERSION)
PUBLIC    := ghcr.io/sasakipochi/mrc-fabric:$(VERSION)
UI_PORT   ?= 8089

.PHONY: all ns image fabric monitoring dashboard console-ui status grafana-password down

all: fabric monitoring

ns:
	kubectl apply -f k8s/namespace.yaml

image:
	docker build -t $(IMAGE) fabric
	docker push $(IMAGE)

fabric: ns image
	# 公開イメージの代わりに、いまビルドしたものを毎回 pull させる
	kubectl kustomize k8s/fabric | sed -e 's#$(PUBLIC)#$(IMAGE)#' -e 's#IfNotPresent#Always#' | kubectl apply -f -
	kubectl -n $(NS) rollout restart deploy/mrc-fabric
	kubectl -n $(NS) rollout status deploy/mrc-fabric --timeout=120s

dashboard:
	python3 tools/make_dashboard.py

monitoring: ns dashboard
	kubectl -n $(NS) get secret grafana-admin >/dev/null 2>&1 || \
	  kubectl -n $(NS) create secret generic grafana-admin --from-literal=admin-user=admin \
	    --from-literal=admin-password="$$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"
	kubectl apply -k k8s/monitoring
	kubectl -n $(NS) rollout restart deploy/grafana
	kubectl -n $(NS) rollout status deploy/prometheus deploy/grafana --timeout=180s

# Pod が入れ替わると port-forward は切れるので、切れたら張り直す
console-ui:
	@echo "操作盤: http://127.0.0.1:$(UI_PORT)/  (Ctrl-C で終了)"
	@while true; do \
	  kubectl -n $(NS) port-forward --address 127.0.0.1 svc/mrc-fabric $(UI_PORT):8080 | grep -v '^Handling connection'; \
	  echo "port-forward が切れました。2秒後に再接続します"; sleep 2; \
	done

status:
	./scripts/status.sh

grafana-password:
	@kubectl -n $(NS) get secret grafana-admin -o jsonpath='{.data.admin-password}' 2>/dev/null | base64 -d | grep . || \
	  kubectl -n $(NS) exec deploy/grafana -- cat /var/lib/grafana/admin-password; echo

down:
	kubectl delete ns $(NS)
