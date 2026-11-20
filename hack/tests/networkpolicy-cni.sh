#!/usr/bin/env bash
set -euo pipefail

release=test
app_namespace=bomhort
operator_namespace=bomhort-operator
values_file="${RUNNER_TEMP:-/tmp}/bomhort-networkpolicy-values.yaml"

kubectl create namespace "$app_namespace"
kubectl create namespace "$operator_namespace"

cat > "$values_file" <<YAML
clickhouse:
  networkPolicy:
    enabled: true
    operatorNamespaceSelector:
      kubernetes.io/metadata.name: $operator_namespace
    operatorPodSelector:
      app.kubernetes.io/name: clickhouse-operator
YAML

helm template "$release" deploy/helm/bomhort \
  --namespace "$app_namespace" \
  --values "$values_file" \
  --show-only templates/networkpolicy-clickhouse.yaml |
  kubectl apply --namespace "$app_namespace" -f -

cat <<YAML | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: clickhouse-netpolicy-test
  namespace: $app_namespace
  labels:
    app: clickhouse-netpolicy-test
    app.kubernetes.io/name: bomhort
    clickhouse.altinity.com/chi: $release-clickhouse
spec:
  containers:
    - name: listener
      image: python:3.12-alpine
      command:
        - python
        - -c
        - |
          import socket, threading, time
          def serve(port):
              server = socket.socket()
              server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
              server.bind(("0.0.0.0", port))
              server.listen()
              while True:
                  client, _ = server.accept()
                  client.close()
          for port in (9000, 8123, 9009):
              threading.Thread(target=serve, args=(port,), daemon=True).start()
          while True:
              time.sleep(3600)
---
apiVersion: v1
kind: Service
metadata:
  name: clickhouse
  namespace: $app_namespace
spec:
  selector:
    app: clickhouse-netpolicy-test
  ports:
    - name: native
      port: 9000
    - name: http
      port: 8123
    - name: interserver
      port: 9009
---
apiVersion: v1
kind: Pod
metadata:
  name: api-client
  namespace: $app_namespace
  labels:
    app.kubernetes.io/name: bomhort
    app.kubernetes.io/instance: $release
    app.kubernetes.io/component: api-gateway
spec:
  containers:
    - name: client
      image: python:3.12-alpine
      command: [python, -c, "import time; time.sleep(3600)"]
---
apiVersion: v1
kind: Pod
metadata:
  name: ui-client
  namespace: $app_namespace
  labels:
    app.kubernetes.io/name: bomhort
    app.kubernetes.io/instance: $release
    app.kubernetes.io/component: ui
spec:
  containers:
    - name: client
      image: python:3.12-alpine
      command: [python, -c, "import time; time.sleep(3600)"]
---
apiVersion: v1
kind: Pod
metadata:
  name: wrong-release-client
  namespace: $app_namespace
  labels:
    app.kubernetes.io/name: bomhort
    app.kubernetes.io/instance: other
    app.kubernetes.io/component: api-gateway
spec:
  containers:
    - name: client
      image: python:3.12-alpine
      command: [python, -c, "import time; time.sleep(3600)"]
---
apiVersion: v1
kind: Pod
metadata:
  name: clickhouse-peer
  namespace: $app_namespace
  labels:
    clickhouse.altinity.com/chi: $release-clickhouse
spec:
  containers:
    - name: peer
      image: python:3.12-alpine
      command: [python, -c, "import time; time.sleep(3600)"]
---
apiVersion: v1
kind: Pod
metadata:
  name: clickhouse-operator
  namespace: $operator_namespace
  labels:
    app.kubernetes.io/name: clickhouse-operator
spec:
  containers:
    - name: operator
      image: python:3.12-alpine
      command: [python, -c, "import time; time.sleep(3600)"]
YAML

for pod in clickhouse-netpolicy-test api-client ui-client wrong-release-client clickhouse-peer; do
  kubectl wait --namespace "$app_namespace" --for=condition=Ready "pod/$pod" --timeout=180s
done
kubectl wait --namespace "$operator_namespace" --for=condition=Ready pod/clickhouse-operator --timeout=180s

expect_allowed() {
  local pod=$1
  local port=$2
  kubectl exec --namespace "$app_namespace" "$pod" -- python -c \
    "import socket; socket.create_connection(('clickhouse.$app_namespace.svc.cluster.local', $port), timeout=3).close()"
}

expect_denied() {
  local namespace=$1
  local pod=$2
  local port=$3
  if kubectl exec --namespace "$namespace" "$pod" -- python -c \
    "import socket; socket.create_connection(('clickhouse.$app_namespace.svc.cluster.local', $port), timeout=3).close()"; then
    echo "unexpectedly allowed $namespace/$pod to ClickHouse port $port" >&2
    return 1
  fi
}

expect_allowed api-client 9000
kubectl exec --namespace "$operator_namespace" clickhouse-operator -- python -c \
  "import socket; socket.create_connection(('clickhouse.$app_namespace.svc.cluster.local', 8123), timeout=3).close()"
expect_allowed clickhouse-peer 9009

expect_denied "$app_namespace" ui-client 9000
expect_denied "$app_namespace" wrong-release-client 9000
expect_denied "$operator_namespace" clickhouse-operator 9000
expect_denied "$operator_namespace" clickhouse-operator 9009
expect_denied "$app_namespace" clickhouse-peer 9000
