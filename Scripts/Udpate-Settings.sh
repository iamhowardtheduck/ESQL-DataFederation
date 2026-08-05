#!/usr/bin/env bash

set -Eeuo pipefail

NAMESPACE="${1:-default}"
ES_NAME="${2:-elasticsearch}"
KIBANA_NAME="${3:-kibana}"

command -v kubectl >/dev/null 2>&1 || {
  echo "ERROR: kubectl is not installed or not in PATH." >&2
  exit 1
}

command -v python3 >/dev/null 2>&1 || {
  echo "ERROR: python3 is required." >&2
  exit 1
}

echo "Namespace:     ${NAMESPACE}"
echo "Elasticsearch: ${ES_NAME}"
echo "Kibana:        ${KIBANA_NAME}"
echo

# Verify the ECK resources exist.
kubectl get elasticsearch "${ES_NAME}" \
  -n "${NAMESPACE}" >/dev/null

kubectl get kibana "${KIBANA_NAME}" \
  -n "${NAMESPACE}" >/dev/null

echo "Updating Elasticsearch setting: esql.federation.enabled=true"

# Retrieve all existing nodeSets, add the setting to each one, and send the
# complete nodeSets array back as a merge patch. This preserves node roles,
# resources, storage, pod templates, and other existing node-set configuration.
kubectl get elasticsearch "${ES_NAME}" \
  -n "${NAMESPACE}" \
  -o json |
python3 -c '
import json
import sys

resource = json.load(sys.stdin)
node_sets = resource.get("spec", {}).get("nodeSets", [])

if not node_sets:
    raise SystemExit("ERROR: Elasticsearch resource has no spec.nodeSets entries")

for node_set in node_sets:
    node_set.setdefault("config", {})
    node_set["config"]["esql.federation.enabled"] = True

print(json.dumps({
    "spec": {
        "nodeSets": node_sets
    }
}))
' |
kubectl patch elasticsearch "${ES_NAME}" \
  -n "${NAMESPACE}" \
  --type=merge \
  --patch-file=/dev/stdin

echo "Updating Kibana setting: xpack.dataFederation.enabled=true"

kubectl patch kibana "${KIBANA_NAME}" \
  -n "${NAMESPACE}" \
  --type=merge \
  -p '{
    "spec": {
      "config": {
        "xpack.dataFederation.enabled": true
      }
    }
  }'

echo
echo "Settings applied. Current ECK configuration:"
echo

kubectl get elasticsearch "${ES_NAME}" \
  -n "${NAMESPACE}" \
  -o json |
python3 -c '
import json
import sys

resource = json.load(sys.stdin)

for node_set in resource["spec"]["nodeSets"]:
    name = node_set.get("name", "<unnamed>")
    value = node_set.get("config", {}).get("esql.federation.enabled")
    print(f"Elasticsearch nodeSet {name}: esql.federation.enabled={value}")
'

KIBANA_VALUE="$(
  kubectl get kibana "${KIBANA_NAME}" \
    -n "${NAMESPACE}" \
    -o jsonpath='{.spec.config.xpack\.dataFederation\.enabled}'
)"

echo "Kibana: xpack.dataFederation.enabled=${KIBANA_VALUE}"

echo
echo "Waiting for Elasticsearch StatefulSet rollout..."

kubectl rollout status statefulset \
  -n "${NAMESPACE}" \
  -l "elasticsearch.k8s.elastic.co/cluster-name=${ES_NAME}" \
  --timeout=15m

echo
echo "Waiting for Kibana Deployment rollout..."

kubectl rollout status deployment \
  -n "${NAMESPACE}" \
  -l "kibana.k8s.elastic.co/name=${KIBANA_NAME}" \
  --timeout=15m

echo
echo "Final pod status:"
kubectl get pods -n "${NAMESPACE}"

echo
echo "Data federation settings enabled successfully."
