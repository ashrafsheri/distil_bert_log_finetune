#!/usr/bin/env bash
# ============================================================
# Upload model artifacts to the anomaly-detection PVC
# Run this AFTER the initial k8s-deploy.sh to seed model files.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ARTIFACTS_DIR="$PROJECT_DIR/artifacts/ensemble_model_export"
NAMESPACE="logguard"

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ -d "$ARTIFACTS_DIR" ]] || error "Artifacts directory not found: $ARTIFACTS_DIR"

# Get the anomaly-detection pod name
POD=$(kubectl get pods -n "$NAMESPACE" -l app=anomaly-detection -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[[ -n "$POD" ]] || error "No anomaly-detection pod found in namespace $NAMESPACE"

info "Uploading model artifacts to pod $POD..."
kubectl cp "$ARTIFACTS_DIR/" "$NAMESPACE/$POD:/app/artifacts/ensemble_model_export/" -c anomaly-detection

info "Verifying upload..."
kubectl exec -n "$NAMESPACE" "$POD" -c anomaly-detection -- ls -la /app/artifacts/ensemble_model_export/

info "Model artifacts uploaded successfully."
info "You may need to restart the anomaly-detection deployment:"
info "  kubectl rollout restart deployment/anomaly-detection -n $NAMESPACE"
