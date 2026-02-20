#!/usr/bin/env bash
# ============================================================
# LogGuard K8s Setup Script
# Sets up the logguard namespace, secrets, and deploys all
# services on a k3s cluster.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
K8S_DIR="$PROJECT_DIR/k8s"

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ------------------------------------------------------------------
# Pre-flight checks
# ------------------------------------------------------------------
command -v kubectl >/dev/null 2>&1 || error "kubectl not found. Is k3s installed?"
kubectl cluster-info >/dev/null 2>&1 || error "Cannot connect to Kubernetes cluster."

info "Connected to cluster:"
kubectl get nodes

# ------------------------------------------------------------------
# 1. Namespace
# ------------------------------------------------------------------
info "Creating namespace 'logguard'..."
kubectl apply -f "$K8S_DIR/namespace.yaml"

# ------------------------------------------------------------------
# 2. GHCR Pull Secret
# ------------------------------------------------------------------
if [[ -z "${GHCR_USERNAME:-}" || -z "${GHCR_PAT:-}" ]]; then
    warn "GHCR_USERNAME and/or GHCR_PAT not set."
    warn "Skipping GHCR secret creation. Set them and re-run, or create manually:"
    warn "  kubectl create secret docker-registry ghcr-secret \\"
    warn "    --docker-server=ghcr.io \\"
    warn "    --docker-username=<user> \\"
    warn "    --docker-password=<pat> \\"
    warn "    -n logguard"
else
    info "Creating GHCR pull secret..."
    kubectl delete secret ghcr-secret -n logguard 2>/dev/null || true
    kubectl create secret docker-registry ghcr-secret \
        --docker-server=ghcr.io \
        --docker-username="$GHCR_USERNAME" \
        --docker-password="$GHCR_PAT" \
        -n logguard
fi

# ------------------------------------------------------------------
# 3. Firebase Secret
# ------------------------------------------------------------------
SERVICE_ACCOUNT_FILE="$PROJECT_DIR/backend/app/serviceAccountKey.json"
if [[ -f "$SERVICE_ACCOUNT_FILE" ]]; then
    info "Creating Firebase service account secret..."
    kubectl delete secret firebase-secret -n logguard 2>/dev/null || true
    kubectl create secret generic firebase-secret \
        --from-file=serviceAccountKey.json="$SERVICE_ACCOUNT_FILE" \
        -n logguard
else
    warn "Firebase service account key not found at $SERVICE_ACCOUNT_FILE"
    warn "Backend will not be able to use Firebase. Add it later with:"
    warn "  kubectl create secret generic firebase-secret --from-file=serviceAccountKey.json=<path> -n logguard"
fi

# ------------------------------------------------------------------
# 4. Apply secrets, PVCs, deployments, services, ingress
# ------------------------------------------------------------------
info "Applying Kubernetes manifests..."

# Secrets
kubectl apply -f "$K8S_DIR/postgres-secret.yaml"
kubectl apply -f "$K8S_DIR/backend-secret.yaml"

# PVCs
kubectl apply -f "$K8S_DIR/postgres-pvc.yaml"
kubectl apply -f "$K8S_DIR/elasticsearch-pvc.yaml"
kubectl apply -f "$K8S_DIR/model-artifacts-pvc.yaml"

# Data tier
kubectl apply -f "$K8S_DIR/postgres-deployment.yaml"
kubectl apply -f "$K8S_DIR/postgres-service.yaml"
kubectl apply -f "$K8S_DIR/elasticsearch-deployment.yaml"
kubectl apply -f "$K8S_DIR/elasticsearch-service.yaml"

info "Waiting for PostgreSQL..."
kubectl rollout status deployment/postgres -n logguard --timeout=120s

info "Waiting for Elasticsearch..."
kubectl rollout status deployment/elasticsearch -n logguard --timeout=180s

# Application tier
kubectl apply -f "$K8S_DIR/backend-deployment.yaml"
kubectl apply -f "$K8S_DIR/backend-service.yaml"
kubectl apply -f "$K8S_DIR/anomaly-detection-deployment.yaml"
kubectl apply -f "$K8S_DIR/anomaly-detection-service.yaml"
kubectl apply -f "$K8S_DIR/frontend-deployment.yaml"
kubectl apply -f "$K8S_DIR/frontend-service.yaml"

# Ingress
kubectl apply -f "$K8S_DIR/ingress.yaml"

# ------------------------------------------------------------------
# 5. Wait for application pods
# ------------------------------------------------------------------
info "Waiting for application deployments..."
kubectl rollout status deployment/backend -n logguard --timeout=120s || warn "Backend rollout timed out"
kubectl rollout status deployment/frontend -n logguard --timeout=120s || warn "Frontend rollout timed out"
kubectl rollout status deployment/anomaly-detection -n logguard --timeout=180s || warn "Anomaly detection rollout timed out"

# ------------------------------------------------------------------
# 6. Status
# ------------------------------------------------------------------
echo ""
info "========== Deployment Status =========="
kubectl get pods -n logguard -o wide
echo ""
kubectl get services -n logguard
echo ""
kubectl get ingress -n logguard
echo ""

SERVER_IP=$(hostname -I | awk '{print $1}')
info "Deployment complete!"
info "Access your app at: http://$SERVER_IP"
info ""
info "Useful commands:"
info "  kubectl get pods -n logguard              # Check pod status"
info "  kubectl logs -n logguard deployment/backend  # View backend logs"
info "  kubectl describe pod <pod-name> -n logguard  # Debug a pod"
