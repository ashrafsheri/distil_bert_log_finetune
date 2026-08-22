# Kubernetes

`k8s/` contains manifests for running the full LogGuard stack.

## Included Resources

- Namespace: `logguard`
- Deployments and services for frontend, backend, anomaly detection, PostgreSQL, and Elasticsearch.
- PVCs for PostgreSQL, Elasticsearch, model artifacts, and anomaly state.
- Ingress routes for `/`, `/api`, `/ws`, `/anomaly`, and `/elasticsearch`.
- Secret templates for PostgreSQL and backend SMTP/Firebase values.

## Before Deploying

1. Replace `ghcr.io/YOUR_GITHUB_ORG_OR_USER/...` images.
2. Replace all values in `postgres-secret.yaml`.
3. Fill `backend-secret.yaml` or create equivalent secrets out of band.
4. Create `firebase-secret` from your Firebase service account JSON.
5. Create `ghcr-secret` or remove `imagePullSecrets` if your images are public.

Apply:

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/
```

The manifests are intentionally plain YAML so they can be adapted to Helm, Kustomize, or GitOps later.
