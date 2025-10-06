# Maliev Authentication Service - Deployment Guide

Complete deployment guide for Kubernetes with GitOps (ArgoCD + Kustomize).

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Google Secret Manager Setup](#google-secret-manager-setup)
3. [Kubernetes Manifests](#kubernetes-manifests)
4. [GitOps Deployment](#gitops-deployment)
5. [Database Migration](#database-migration)
6. [CI/CD Pipeline](#cicd-pipeline)
7. [Monitoring & Alerts](#monitoring--alerts)
8. [Rollback Procedures](#rollback-procedures)
9. [Security Hardening](#security-hardening)

---

## Prerequisites

### Required Tools

```bash
# Kubernetes CLI
kubectl version --client

# Kustomize
curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
sudo mv kustomize /usr/local/bin/

# Google Cloud SDK
gcloud --version

# Docker
docker --version
```

### GKE Cluster Access

```bash
# Authenticate with GCP
gcloud auth login

# Get cluster credentials
gcloud container clusters get-credentials maliev-cluster \
  --region=asia-southeast1 \
  --project=maliev-website

# Verify access
kubectl get nodes
kubectl get namespaces
```

---

## Google Secret Manager Setup

### 1. Create JWT Signing Key

```bash
# Generate ECDSA P-256 private key
openssl ecparam -name prime256v1 -genkey -noout -out jwt-private-key.pem

# Verify key format
openssl ec -in jwt-private-key.pem -text -noout

# Create secret in Google Secret Manager
gcloud secrets create maliev-auth-jwt-signing-key \
  --data-file=jwt-private-key.pem \
  --replication-policy=automatic \
  --project=maliev-website

# Verify secret created
gcloud secrets describe maliev-auth-jwt-signing-key --project=maliev-website

# CRITICAL: Delete local key file after upload
shred -u jwt-private-key.pem
```

### 2. Create Database Connection String

```bash
# Get PostgreSQL password from existing secret
kubectl get secret postgres-cluster-app -n maliev-dev -o jsonpath='{.data.password}' | base64 -d

# Create connection string secret
echo -n "Server=postgres-cluster-rw.maliev-dev.svc.cluster.local;Port=5432;Database=auth_db;User Id=postgres;Password=YOUR_PASSWORD_HERE;" | \
  gcloud secrets create maliev-auth-db-connection-string \
    --data-file=- \
    --replication-policy=automatic \
    --project=maliev-website
```

### 3. Configure External Secrets Operator

Create `ExternalSecret` resource to sync secrets from Google Secret Manager:

```yaml
# maliev-gitops/3-apps/auth-service/base/external-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: maliev-auth-secrets
  namespace: maliev-dev
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: gcpsm-secret-store  # Existing Google Secret Manager store
    kind: ClusterSecretStore
  target:
    name: maliev-auth-secrets
    creationPolicy: Owner
  data:
    - secretKey: Jwt__SigningKey
      remoteRef:
        key: maliev-auth-jwt-signing-key
    - secretKey: Database__ConnectionString
      remoteRef:
        key: maliev-auth-db-connection-string
```

**Verify secrets synced:**
```bash
# Check ExternalSecret status
kubectl get externalsecret maliev-auth-secrets -n maliev-dev

# Verify Kubernetes secret created
kubectl get secret maliev-auth-secrets -n maliev-dev -o yaml
```

---

## Kubernetes Manifests

### Directory Structure

```
maliev-gitops/
└── 3-apps/
    └── auth-service/
        ├── base/
        │   ├── deployment.yaml
        │   ├── service.yaml
        │   ├── external-secret.yaml
        │   └── kustomization.yaml
        └── overlays/
            ├── development/
            │   └── kustomization.yaml
            ├── staging/
            │   └── kustomization.yaml
            └── production/
                └── kustomization.yaml
```

### Base Deployment (base/deployment.yaml)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: maliev-auth-service
  labels:
    app: maliev-auth-service
    version: v1
spec:
  replicas: 2
  selector:
    matchLabels:
      app: maliev-auth-service
  template:
    metadata:
      labels:
        app: maliev-auth-service
        version: v1
    spec:
      serviceAccountName: maliev-auth-service
      containers:
      - name: auth-service
        image: asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-dev/auth-service:latest
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        env:
        - name: ASPNETCORE_ENVIRONMENT
          value: "Production"
        - name: ASPNETCORE_URLS
          value: "http://+:8080"
        envFrom:
        - secretRef:
            name: maliev-auth-secrets
        livenessProbe:
          httpGet:
            path: /auth/liveness
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /auth/readiness
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        resources:
          requests:
            cpu: 200m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: false
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
      restartPolicy: Always
```

### Base Service (base/service.yaml)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: maliev-auth-service
  labels:
    app: maliev-auth-service
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
    name: http
  selector:
    app: maliev-auth-service
```

### Base Kustomization (base/kustomization.yaml)

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - deployment.yaml
  - service.yaml
  - external-secret.yaml

commonLabels:
  app.kubernetes.io/name: maliev-auth-service
  app.kubernetes.io/component: authentication
  app.kubernetes.io/part-of: maliev-platform

namespace: maliev-dev
```

### Development Overlay (overlays/development/kustomization.yaml)

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base

namespace: maliev-dev

images:
  - name: auth-service
    newName: asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-dev/auth-service
    newTag: latest  # Replaced by CI/CD with commit SHA

patchesStrategicMerge:
  - |-
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: maliev-auth-service
    spec:
      replicas: 1
      template:
        spec:
          containers:
          - name: auth-service
            env:
            - name: ASPNETCORE_ENVIRONMENT
              value: "Development"
```

### Staging Overlay (overlays/staging/kustomization.yaml)

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base

namespace: maliev-staging

images:
  - name: auth-service
    newName: asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-staging/auth-service
    newTag: latest

patchesStrategicMerge:
  - |-
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: maliev-auth-service
    spec:
      replicas: 2
```

### Production Overlay (overlays/production/kustomization.yaml)

```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - ../../base

namespace: maliev-prod

images:
  - name: auth-service
    newName: asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-prod/auth-service
    newTag: latest

patchesStrategicMerge:
  - |-
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: maliev-auth-service
    spec:
      replicas: 3
      template:
        spec:
          containers:
          - name: auth-service
            resources:
              requests:
                cpu: 500m
                memory: 512Mi
              limits:
                cpu: 1000m
                memory: 1Gi
```

---

## GitOps Deployment

### ArgoCD Application

```yaml
# maliev-gitops/1-argocd/applications/auth-service-dev.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: maliev-auth-service-dev
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/MALIEV-Co-Ltd/maliev-gitops.git
    targetRevision: main
    path: 3-apps/auth-service/overlays/development
  destination:
    server: https://kubernetes.default.svc
    namespace: maliev-dev
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

### Manual Deployment (Development)

```bash
# Clone GitOps repository
git clone https://github.com/MALIEV-Co-Ltd/maliev-gitops.git
cd maliev-gitops/3-apps/auth-service/overlays/development

# Preview manifests
kustomize build .

# Apply manifests (MANUAL - ArgoCD handles this normally)
kubectl apply -k .

# Verify deployment
kubectl get pods -n maliev-dev | grep auth-service
kubectl get svc -n maliev-dev | grep auth-service

# View logs
kubectl logs -f deployment/maliev-auth-service -n maliev-dev

# Check health
kubectl get deployment maliev-auth-service -n maliev-dev
```

### Verify Deployment

```bash
# Port-forward to service
kubectl port-forward -n maliev-dev svc/maliev-auth-service 8080:8080 &

# Test liveness
curl http://localhost:8080/auth/liveness

# Test readiness
curl http://localhost:8080/auth/readiness

# Test login (requires external services running)
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "SecurePass123!",
    "user_type": "customer"
  }'
```

---

## Database Migration

### Prerequisites

1. **PostgreSQL Running:**
   ```bash
   kubectl get pods -n maliev-dev | grep postgres
   ```

2. **Port-Forward to Pod (NOT Service):**
   ```bash
   # Find PostgreSQL pod name
   kubectl get pods -n maliev-dev | grep postgres

   # Port-forward to pod (e.g., postgres-cluster-1)
   kubectl port-forward -n maliev-dev postgres-cluster-1 5432:5432 &
   ```

3. **Get PostgreSQL Password:**
   ```bash
   kubectl get secret postgres-cluster-app -n maliev-dev -o jsonpath='{.data.password}' | base64 -d
   ```

### Apply Migration

```bash
# Set connection string (use password from above)
export AuthDbContext="Server=localhost;Port=5432;Database=auth_db;User Id=postgres;Password=YOUR_PASSWORD;"

# Navigate to service directory
cd Maliev.AuthService

# Add migration (if not already created)
dotnet ef migrations add InitialCreate --project Maliev.AuthService.Data

# Apply migration
dotnet ef database update --project Maliev.AuthService.Data

# Verify tables created
PGPASSWORD=YOUR_PASSWORD psql -h localhost -U postgres -d auth_db -c "\dt"
```

### Verify Migration

```sql
-- Connect to database
PGPASSWORD=YOUR_PASSWORD psql -h localhost -U postgres -d auth_db

-- Check tables
\dt

-- Expected tables:
-- public | __EFMigrationsHistory    | table | postgres
-- public | RevokedAccessTokens      | table | postgres
-- public | TokenFamilies            | table | postgres
-- public | RefreshTokens            | table | postgres

-- Check migration history
SELECT * FROM "__EFMigrationsHistory";

-- Exit
\q
```

### Production Migration (CI/CD)

**Automated migration via init container:**

```yaml
# deployment.yaml - Add init container for migrations
spec:
  template:
    spec:
      initContainers:
      - name: migration
        image: asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-prod/auth-service:latest
        command:
        - dotnet
        - ef
        - database
        - update
        - --project
        - Maliev.AuthService.Data
        envFrom:
        - secretRef:
            name: maliev-auth-secrets
      containers:
      - name: auth-service
        # ... main container
```

**Manual migration (recommended for production):**
```bash
# Create dedicated migration job
kubectl run migration-job --rm -it \
  --image=asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-prod/auth-service:latest \
  --env-from=secret/maliev-auth-secrets \
  --restart=Never \
  -- dotnet ef database update --project Maliev.AuthService.Data
```

---

## CI/CD Pipeline

### GitHub Actions Workflows

**Required workflows:**
- `.github/workflows/ci-develop.yml` - Development branch
- `.github/workflows/ci-staging.yml` - Staging branch
- `.github/workflows/ci-main.yml` - Production branch

### Development Workflow (.github/workflows/ci-develop.yml)

```yaml
name: CI - Develop
on:
  push:
    branches: [develop, 001-create-a-jwt]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      # 1. Checkout source code
      - name: Checkout code
        uses: actions/checkout@v5

      # 2. Setup .NET 9.0
      - name: Setup .NET
        uses: actions/setup-dotnet@v5
        with:
          dotnet-version: '9.x'

      # 3. Restore dependencies
      - name: Restore dependencies
        run: dotnet restore Maliev.AuthService.sln

      # 4. Build solution
      - name: Build solution
        run: dotnet build Maliev.AuthService.sln --no-restore --configuration Release

      # 5. Run tests
      - name: Run tests
        run: dotnet test Maliev.AuthService.sln --no-build --verbosity normal --configuration Release

      # 6. Authenticate with GCP
      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@v3
        with:
          credentials_json: '${{ secrets.GCP_SA_KEY }}'

      # 7. Configure Docker for Artifact Registry
      - name: Configure Docker
        run: gcloud auth configure-docker asia-southeast1-docker.pkg.dev

      # 8. Build Docker image
      - name: Build Docker image
        run: |
          docker build -t asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-dev/auth-service:${{ github.sha }} \
                       -t asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-dev/auth-service:latest \
                       -f Maliev.AuthService.Api/Dockerfile .

      # 9. Push Docker image
      - name: Push Docker image
        run: |
          docker push asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-dev/auth-service:${{ github.sha }}
          docker push asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-dev/auth-service:latest

      # 10. Update GitOps repository
      - name: Checkout GitOps repository
        uses: actions/checkout@v5
        with:
          repository: 'MALIEV-Co-Ltd/maliev-gitops'
          token: '${{ secrets.GITOPS_PAT }}'
          path: 'maliev-gitops'

      # 11. Install Kustomize
      - name: Install Kustomize
        run: |
          curl -s "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh" | bash
          sudo mv kustomize /usr/local/bin/

      # 12. Update image tag in GitOps
      - name: Update Kustomize image
        run: |
          cd maliev-gitops/3-apps/auth-service/overlays/development
          kustomize edit set image auth-service=asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-dev/auth-service:${{ github.sha }}

      # 13. Commit and push GitOps changes
      - name: Commit and push GitOps changes
        run: |
          cd maliev-gitops
          git config --global user.name 'github-actions[bot]'
          git config --global user.email 'github-actions[bot]@users.noreply.github.com'
          git add 3-apps/auth-service/overlays/development/kustomization.yaml
          git commit -m "Update auth-service image to ${{ github.sha }}"
          git pull --rebase origin main
          git push
```

### Secrets Configuration

**Required GitHub Secrets:**
- `GCP_SA_KEY` - Google Cloud service account JSON key
- `GITOPS_PAT` - GitHub Personal Access Token with repo write access

**Create GCP Service Account:**
```bash
# Create service account
gcloud iam service-accounts create github-actions-auth-service \
  --description="GitHub Actions for Auth Service" \
  --display-name="GitHub Actions Auth Service"

# Grant Artifact Registry write permissions
gcloud projects add-iam-policy-binding maliev-website \
  --member="serviceAccount:github-actions-auth-service@maliev-website.iam.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"

# Create JSON key
gcloud iam service-accounts keys create github-actions-key.json \
  --iam-account=github-actions-auth-service@maliev-website.iam.gserviceaccount.com

# Add to GitHub Secrets (Settings > Secrets and variables > Actions > New repository secret)
# Name: GCP_SA_KEY
# Value: <paste contents of github-actions-key.json>

# Delete local key file
shred -u github-actions-key.json
```

---

## Monitoring & Alerts

### Grafana Dashboard

```bash
# Open Grafana (from maliev-gitops repository)
cd maliev-gitops
./scripts/open-grafana.ps1
```

**Recommended metrics:**
- Pod CPU/Memory usage
- Request rate (requests/second)
- Error rate (5xx responses)
- Login success/failure rate
- Token rotation operations
- External service call latency

### Prometheus Metrics (Planned)

Add Prometheus metrics endpoint:
```csharp
// Program.cs
app.UseHttpMetrics();  // Prometheus middleware

app.MapMetrics();      // /metrics endpoint
```

**Example metrics:**
```prometheus
# Login attempts
auth_login_attempts_total{status="success"} 1234
auth_login_attempts_total{status="failure"} 56

# Token operations
auth_refresh_operations_total{status="success"} 890
auth_refresh_operations_total{status="reuse_detected"} 2

# External service calls
auth_external_service_duration_seconds{service="customer",quantile="0.95"} 0.234
```

### Logs

```bash
# View live logs
kubectl logs -f deployment/maliev-auth-service -n maliev-dev

# Filter by correlation ID
kubectl logs deployment/maliev-auth-service -n maliev-dev | grep "abc-123-def"

# Export logs (last 1 hour)
kubectl logs deployment/maliev-auth-service -n maliev-dev --since=1h > auth-service-logs.txt
```

---

## Rollback Procedures

### Kubernetes Rollout Rollback

```bash
# View deployment history
kubectl rollout history deployment/maliev-auth-service -n maliev-dev

# Rollback to previous version
kubectl rollout undo deployment/maliev-auth-service -n maliev-dev

# Rollback to specific revision
kubectl rollout undo deployment/maliev-auth-service -n maliev-dev --to-revision=3

# Monitor rollback status
kubectl rollout status deployment/maliev-auth-service -n maliev-dev
```

### GitOps Rollback

```bash
# Find previous commit SHA
cd maliev-gitops
git log --oneline 3-apps/auth-service/overlays/development/kustomization.yaml

# Revert to previous image
cd 3-apps/auth-service/overlays/development
kustomize edit set image auth-service=asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-dev/auth-service:PREVIOUS_SHA

# Commit and push
git add kustomization.yaml
git commit -m "Rollback auth-service to PREVIOUS_SHA"
git push

# ArgoCD will automatically sync
```

### Database Migration Rollback

```bash
# List migrations
dotnet ef migrations list --project Maliev.AuthService.Data

# Rollback to specific migration
dotnet ef database update PreviousMigrationName --project Maliev.AuthService.Data

# Remove migration (if not applied)
dotnet ef migrations remove --project Maliev.AuthService.Data
```

---

## Security Hardening

### Network Policies

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: maliev-auth-service-policy
  namespace: maliev-dev
spec:
  podSelector:
    matchLabels:
      app: maliev-auth-service
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: maliev-dev
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: maliev-dev
    ports:
    - protocol: TCP
      port: 5432  # PostgreSQL
  - to:
    - namespaceSelector:
        matchLabels:
          name: maliev-dev
    ports:
    - protocol: TCP
      port: 8080  # External services
```

### Pod Security Standards

```yaml
# Apply restricted pod security standard
apiVersion: v1
kind: Namespace
metadata:
  name: maliev-dev
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### RBAC Configuration

```yaml
# service-account.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: maliev-auth-service
  namespace: maliev-dev

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: maliev-auth-service-role
  namespace: maliev-dev
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["maliev-auth-secrets"]
  verbs: ["get"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: maliev-auth-service-binding
  namespace: maliev-dev
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: maliev-auth-service-role
subjects:
- kind: ServiceAccount
  name: maliev-auth-service
  namespace: maliev-dev
```

### TLS/SSL Configuration (Future)

```yaml
# ingress.yaml (with cert-manager)
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: maliev-auth-ingress
  namespace: maliev-dev
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - auth.maliev.com
    secretName: maliev-auth-tls
  rules:
  - host: auth.maliev.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: maliev-auth-service
            port:
              number: 8080
```

---

## Appendix

### Useful Commands Cheat Sheet

```bash
# Deployment
kubectl apply -k maliev-gitops/3-apps/auth-service/overlays/development
kubectl get pods -n maliev-dev | grep auth
kubectl logs -f deployment/maliev-auth-service -n maliev-dev
kubectl port-forward -n maliev-dev svc/maliev-auth-service 8080:8080

# Secrets
kubectl get secret maliev-auth-secrets -n maliev-dev -o yaml
kubectl get externalsecret maliev-auth-secrets -n maliev-dev
gcloud secrets list --project=maliev-website

# Database
kubectl get pods -n maliev-dev | grep postgres
kubectl port-forward -n maliev-dev postgres-cluster-1 5432:5432
PGPASSWORD=xxx psql -h localhost -U postgres -d auth_db

# Health Checks
curl http://localhost:8080/auth/liveness
curl http://localhost:8080/auth/readiness

# Debugging
kubectl describe pod <pod-name> -n maliev-dev
kubectl exec -it <pod-name> -n maliev-dev -- /bin/bash
kubectl top pods -n maliev-dev | grep auth

# ArgoCD
kubectl get applications -n argocd
kubectl describe application maliev-auth-service-dev -n argocd
```

### Environment Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| `ASPNETCORE_ENVIRONMENT` | Environment name | `Production`, `Development`, `Staging` |
| `ASPNETCORE_URLS` | Listen URLs | `http://+:8080` |
| `Jwt__SigningKey` | ECDSA P-256 private key (PEM) | `-----BEGIN EC PRIVATE KEY-----...` |
| `Jwt__Issuer` | JWT issuer claim | `https://auth.maliev.com` |
| `Jwt__Audience` | JWT audience claim | `maliev-services` |
| `Database__ConnectionString` | PostgreSQL connection | `Server=postgres-cluster-rw;Port=5432;...` |
| `ExternalServices__CustomerServiceUrl` | Customer service URL | `http://customer-service:8080/api/v1` |
| `ExternalServices__EmployeeServiceUrl` | Employee service URL | `http://employee-service:8080/api/v1` |

### Troubleshooting Common Deployment Issues

**Issue:** Pod stuck in `CrashLoopBackOff`
```bash
# Check logs
kubectl logs <pod-name> -n maliev-dev

# Common causes:
# 1. Missing JWT signing key → Check ExternalSecret synced
# 2. Database connection failed → Verify PostgreSQL running
# 3. Invalid configuration → Check appsettings.json
```

**Issue:** Readiness probe failing
```bash
# Check database connectivity
kubectl exec -it <pod-name> -n maliev-dev -- curl http://localhost:8080/auth/readiness

# Port-forward to PostgreSQL and test connection
kubectl port-forward postgres-cluster-1 5432:5432 -n maliev-dev
PGPASSWORD=xxx psql -h localhost -U postgres -d auth_db -c "SELECT 1;"
```

**Issue:** ExternalSecret not syncing
```bash
# Check ExternalSecret status
kubectl describe externalsecret maliev-auth-secrets -n maliev-dev

# Verify ClusterSecretStore configured
kubectl get clustersecretstore gcpsm-secret-store

# Check secret exists in Google Secret Manager
gcloud secrets describe maliev-auth-jwt-signing-key --project=maliev-website
```

---

## Support

For deployment issues:
- **GitHub Issues:** https://github.com/MALIEV-Co-Ltd/Maliev.AuthService/issues
- **DevOps Contact:** devops@maliev.com
- **Documentation:** See README.md for API documentation

**Emergency Rollback:** Follow [Rollback Procedures](#rollback-procedures) section above.
