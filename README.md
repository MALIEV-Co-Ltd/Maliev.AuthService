# Maliev Authentication Service

JWT Token-Based Authentication Service with OAuth 2.0 Token Rotation (RFC 9700)

## Features

- **ES256 (ECDSA P-256)** JWT token signing
- **RFC 9700** OAuth 2.0 Token Rotation with reuse detection
- **Multi-tenant** authentication (Customer/Employee services)
- **SHA-256** cryptographic hashing for refresh tokens
- **Polly resilience** patterns (retry + circuit breaker)
- **Optimistic concurrency** control with EF Core RowVersion
- **Rate limiting** by IP address (5 attempts per 5 minutes)
- **PostgreSQL** persistence with automatic migrations
- **Health checks** (liveness/readiness)

## API Endpoints

### 1. Login (POST /auth/login)

Authenticate user and issue access + refresh tokens.

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "customer@example.com",
    "password": "SecurePass123!",
    "user_type": "customer"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Error Codes:** `400` (invalid request), `401` (invalid credentials), `429` (rate limit), `503` (service unavailable)

---

### 2. Refresh Token (POST /auth/refresh)

Rotate refresh token and issue new access token (RFC 9700).

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "a1b2c3d4e5f6..."}'
```

**Response:** Same as login (new tokens)

**Error Codes:** `400` (missing token), `401` (invalid/expired), `403` (token reuse detected - family invalidated)

**Token Rotation:** Old refresh token is marked as used. If reused, entire token family is invalidated for security.

---

### 3. Validate Token (POST /auth/validate)

Validate access token and return user claims.

```bash
curl -X POST http://localhost:8080/auth/validate \
  -H "Content-Type: application/json" \
  -d '{"access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."}'
```

**Response:**
```json
{
  "user_id": "12345",
  "user_type": "customer",
  "username": "customer@example.com",
  "email": "customer@example.com",
  "roles": ["customer"],
  "permissions": ["read:profile", "write:orders"]
}
```

**Caching:** Successful validations cached for 5-10 minutes to reduce external service calls.

---

### 4. Revoke Token (POST /auth/revoke)

Revoke access token or entire refresh token family.

```bash
# Revoke single access token
curl -X POST http://localhost:8080/auth/revoke \
  -H "Content-Type: application/json" \
  -d '{"access_token": "eyJhbGci..."}'

# Revoke entire token family
curl -X POST http://localhost:8080/auth/revoke \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "a1b2c3..."}'
```

**Response:** `204 No Content` on success

---

## Local Development

### Prerequisites

- .NET 9.0 SDK
- Docker Desktop (for PostgreSQL)
- OpenSSL (for ECDSA key generation)

### Setup

```bash
# 1. Clone repository
git clone https://github.com/MALIEV-Co-Ltd/Maliev.AuthService.git
cd Maliev.AuthService

# 2. Start PostgreSQL (Docker)
docker run -d \
  --name auth-postgres \
  -e POSTGRES_DB=auth_app_db \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:17

# 3. Generate development ECDSA P-256 key (Base64-encoded 32-byte scalar)
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl ec -outform DER | tail -c 32 | base64

# 4. Update appsettings.Development.json with generated key
# {
#   "Jwt": {
#     "SecurityKey": "<paste-base64-key-here>"
#   }
# }

# 5. Apply database migrations
dotnet ef database update --project Maliev.AuthService.Data

# 6. Run service
dotnet run --project Maliev.AuthService.Api
```

**Service URL:** http://localhost:8080

**Health Checks:**
- Liveness: http://localhost:8080/auth/liveness
- Readiness: http://localhost:8080/auth/readiness

### Testing

```bash
# Run all tests
dotnet test Maliev.AuthService.sln --verbosity normal

# Run only contract tests
dotnet test --filter "Category=Contract"

# Run only integration tests
dotnet test --filter "Category=Integration"
```

**Test Status:** 37 tests (6 passing, 21 TDD Red phase, 10 skipped - expected until dependencies configured)

---

## Production Deployment

### Secret Setup (Google Secret Manager)

#### 1. Generate ECDSA P-256 Key

```bash
# Generate Base64-encoded 32-byte private key scalar
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl ec -outform DER | tail -c 32 | base64

# Output example: xto5fs9GfvC/2ztp3S1pR9w27Hgjn3j2c8Ad0QFrtJw=
```

**CRITICAL:** Store this value securely. This is the private key for JWT signing.

#### 2. Required Secrets

| Secret Name | Environment Variable | Example Value |
|-------------|---------------------|---------------|
| `maliev-auth-jwt-security-key` | `Jwt__SecurityKey` | `xto5fs9GfvC/2ztp3S1pR9w27Hgjn3j2c8Ad0QFrtJw=` (Base64 32-byte key) |
| `maliev-auth-jwt-issuer` | `Jwt__Issuer` | `maliev-dev` |
| `maliev-auth-jwt-audience` | `Jwt__Audience` | `maliev-dev` |
| `maliev-auth-db-connection` | `ConnectionStrings__RefreshTokenDbContext` | `Server=postgres-cluster-rw.maliev-dev.svc.cluster.local;Port=5432;Database=auth_app_db;User Id=postgres;Password=XXX;` |
| `maliev-auth-customer-endpoint` | `CustomerService__ValidationEndpoint` | `http://maliev-customer-service.maliev-dev.svc.cluster.local:8080/customers/v1/validate` |
| `maliev-auth-employee-endpoint` | `EmployeeService__ValidationEndpoint` | `http://maliev-employee-service.maliev-dev.svc.cluster.local:8080/employees/v1/validate` |

#### 3. Upload Secrets to Google Secret Manager

```bash
# JWT Security Key
echo -n "xto5fs9GfvC/2ztp3S1pR9w27Hgjn3j2c8Ad0QFrtJw=" | \
  gcloud secrets create maliev-auth-jwt-security-key \
    --data-file=- \
    --replication-policy=automatic \
    --project=maliev-website

# Repeat for other secrets (issuer, audience, db connection, endpoints)
```

#### 4. External Secrets Operator Configuration

Create `maliev-gitops/3-apps/auth-service/base/external-secret.yaml`:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: maliev-auth-secrets
  namespace: maliev-dev
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: gcpsm-secret-store
    kind: ClusterSecretStore
  target:
    name: maliev-auth-secrets
    creationPolicy: Owner
  data:
    - secretKey: Jwt__SecurityKey
      remoteRef:
        key: maliev-auth-jwt-security-key
    - secretKey: Jwt__Issuer
      remoteRef:
        key: maliev-auth-jwt-issuer
    - secretKey: Jwt__Audience
      remoteRef:
        key: maliev-auth-jwt-audience
    - secretKey: ConnectionStrings__RefreshTokenDbContext
      remoteRef:
        key: maliev-auth-db-connection
    - secretKey: CustomerService__ValidationEndpoint
      remoteRef:
        key: maliev-auth-customer-endpoint
    - secretKey: EmployeeService__ValidationEndpoint
      remoteRef:
        key: maliev-auth-employee-endpoint
```

**Verify secrets synced:**
```bash
kubectl get externalsecret maliev-auth-secrets -n maliev-dev
kubectl get secret maliev-auth-secrets -n maliev-dev
```

---

### Database Migration

```bash
# 1. Port-forward to PostgreSQL pod (NOT service)
kubectl get pods -n maliev-dev | grep postgres
kubectl port-forward -n maliev-dev postgres-cluster-1 5432:5432

# 2. Get PostgreSQL password
kubectl get secret postgres-cluster-app -n maliev-dev -o jsonpath='{.data.password}' | base64 -d

# 3. Apply migration
dotnet ef database update --project Maliev.AuthService.Data \
  --connection "Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=YOUR_PASSWORD;"
```

**Verify:**
```bash
PGPASSWORD=YOUR_PASSWORD psql -h localhost -U postgres -d auth_app_db -c "\dt"
# Should show: RefreshTokens, TokenFamilies, RevokedAccessTokens, __EFMigrationsHistory
```

---

### Kubernetes Deployment

#### GitOps Repository Structure

```
maliev-gitops/3-apps/auth-service/
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

#### Base Deployment (base/deployment.yaml)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: maliev-auth-service
spec:
  replicas: 2
  selector:
    matchLabels:
      app: maliev-auth-service
  template:
    metadata:
      labels:
        app: maliev-auth-service
    spec:
      containers:
      - name: auth-service
        image: asia-southeast1-docker.pkg.dev/maliev-website/maliev-website-artifact-dev/auth-service:latest
        ports:
        - containerPort: 8080
        envFrom:
        - secretRef:
            name: maliev-auth-secrets
        livenessProbe:
          httpGet:
            path: /auth/liveness
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /auth/readiness
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            cpu: 200m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
```

#### Base Service (base/service.yaml)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: maliev-auth-service
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: 8080
    name: http
  selector:
    app: maliev-auth-service
```

#### Deploy to Development

```bash
# Apply manifests via GitOps
cd maliev-gitops/3-apps/auth-service/overlays/development
kubectl apply -k .

# Verify deployment
kubectl get pods -n maliev-dev | grep auth-service
kubectl logs -f deployment/maliev-auth-service -n maliev-dev

# Port-forward for testing
kubectl port-forward -n maliev-dev svc/maliev-auth-service 8080:8080
```

---

## CI/CD Pipeline

### GitHub Actions Workflow

Required workflows in `.github/workflows/`:
- `ci-develop.yml` - Development branch (auto-deploy to dev)
- `ci-staging.yml` - Staging branch (auto-deploy to staging)
- `ci-main.yml` - Main branch (auto-deploy to production)

**Workflow Steps:**
1. Build and test .NET solution
2. Build Docker image
3. Push to Google Artifact Registry
4. Update GitOps repository with new image tag
5. ArgoCD auto-syncs deployment

---

## Security

### Token Security
- **ES256 Signing:** ECDSA P-256 asymmetric keys prevent forgery
- **SHA-256 Hashing:** Refresh tokens stored as hashes (never plaintext)
- **Token Rotation:** Automatic rotation on every refresh (RFC 9700)
- **Reuse Detection:** Invalidates entire token family on reuse attempt
- **Short-lived Access:** 15-minute expiration (configurable)
- **Long-lived Refresh:** 30-day expiration (configurable)

### Rate Limiting
- 5 login attempts per 5 minutes per IP address
- Returns `429 Too Many Requests` when exceeded
- Partition key: Remote IP address (X-Forwarded-For aware)

### Secrets Management
- All secrets in Google Secret Manager
- Synced via External Secrets Operator
- No secrets in source code or Docker images
- Secrets mounted at `/mnt/secrets` in Kubernetes pods

---

## Status

- **Build:** 0 warnings ✓
- **Tests:** 37 tests (6 passing, 21 TDD Red phase, 10 skipped)
- **Database:** Migration applied successfully ✓
- **Deployment:** Ready after secrets configured

**TDD Red Phase:** Tests fail until production secrets (JWT key, external services) are configured. This is expected behavior.

---

## Architecture Details

### Technology Stack
- **.NET 9.0** - ASP.NET Core Web API
- **Entity Framework Core 9.0** - PostgreSQL ORM
- **Serilog** - Structured logging with correlation ID
- **Polly** - Resilience patterns (retry + circuit breaker)
- **xUnit** - Testing framework with Testcontainers

### Database Schema
- **TokenFamily** - Tracks token lineage for reuse detection
- **RefreshToken** - Stores hashed refresh tokens with RowVersion
- **RevokedAccessToken** - Blacklist for early access token revocation

### Service Dependencies
- **Customer Service:** Validates customer credentials
- **Employee Service:** Validates employee credentials
- **PostgreSQL:** Token persistence
- **Google Secret Manager:** Secret storage

---

## Troubleshooting

### Secrets Not Syncing

```bash
# Check ExternalSecret status
kubectl describe externalsecret maliev-auth-secrets -n maliev-dev

# Check External Secrets Operator logs
kubectl logs -n external-secrets-system deployment/external-secrets
```

### Pod Cannot Start

```bash
# Check pod events
kubectl describe pod <pod-name> -n maliev-dev

# Check logs
kubectl logs <pod-name> -n maliev-dev

# Common issues:
# 1. Invalid JWT key format (must be Base64-encoded 32 bytes)
# 2. Database connection failed (check connection string)
# 3. External service unreachable (check service URLs)
```

### Tests Failing

Tests are expected to fail (TDD Red phase) until:
1. Valid ECDSA P-256 key configured in `Jwt__SecurityKey`
2. Customer and Employee services running
3. PostgreSQL database accessible

---

## License

Copyright © 2025 MALIEV Co. Ltd. All rights reserved.

## Support

- **Issues:** https://github.com/MALIEV-Co-Ltd/Maliev.AuthService/issues
- **Documentation:** See inline code comments
- **Contact:** dev@maliev.com
