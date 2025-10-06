# Google Secret Manager Setup Guide

Complete guide for setting up secrets for the Auth Service in Google Secret Manager.

## Prerequisites

```bash
# Install OpenSSL (if not already installed)
# Windows: Download from https://slproweb.com/products/Win32OpenSSL.html
# macOS: brew install openssl
# Linux: apt-get install openssl

# Install Google Cloud SDK
# https://cloud.google.com/sdk/docs/install

# Authenticate with GCP
gcloud auth login

# Set project
gcloud config set project maliev-website
```

---

## 1. Generate ECDSA P-256 Private Key for JWT Signing

### Important: Use P-256 Curve (NOT secp256k1)

The service uses **ES256** algorithm which requires **P-256 (secp256r1)** curve, not secp256k1.

```bash
# Generate ECDSA P-256 private key
openssl ecparam -name prime256v1 -genkey -noout -out jwt-private-key.pem

# Verify the curve is P-256
openssl ec -in jwt-private-key.pem -text -noout | grep "ASN1 OID"
# Should output: ASN1 OID: prime256v1
# ✅ Correct: prime256v1 (P-256)
# ❌ Wrong: secp256k1 (K-256 - Bitcoin curve)

# View the private key content
cat jwt-private-key.pem
```

**Expected output:**
```
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIH+1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO
PQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890+/=
-----END EC PRIVATE KEY-----
```

### Extract Public Key (for other services)

```bash
# Extract public key
openssl ec -in jwt-private-key.pem -pubout -out jwt-public-key.pem

# View public key
cat jwt-public-key.pem
```

---

## 2. Upload Secrets to Google Secret Manager

### 2.1. JWT Security Key (Private Key PEM)

```bash
# Create secret with ENTIRE PEM file content (including BEGIN/END markers)
gcloud secrets create maliev-auth-jwt-security-key \
  --data-file=jwt-private-key.pem \
  --replication-policy=automatic \
  --project=maliev-website

# Verify secret created
gcloud secrets describe maliev-auth-jwt-security-key --project=maliev-website

# View secret content (for verification)
gcloud secrets versions access latest --secret=maliev-auth-jwt-security-key --project=maliev-website
```

**Secret Name:** `maliev-auth-jwt-security-key`
**Environment Variable:** `Jwt__SecurityKey`
**Content:** Full PEM file (multi-line text with BEGIN/END markers)

### 2.2. JWT Issuer

```bash
# Create JWT issuer secret
echo -n "maliev-dev" | gcloud secrets create maliev-auth-jwt-issuer \
  --data-file=- \
  --replication-policy=automatic \
  --project=maliev-website
```

**Secret Name:** `maliev-auth-jwt-issuer`
**Environment Variable:** `Jwt__Issuer`
**Content:** `maliev-dev`

### 2.3. JWT Audience

```bash
# Create JWT audience secret
echo -n "maliev-dev" | gcloud secrets create maliev-auth-jwt-audience \
  --data-file=- \
  --replication-policy=automatic \
  --project=maliev-website
```

**Secret Name:** `maliev-auth-jwt-audience`
**Environment Variable:** `Jwt__Audience`
**Content:** `maliev-dev`

### 2.4. Database Connection String

```bash
# Get PostgreSQL password from existing secret
kubectl get secret postgres-cluster-app -n maliev-dev -o jsonpath='{.data.password}' | base64 -d

# Create database connection string secret (replace PASSWORD with actual password)
echo -n "Server=postgres-cluster-rw.maliev-dev.svc.cluster.local;Port=5432;Database=auth_app_db;User Id=postgres;Password=YOUR_PASSWORD;" | \
  gcloud secrets create maliev-auth-db-connection-string \
    --data-file=- \
    --replication-policy=automatic \
    --project=maliev-website
```

**Secret Name:** `maliev-auth-db-connection-string`
**Environment Variable:** `ConnectionStrings__RefreshTokenDbContext`
**Content:** PostgreSQL connection string

### 2.5. Customer Service Validation Endpoint

```bash
# Create customer service endpoint secret
echo -n "http://maliev-customer-service.maliev-dev.svc.cluster.local:8080/customers/v1/validate" | \
  gcloud secrets create maliev-auth-customer-service-endpoint \
    --data-file=- \
    --replication-policy=automatic \
    --project=maliev-website
```

**Secret Name:** `maliev-auth-customer-service-endpoint`
**Environment Variable:** `CustomerService__ValidationEndpoint`
**Content:** Customer service validation URL

### 2.6. Employee Service Validation Endpoint

```bash
# Create employee service endpoint secret
echo -n "http://maliev-employee-service.maliev-dev.svc.cluster.local:8080/employees/v1/validate" | \
  gcloud secrets create maliev-auth-employee-service-endpoint \
    --data-file=- \
    --replication-policy=automatic \
    --project=maliev-website
```

**Secret Name:** `maliev-auth-employee-service-endpoint`
**Environment Variable:** `EmployeeService__ValidationEndpoint`
**Content:** Employee service validation URL

---

## 3. Configure External Secrets Operator

Create `ExternalSecret` resource in Kubernetes to sync secrets from Google Secret Manager.

### 3.1. Create ExternalSecret Manifest

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
    # JWT Configuration
    - secretKey: Jwt__SecurityKey
      remoteRef:
        key: maliev-auth-jwt-security-key

    - secretKey: Jwt__Issuer
      remoteRef:
        key: maliev-auth-jwt-issuer

    - secretKey: Jwt__Audience
      remoteRef:
        key: maliev-auth-jwt-audience

    # Database Configuration
    - secretKey: ConnectionStrings__RefreshTokenDbContext
      remoteRef:
        key: maliev-auth-db-connection-string

    # External Services
    - secretKey: CustomerService__ValidationEndpoint
      remoteRef:
        key: maliev-auth-customer-service-endpoint

    - secretKey: EmployeeService__ValidationEndpoint
      remoteRef:
        key: maliev-auth-employee-service-endpoint
```

### 3.2. Apply ExternalSecret

```bash
# Apply the ExternalSecret manifest
kubectl apply -f maliev-gitops/3-apps/auth-service/base/external-secret.yaml

# Verify ExternalSecret synced
kubectl get externalsecret maliev-auth-secrets -n maliev-dev

# Check Kubernetes secret created
kubectl get secret maliev-auth-secrets -n maliev-dev

# View secret keys (not values)
kubectl describe secret maliev-auth-secrets -n maliev-dev
```

**Expected output:**
```
Name:         maliev-auth-secrets
Namespace:    maliev-dev
Type:         Opaque

Data
====
ConnectionStrings__RefreshTokenDbContext:  XXX bytes
CustomerService__ValidationEndpoint:       XXX bytes
EmployeeService__ValidationEndpoint:       XXX bytes
Jwt__Audience:                             XXX bytes
Jwt__Issuer:                               XXX bytes
Jwt__SecurityKey:                          XXX bytes
```

---

## 4. Verify Secret Content

### 4.1. Verify JWT Private Key Format

```bash
# Get the JWT SecurityKey from Kubernetes secret
kubectl get secret maliev-auth-secrets -n maliev-dev -o jsonpath='{.data.Jwt__SecurityKey}' | base64 -d

# Should output PEM format:
# -----BEGIN EC PRIVATE KEY-----
# MHcCAQEE...
# -----END EC PRIVATE KEY-----
```

### 4.2. Verify Connection String

```bash
# Get connection string
kubectl get secret maliev-auth-secrets -n maliev-dev -o jsonpath='{.data.ConnectionStrings__RefreshTokenDbContext}' | base64 -d

# Should output:
# Server=postgres-cluster-rw.maliev-dev.svc.cluster.local;Port=5432;Database=auth_app_db;User Id=postgres;Password=...;
```

### 4.3. Verify Service Endpoints

```bash
# Get customer service endpoint
kubectl get secret maliev-auth-secrets -n maliev-dev -o jsonpath='{.data.CustomerService__ValidationEndpoint}' | base64 -d

# Should output:
# http://maliev-customer-service.maliev-dev.svc.cluster.local:8080/customers/v1/validate

# Get employee service endpoint
kubectl get secret maliev-auth-secrets -n maliev-dev -o jsonpath='{.data.EmployeeService__ValidationEndpoint}' | base64 -d

# Should output:
# http://maliev-employee-service.maliev-dev.svc.cluster.local:8080/employees/v1/validate
```

---

## 5. Security Best Practices

### 5.1. Delete Local Key Files

```bash
# CRITICAL: Securely delete local private key files after upload
shred -u jwt-private-key.pem jwt-public-key.pem

# On Windows (use SDelete from Sysinternals):
# sdelete -p 7 jwt-private-key.pem
```

### 5.2. Rotate Keys Regularly

```bash
# Generate new key
openssl ecparam -name prime256v1 -genkey -noout -out jwt-private-key-new.pem

# Create new secret version
gcloud secrets versions add maliev-auth-jwt-security-key \
  --data-file=jwt-private-key-new.pem

# Old version automatically disabled after new version deployed
# Deployment will pick up new key on restart
```

### 5.3. Access Control

```bash
# Grant Auth Service service account access to secrets
gcloud secrets add-iam-policy-binding maliev-auth-jwt-security-key \
  --member="serviceAccount:maliev-auth-service@maliev-website.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Repeat for all secrets
for SECRET in maliev-auth-jwt-issuer maliev-auth-jwt-audience maliev-auth-db-connection-string maliev-auth-customer-service-endpoint maliev-auth-employee-service-endpoint
do
  gcloud secrets add-iam-policy-binding $SECRET \
    --member="serviceAccount:maliev-auth-service@maliev-website.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
done
```

---

## 6. Troubleshooting

### Secret Not Syncing

```bash
# Check ExternalSecret status
kubectl describe externalsecret maliev-auth-secrets -n maliev-dev

# Check External Secrets Operator logs
kubectl logs -n external-secrets-system deployment/external-secrets

# Common issues:
# 1. ClusterSecretStore not configured
# 2. Service account lacks secretAccessor role
# 3. Secret name typo in ExternalSecret manifest
```

### Invalid JWT Key Format

```bash
# Verify key is valid ECDSA P-256
openssl ec -in jwt-private-key.pem -text -noout

# Should show:
# Private-Key: (256 bit)
# ASN1 OID: prime256v1

# If shows secp256k1: Regenerate with prime256v1 curve
```

### Pod Cannot Read Secrets

```bash
# Check if secret is mounted in pod
kubectl exec -it deployment/maliev-auth-service -n maliev-dev -- env | grep Jwt__

# Should show:
# Jwt__SecurityKey=-----BEGIN EC PRIVATE KEY-----...
# Jwt__Issuer=maliev-dev
# Jwt__Audience=maliev-dev

# If not shown:
# 1. Check deployment.yaml has envFrom.secretRef
# 2. Check secret exists: kubectl get secret maliev-auth-secrets -n maliev-dev
```

---

## 7. Summary

**Secrets Required:**

| Secret Name | Environment Variable | Purpose |
|-------------|---------------------|---------|
| `maliev-auth-jwt-security-key` | `Jwt__SecurityKey` | ECDSA P-256 private key (PEM format) |
| `maliev-auth-jwt-issuer` | `Jwt__Issuer` | JWT issuer claim (`maliev-dev`) |
| `maliev-auth-jwt-audience` | `Jwt__Audience` | JWT audience claim (`maliev-dev`) |
| `maliev-auth-db-connection-string` | `ConnectionStrings__RefreshTokenDbContext` | PostgreSQL connection string |
| `maliev-auth-customer-service-endpoint` | `CustomerService__ValidationEndpoint` | Customer service validation URL |
| `maliev-auth-employee-service-endpoint` | `EmployeeService__ValidationEndpoint` | Employee service validation URL |

**Quick Verification:**

```bash
# List all auth service secrets
gcloud secrets list --filter="name~maliev-auth" --project=maliev-website

# Verify ExternalSecret synced
kubectl get externalsecret maliev-auth-secrets -n maliev-dev -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
# Should output: True

# Verify pod can access secrets
kubectl exec deployment/maliev-auth-service -n maliev-dev -- env | grep -E '(Jwt__|ConnectionStrings__|CustomerService__|EmployeeService__)'
```

---

## Support

For issues with secret setup:
- **External Secrets Operator:** https://external-secrets.io/latest/
- **Google Secret Manager:** https://cloud.google.com/secret-manager/docs
- **OpenSSL ECDSA:** https://www.openssl.org/docs/man1.1.1/man1/openssl-ec.html

**Emergency Rollback:** Revert to previous secret version:
```bash
gcloud secrets versions disable latest --secret=maliev-auth-jwt-security-key
gcloud secrets versions enable PREVIOUS_VERSION --secret=maliev-auth-jwt-security-key
kubectl rollout restart deployment/maliev-auth-service -n maliev-dev
```
