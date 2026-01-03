# Maliev Auth Service

A production-ready JWT-based authentication service with OAuth 2.0 token rotation compliance (RFC 9700) built on .NET 10.

Role in MALIEV Architecture: Central authentication service that issues and validates JWT tokens for all users (customers, employees, services) across the MALIEV platform. Provides RSA-2048 asymmetric signing for enhanced security.

---

## Architecture

- Framework: ASP.NET Core 10.0
- Database: PostgreSQL 18
- Cache: Redis 7.x
- Messaging: RabbitMQ via MassTransit
- Authentication: RSA-2048 asymmetric signing
- Authorization: IAM integration
- API Documentation: OpenAPI + Scalar UI
- Logging: Serilog

---

## Constitution Rules

**Banned Libraries** (NOT used in this service):

- ❌ AutoMapper - Uses explicit manual mapping
- ❌ FluentValidation - Uses Data Annotations for validation
- ❌ FluentAssertions - Uses xUnit Assert.* methods
- ❌ In-memory test DB - Uses Testcontainers with real PostgreSQL

**Mandatory Practices**:

- ✅ TreatWarningsAsErrors enabled in all *.csproj files
- ✅ XML Documentation on ALL public methods, properties, and classes
- ✅ No Secrets in Code - All secrets via environment variables
- ✅ No Test Config in Program.cs - Test configuration in test fixtures only
- ✅ IAM Integration - Uses GCP-style permission naming: `auth.{resource}.{action}`

---

## Prerequisites

- .NET 10 SDK
- PostgreSQL 18
- Redis (optional)
- Docker (optional for local DB)

---

## Quick Start

### 1. Set connection string

```powershell
# Windows PowerShell
$env:ConnectionStrings__AuthDbContext="Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=YOUR_PASSWORD;"
```

```bash
# Linux/macOS
export ConnectionStrings__AuthDbContext="Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=YOUR_PASSWORD;"
```

### 2. Run migrations

```bash
 dotnet ef database update --project Maliev.AuthService.Data
```

### 3. Run the service

```bash
 dotnet run --project Maliev.AuthService.Api
```

### 4. Access API docs (OpenAPI/Scalar)

```text
http://localhost:5000/auth/scalar
```

---

## Health

- Liveness: /auth/liveness
- Readiness: /auth/readiness
- Metrics: /auth/metrics

---

## Secrets

- Do not store secrets in code. Use Google Secret Manager in production.
