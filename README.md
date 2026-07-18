# Maliev Authentication Service

[![Build Status](https://img.shields.io/badge/Build-Passing-success)](https://github.com/ORGANIZATION/Maliev.AuthService)
[![.NET Version](https://img.shields.io/badge/.NET-10.0-blue)](https://dotnet.microsoft.com/download/dotnet/10.0)
[![Database](https://img.shields.io/badge/Database-PostgreSQL%2018-blue)](https://www.postgresql.org/)

Production-ready, highly secure authentication microservice providing JWT issuance and validation with OAuth 2.0 token rotation compliance (RFC 9700).

**Role in MALIEV Architecture**: The central identity provider for the entire platform. It issues RSA-2048 signed JWT tokens for customers, employees, and internal microservices, ensuring secure communication and centralized identity management.

---

## 🏗️ Architecture & Tech Stack

- **Framework**: ASP.NET Core 10.0 (C# 13)
- **Database**: PostgreSQL 18 with Entity Framework Core 10.x
- **Distributed Cache**: Redis 7.x (Token revocation & rate limiting)
- **Messaging**: RabbitMQ via MassTransit
- **Security**: RSA-2048 Asymmetric Signing (Public/Private Key)
- **API Documentation**: OpenAPI 3.1 + Scalar UI
- **Observability**: OpenTelemetry (Metrics, Traces, Logging)

---

## ⚖️ Constitution Rules

This service strictly adheres to the platform development mandates:

### Banned Libraries
To maintain high performance and low complexity, the following are **NOT** used:
- ❌ **AutoMapper**: Explicit manual mapping only.
- ❌ **FluentValidation**: Standard Data Annotations (`[Required]`, `[EmailAddress]`) only.
- ❌ **FluentAssertions**: Standard xUnit `Assert` methods only.
- ❌ **In-memory Test DB**: All integration tests use **Testcontainers** with real PostgreSQL 18.

### Mandatory Practices
- ✅ **TreatWarningsAsErrors**: Enabled in all `.csproj` files.
- ✅ **XML Documentation**: Required on all public methods and properties.
- ✅ **No Secrets in Code**: All sensitive configuration injected via environment variables.
- ✅ **No Test Config in Program.cs**: Test configuration in test fixtures only.
- ✅ **IAM Integration**: Self-registers permissions with the IAM Service using GCP-style naming: `{service}.{resource}.{action}`.

---

## ✨ Key Features

- **RSA-2048 Asymmetric Signing**: Higher security than symmetric keys; services only need the public key to validate tokens.
- **RFC 9700 Compliance**: Automatic refresh token rotation with built-in reuse detection to prevent theft.
- **Dual User Contexts**: Specialized authentication flows for both public Customers and internal Employees.
- **Service-to-Service Auth**: Secure machine-to-machine authentication for microservices.
- **Token Revocation**: Global logout capability by revoking token families in Redis.
- **Rate Limiting**: Protection against brute-force attacks on login endpoints.

---

## 🚀 Quick Start

### Prerequisites
- .NET 10.0 SDK
- Docker Desktop (for infrastructure)
- PostgreSQL 18 (Alpine)

### Local Development Setup

1. **Clone the repository**
```bash
git clone https://github.com/ORGANIZATION/Maliev.AuthService.git
cd Maliev.AuthService
```

2. **Spin up Infrastructure**
```bash
docker run --name auth-db -e POSTGRES_PASSWORD=YOUR_PASSWORD -p 5432:5432 -d postgres:18-alpine
docker run --name auth-redis -p 6379:6379 -d redis:7-alpine
```

3. **Configure Environment**
```powershell
# Windows PowerShell
$env:ConnectionStrings__AuthDbContext="YOUR_POSTGRES_CONNECTION_STRING"
$env:ConnectionStrings__Cache="YOUR_REDIS_CONNECTION_STRING"
```

4. **Apply Migrations & Run**
```bash
dotnet ef database update --project Maliev.AuthService.Data
dotnet run --project Maliev.AuthService.Api
```

The service will be available at `http://localhost:5000/auth`. Access the interactive documentation at `http://localhost:5000/auth/scalar`.

---

## 📡 API Endpoints

All endpoints are prefixed with `/auth/v1/`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/login` | Authenticate and receive JWT + Refresh Token |
| POST | `/refresh` | Exchange refresh token for new pair (Rotation) |
| POST | `/logout` | Revoke current refresh token family |
| POST | `/validate` | Validate an existing JWT (Internal use) |
| GET | `/me` | Get current authenticated user details |

---

## 🏥 Health & Monitoring

Standardized health probes for Kubernetes orchestration:
- **Liveness**: `GET /auth/liveness`
- **Readiness**: `GET /auth/readiness` (Checks DB and Redis connectivity)
- **Metrics**: `GET /auth/metrics` (Prometheus format)

---

## 🧪 Testing

We prioritize reliable tests over mock-heavy unit tests.

```bash
# Run all tests using Testcontainers
dotnet test --verbosity normal
```

- **Integration Tests**: Use real PostgreSQL 18 containers.
- **Contract Tests**: Ensure API stability for consumers.

---

## 📦 Deployment

Infrastructure management is handled via GitOps patterns.

- **Docker Image**: `REGION-docker.pkg.dev/PROJECT_ID/REPOSITORY/maliev-auth-service:{sha}`
- **Environments**: Development, Staging, Production

---

## Validation and Release Boundary

GitHub Actions validates pull requests, `main`, `develop`, and `release/v*`
tags by restoring and auditing dependencies, building the solution, and running
the complete test suite.

No workflow in this repository publishes container images, authenticates to
Google Cloud, modifies GitOps, or deploys to Kubernetes. Release promotion is
separate and remains pending Aspire owner review. This validation boundary does
not authorize or perform a production cutover.

---

## 📄 License

Proprietary - © 2025 MALIEV Co., Ltd. All rights reserved.
