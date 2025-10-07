# Maliev.AuthService - CLAUDE.md

This file provides guidance to Claude Code when working with the Maliev Authentication Service.

## Project Overview

JWT token-based authentication service for Maliev microservices architecture. Provides secure authentication, token generation, validation, and refresh with OAuth 2.0 RFC 9700 compliance.

### Key Features
- **RSA-2048 Asymmetric Signing**: Public/private key JWT signing
- **OAuth 2.0 RFC 9700**: Automatic refresh token rotation with reuse detection
- **Dual User Types**: Customer and employee authentication with external validation
- **Multi-Layer Security**: Account lockout, IP rate limiting, progressive delays
- **Service-to-Service Auth**: Dedicated authentication flow for microservices
- **Token Lifecycle Management**: Generation, validation, refresh, revocation with audit logging

### Technology Stack
- **.NET 9.0**: ASP.NET Core Web API
- **PostgreSQL**: Primary database with Entity Framework Core 9.0
- **Google Secret Manager**: RSA key storage (production)
- **Serilog**: Structured logging
- **FluentValidation**: Request validation
- **MSTest**: Testing framework with FluentAssertions

## Project Structure

```
Maliev.AuthService/
├── Maliev.AuthService.Api/          # Web API
│   ├── Controllers/                 # AuthenticationController
│   ├── Services/                    # TokenGenerator, TokenValidator, etc.
│   ├── Validators/                  # FluentValidation validators
│   ├── Models/Request/              # Request DTOs
│   ├── Models/Response/             # Response DTOs
│   ├── Middleware/                  # Correlation ID, Exception handling
│   └── Program.cs                   # Application entry point
├── Maliev.AuthService.Data/         # Data layer
│   ├── DbContexts/                  # AuthDbContext
│   ├── Entities/                    # 7 database entities
│   ├── Configurations/              # EF Core configurations
│   ├── Repositories/                # Repository pattern
│   └── Migrations/                  # EF Core migrations
└── Maliev.AuthService.Tests/        # Tests
    ├── Contract/                    # API contract tests
    └── Integration/                 # Integration tests
```

## Database Schema

7 entities managed by Entity Framework Core:

1. **RefreshToken** - Hashed refresh tokens with family tracking
2. **TokenFamily** - Token rotation lineage (OAuth 2.0 RFC 9700)
3. **RevokedAccessToken** - Revoked access tokens (JTI tracking)
4. **AccountLockout** - Failed login attempt tracking
5. **IpRateLimit** - IP-based rate limiting
6. **AuthAuditLog** - Comprehensive audit trail
7. **ServiceCredential** - Service-to-service authentication

## Common Commands

### Build and Test
```powershell
# Build solution
dotnet build Maliev.AuthService.sln

# Run tests (27 tests)
dotnet test Maliev.AuthService.sln --verbosity normal

# Run specific test project
dotnet test Maliev.AuthService.Tests --verbosity normal
```

### Database Migrations
```powershell
# Port forward to PostgreSQL pod (MUST use pod, not service)
kubectl port-forward -n maliev-dev postgres-cluster-1 5432:5432

# Set connection string environment variable
$env:AuthDbContext="Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=<password>;"

# Create migration
dotnet ef migrations add MigrationName --project Maliev.AuthService.Data

# Apply migration
dotnet ef database update --project Maliev.AuthService.Data

# Rollback migration
dotnet ef database update PreviousMigrationName --project Maliev.AuthService.Data
```

### Local Development
```powershell
# Run API locally (uses appsettings.Development.json)
dotnet run --project Maliev.AuthService.Api

# Access Swagger UI (dev/staging only)
# http://localhost:5000/auth/swagger

# Test health checks
curl http://localhost:5000/auth/liveness
curl http://localhost:5000/auth/readiness
```

## API Endpoints

All endpoints are prefixed with `/auth` (configured via `UsePathBase("/auth")`):

- `POST /auth/v1/login` - Customer/employee login
- `POST /auth/v1/service/login` - Service authentication
- `POST /auth/v1/refresh` - Refresh access token (with rotation)
- `POST /auth/v1/validate` - Validate access token
- `POST /auth/v1/revoke` - Revoke access token
- `POST /auth/v1/logout` - Logout and revoke all tokens
- `GET /auth/liveness` - Liveness probe
- `GET /auth/readiness` - Readiness probe (DB health check)
- `GET /auth/swagger` - Swagger UI (dev/staging only)

## Configuration

### Required Secrets (Google Secret Manager)
```
Jwt:PrivateKey - Base64-encoded RSA-2048 private key (PEM format)
Jwt:PublicKey  - Base64-encoded RSA-2048 public key (PEM format)
ConnectionStrings:AuthDbContext - PostgreSQL connection string
```

### Environment Variables
```
AuthDbContext="Server=localhost;Port=5432;Database=auth_app_db;..."
Jwt:Issuer="https://dev.api.maliev.com/auth"
Jwt:Audience="https://dev.api.maliev.com"
ExternalServices:CustomerService:BaseUrl="http://localhost:5001"
ExternalServices:EmployeeService:BaseUrl="http://localhost:5002"
```

### appsettings Files
- `appsettings.json` - Production settings (no secrets)
- `appsettings.Development.json` - Local development overrides
- `appsettings.Testing.json` - Test configuration with test RSA keys

## Security Implementation

### Token Flow
1. **Login**: Validate credentials → Generate access token (15min) + refresh token (7 days)
2. **Refresh**: Validate refresh token → Rotate to new refresh token → Issue new access token
3. **Reuse Detection**: If old refresh token is reused → Invalidate entire token family
4. **Revocation**: Mark access token JTI in RevokedAccessToken table

### Rate Limiting
- Account lockout: 5 failed attempts in 15 minutes
- IP rate limiting: 20 requests per 15 minutes
- Progressive delays on failed attempts

### Cryptography
- **RSA-2048**: Asymmetric signing (private key signs, public key verifies)
- **SHA-256**: Refresh token hashing (stored as hash, not plaintext)
- **Constant-time comparison**: Protection against timing attacks

## Testing

### Test Coverage
27 tests across 7 test suites (100% pass rate):
- Authentication Contract Tests (6 tests)
- Service Login Contract Tests (4 tests)
- Token Refresh Contract Tests (5 tests)
- Token Validation Contract Tests (5 tests)
- Token Revocation Contract Tests (3 tests)
- Logout Contract Tests (3 tests)
- Health Check Contract Tests (2 tests)

### Running Tests
```powershell
# Run all tests
dotnet test Maliev.AuthService.sln --verbosity normal

# Run with coverage
dotnet test Maliev.AuthService.sln --collect:"XPlat Code Coverage"

# Run specific test class
dotnet test --filter "FullyQualifiedName~AuthenticationContractTests"
```

## Kubernetes Deployment

### Port Forwarding
```powershell
# Forward to service
kubectl port-forward -n maliev-dev svc/maliev-auth-service 8080:8080

# Forward to PostgreSQL (for migrations)
kubectl port-forward -n maliev-dev postgres-cluster-1 5432:5432
```

### Logs
```powershell
# Tail logs
kubectl logs -f deployment/maliev-auth-service -n maliev-dev

# Get pod status
kubectl get pods -n maliev-dev | grep auth-service
```

## Common Issues

### Issue: Tests fail with "Database connection string not configured"
**Solution**: Tests use in-memory database. Ensure `IsEnvironment("Testing")` check in Program.cs.

### Issue: Migration fails with "AuthDbContext environment variable not set"
**Solution**: Set environment variable before running `dotnet ef database update`:
```powershell
$env:AuthDbContext="Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=<password>;"
```

### Issue: Swagger UI returns 404
**Solution**: Swagger is disabled in production. Check environment is Development or Staging.

### Issue: All token validations fail
**Solution**: Ensure RSA keys are correctly configured in Google Secret Manager and match public/private key pair.

## Development Guidelines

### Adding New Endpoints
1. Create request/response models in `Models/`
2. Add validator in `Validators/`
3. Implement service logic in `Services/`
4. Add controller action in `Controllers/AuthenticationController.cs`
5. Write contract tests in `Tests/Contract/`
6. Update API documentation in README.md

### Adding New Database Entities
1. Create entity class in `Data/Entities/`
2. Add EF Core configuration in `Data/Configurations/`
3. Update `AuthDbContext.cs` with DbSet
4. Create migration: `dotnet ef migrations add EntityName --project Maliev.AuthService.Data`
5. Apply migration: `dotnet ef database update --project Maliev.AuthService.Data`

### Code Style
- Follow .NET naming conventions
- Use async/await for all I/O operations
- Implement repository pattern for data access
- Use dependency injection for all services
- Add XML documentation comments for public APIs
- Include structured logging with correlation IDs

## CI/CD

Service uses GitHub Actions workflows:
- `ci-develop.yml` - Deploy to development environment
- `ci-staging.yml` - Deploy to staging environment
- `ci-main.yml` - Deploy to production environment

Deployments are managed via GitOps (ArgoCD) in the `maliev-gitops` repository.
