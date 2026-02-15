# Maliev.AuthService - Agentic Coding Guidelines

This repository hosts the Maliev Authentication Service, a .NET 9.0 ASP.NET Core Web API using PostgreSQL and Entity Framework Core 9.0.

## 1. Build & Test Commands

### Build
```powershell
dotnet build Maliev.AuthService.slnx
```

### Testing
Run all tests:
```powershell
dotnet test Maliev.AuthService.slnx --verbosity normal
```

Run a specific test suite (by class name):
```powershell
dotnet test --filter "FullyQualifiedName~AuthenticationContractTests"
```

Run a single test method:
```powershell
dotnet test --filter "FullyQualifiedName~AuthenticationContractTests.Login_WithValidCredentials_ReturnsTokens"
```

Run tests with coverage:
```powershell
dotnet test Maliev.AuthService.slnx --collect:"XPlat Code Coverage"
```

### Database Migrations
Port forward PostgreSQL (if needed):
```powershell
kubectl port-forward -n maliev-dev postgres-cluster-1 5432:5432
```
Set connection string:
```powershell
$env:AuthDbContext="Server=localhost;Port=5432;Database=auth_app_db;User Id=postgres;Password=<password>;"
```
Apply migrations:
```powershell
dotnet ef database update --project Maliev.AuthService.Data
```

## 2. Code Style & Conventions

### Structure & Naming
- **Framework**: .NET 9.0. Follow standard C#/.NET naming conventions (PascalCase for classes/methods, camelCase for local variables).
- **Architecture**:
  - `Maliev.AuthService.Api`: Controllers, Middleware, Validators.
  - `Maliev.AuthService.Data`: EF Core entities, repositories, migrations.
  - `Maliev.AuthService.Tests`: MSTest contract and integration tests.
- **Async/Await**: Use `async`/`await` for all I/O bound operations. Avoid `.Result` or `.Wait()`.
- **Dependency Injection**: Use constructor injection for all services.

### Coding Patterns
- **Repository Pattern**: Encapsulate data access logic in repositories (e.g., `IRefreshTokenRepository`).
- **Validation**: Use `FluentValidation` for request models. Validators reside in `Maliev.AuthService.Api/Validators`.
- **Logging**: Use Serilog for structured logging. Ensure correlation IDs are logged.
- **Endpoints**: Prefix all endpoints with `/auth` (e.g., `/auth/v1/login`).
- **DTOs**: Separate Request and Response models in `Models/Request` and `Models/Response`.

### Error Handling
- Use global exception handling middleware.
- Return standard HTTP status codes (200 OK, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 500 Internal Error).
- Do not expose sensitive stack traces in production responses.

### Testing Guidelines
- **Framework**: MSTest with `FluentAssertions`.
- **Scope**: Maintain high coverage (aim for 100% on contract/logic).
- **Environment**: Tests run against an in-memory database or mocked dependencies unless strictly integration tests.
- **Naming**: `MethodName_StateUnderWhich_ExpectedBehavior`.

## 3. Agent Directives
- **Safety**: Do not commit secrets/keys. Use Google Secret Manager or environment variables.
- **Verification**: Always run `dotnet test` after making changes to ensure no regressions.
- **Context**: Read `CLAUDE.md` for deep architectural details if needed.
