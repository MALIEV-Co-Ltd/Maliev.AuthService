# Maliev.AuthService - Agentic Coding Guidelines

This repository hosts the Maliev Authentication Service, a .NET 10.0 ASP.NET Core Web API using PostgreSQL and Entity Framework Core 10.0.

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
dotnet ef database update --project Maliev.AuthService.Infrastructure --startup-project Maliev.AuthService.Api
```

## 2. Code Style & Conventions

### Structure & Naming
- **Framework**: .NET 10.0. Follow standard C#/.NET naming conventions (PascalCase for classes/methods, camelCase for local variables).
- **Architecture**:
  - `Maliev.AuthService.Api`: Controllers, Middleware.
  - `Maliev.AuthService.Application`: Use cases, handlers.
  - `Maliev.AuthService.Domain`: Entities, interfaces.
  - `Maliev.AuthService.Infrastructure`: EF Core, repositories.
  - `Maliev.AuthService.Tests`: xUnit integration tests.
- **Async/Await**: Use `async`/`await` for all I/O bound operations. Avoid `.Result` or `.Wait()`.
- **Dependency Injection**: Use constructor injection for all services.

### Coding Patterns
- **Repository Pattern**: Encapsulate data access logic in repositories (e.g., `IRefreshTokenRepository`).
- **Validation**: Use Data Annotations (`[Required]`, `[EmailAddress]`) on DTOs.
- **Logging**: Use `ILogger` with source-generated logging. Ensure correlation IDs are logged.
- **Endpoints**: Prefix all endpoints with `/auth` (e.g., `/auth/v1/login`).
- **DTOs**: Separate Request and Response models in `Models/Request` and `Models/Response`.

### Error Handling
- Use global exception handling middleware.
- Return standard HTTP status codes (200 OK, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 500 Internal Error).
- Do not expose sensitive stack traces in production responses.

### Testing Guidelines
- **Framework**: xUnit with standard `Assert`.
- **Scope**: Maintain high coverage (aim for 80%+).
- **Environment**: Use Testcontainers (PostgreSQL) for integration tests.
- **Naming**: `MethodName_StateUnderWhich_ExpectedBehavior`.

### Dependencies
- **EF Core Design-Time Packages**: Only `Microsoft.EntityFrameworkCore.Design` (or similar design-time packages) may exist in the Infrastructure project where migrations are located. The API project and other projects must NOT reference EF Core design-time packages. This ensures migrations are only managed from a single location.

## 3. Agent Directives
- **EF Core Restriction**: Never add EF Core design-time packages (e.g., `Microsoft.EntityFrameworkCore.Design`) to any project except the Infrastructure project where migrations are located. This rule is enforced; any PR with design-time packages in other projects must be rejected.
- **Safety**: Do not commit secrets/keys. Use Google Secret Manager or environment variables.
- **Verification**: Always run `dotnet test` after making changes to ensure no regressions.
- **Context**: Read `CLAUDE.md` for deep architectural details if needed.


## Database & EF Core — Mandatory Rules

### EF Core Design Package
- ❌ `Microsoft.EntityFrameworkCore.Design` MUST NOT be in Api projects
- ✅ It belongs ONLY in the Infrastructure (or Data) project where migrations live
- Migration commands must target Infrastructure, not Api:
  ```
  dotnet ef migrations add <Name> --project Maliev.<Domain>Service.Infrastructure --startup-project ../Maliev.<Domain>Service.Api
  ```

### PostgreSQL xmin Concurrency — Mandatory Pattern
Use shadow property ONLY. Never add a Xmin/xmin property to domain entities.
```csharp
entity.Property<uint>("xmin").HasColumnType("xid").IsRowVersion();
```
- ❌ Never use `UseXminAsConcurrencyToken()` (removed in Npgsql EF v7)
- ❌ Never use entity property `public uint Xmin { get; set; }` or `public uint xmin { get; set; }`
- ❌ Never use `.Ignore(e => e.Xmin)` — remove the entity property instead
