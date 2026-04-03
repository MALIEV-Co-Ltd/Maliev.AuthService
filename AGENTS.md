# Maliev.AuthService - Agentic Coding Guidelines

This repository hosts the Maliev Authentication Service, a .NET 10.0 ASP.NET Core Web API using PostgreSQL and Entity Framework Core 10.0.

---

## Build, Test & Lint Commands

All commands run from within this service directory (`B:\maliev\Maliev.AuthService`).

```powershell
# Build (treats warnings as errors — all must be fixed)
dotnet build Maliev.AuthService.slnx

# Run all tests
dotnet test Maliev.AuthService.slnx --verbosity normal

# Run a single test method
dotnet test --filter "FullyQualifiedName~AuthenticationContractTests.Login_WithValidCredentials_ReturnsTokens"

# Run all tests in a class
dotnet test --filter "FullyQualifiedName~AuthenticationContractTests"

# Run with code coverage
dotnet test Maliev.AuthService.slnx --collect:"XPlat Code Coverage"

# Format check
dotnet format Maliev.AuthService.slnx

# EF Core migrations (Infrastructure project only)
dotnet ef migrations add <Name> --project Maliev.AuthService.Infrastructure --startup-project Maliev.AuthService.Infrastructure
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
dotnet ef database update --project Maliev.AuthService.Infrastructure --startup-project Maliev.AuthService.Infrastructure
```

---

## Code Style & Conventions

### Workspace Structure
```
Maliev.AuthService/
├── Maliev.AuthService.Api/           # Controllers, Middleware
├── Maliev.AuthService.Application/   # Use cases, DTOs, Interfaces, Handlers
├── Maliev.AuthService.Domain/        # Entities, value objects, domain interfaces
├── Maliev.AuthService.Infrastructure/ # EF Core DbContext, repositories, HTTP clients
├── Maliev.AuthService.Tests/         # Unit + Integration tests (xUnit)
├── Directory.Build.props             # Central package versioning
└── Maliev.AuthService.slnx          # Solution file (.slnx preferred over .sln)
```

### C# Naming & Formatting
- **Namespaces**: File-scoped (`namespace Maliev.AuthService.Domain.Entities;`)
- **Classes/Methods/Properties**: `PascalCase`
- **Private fields**: `_camelCase` (underscore prefix)
- **Parameters/locals**: `camelCase`
- **Async methods**: Suffix with `Async` (e.g., `AuthenticateAsync`)
- **Interfaces**: Prefix with `I` (e.g., `IAuthenticationService`)
- **Permissions**: GCP-style `{domain}.{plural-resource}.{action}` as `public const string` in a `Permissions` static class
  - Valid: `auth.tokens.revoke`, `auth.sessions.create`
  - Invalid: `auth.token.revoke` (singular), `auth.revoke` (missing resource)
- **XML docs**: Required on ALL public methods and properties
- **Nullable**: Enabled (`<Nullable>enable</Nullable>`). Use `?` explicitly
- **Imports**: System first, then third-party, then local. Alphabetize within groups. Remove unused `using`
- **Braces**: Allman style (new line) for methods and control structures. Expression-bodied for properties/accessors
- **Indentation**: 4 spaces, LF line endings, UTF-8, trim trailing whitespace

### C# Patterns
- **DI**: Constructor injection with `private readonly` fields
- **Controllers**: `[ApiController]`, `[ApiVersion("1")]`, `[Route("auth/v{version:apiVersion}")]`
- **Logging**: `ILogger<T>` with structured placeholders (never interpolate): `_logger.LogInformation("Processing {FileId}", fileId)`
- **Error handling**: Global exception middleware. Return `ProblemDetails` / `ErrorResponse` DTOs. Never expose stack traces
- **JSON**: Snake_case_lower for Auth service (`JsonNamingPolicy.SnakeCaseLower`)
- **Manual mapping**: Static extension methods (`ToDto()`, `ToEntity()`). AutoMapper is banned
- **Validation**: `System.ComponentModel.DataAnnotations` on DTOs. FluentValidation is banned
- **Repository Pattern**: Encapsulate data access logic in repositories (e.g., `IRefreshTokenRepository`)
- **DTOs**: Separate Request and Response models in `Models/Request` and `Models/Response`
- **Endpoints**: Prefix all endpoints with `/auth` (e.g., `/auth/v1/login`)

---

## Banned Libraries (Build Will Fail)

| Banned | Use Instead |
|--------|-------------|
| AutoMapper | Manual mapping extensions |
| FluentValidation | DataAnnotations or manual validation |
| FluentAssertions | Standard xUnit `Assert.*` |
| Swashbuckle/Swagger | Scalar (at `/auth/scalar`) |
| InMemoryDatabase (EF Core) | Testcontainers with real PostgreSQL |

---

## Testing Rules

- **Framework**: xUnit with standard `Assert` (`Assert.Equal`, `Assert.NotNull`, etc.)
- **Naming**: `MethodName_StateUnderTest_ExpectedBehavior` or `HTTP_METHOD_Path_Scenario_ExpectedStatus`
- **Coverage**: Minimum 80% per service
- **Integration tests**: `BaseIntegrationTestFactory<TProgram, TDbContext>` with Testcontainers (PostgreSQL, Redis, RabbitMQ). Never InMemoryDatabase
- **System tests** (Tier 3): `AspireTestFixture` with `[Collection("AspireDomainTests")]` — shared AppHost, never one per class
- **Eventual consistency**: Use `TestHelpers.WaitForAsync`. Never `Task.Delay`
- **MassTransit consumers**: Must have consumer tests using `AddMassTransitTestHarness()`

### Testing Strategy (4-Tier Pyramid Context)

This service's tests cover **Tier 1 (Unit)** and **Tier 2 (Service Integration)** of the Maliev testing pyramid:

| Tier | What to Test | Infrastructure |
|------|-------------|---------------|
| **Unit** | Business logic, domain models, service methods with mocked dependencies | None (mocks only) |
| **Service Integration** | API endpoints, database persistence, permission enforcement, input validation | `BaseIntegrationTestFactory` + Testcontainers (Postgres/Redis/RabbitMQ) |

**Tier 3 (System Integration)** — cross-service workflows and event chains — is tested in `Maliev.Aspire.Tests/`.

> Full ecosystem test strategy: `Maliev.Aspire.Tests/TEST_PLAN.md`

---

## Mandatory Rules

- **`TreatWarningsAsErrors = true`**: Zero warnings allowed. No suppression
- **`[RequirePermission("domain.resources.action")]`**: On all endpoints, not plain `[Authorize]`
- **API versioning**: All routes versioned (`v1/`)
- **Service prefix**: Routes prefixed with `/auth`
- **Scalar docs**: Configured at `/auth/scalar`
- **Secrets**: Never hardcoded. Use GCP Secret Manager or environment variables
- **Async/await**: All the way down. Pass `CancellationToken`
- **EF Core Design package**: Only in Infrastructure project, never in Api
- **PostgreSQL xmin**: Shadow property only — `entity.Property<uint>("xmin").HasColumnType("xid").IsRowVersion()`. Never add entity property
- **Temporary files**: Generate in `/temp` folder, clean up afterwards

---

## Agent Directives

- **Employee Auto-Provisioning**: When a Google SSO user with `@maliev.com` domain authenticates for the first time and no employee record exists, the AuthService automatically provisions a new employee via `EmployeeService` and grants the Platform Owner role to the first user. This is by design — no pre-registration is required for employees.
- **Verification**: Always run `dotnet test` after making changes to ensure no regressions.
- **Context**: Read `CLAUDE.md` for deep architectural details if needed.

---

## Git Rules

- This is an independent git repo. Run git commands from within `B:\maliev\Maliev.AuthService`
- **Commit early and often** after every meaningful unit of work. Do not accumulate changes
- **Never use `git checkout` to restore files** — commit first, then `git revert` or `git reset --soft`
- Feature branches merged to `develop` via PR. Do not push without being asked

---

## Database & EF Core — Mandatory Rules

### EF Core Design Package
- `Microsoft.EntityFrameworkCore.Design` MUST NOT be in Api projects
- It belongs ONLY in the Infrastructure project where migrations live
- Migration commands must target Infrastructure as both project and startup-project:
  ```
  dotnet ef migrations add <Name> --project Maliev.AuthService.Infrastructure --startup-project Maliev.AuthService.Infrastructure
  ```

### PostgreSQL xmin Concurrency — Mandatory Pattern
Use shadow property ONLY. Never add a Xmin/xmin property to domain entities.
```csharp
entity.Property<uint>("xmin").HasColumnType("xid").IsRowVersion();
```
- Never use `UseXminAsConcurrencyToken()` (removed in Npgsql EF v7)
- Never use entity property `public uint Xmin { get; set; }` or `public uint xmin { get; set; }`
- Never use `.Ignore(e => e.Xmin)` — remove the entity property instead
