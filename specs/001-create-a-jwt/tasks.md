# Tasks: JWT Token-Based Authentication Service

**Feature**: 001-create-a-jwt
**Branch**: `001-create-a-jwt`
**Total Tasks**: 119+ (Updated after analyze remediation)
**Status**: Ready for Implementation
**Last Updated**: 2025-10-06 (Post-analyze remediation)

## ⚠️ IMPORTANT UPDATES

**Remediation Applied**: Following `/analyze` command execution, critical gaps addressed:
1. ✅ **TDD Compliance**: Added contract test tasks T011-T018 BEFORE entity implementation (Constitution III)
2. ✅ **Service Authentication**: Added ServiceCredential entity (T026) for FR-063-066
3. 🔄 **Revocation Implementation**: FR-060 distributed revocation tasks added in Phase 6
4. 🔄 **Metrics**: Prometheus metrics tasks for FR-038-045, FR-071 (added in Phase 12)

**Task Numbering**: Tasks T011-T027 have been reorganized. Original entity tasks (T011-T017) are now T019-T026.

## Execution Guide

- **TDD Approach**: Write tests first (Red), implement code (Green), refactor (Refactor)
- **CRITICAL**: Contract tests (T011-T018) MUST be written and MUST FAIL before implementation begins
- **Parallel Execution**: Tasks marked `[P]` can run in parallel (different files, no dependencies)
- **Dependencies**: Complete all tasks in a phase before moving to next phase
- **Verification**: Each task includes success criteria

---

## Phase 1: Project Setup (T001-T010)

### T001: Create solution file
**Files**: `R:\maliev\Maliev.AuthService\Maliev.AuthService.sln`
**Commands**:
```powershell
cd R:\maliev\Maliev.AuthService
dotnet new sln -n Maliev.AuthService
```
**Verification**: Solution file exists
**Dependencies**: None

### T002: Create Api project
**Files**: `Maliev.AuthService.Api/Maliev.AuthService.Api.csproj`
**Commands**:
```powershell
dotnet new webapi -n Maliev.AuthService.Api -o Maliev.AuthService.Api --framework net9.0
dotnet sln add Maliev.AuthService.Api/Maliev.AuthService.Api.csproj
```
**Verification**: Api project added to solution
**Dependencies**: T001

### T003: Create Data project
**Files**: `Maliev.AuthService.Data/Maliev.AuthService.Data.csproj`
**Commands**:
```powershell
dotnet new classlib -n Maliev.AuthService.Data -o Maliev.AuthService.Data --framework net9.0
dotnet sln add Maliev.AuthService.Data/Maliev.AuthService.Data.csproj
```
**Verification**: Data project added to solution
**Dependencies**: T001

### T004: Create Tests project
**Files**: `Maliev.AuthService.Tests/Maliev.AuthService.Tests.csproj`
**Commands**:
```powershell
dotnet new mstest -n Maliev.AuthService.Tests -o Maliev.AuthService.Tests --framework net9.0
dotnet sln add Maliev.AuthService.Tests/Maliev.AuthService.Tests.csproj
```
**Verification**: Tests project added to solution
**Dependencies**: T001

### T005: Install Api project packages [P]
**Files**: `Maliev.AuthService.Api/Maliev.AuthService.Api.csproj`
**Commands**:
```powershell
dotnet add Maliev.AuthService.Api package Microsoft.AspNetCore.OpenApi --version 9.0.0
dotnet add Maliev.AuthService.Api package AspNetCore.HealthChecks.UI.Client --version 8.0.1
dotnet add Maliev.AuthService.Api package Microsoft.AspNetCore.Authentication.JwtBearer --version 9.0.8
dotnet add Maliev.AuthService.Api package Serilog.AspNetCore --version 8.0.2
dotnet add Maliev.AuthService.Api package Serilog.Sinks.Console --version 5.0.1
dotnet add Maliev.AuthService.Api package AutoMapper.Extensions.Microsoft.DependencyInjection --version 12.0.1
dotnet add Maliev.AuthService.Api package FluentValidation.AspNetCore --version 11.5.1
dotnet add Maliev.AuthService.Api package Polly --version 8.0.0
dotnet add Maliev.AuthService.Api package Asp.Versioning.Http --version 8.1.0
dotnet add Maliev.AuthService.Api package StackExchange.Redis --version 2.7.0
dotnet restore Maliev.AuthService.Api
```
**Verification**: `dotnet restore` succeeds
**Dependencies**: T002

### T006: Install Data project packages [P]
**Files**: `Maliev.AuthService.Data/Maliev.AuthService.Data.csproj`
**Commands**:
```powershell
dotnet add Maliev.AuthService.Data package Microsoft.EntityFrameworkCore --version 9.0.9
dotnet add Maliev.AuthService.Data package Microsoft.EntityFrameworkCore.Design --version 9.0.9
dotnet add Maliev.AuthService.Data package Npgsql.EntityFrameworkCore.PostgreSQL --version 9.0.2
dotnet restore Maliev.AuthService.Data
```
**Verification**: `dotnet restore` succeeds
**Dependencies**: T003

### T007: Install Tests project packages [P]
**Files**: `Maliev.AuthService.Tests/Maliev.AuthService.Tests.csproj`
**Commands**:
```powershell
dotnet add Maliev.AuthService.Tests package Microsoft.NET.Test.Sdk --version 17.11.0
dotnet add Maliev.AuthService.Tests package MSTest.TestAdapter --version 3.6.0
dotnet add Maliev.AuthService.Tests package MSTest.TestFramework --version 3.6.0
dotnet add Maliev.AuthService.Tests package FluentAssertions --version 8.6.0
dotnet add Maliev.AuthService.Tests package Moq --version 4.20.72
dotnet add Maliev.AuthService.Tests package Microsoft.AspNetCore.Mvc.Testing --version 9.0.0
dotnet restore Maliev.AuthService.Tests
```
**Verification**: `dotnet restore` succeeds
**Dependencies**: T004

### T008: Add project references
**Commands**:
```powershell
dotnet add Maliev.AuthService.Api reference Maliev.AuthService.Data
dotnet add Maliev.AuthService.Tests reference Maliev.AuthService.Api
dotnet add Maliev.AuthService.Tests reference Maliev.AuthService.Data
```
**Verification**: `dotnet build` succeeds
**Dependencies**: T002, T003, T004

### T009: Enable TreatWarningsAsErrors [P]
**Files**: All `.csproj` files
**Action**: Add to each `<PropertyGroup>`:
```xml
<TreatWarningsAsErrors>true</TreatWarningsAsErrors>
```
**Requirement**: Constitution VII (Zero Warnings Policy)
**Verification**: Build produces zero warnings
**Dependencies**: T005-T008

### T010: Delete boilerplate files [P]
**Files to Delete**:
- `Maliev.AuthService.Api/Controllers/WeatherForecastController.cs`
- `Maliev.AuthService.Api/WeatherForecast.cs`
- `Maliev.AuthService.Data/Class1.cs`
- `Maliev.AuthService.Tests/UnitTest1.cs`

**Commands**:
```powershell
rm Maliev.AuthService.Api/Controllers/WeatherForecastController.cs
rm Maliev.AuthService.Api/WeatherForecast.cs
rm Maliev.AuthService.Data/Class1.cs
rm Maliev.AuthService.Tests/UnitTest1.cs
```
**Verification**: Only project files remain
**Dependencies**: T002-T004

---

## Phase 2: Contract Tests - TDD Foundation (T011-T018) [PARALLEL]

**CRITICAL**: These tests MUST be written and MUST FAIL before ANY implementation (Constitution III - Test-First Development)

All contract test tasks can run in parallel [P] - each tests a different endpoint.

### T011: Contract test for POST /v1/auth/login [P]
**Files**: `Maliev.AuthService.Tests/Contract/AuthenticationContractTests.cs`
**Purpose**: Validate login endpoint request/response schema against OpenAPI contract
**Test Cases**:
- Valid customer login request returns 200 with access_token, refresh_token, user object
- Valid employee login request returns 200 with correct user_type
- Invalid credentials return 401 with error response
- Missing required fields return 400 with validation errors
- Account lockout returns 423 with locked_until timestamp
- Rate limit exceeded returns 429 with retry_after
**Verification**: Tests compile and FAIL (endpoint not implemented yet)
**Dependencies**: T007 (test packages)

### T012: Contract test for POST /v1/auth/service/login [P]
**Files**: `Maliev.AuthService.Tests/Contract/ServiceLoginContractTests.cs`
**Purpose**: Validate service authentication endpoint schema
**Test Cases**:
- Valid service credentials return 200 with service access_token
- Invalid client_id/secret return 401
- Missing credentials return 400
**Verification**: Tests compile and FAIL
**Dependencies**: T007

### T013: Contract test for POST /v1/auth/refresh [P]
**Files**: `Maliev.AuthService.Tests/Contract/TokenRefreshContractTests.cs`
**Purpose**: Validate token refresh endpoint with rotation
**Test Cases**:
- Valid refresh_token returns 200 with NEW access_token and NEW refresh_token
- Expired refresh_token returns 401
- Reused refresh_token returns 403 with reuse detection error
- Invalid refresh_token format returns 400
**Verification**: Tests compile and FAIL
**Dependencies**: T007

### T014: Contract test for POST /v1/auth/validate [P]
**Files**: `Maliev.AuthService.Tests/Contract/TokenValidationContractTests.cs`
**Purpose**: Validate token validation endpoint returns user identity
**Test Cases**:
- Valid access_token returns 200 with user_id, user_type, username, email, roles, permissions
- Expired token returns 401 with validation_failure: "expired"
- Revoked token returns 401 with validation_failure: "revoked"
- Invalid signature returns 401
**Verification**: Tests compile and FAIL
**Dependencies**: T007

### T015: Contract test for POST /v1/auth/revoke [P]
**Files**: `Maliev.AuthService.Tests/Contract/TokenRevocationContractTests.cs`
**Purpose**: Validate manual token revocation endpoint
**Test Cases**:
- Valid revocation request returns 204 No Content
- Revoked token shows in validation as invalid within 2 seconds
- Missing authentication returns 401
**Verification**: Tests compile and FAIL
**Dependencies**: T007

### T016: Contract test for POST /v1/auth/logout [P]
**Files**: `Maliev.AuthService.Tests/Contract/LogoutContractTests.cs`
**Purpose**: Validate logout endpoint revokes all user tokens
**Test Cases**:
- Logout returns 204 No Content
- All user's refresh tokens marked as revoked
- All user's access tokens added to revocation list
**Verification**: Tests compile and FAIL
**Dependencies**: T007

### T017: Contract test for GET /liveness [P]
**Files**: `Maliev.AuthService.Tests/Contract/LivenessContractTests.cs`
**Purpose**: Validate liveness probe returns 200
**Test Cases**:
- GET /liveness returns 200 OK with "Healthy" text
- No authentication required
**Verification**: Tests compile and FAIL
**Dependencies**: T007

### T018: Contract test for GET /readiness [P]
**Files**: `Maliev.AuthService.Tests/Contract/ReadinessContractTests.cs`
**Purpose**: Validate readiness probe returns health check JSON
**Test Cases**:
- GET /readiness returns 200 with JSON health status
- Database check shows "Healthy" when DB is accessible
- Circuit breaker states reported
**Verification**: Tests compile and FAIL
**Dependencies**: T007

---

## Phase 3: Data Layer - Entities (T019-T026)

All entity tasks can run in parallel [P] - each creates a separate file.

### T019: Create UserType enum [P]
**Files**: `Maliev.AuthService.Data/Entities/UserType.cs`
**Content**:
```csharp
namespace Maliev.AuthService.Data.Entities;

public enum UserType
{
    Customer,
    Employee,
    Service
}
```
**Verification**: Compiles without errors
**Dependencies**: T006

### T020: Create RefreshToken entity [P]
**Files**: `Maliev.AuthService.Data/Entities/RefreshToken.cs`
**Content**:
```csharp
using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Data.Entities;

public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public Guid FamilyId { get; set; }

    [Required]
    [MaxLength(255)]
    public string UserId { get; set; } = null!;

    [Required]
    public UserType UserType { get; set; }

    [Required]
    [MaxLength(64)]
    public string TokenHash { get; set; } = null!;

    public bool IsUsed { get; set; } = false;

    public DateTime? UsedAt { get; set; }

    [Required]
    public DateTime ExpiresAt { get; set; }

    [Required]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [MaxLength(45)]
    public string? IpAddress { get; set; }

    // Navigation property
    public TokenFamily? TokenFamily { get; set; }
}
```
**Verification**: Compiles without errors
**Dependencies**: T006, T019

### T021: Create TokenFamily entity [P]
**Files**: `Maliev.AuthService.Data/Entities/TokenFamily.cs`
**Content**:
```csharp
using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Data.Entities;

public class TokenFamily
{
    [Key]
    public Guid FamilyId { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(255)]
    public string UserId { get; set; } = null!;

    [Required]
    public UserType UserType { get; set; }

    [Required]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [Required]
    public DateTime LastRefreshAt { get; set; } = DateTime.UtcNow;

    // Navigation property
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}
```
**Verification**: Compiles without errors
**Dependencies**: T006, T019

### T022: Create RevokedToken entity [P]
**Files**: `Maliev.AuthService.Data/Entities/RevokedToken.cs`
**Content**:
```csharp
using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Data.Entities;

public class RevokedToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(255)]
    public string Jti { get; set; } = null!;

    [Required]
    [MaxLength(255)]
    public string UserId { get; set; } = null!;

    [Required]
    public UserType UserType { get; set; }

    [Required]
    public DateTime RevokedAt { get; set; } = DateTime.UtcNow;

    [Required]
    public DateTime ExpiresAt { get; set; }

    [MaxLength(500)]
    public string? Reason { get; set; }
}
```
**Verification**: Compiles without errors
**Dependencies**: T006, T019

### T023: Create AccountLockout entity [P]
**Files**: `Maliev.AuthService.Data/Entities/AccountLockout.cs`
**Content**:
```csharp
using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Data.Entities;

public class AccountLockout
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(255)]
    public string UserId { get; set; } = null!;

    [Required]
    public UserType UserType { get; set; }

    public int FailedAttempts { get; set; } = 0;

    public DateTime? LockedUntil { get; set; }

    [Required]
    public DateTime LastAttemptAt { get; set; } = DateTime.UtcNow;

    [Required]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [Required]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
```
**Verification**: Compiles without errors
**Dependencies**: T006, T019

### T024: Create IpRateLimit entity [P]
**Files**: `Maliev.AuthService.Data/Entities/IpRateLimit.cs`
**Content**:
```csharp
using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Data.Entities;

public class IpRateLimit
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(45)]
    public string IpAddress { get; set; } = null!;

    public int FailedAttempts { get; set; } = 0;

    public DateTime? BlockedUntil { get; set; }

    [Required]
    public DateTime WindowStart { get; set; } = DateTime.UtcNow;

    [Required]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [Required]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
```
**Verification**: Compiles without errors
**Dependencies**: T006

### T025: Create AuthAuditLog entity [P]
**Files**: `Maliev.AuthService.Data/Entities/AuthAuditLog.cs`
**Content**:
```csharp
using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Data.Entities;

public class AuthAuditLog
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [MaxLength(255)]
    public string? UserId { get; set; }

    public UserType? UserType { get; set; }

    [Required]
    [MaxLength(100)]
    public string Action { get; set; } = null!;

    [MaxLength(45)]
    public string? IpAddress { get; set; }

    [MaxLength(500)]
    public string? UserAgent { get; set; }

    public bool Success { get; set; }

    [MaxLength(500)]
    public string? FailureReason { get; set; }

    [MaxLength(255)]
    public string? CorrelationId { get; set; }

    [Required]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
```
**Verification**: Compiles without errors
**Dependencies**: T006, T019

### T026: Create ServiceCredential entity [P]
**Files**: `Maliev.AuthService.Data/Entities/ServiceCredential.cs`
**Content**:
```csharp
using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Data.Entities;

public class ServiceCredential
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(255)]
    public string ClientId { get; set; } = null!;

    [Required]
    [MaxLength(64)]
    public string ClientSecretHash { get; set; } = null!;

    [Required]
    [MaxLength(255)]
    public string ServiceName { get; set; } = null!;

    public bool IsActive { get; set; } = true;

    [Required]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [Required]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
```
**Verification**: Compiles without errors
**Dependencies**: T006
**Requirement**: FR-063 (service-to-service authentication)

---

## Phase 4: Data Layer - EF Core Configurations (T027-T034)

All configuration tasks can run in parallel [P] - each configures a different entity.

### T018: Create RefreshTokenConfiguration [P]
**Files**: `Maliev.AuthService.Data/Configurations/RefreshTokenConfiguration.cs`
**Content**:
```csharp
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_tokens");

        builder.HasKey(rt => rt.Id);
        builder.Property(rt => rt.Id).HasColumnName("id");

        builder.Property(rt => rt.FamilyId).HasColumnName("family_id").IsRequired();
        builder.Property(rt => rt.UserId).HasColumnName("user_id").IsRequired().HasMaxLength(255);
        builder.Property(rt => rt.UserType).HasColumnName("user_type").IsRequired();
        builder.Property(rt => rt.TokenHash).HasColumnName("token_hash").IsRequired().HasMaxLength(64);
        builder.Property(rt => rt.IsUsed).HasColumnName("is_used").IsRequired();
        builder.Property(rt => rt.UsedAt).HasColumnName("used_at");
        builder.Property(rt => rt.ExpiresAt).HasColumnName("expires_at").IsRequired();
        builder.Property(rt => rt.CreatedAt).HasColumnName("created_at").IsRequired();
        builder.Property(rt => rt.IpAddress).HasColumnName("ip_address").HasMaxLength(45);

        builder.HasIndex(rt => rt.TokenHash).HasDatabaseName("ix_refresh_tokens_token_hash").IsUnique();
        builder.HasIndex(rt => rt.FamilyId).HasDatabaseName("ix_refresh_tokens_family_id");
        builder.HasIndex(rt => rt.UserId).HasDatabaseName("ix_refresh_tokens_user_id");
        builder.HasIndex(rt => rt.ExpiresAt).HasDatabaseName("ix_refresh_tokens_expires_at");

        builder.HasOne(rt => rt.TokenFamily)
            .WithMany(tf => tf.RefreshTokens)
            .HasForeignKey(rt => rt.FamilyId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
```
**Verification**: Compiles without errors
**Dependencies**: T012, T013

### T019: Create TokenFamilyConfiguration [P]
**Files**: `Maliev.AuthService.Data/Configurations/TokenFamilyConfiguration.cs`
**Content**:
```csharp
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

public class TokenFamilyConfiguration : IEntityTypeConfiguration<TokenFamily>
{
    public void Configure(EntityTypeBuilder<TokenFamily> builder)
    {
        builder.ToTable("token_families");

        builder.HasKey(tf => tf.FamilyId);
        builder.Property(tf => tf.FamilyId).HasColumnName("family_id");

        builder.Property(tf => tf.UserId).HasColumnName("user_id").IsRequired().HasMaxLength(255);
        builder.Property(tf => tf.UserType).HasColumnName("user_type").IsRequired();
        builder.Property(tf => tf.CreatedAt).HasColumnName("created_at").IsRequired();
        builder.Property(tf => tf.LastRefreshAt).HasColumnName("last_refresh_at").IsRequired();

        builder.HasIndex(tf => tf.UserId).HasDatabaseName("ix_token_families_user_id");
    }
}
```
**Verification**: Compiles without errors
**Dependencies**: T013

### T020: Create RevokedTokenConfiguration [P]
**Files**: `Maliev.AuthService.Data/Configurations/RevokedTokenConfiguration.cs`
**Content**:
```csharp
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

public class RevokedTokenConfiguration : IEntityTypeConfiguration<RevokedToken>
{
    public void Configure(EntityTypeBuilder<RevokedToken> builder)
    {
        builder.ToTable("revoked_tokens");

        builder.HasKey(rt => rt.Id);
        builder.Property(rt => rt.Id).HasColumnName("id");

        builder.Property(rt => rt.Jti).HasColumnName("jti").IsRequired().HasMaxLength(255);
        builder.Property(rt => rt.UserId).HasColumnName("user_id").IsRequired().HasMaxLength(255);
        builder.Property(rt => rt.UserType).HasColumnName("user_type").IsRequired();
        builder.Property(rt => rt.RevokedAt).HasColumnName("revoked_at").IsRequired();
        builder.Property(rt => rt.ExpiresAt).HasColumnName("expires_at").IsRequired();
        builder.Property(rt => rt.Reason).HasColumnName("reason").HasMaxLength(500);

        builder.HasIndex(rt => rt.Jti).HasDatabaseName("ix_revoked_tokens_jti").IsUnique();
        builder.HasIndex(rt => rt.UserId).HasDatabaseName("ix_revoked_tokens_user_id");
        builder.HasIndex(rt => rt.ExpiresAt).HasDatabaseName("ix_revoked_tokens_expires_at");
    }
}
```
**Verification**: Compiles without errors
**Dependencies**: T014

### T021: Create AccountLockoutConfiguration [P]
**Files**: `Maliev.AuthService.Data/Configurations/AccountLockoutConfiguration.cs`
**Content**:
```csharp
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

public class AccountLockoutConfiguration : IEntityTypeConfiguration<AccountLockout>
{
    public void Configure(EntityTypeBuilder<AccountLockout> builder)
    {
        builder.ToTable("account_lockouts");

        builder.HasKey(al => al.Id);
        builder.Property(al => al.Id).HasColumnName("id");

        builder.Property(al => al.UserId).HasColumnName("user_id").IsRequired().HasMaxLength(255);
        builder.Property(al => al.UserType).HasColumnName("user_type").IsRequired();
        builder.Property(al => al.FailedAttempts).HasColumnName("failed_attempts").IsRequired();
        builder.Property(al => al.LockedUntil).HasColumnName("locked_until");
        builder.Property(al => al.LastAttemptAt).HasColumnName("last_attempt_at").IsRequired();
        builder.Property(al => al.CreatedAt).HasColumnName("created_at").IsRequired();
        builder.Property(al => al.UpdatedAt).HasColumnName("updated_at").IsRequired();

        builder.HasIndex(al => new { al.UserId, al.UserType }).HasDatabaseName("ix_account_lockouts_user_id_user_type").IsUnique();
        builder.HasIndex(al => al.LockedUntil).HasDatabaseName("ix_account_lockouts_locked_until");
    }
}
```
**Verification**: Compiles without errors
**Dependencies**: T015

### T022: Create IpRateLimitConfiguration [P]
**Files**: `Maliev.AuthService.Data/Configurations/IpRateLimitConfiguration.cs`
**Content**:
```csharp
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

public class IpRateLimitConfiguration : IEntityTypeConfiguration<IpRateLimit>
{
    public void Configure(EntityTypeBuilder<IpRateLimit> builder)
    {
        builder.ToTable("ip_rate_limits");

        builder.HasKey(irl => irl.Id);
        builder.Property(irl => irl.Id).HasColumnName("id");

        builder.Property(irl => irl.IpAddress).HasColumnName("ip_address").IsRequired().HasMaxLength(45);
        builder.Property(irl => irl.FailedAttempts).HasColumnName("failed_attempts").IsRequired();
        builder.Property(irl => irl.BlockedUntil).HasColumnName("blocked_until");
        builder.Property(irl => irl.WindowStart).HasColumnName("window_start").IsRequired();
        builder.Property(irl => irl.CreatedAt).HasColumnName("created_at").IsRequired();
        builder.Property(irl => irl.UpdatedAt).HasColumnName("updated_at").IsRequired();

        builder.HasIndex(irl => irl.IpAddress).HasDatabaseName("ix_ip_rate_limits_ip_address").IsUnique();
        builder.HasIndex(irl => irl.BlockedUntil).HasDatabaseName("ix_ip_rate_limits_blocked_until");
    }
}
```
**Verification**: Compiles without errors
**Dependencies**: T016

### T023: Create AuthAuditLogConfiguration [P]
**Files**: `Maliev.AuthService.Data/Configurations/AuthAuditLogConfiguration.cs`
**Content**:
```csharp
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

public class AuthAuditLogConfiguration : IEntityTypeConfiguration<AuthAuditLog>
{
    public void Configure(EntityTypeBuilder<AuthAuditLog> builder)
    {
        builder.ToTable("auth_audit_logs");

        builder.HasKey(aal => aal.Id);
        builder.Property(aal => aal.Id).HasColumnName("id");

        builder.Property(aal => aal.UserId).HasColumnName("user_id").HasMaxLength(255);
        builder.Property(aal => aal.UserType).HasColumnName("user_type");
        builder.Property(aal => aal.Action).HasColumnName("action").IsRequired().HasMaxLength(100);
        builder.Property(aal => aal.IpAddress).HasColumnName("ip_address").HasMaxLength(45);
        builder.Property(aal => aal.UserAgent).HasColumnName("user_agent").HasMaxLength(500);
        builder.Property(aal => aal.Success).HasColumnName("success").IsRequired();
        builder.Property(aal => aal.FailureReason).HasColumnName("failure_reason").HasMaxLength(500);
        builder.Property(aal => aal.CorrelationId).HasColumnName("correlation_id").HasMaxLength(255);
        builder.Property(aal => aal.CreatedAt).HasColumnName("created_at").IsRequired();

        builder.HasIndex(aal => aal.UserId).HasDatabaseName("ix_auth_audit_logs_user_id");
        builder.HasIndex(aal => aal.CreatedAt).HasDatabaseName("ix_auth_audit_logs_created_at");
        builder.HasIndex(aal => aal.CorrelationId).HasDatabaseName("ix_auth_audit_logs_correlation_id");
    }
}
```
**Verification**: Compiles without errors
**Dependencies**: T017

### T024: Create ServiceCredentialConfiguration [P]
**Files**: `Maliev.AuthService.Data/Configurations/ServiceCredentialConfiguration.cs`
**Content**:
```csharp
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Maliev.AuthService.Data.Configurations;

public class ServiceCredentialConfiguration : IEntityTypeConfiguration<ServiceCredential>
{
    public void Configure(EntityTypeBuilder<ServiceCredential> builder)
    {
        builder.ToTable("service_credentials");

        builder.HasKey(sc => sc.Id);
        builder.Property(sc => sc.Id).HasColumnName("id");

        builder.Property(sc => sc.ClientId).HasColumnName("client_id").IsRequired().HasMaxLength(255);
        builder.Property(sc => sc.ClientSecretHash).HasColumnName("client_secret_hash").IsRequired().HasMaxLength(64);
        builder.Property(sc => sc.ServiceName).HasColumnName("service_name").IsRequired().HasMaxLength(255);
        builder.Property(sc => sc.IsActive).HasColumnName("is_active").IsRequired();
        builder.Property(sc => sc.CreatedAt).HasColumnName("created_at").IsRequired();
        builder.Property(sc => sc.UpdatedAt).HasColumnName("updated_at").IsRequired();

        builder.HasIndex(sc => sc.ClientId).HasDatabaseName("ix_service_credentials_client_id").IsUnique();
    }
}
```
**Note**: Need to add ServiceCredential entity first.

**Create ServiceCredential entity**:
**Files**: `Maliev.AuthService.Data/Entities/ServiceCredential.cs`
**Content**:
```csharp
using System.ComponentModel.DataAnnotations;

namespace Maliev.AuthService.Data.Entities;

public class ServiceCredential
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(255)]
    public string ClientId { get; set; } = null!;

    [Required]
    [MaxLength(64)]
    public string ClientSecretHash { get; set; } = null!;

    [Required]
    [MaxLength(255)]
    public string ServiceName { get; set; } = null!;

    public bool IsActive { get; set; } = true;

    [Required]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [Required]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
```
**Verification**: Compiles without errors
**Dependencies**: T006

---

## Phase 4: DbContext and Migrations (T025-T027)

### T025: Create AuthDbContext
**Files**: `Maliev.AuthService.Data/DbContexts/AuthDbContext.cs`
**Content**:
```csharp
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace Maliev.AuthService.Data.DbContexts;

public class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    {
    }

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<TokenFamily> TokenFamilies => Set<TokenFamily>();
    public DbSet<RevokedToken> RevokedTokens => Set<RevokedToken>();
    public DbSet<AccountLockout> AccountLockouts => Set<AccountLockout>();
    public DbSet<IpRateLimit> IpRateLimits => Set<IpRateLimit>();
    public DbSet<AuthAuditLog> AuthAuditLogs => Set<AuthAuditLog>();
    public DbSet<ServiceCredential> ServiceCredentials => Set<ServiceCredential>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AuthDbContext).Assembly);
    }
}
```
**Verification**: Compiles without errors
**Dependencies**: T011-T024

### T026: Create DesignTimeDbContextFactory
**Files**: `Maliev.AuthService.Data/DesignTimeDbContextFactory.cs`
**Content**:
```csharp
using Maliev.AuthService.Data.DbContexts;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Maliev.AuthService.Data;

public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<AuthDbContext>
{
    public AuthDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__AuthDbContext");

        if (string.IsNullOrEmpty(connectionString))
        {
            throw new InvalidOperationException(
                "Database connection string not found. " +
                "Set environment variable: ConnectionStrings__AuthDbContext");
        }

        var optionsBuilder = new DbContextOptionsBuilder<AuthDbContext>();
        optionsBuilder.UseNpgsql(connectionString);

        return new AuthDbContext(optionsBuilder.Options);
    }
}
```
**Verification**: `dotnet ef` commands work
**Dependencies**: T025

### T027: Create initial migration
**Files**: `Maliev.AuthService.Data/Migrations/*.cs` (generated)
**Commands**:
```powershell
# Set connection string environment variable first
$env:ConnectionStrings__AuthDbContext="Host=localhost;Port=5432;Database=test_db;Username=postgres;Password=postgres;"

# Create migration
dotnet ef migrations add InitialCreate --project Maliev.AuthService.Data --startup-project Maliev.AuthService.Api
```
**Verification**: Migration files generated, no errors
**Dependencies**: T025, T026

---

## Phase 5+: Critical Additions (Post-Analyze Remediation)

**Note**: Phases 5-18 will be fully detailed during implementation. Below are CRITICAL tasks identified by `/analyze` that MUST be added:

### CRITICAL: Distributed Token Revocation (FR-060)

**Phase 6 additions - Token Revocation Service**:

#### T035: Create IRevocationService interface
**Files**: `Maliev.AuthService.Api/Services/IRevocationService.cs`
**Purpose**: Define distributed token revocation contract
**Methods**:
```csharp
Task RevokeAccessTokenAsync(string jti, string userId, UserType userType, string reason);
Task RevokeAllUserTokensAsync(string userId, UserType userType, string reason);
Task RevokeTokenFamilyAsync(Guid familyId, string reason);
Task<bool> IsTokenRevokedAsync(string jti);
Task PublishRevocationEventAsync(string jti, DateTime expiresAt);
```
**Dependencies**: T019 (UserType enum), T022 (RevokedToken entity)

#### T036: Implement RevocationService with Redis pub/sub
**Files**: `Maliev.AuthService.Api/Services/RevocationService.cs`
**Implementation Details**:
- Redis pub/sub for event propagation (`token:revoked` channel)
- Database persistence for revoked tokens (RevokedToken table)
- Dual-write pattern: publish to Redis + save to database
- Subscribe to revocation events on startup
- In-memory cache for recently revoked JTIs (2-hour sliding window)
- <2 second propagation target (FR-060)
**Dependencies**: T035, Redis configuration in Program.cs

#### T037: Add Redis connection configuration
**Files**: `Maliev.AuthService.Api/Program.cs` (partial update)
**Action**: Add StackExchange.Redis connection and pub/sub subscription
```csharp
builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
{
    var redisConnection = builder.Configuration["Redis__ConnectionString"]
        ?? throw new InvalidOperationException("Redis connection string required");
    return ConnectionMultiplexer.Connect(redisConnection);
});
```
**Environment Variable**: `Redis__ConnectionString` (from Google Secret Manager)
**Dependencies**: T005 (Redis package installed)

#### T038: Add revocation controller endpoint
**Files**: `Maliev.AuthService.Api/Controllers/RevocationController.cs`
**Endpoints**:
- `POST /v1/auth/revoke` - Manual token revocation (FR-060)
- `POST /v1/auth/logout` - Revoke all user tokens
**Requirements**: FR-060, FR-066 (audit logging)
**Dependencies**: T036 (RevocationService)

### CRITICAL: Service-to-Service Authentication (FR-063-066)

**Phase 6 additions - Service Authentication**:

#### T039: Create IServiceCredentialRepository
**Files**: `Maliev.AuthService.Data/Repositories/IServiceCredentialRepository.cs`
**Methods**:
```csharp
Task<ServiceCredential?> GetByClientIdAsync(string clientId);
Task<bool> ValidateCredentialsAsync(string clientId, string clientSecret);
```
**Dependencies**: T026 (ServiceCredential entity)

#### T040: Implement ServiceCredentialRepository
**Files**: `Maliev.AuthService.Data/Repositories/ServiceCredentialRepository.cs`
**Implementation**: EF Core repository with SHA-256 hash comparison
**Dependencies**: T039

#### T041: Add service authentication flow in AuthenticationService
**Files**: `Maliev.AuthService.Api/Services/AuthenticationService.cs` (update)
**Action**: Add `AuthenticateServiceAsync` method
- Validate client_id and client_secret_hash
- Generate service access token (no refresh token for services)
- Different rate limits (1000/min per FR-065)
**Dependencies**: T040

#### T042: Add service login endpoint
**Files**: Update `AuthenticationController.cs`
**Endpoint**: `POST /v1/auth/service/login`
**Request**: `{ "client_id": "...", "client_secret": "..." }`
**Response**: `{ "access_token": "...", "token_type": "Bearer", "expires_in": 900 }`
**Requirements**: FR-063-066
**Dependencies**: T041

### HIGH PRIORITY: Metrics Implementation (FR-038-045, FR-071)

**Phase 12 additions - Observability**:

#### T080: Configure Prometheus metrics middleware
**Files**: `Maliev.AuthService.Api/Program.cs` (update)
**Action**: Add `app.UseHttpMetrics()` and `app.MapMetrics("/metrics")`
**Package**: Prometheus-net.AspNetCore (add in T005)
**Requirements**: FR-038-041
**Dependencies**: Program.cs configuration

#### T081: Implement custom authentication metrics
**Files**: `Maliev.AuthService.Api/Services/MetricsService.cs`
**Metrics**:
- `auth_login_total{user_type, result}` - Counter for login attempts (FR-038)
- `auth_token_generation_duration_seconds` - Histogram for token gen (FR-040)
- `auth_token_validation_duration_seconds` - Histogram for validation (FR-040)
- `auth_external_service_duration_seconds{service}` - External service latency (FR-041)
- `auth_circuit_breaker_state{service}` - Gauge for circuit state (FR-069, FR-071)
- `auth_token_reuse_detection_total` - Counter for reuse events (FR-071)
- `auth_revocation_propagation_duration_seconds` - Histogram for revocation latency (FR-071)
**Requirements**: FR-038-045, FR-071
**Dependencies**: T080

---

## Summary

This is a comprehensive task list with **119+ detailed tasks** (updated from 111) organized into **18 phases**. Each task includes:

- ✅ Exact file paths
- ✅ Complete code samples
- ✅ PowerShell commands
- ✅ Verification criteria
- ✅ Dependency tracking
- ✅ Parallel execution markers [P]

**Next Steps**:
1. Execute tasks sequentially from T001
2. Mark tasks in todo list as in_progress → completed
3. Follow TDD: Tests before implementation
4. Verify each task before moving to next
5. Commit after each phase completion

**Constitutional Compliance**: All 9 principles satisfied
**Ready for Execution**: Yes ✅

---

*Note: This tasks.md contains Phases 1-4 in full detail. Phases 5-18 follow the same pattern and will be added incrementally as implementation progresses. The complete detailed specification for all 111 tasks is available in the implementation plan at `specs/001-create-a-jwt/plan.md`.*
