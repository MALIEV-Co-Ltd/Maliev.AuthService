# Data Model Design: JWT Authentication Service

**Project**: Maliev.AuthService
**Feature**: 001-create-a-jwt
**Date**: 2025-10-05
**Purpose**: Define database entities, relationships, validation rules, and state transitions for token management

---

## Overview

The authentication service requires persistent storage for:
1. **Refresh Tokens**: Long-lived tokens with rotation tracking
2. **Token Families**: Grouping of tokens from same authentication session
3. **Revoked Access Tokens**: Short-term blacklist for revoked JWTs

**Database**: PostgreSQL 18
**ORM**: Entity Framework Core 9.0.9
**Provider**: Npgsql 9.0.2

---

## Entities

### 1. RefreshToken

Stores hashed refresh tokens with rotation and reuse detection support.

#### Properties

| Property | Type | Nullable | Description |
|----------|------|----------|-------------|
| Id | Guid | No | Primary key (auto-generated) |
| TokenHash | string(64) | No | SHA-256 hash of refresh token (hex format) |
| UserId | Guid | No | Reference to user in external service |
| UserType | UserType (enum) | No | Customer or Employee |
| FamilyId | Guid | No | Foreign key to TokenFamily |
| CreatedAt | DateTimeOffset | No | Token creation timestamp (UTC) |
| ExpiresAt | DateTimeOffset | No | Token expiration timestamp (UTC) |
| IsRevoked | bool | No | True if token has been revoked |
| IsUsed | bool | No | True if token has been used for rotation |
| RevokedAt | DateTimeOffset | Yes | Timestamp when token was revoked |
| Version | uint | No | Concurrency token (PostgreSQL xmin) |

#### Validation Rules

- **TokenHash**:
  - Required, exactly 64 characters (SHA-256 hex output)
  - Unique constraint (indexed)
  - Format: `^[a-f0-9]{64}$`

- **UserId**:
  - Required, valid Guid
  - No foreign key constraint (user exists in external service)

- **UserType**:
  - Required, must be `Customer` or `Employee`

- **FamilyId**:
  - Required, must reference existing TokenFamily.FamilyId
  - Foreign key with cascade delete

- **ExpiresAt**:
  - Required, must be > CreatedAt
  - Typically CreatedAt + 7 days

- **IsRevoked / IsUsed**:
  - Both default to false
  - IsUsed = true when token is rotated (new token issued)
  - IsRevoked = true when family is invalidated (reuse detection)
  - Cannot both be true simultaneously (check constraint)

#### State Transitions

```
[Active]
  ├─ IsUsed = false, IsRevoked = false
  ├─ Can be used for token refresh
  │
  ├─> [Used] (on successful refresh)
  │    ├─ IsUsed = true, IsRevoked = false
  │    ├─ New token generated in same family
  │    └─ Cannot be used again
  │
  └─> [Revoked] (on reuse detection or manual revocation)
       ├─ IsRevoked = true, RevokedAt = timestamp
       ├─ Entire family invalidated
       └─ User must re-authenticate

[Used]
  └─> [Revoked] (if reuse detected)
       └─ All tokens in family revoked
```

#### Indexes

```sql
-- Primary key index (automatic)
CREATE UNIQUE INDEX pk_refresh_tokens ON refresh_tokens (id);

-- Token lookup index (critical for validation performance)
CREATE UNIQUE INDEX ix_refresh_tokens_token_hash ON refresh_tokens (token_hash);

-- Family lookup index (for invalidation queries)
CREATE INDEX ix_refresh_tokens_family_id ON refresh_tokens (family_id);

-- User query index (for logout all sessions)
CREATE INDEX ix_refresh_tokens_user_composite
ON refresh_tokens (user_id, user_type, is_revoked, is_used);

-- Cleanup query index (for expired token deletion)
CREATE INDEX ix_refresh_tokens_expires_at ON refresh_tokens (expires_at)
WHERE is_revoked = false;
```

#### EF Core Configuration

```csharp
public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("refresh_tokens");

        builder.HasKey(e => e.Id);

        builder.Property(e => e.TokenHash)
            .IsRequired()
            .HasMaxLength(64)
            .IsFixedLength();

        builder.Property(e => e.UserId)
            .IsRequired();

        builder.Property(e => e.UserType)
            .IsRequired()
            .HasConversion<string>(); // Store as "Customer" or "Employee"

        builder.Property(e => e.FamilyId)
            .IsRequired();

        builder.Property(e => e.CreatedAt)
            .IsRequired();

        builder.Property(e => e.ExpiresAt)
            .IsRequired();

        builder.Property(e => e.IsRevoked)
            .IsRequired()
            .HasDefaultValue(false);

        builder.Property(e => e.IsUsed)
            .IsRequired()
            .HasDefaultValue(false);

        builder.Property(e => e.RevokedAt)
            .IsRequired(false);

        // PostgreSQL xmin for optimistic concurrency
        builder.Property(e => e.Version)
            .IsRowVersion()
            .HasColumnName("xmin")
            .HasColumnType("xid")
            .ValueGeneratedOnAddOrUpdate();

        // Indexes
        builder.HasIndex(e => e.TokenHash)
            .IsUnique();

        builder.HasIndex(e => e.FamilyId);

        builder.HasIndex(e => new { e.UserId, e.UserType, e.IsRevoked, e.IsUsed });

        builder.HasIndex(e => e.ExpiresAt)
            .HasFilter("is_revoked = false");

        // Foreign key relationship
        builder.HasOne(e => e.Family)
            .WithMany(f => f.Tokens)
            .HasForeignKey(e => e.FamilyId)
            .OnDelete(DeleteBehavior.Cascade);

        // Check constraint
        builder.HasCheckConstraint(
            "ck_refresh_tokens_not_both_used_and_revoked",
            "NOT (is_used = true AND is_revoked = true)");
    }
}
```

---

### 2. TokenFamily

Tracks token rotation chains for reuse detection.

#### Properties

| Property | Type | Nullable | Description |
|----------|------|----------|-------------|
| FamilyId | Guid | No | Primary key (auto-generated) |
| UserId | Guid | No | User who owns this token family |
| UserType | UserType (enum) | No | Customer or Employee |
| CreatedAt | DateTimeOffset | No | When family was created (initial login) |
| LastUsedAt | DateTimeOffset | No | Last token refresh timestamp |

#### Validation Rules

- **FamilyId**:
  - Required, unique
  - Generated on initial login

- **UserId**:
  - Required, valid Guid
  - Same user for all tokens in family

- **LastUsedAt**:
  - Updated on every token rotation
  - Must be >= CreatedAt

#### Lifecycle

```
[Family Created] (on login)
  ├─ FamilyId generated
  ├─ Initial refresh token created with this FamilyId
  │
  ├─> [Active Usage]
  │    ├─ LastUsedAt updated on each refresh
  │    ├─ New tokens added to family
  │    ├─ Old tokens marked as Used
  │    │
  │    └─> [Family Invalidated] (on reuse detection)
  │         ├─ All tokens in family marked IsRevoked = true
  │         └─ Family preserved for audit (cascade delete disabled)
  │
  └─> [Natural Expiry]
       └─ All tokens expire after 7 days
       └─ Family can be deleted by cleanup job
```

#### Indexes

```sql
CREATE UNIQUE INDEX pk_token_families ON token_families (family_id);

CREATE INDEX ix_token_families_user_id ON token_families (user_id);

CREATE INDEX ix_token_families_last_used_at ON token_families (last_used_at);
```

#### EF Core Configuration

```csharp
public class TokenFamilyConfiguration : IEntityTypeConfiguration<TokenFamily>
{
    public void Configure(EntityTypeBuilder<TokenFamily> builder)
    {
        builder.ToTable("token_families");

        builder.HasKey(e => e.FamilyId);

        builder.Property(e => e.UserId)
            .IsRequired();

        builder.Property(e => e.UserType)
            .IsRequired()
            .HasConversion<string>();

        builder.Property(e => e.CreatedAt)
            .IsRequired();

        builder.Property(e => e.LastUsedAt)
            .IsRequired();

        builder.HasIndex(e => e.UserId);

        builder.HasIndex(e => e.LastUsedAt);

        // Navigation property
        builder.HasMany(e => e.Tokens)
            .WithOne(t => t.Family)
            .HasForeignKey(t => t.FamilyId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
```

---

### 3. RevokedAccessToken

Short-term blacklist for revoked access tokens (expires with token TTL).

#### Properties

| Property | Type | Nullable | Description |
|----------|------|----------|-------------|
| Jti | string(64) | No | JWT ID claim (unique identifier) |
| RevokedAt | DateTimeOffset | No | When token was revoked |
| ExpiresAt | DateTimeOffset | No | When token expires naturally (15 min from issue) |
| Reason | string(200) | No | Revocation reason (audit trail) |

#### Validation Rules

- **Jti**:
  - Required, primary key
  - Unique identifier from JWT `jti` claim
  - Format: Guid string

- **RevokedAt**:
  - Required, timestamp when revocation occurred
  - Must be <= current time

- **ExpiresAt**:
  - Required, must be > RevokedAt
  - Typically RevokedAt + remaining token lifetime
  - Used for automatic cleanup (no need to store expired revocations)

- **Reason**:
  - Required, max 200 characters
  - Enum values: "user_logout", "password_changed", "admin_action", "suspicious_activity", "token_family_invalidated"

#### Lifecycle

```
[Token Revoked]
  ├─ Added to RevokedAccessToken table
  ├─ Event published to Redis (distributed revocation)
  │
  └─> [Cached in Memory] (all services)
       ├─ Validation checks in-memory cache first
       ├─ Falls back to database on cache miss
       │
       └─> [Auto-Expiry]
            ├─ Removed from cache after ExpiresAt
            ├─ Deleted from database by cleanup job
            └─ Token would be expired anyway (15 min)
```

#### Indexes

```sql
CREATE UNIQUE INDEX pk_revoked_access_tokens ON revoked_access_tokens (jti);

CREATE INDEX ix_revoked_access_tokens_expires_at ON revoked_access_tokens (expires_at);
```

#### EF Core Configuration

```csharp
public class RevokedAccessTokenConfiguration : IEntityTypeConfiguration<RevokedAccessToken>
{
    public void Configure(EntityTypeBuilder<RevokedAccessToken> builder)
    {
        builder.ToTable("revoked_access_tokens");

        builder.HasKey(e => e.Jti);

        builder.Property(e => e.Jti)
            .IsRequired()
            .HasMaxLength(64);

        builder.Property(e => e.RevokedAt)
            .IsRequired();

        builder.Property(e => e.ExpiresAt)
            .IsRequired();

        builder.Property(e => e.Reason)
            .IsRequired()
            .HasMaxLength(200);

        builder.HasIndex(e => e.ExpiresAt);
    }
}
```

---

## Enumerations

### UserType

```csharp
public enum UserType
{
    Customer = 1,
    Employee = 2
}
```

**Usage**: Distinguishes between customer and employee authentication flows
**Storage**: String in database ("Customer", "Employee")

---

## Relationships

### Entity Relationship Diagram

```
┌─────────────────┐
│  TokenFamily    │
│─────────────────│
│ FamilyId (PK)   │◄─────┐
│ UserId          │      │
│ UserType        │      │ One-to-Many
│ CreatedAt       │      │
│ LastUsedAt      │      │
└─────────────────┘      │
                         │
                         │
                         │
┌─────────────────┐      │
│  RefreshToken   │      │
│─────────────────│      │
│ Id (PK)         │      │
│ TokenHash       │      │
│ UserId          │      │
│ UserType        │      │
│ FamilyId (FK)   │──────┘
│ CreatedAt       │
│ ExpiresAt       │
│ IsRevoked       │
│ IsUsed          │
│ RevokedAt       │
│ Version         │
└─────────────────┘

┌─────────────────────┐
│ RevokedAccessToken  │
│─────────────────────│
│ Jti (PK)            │
│ RevokedAt           │
│ ExpiresAt           │
│ Reason              │
└─────────────────────┘
(No relationships - standalone blacklist)
```

---

## Database Cleanup Strategy

### Expired Refresh Tokens

```sql
-- Run daily via scheduled job
DELETE FROM refresh_tokens
WHERE expires_at < NOW() - INTERVAL '7 days';
-- Keep 7 days history for audit
```

### Expired Access Token Revocations

```sql
-- Run hourly
DELETE FROM revoked_access_tokens
WHERE expires_at < NOW();
-- No need to keep expired entries
```

### Inactive Token Families

```sql
-- Run weekly
DELETE FROM token_families
WHERE last_used_at < NOW() - INTERVAL '30 days'
AND NOT EXISTS (
    SELECT 1 FROM refresh_tokens
    WHERE family_id = token_families.family_id
    AND is_revoked = false
);
-- Cleanup families with all tokens expired/revoked
```

---

## Sample Data Scenarios

### Scenario 1: Successful Token Rotation

```sql
-- Initial login (2025-10-05 10:00:00)
INSERT INTO token_families VALUES (
    'a1b2c3d4-...', -- FamilyId
    'user-123',     -- UserId
    'Customer',     -- UserType
    '2025-10-05 10:00:00+00',
    '2025-10-05 10:00:00+00'
);

INSERT INTO refresh_tokens VALUES (
    'token-001',    -- Id
    'abc123...def', -- TokenHash (SHA-256)
    'user-123',
    'Customer',
    'a1b2c3d4-...',
    '2025-10-05 10:00:00+00',
    '2025-10-12 10:00:00+00', -- +7 days
    false,          -- IsRevoked
    false,          -- IsUsed
    NULL
);

-- Token refresh (2025-10-05 12:00:00)
UPDATE refresh_tokens SET is_used = true WHERE id = 'token-001';

INSERT INTO refresh_tokens VALUES (
    'token-002',
    'xyz789...uvw',
    'user-123',
    'Customer',
    'a1b2c3d4-...', -- Same family
    '2025-10-05 12:00:00+00',
    '2025-10-12 12:00:00+00',
    false,
    false,
    NULL
);

UPDATE token_families
SET last_used_at = '2025-10-05 12:00:00+00'
WHERE family_id = 'a1b2c3d4-...';
```

### Scenario 2: Token Reuse Detection

```sql
-- Attacker tries to reuse token-001 (already used)
-- Service detects IsUsed = true

-- Invalidate entire family
UPDATE refresh_tokens
SET is_revoked = true, revoked_at = NOW()
WHERE family_id = 'a1b2c3d4-...';

-- Result: Both token-001 and token-002 are revoked
-- User must re-authenticate
```

### Scenario 3: Access Token Revocation

```sql
-- User logs out
INSERT INTO revoked_access_tokens VALUES (
    'jwt-jti-567', -- Jti from access token
    '2025-10-05 14:00:00+00',
    '2025-10-05 14:15:00+00', -- +15 min (token TTL)
    'user_logout'
);

-- Redis pub/sub event sent to all services
-- Services cache this Jti in memory for 15 minutes
```

---

## Migration Strategy

### Initial Migration

```bash
# Create migration
dotnet ef migrations add InitialCreate --project Maliev.AuthService.Data

# Review generated migration
# Apply to development
export AuthDbContext="Server=localhost;Port=5432;Database=auth_db;User Id=postgres;Password=***;"
dotnet ef database update --project Maliev.AuthService.Data

# Verify schema
psql -d auth_db -c "\d refresh_tokens"
psql -d auth_db -c "\d token_families"
psql -d auth_db -c "\d revoked_access_tokens"
```

### Production Deployment

```bash
# Port forward to PostgreSQL pod (NOT service)
kubectl port-forward -n maliev-dev postgres-cluster-1 5432:5432

# Apply migration
export AuthDbContext="Server=localhost;Port=5432;Database=maliev_auth;User Id=postgres;Password=***;"
dotnet ef database update --project Maliev.AuthService.Data

# Verify
kubectl exec -n maliev-dev postgres-cluster-1 -- psql -U postgres -d maliev_auth -c "SELECT COUNT(*) FROM refresh_tokens;"
```

---

## Performance Considerations

### Expected Load

- **Reads**: 10,000 token validations/min (across all services)
- **Writes**: 500 token rotations/min during peak hours
- **Storage**: ~100,000 active refresh tokens (estimate)

### Optimization Strategies

1. **Indexing**: All critical query paths indexed
2. **Connection Pooling**: EF Core with Npgsql connection pooling (max 100 connections)
3. **Read Replicas**: Token validation queries can use read replicas if needed
4. **Partitioning**: Consider table partitioning by CreatedAt if >10M rows

### Query Performance Targets

- **Token lookup by hash**: <5ms (indexed)
- **Family invalidation**: <50ms (indexed by FamilyId)
- **Revocation check**: <2ms (in-memory cache) or <10ms (database fallback)

---

## Security Considerations

1. **Token Hash Storage**: SHA-256 one-way hash, irreversible
2. **Constant-Time Comparison**: Use CryptographicOperations.FixedTimeEquals
3. **Concurrency Control**: PostgreSQL xmin prevents race conditions
4. **Audit Trail**: All revocations logged with timestamp and reason
5. **No Plaintext Tokens**: Never log or expose actual refresh token values

---

## Next Steps

- **Phase 1**: Create OpenAPI contracts for endpoints that interact with this data model
- **Phase 1**: Define integration tests for token rotation and reuse detection scenarios
- **Phase 2**: Implement repository interfaces and EF Core DbContext

---

**Document Status**: Complete ✅
**Reviewed By**: Technical Planning Phase
**Next Artifact**: contracts/openapi.yaml
