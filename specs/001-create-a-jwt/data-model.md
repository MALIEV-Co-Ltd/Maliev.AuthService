# Data Model: JWT Authentication Service

**Feature**: 001-create-a-jwt
**Date**: 2025-10-06
**Database**: PostgreSQL 18 (auth_app_db)

## Entity Relationship Diagram

```
┌─────────────────┐
│  RefreshToken   │
├─────────────────┤
│ id (PK)         │
│ family_id       │◄──────┐
│ user_id         │       │ Token Family
│ user_type       │       │ Relationship
│ token_hash      │       │
│ is_used         │       │
│ used_at         │       │
│ expires_at      │       │
│ created_at      │       │
│ ip_address      │       │
└─────────────────┘       │
                          │
┌─────────────────┐       │
│  TokenFamily    │       │
├─────────────────┤       │
│ family_id (PK)  │───────┘
│ user_id         │
│ user_type       │
│ created_at      │
│ last_refresh_at │
└─────────────────┘

┌─────────────────┐
│  RevokedToken   │
├─────────────────┤
│ id (PK)         │
│ jti             │◄────── JWT ID claim
│ user_id         │
│ user_type       │
│ revoked_at      │
│ expires_at      │
│ reason          │
└─────────────────┘

┌─────────────────┐
│  AccountLockout │
├─────────────────┤
│ id (PK)         │
│ user_id         │
│ user_type       │
│ failed_attempts │
│ locked_until    │
│ last_attempt_at │
│ created_at      │
│ updated_at      │
└─────────────────┘

┌─────────────────┐
│  IpRateLimit    │
├─────────────────┤
│ id (PK)         │
│ ip_address      │
│ failed_attempts │
│ blocked_until   │
│ window_start    │
│ created_at      │
│ updated_at      │
└─────────────────┘

┌─────────────────┐
│  AuthAuditLog   │
├─────────────────┤
│ id (PK)         │
│ user_id         │
│ user_type       │
│ action          │
│ ip_address      │
│ user_agent      │
│ success         │
│ failure_reason  │
│ correlation_id  │
│ created_at      │
└─────────────────┘

┌─────────────────┐
│ ServiceCredential│
├─────────────────┤
│ id (PK)         │
│ client_id       │
│ client_secret_hash│
│ service_name    │
│ is_active       │
│ created_at      │
│ updated_at      │
└─────────────────┘
```

---

## Entity Definitions

### 1. RefreshToken

**Purpose**: Stores hashed refresh tokens with family tracking for rotation and reuse detection

**Fields**:
| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PRIMARY KEY | Unique token identifier |
| family_id | UUID | NOT NULL, FK → TokenFamily | Links tokens from same login session |
| user_id | UUID | NOT NULL | User identifier from external service |
| user_type | VARCHAR(20) | NOT NULL, CHECK IN ('customer', 'employee') | Distinguishes user type |
| token_hash | VARCHAR(64) | NOT NULL, UNIQUE | SHA-256 hash of refresh token |
| is_used | BOOLEAN | DEFAULT FALSE | Indicates if token has been used for refresh |
| used_at | TIMESTAMP | NULLABLE | When token was used (for audit) |
| expires_at | TIMESTAMP | NOT NULL | Token expiration (7 days from creation) |
| created_at | TIMESTAMP | DEFAULT NOW() | Token creation timestamp |
| ip_address | VARCHAR(45) | NULLABLE | IP address when token was issued |

**Indexes**:
- PRIMARY KEY on `id`
- UNIQUE INDEX on `token_hash`
- INDEX on `family_id` (for reuse detection queries)
- INDEX on `user_id` (for user token lookup)
- INDEX on `expires_at` (for cleanup queries)

**Validation Rules**:
- `token_hash` must be exactly 64 characters (SHA-256 hex output)
- `expires_at` must be in the future when creating
- `user_type` must be 'customer' or 'employee'
- `is_used` cannot be changed from TRUE to FALSE

**State Transitions**:
1. Created: `is_used = FALSE, used_at = NULL`
2. Used for Refresh: `is_used = TRUE, used_at = NOW()`
3. Expired: Soft delete or hard delete after grace period

---

### 2. TokenFamily

**Purpose**: Tracks lineage of refresh tokens for detecting reuse across multiple refresh cycles

**Fields**:
| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| family_id | UUID | PRIMARY KEY | Unique family identifier |
| user_id | UUID | NOT NULL | User who owns this token family |
| user_type | VARCHAR(20) | NOT NULL, CHECK IN ('customer', 'employee') | User type |
| created_at | TIMESTAMP | DEFAULT NOW() | When family was created (initial login) |
| last_refresh_at | TIMESTAMP | DEFAULT NOW() | Last time any token in family was refreshed |

**Indexes**:
- PRIMARY KEY on `family_id`
- INDEX on `user_id` (for user family lookup)

**Validation Rules**:
- `last_refresh_at` must be >= `created_at`
- Cannot have multiple active families for same user (business rule enforced in service layer)

**Lifecycle**:
1. Created on user login
2. Updated on each token refresh (last_refresh_at)
3. Invalidated on reuse detection
4. Deleted after all tokens expire + grace period (30 days)

---

### 3. RevokedToken

**Purpose**: Stores revoked access tokens for distributed validation (supports <2s propagation via Redis + DB fallback)

**Fields**:
| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PRIMARY KEY | Unique record identifier |
| jti | VARCHAR(100) | NOT NULL, UNIQUE | JWT ID claim from token |
| user_id | UUID | NOT NULL | User whose token was revoked |
| user_type | VARCHAR(20) | NOT NULL, CHECK IN ('customer', 'employee') | User type |
| revoked_at | TIMESTAMP | DEFAULT NOW() | When token was revoked |
| expires_at | TIMESTAMP | NOT NULL | Token expiration (for cleanup) |
| reason | VARCHAR(100) | NOT NULL | Revocation reason (logout, password_change, admin_action, etc.) |

**Indexes**:
- PRIMARY KEY on `id`
- UNIQUE INDEX on `jti` (fast lookup during validation)
- INDEX on `expires_at` (for cleanup queries)
- INDEX on `user_id` (for user-specific revocation)

**Validation Rules**:
- `jti` must be unique (duplicate revocation is idempotent)
- `expires_at` must be >= `revoked_at`
- `reason` must be one of: logout, password_change, account_disabled, admin_action, reuse_detected

**Cleanup Strategy**:
- Delete records where `expires_at < NOW()` (tokens already expired)
- Run cleanup job daily to remove expired revocation records

---

### 4. AccountLockout

**Purpose**: Tracks failed login attempts and lockout state per user account

**Fields**:
| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PRIMARY KEY | Unique record identifier |
| user_id | UUID | NOT NULL | User identifier |
| user_type | VARCHAR(20) | NOT NULL, CHECK IN ('customer', 'employee') | User type |
| failed_attempts | INTEGER | DEFAULT 0, CHECK >= 0 | Number of consecutive failed attempts |
| locked_until | TIMESTAMP | NULLABLE | Lockout expiration (15 min from 5th failure) |
| last_attempt_at | TIMESTAMP | DEFAULT NOW() | Last authentication attempt timestamp |
| created_at | TIMESTAMP | DEFAULT NOW() | Record creation timestamp |
| updated_at | TIMESTAMP | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- PRIMARY KEY on `id`
- UNIQUE INDEX on `(user_id, user_type)` (one lockout record per user)
- INDEX on `locked_until` (for active lockout queries)

**Validation Rules**:
- `failed_attempts` must be >= 0 and <= 5
- `locked_until` must be NULL OR >= `last_attempt_at`
- Reset `failed_attempts = 0` on successful login

**State Transitions**:
1. 0-4 failures: `failed_attempts++, locked_until = NULL`
2. 5th failure: `failed_attempts = 5, locked_until = NOW() + 15 minutes`
3. Successful login: `failed_attempts = 0, locked_until = NULL`
4. Lockout expired: `failed_attempts = 0, locked_until = NULL` (reset on next attempt)

---

### 5. IpRateLimit

**Purpose**: Tracks failed authentication attempts per IP address for distributed brute force protection

**Fields**:
| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PRIMARY KEY | Unique record identifier |
| ip_address | VARCHAR(45) | NOT NULL, UNIQUE | IPv4 or IPv6 address |
| failed_attempts | INTEGER | DEFAULT 0, CHECK >= 0 | Failed attempts in current window |
| blocked_until | TIMESTAMP | NULLABLE | IP block expiration (15 min from 20th failure) |
| window_start | TIMESTAMP | DEFAULT NOW() | Start of current 15-minute window |
| created_at | TIMESTAMP | DEFAULT NOW() | Record creation timestamp |
| updated_at | TIMESTAMP | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- PRIMARY KEY on `id`
- UNIQUE INDEX on `ip_address` (fast lookup during authentication)
- INDEX on `blocked_until` (for active block queries)

**Validation Rules**:
- `failed_attempts` must be >= 0 and <= 20
- `blocked_until` must be NULL OR >= `window_start`
- Reset `failed_attempts = 0, window_start = NOW()` when window expires (15 minutes)

**State Transitions**:
1. 0-19 failures: `failed_attempts++`
2. 20th failure: `failed_attempts = 20, blocked_until = NOW() + 15 minutes`
3. Block expired: `failed_attempts = 0, window_start = NOW(), blocked_until = NULL`
4. Window expired (no block): `failed_attempts = 0, window_start = NOW()`

---

### 6. AuthAuditLog

**Purpose**: Immutable audit trail of all authentication events for security monitoring and compliance

**Fields**:
| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PRIMARY KEY | Unique log entry identifier |
| user_id | UUID | NULLABLE | User identifier (NULL for failed attempts with invalid username) |
| user_type | VARCHAR(20) | NULLABLE, CHECK IN ('customer', 'employee', 'service') | User type |
| action | VARCHAR(50) | NOT NULL | Action performed (login, refresh, validate, revoke, logout) |
| ip_address | VARCHAR(45) | NOT NULL | Client IP address |
| user_agent | TEXT | NULLABLE | Client user agent string |
| success | BOOLEAN | NOT NULL | Whether action succeeded |
| failure_reason | VARCHAR(200) | NULLABLE | Reason for failure (invalid_credentials, account_locked, etc.) |
| correlation_id | VARCHAR(100) | NULLABLE | Request correlation ID for distributed tracing |
| created_at | TIMESTAMP | DEFAULT NOW() | Log entry timestamp |

**Indexes**:
- PRIMARY KEY on `id`
- INDEX on `user_id` (for user activity queries)
- INDEX on `created_at` (for time-based queries)
- INDEX on `correlation_id` (for tracing)
- INDEX on `action, success` (for metrics)

**Validation Rules**:
- `action` must be one of: login, refresh, validate, revoke, logout, service_auth
- `failure_reason` is REQUIRED when `success = FALSE`
- Records are IMMUTABLE (no updates, only inserts)

**Retention Policy**:
- Keep audit logs for 90 days minimum (compliance requirement)
- Archive to cold storage after 90 days
- Never delete audit logs (regulatory compliance)

---

### 7. ServiceCredential

**Purpose**: Stores service-to-service authentication credentials for microservice integration

**Fields**:
| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PRIMARY KEY | Unique credential identifier |
| client_id | VARCHAR(100) | NOT NULL, UNIQUE | Service client identifier |
| client_secret_hash | VARCHAR(64) | NOT NULL | SHA-256 hash of client secret |
| service_name | VARCHAR(100) | NOT NULL | Descriptive service name |
| is_active | BOOLEAN | DEFAULT TRUE | Whether credential is active |
| created_at | TIMESTAMP | DEFAULT NOW() | Credential creation timestamp |
| updated_at | TIMESTAMP | DEFAULT NOW() | Last update timestamp |

**Indexes**:
- PRIMARY KEY on `id`
- UNIQUE INDEX on `client_id` (fast lookup during service auth)
- INDEX on `is_active` (for active credential queries)

**Validation Rules**:
- `client_id` must be unique and follow pattern: `service-{environment}-{name}`
- `client_secret_hash` must be exactly 64 characters (SHA-256 hex output)
- Cannot delete credentials, only mark `is_active = FALSE`

**Security**:
- Client secrets NEVER stored in plaintext (SHA-256 hash only)
- Secret rotation requires creating new record and deactivating old one
- Constant-time comparison when validating secrets

---

## Database Naming Conventions

**Tables**: snake_case (e.g., `refresh_tokens`, `account_lockouts`)
**Columns**: snake_case (e.g., `user_id`, `expires_at`)
**Indexes**: `idx_{table}_{column}` (e.g., `idx_refresh_tokens_family_id`)
**Foreign Keys**: `fk_{source_table}_{target_table}` (e.g., `fk_refresh_tokens_token_families`)

---

## Optimistic Concurrency Control

**Pattern**: RowVersion byte array on entities requiring concurrent update protection

**Entities with RowVersion**:
- `AccountLockout` (prevents race conditions on failed attempt increments)
- `IpRateLimit` (prevents race conditions on IP-based rate limiting)

**Implementation**:
```sql
ALTER TABLE account_lockouts ADD COLUMN version BYTEA DEFAULT '\\x0000000000000000'::bytea;
ALTER TABLE ip_rate_limits ADD COLUMN version BYTEA DEFAULT '\\x0000000000000000'::bytea;
```

**EF Core Configuration**:
```csharp
builder.Property(e => e.Version)
    .HasColumnName("version")
    .IsRowVersion()
    .HasDefaultValueSql("'\\x0000000000000000'::bytea")
    .ValueGeneratedOnAddOrUpdate()
    .IsRequired();
```

---

## Data Retention and Cleanup

| Entity | Retention Policy | Cleanup Strategy |
|--------|------------------|------------------|
| RefreshToken | 7 days + 30 day grace period | Hard delete expired tokens after grace period |
| TokenFamily | Until all tokens expire + 30 days | Cascade delete when cleanup runs |
| RevokedToken | Until token expiration | Hard delete after `expires_at` |
| AccountLockout | 90 days of inactivity | Delete records not updated in 90 days |
| IpRateLimit | 90 days of inactivity | Delete records not updated in 90 days |
| AuthAuditLog | 90 days (then archive) | Archive to cold storage, never delete |
| ServiceCredential | Indefinite (soft delete only) | Mark `is_active = FALSE`, never hard delete |

**Cleanup Jobs**:
1. **Daily Cleanup**: Remove expired tokens and revocations
2. **Weekly Cleanup**: Remove stale lockout and rate limit records
3. **Monthly Archive**: Move old audit logs to cold storage

---

## Entity Relationship Rules

### RefreshToken ↔ TokenFamily
- **Relationship**: Many-to-One (many tokens belong to one family)
- **Cascade**: When family is deleted, all tokens are deleted
- **Constraint**: All tokens in a family must have same `user_id` and `user_type`

### Token Reuse Detection Flow
1. Refresh request with token T1 from family F1
2. Check if T1 has `is_used = TRUE`
3. If YES → Find all tokens with `family_id = F1` → Mark all as invalid
4. If NO → Mark T1 as `is_used = TRUE` → Create new token T2 with same `family_id = F1`

---

## Security Considerations

### Hash Storage
- **RefreshToken.token_hash**: SHA-256 hash of refresh token (256-bit security)
- **ServiceCredential.client_secret_hash**: SHA-256 hash of service secret
- **Constant-Time Comparison**: Use `CryptographicOperations.FixedTimeEquals()` to prevent timing attacks

### Sensitive Data Protection
- Never log or expose token values (only hashes)
- Never return `token_hash` or `client_secret_hash` in API responses
- Redact IP addresses in logs after 30 days (GDPR compliance)

### Database Security
- Row-level security policies for multi-tenant isolation (future enhancement)
- Encrypted connections (SSL/TLS) required for all database access
- Least privilege access for application database user (no DDL permissions)

---

## Status

✅ **Entity Design Complete** - All entities defined with fields and constraints
✅ **Relationships Mapped** - Token family tracking and audit relationships
✅ **Indexes Planned** - Performance-optimized query patterns
✅ **Security Validated** - Hash storage, no plaintext secrets
✅ **Cleanup Strategy Defined** - Data retention and archival policies

**Next Step**: Generate OpenAPI contracts from functional requirements
