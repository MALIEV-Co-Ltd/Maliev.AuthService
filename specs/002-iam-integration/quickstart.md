# Quickstart: AuthService IAM Integration

## Overview
This feature integrates AuthService with IAM to provide permission-rich JWT tokens.

## Configuration
Add the following to your `appsettings.Development.json`:

```json
{
  "Services": {
    "IAMService": {
      "BaseUrl": "http://localhost:5100",
      "ServiceAccountToken": "dev-token-local",
      "Timeout": 200,
      "RetryCount": 2,
      "CircuitBreakerThreshold": 5
    }
  }
}
```

## Running the Integration
1. Start the **IAM Service** on port 5100.
2. Start the **AuthService**.
3. Perform a login via POST `/auth/v1/login`.
4. Inspect the returned `accessToken` (JWT).

## Verifying JWT
Decode the JWT at [jwt.io](https://jwt.io). You should see:
- `sub`: The principal's ID.
- `permissions`: An array of permissions (if enabled).
- `roles`: An array of roles (if enabled).

## Troubleshooting
- **IAM Service Down?** AuthService will log a warning and return an empty permissions array (resilience mode).
- **Latency issues?** Check `IAM Client Latency` metrics.
