using Maliev.AuthService.Api.Models.Request;
using Maliev.AuthService.Api.Models.Response;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Maliev.AuthService.Api.Services;
/// <summary>
/// Service for Authentication operations
/// </summary>

public class AuthenticationService : IAuthenticationService
{
    private readonly AuthDbContext _dbContext;
    private readonly ITokenGenerator _tokenGenerator;
    private readonly ITokenValidator _tokenValidator;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IAccountLockoutService _accountLockoutService;
    private readonly IRateLimitService _rateLimitService;
    private readonly IIAMServiceClient _iamServiceClient;
    private readonly ILogger<AuthenticationService> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
    private readonly MassTransit.IPublishEndpoint _publishEndpoint;
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticationService"/> class.
    /// </summary>

    public AuthenticationService(
        AuthDbContext dbContext,
        ITokenGenerator tokenGenerator,
        ITokenValidator tokenValidator,
        IRefreshTokenService refreshTokenService,
        IAccountLockoutService accountLockoutService,
        IRateLimitService rateLimitService,
        IIAMServiceClient iamServiceClient,
        ILogger<AuthenticationService> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration,
        MassTransit.IPublishEndpoint publishEndpoint)
    {
        _dbContext = dbContext;
        _tokenGenerator = tokenGenerator;
        _tokenValidator = tokenValidator;
        _refreshTokenService = refreshTokenService;
        _accountLockoutService = accountLockoutService;
        _rateLimitService = rateLimitService;
        _iamServiceClient = iamServiceClient;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
        _publishEndpoint = publishEndpoint;
    }
    /// <inheritdoc/>
    public async Task<AuthenticationResult> AuthenticateAsync(LoginRequest request, string? ipAddress)
    {
        // Authenticate user against external services and issue JWT tokens with IAM permissions
        if (string.IsNullOrWhiteSpace(request.UserType))
        {
            throw new ArgumentException("UserType is required");
        }

        var normalizedType = request.UserType.ToLowerInvariant();
        if (normalizedType != "customer" && normalizedType != "employee")
        {
            throw new ArgumentException("Invalid UserType");
        }

        var userType = normalizedType == "customer" ? UserType.Customer : UserType.Employee;

        // Check rate limiting first
        if (!string.IsNullOrEmpty(ipAddress) && await _rateLimitService.IsRateLimitExceededAsync(ipAddress))
        {
            await LogAuditAsync(null, userType, "login", ipAddress, false, "Rate limit exceeded");

            await _publishEndpoint.Publish(new Maliev.MessagingContracts.Generated.LoginFailedEvent(
                Guid.NewGuid(),
                "LoginFailedEvent",
                Maliev.MessagingContracts.Generated.MessageType.Event,
                "1.0.0",
                "AuthService",
                ["NotificationService"],
                Guid.NewGuid(),
                null,
                DateTimeOffset.UtcNow,
                false,
                new Maliev.MessagingContracts.Generated.LoginFailedEventPayload(
                    request.Username,
                    null,
                    normalizedType == "customer" ? "Customer" : "Employee",
                    ipAddress,
                    "RateLimitExceeded",
                    DateTimeOffset.UtcNow
                )
            ));

            var blockedUntil = await _rateLimitService.GetBlockedUntilAsync(ipAddress);
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "rate_limit_exceeded",
                ErrorDescription = "Too many failed attempts. Please try again later.",
                RetryAfter = blockedUntil
            };
        }

        var validationResult = await ValidateCredentialsAsync(request.Username, request.Password, userType);

        // Check account lockout BEFORE returning invalid credentials error
        // This ensures locked accounts return 423 instead of 401
        if (validationResult.UserId.HasValue && await _accountLockoutService.IsAccountLockedAsync(validationResult.UserId.Value, userType))
        {
            await LogAuditAsync(validationResult.UserId.Value, userType, "login", ipAddress, false, "Account locked");

            await _publishEndpoint.Publish(new Maliev.MessagingContracts.Generated.LoginFailedEvent(
                Guid.NewGuid(),
                "LoginFailedEvent",
                Maliev.MessagingContracts.Generated.MessageType.Event,
                "1.0.0",
                "AuthService",
                ["NotificationService"],
                Guid.NewGuid(),
                null,
                DateTimeOffset.UtcNow,
                false,
                new Maliev.MessagingContracts.Generated.LoginFailedEventPayload(
                    request.Username,
                    validationResult.UserId.Value.ToString(),
                    normalizedType == "customer" ? "Customer" : "Employee",
                    ipAddress,
                    "AccountLocked",
                    DateTimeOffset.UtcNow
                )
            ));

            var lockedUntil = await _accountLockoutService.GetLockedUntilAsync(validationResult.UserId.Value, userType);
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "account_locked",
                ErrorDescription = "Account is locked due to too many failed login attempts.",
                LockedUntil = lockedUntil
            };
        }

        if (!validationResult.IsValid)
        {
            // Record failed attempt for rate limiting
            if (!string.IsNullOrEmpty(ipAddress))
            {
                await _rateLimitService.RecordFailedAttemptAsync(ipAddress);
            }

            // Record failed attempt for account lockout if we have a userId
            if (validationResult.UserId.HasValue)
            {
                await _accountLockoutService.RecordFailedAttemptAsync(validationResult.UserId.Value, userType);
            }

            await LogAuditAsync(validationResult.UserId, userType, "login", ipAddress, false, validationResult.FailureReason);

            await _publishEndpoint.Publish(new Maliev.MessagingContracts.Generated.LoginFailedEvent(
                Guid.NewGuid(),
                "LoginFailedEvent",
                Maliev.MessagingContracts.Generated.MessageType.Event,
                "1.0.0",
                "AuthService",
                ["NotificationService"],
                Guid.NewGuid(),
                null,
                DateTimeOffset.UtcNow,
                false,
                new Maliev.MessagingContracts.Generated.LoginFailedEventPayload(
                    request.Username,
                    validationResult.UserId?.ToString(),
                    normalizedType == "customer" ? "Customer" : "Employee",
                    ipAddress,
                    "InvalidCredentials",
                    DateTimeOffset.UtcNow
                )
            ));

            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "invalid_credentials",
                ErrorDescription = "Invalid username or password"
            };
        }

        var userId = validationResult.UserId!.Value;
        var principalId = (validationResult.PrincipalId == null || validationResult.PrincipalId == Guid.Empty)
            ? userId
            : validationResult.PrincipalId.Value;

        // Validate credentials succeeded, reset lockout
        await _accountLockoutService.ResetFailedAttemptsAsync(userId, userType);

        // Resolve permissions from IAM (Always enabled)
        IEnumerable<string>? permissions = null;
        IEnumerable<string>? roles = null;

        try
        {
            var iamResponse = await _iamServiceClient.ResolvePermissionsAsync(principalId);
            permissions = iamResponse.Permissions;
            roles = iamResponse.Roles;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve permissions from IAM for user {UserId}. Issuing token without permissions.", userId);
            // Fail open: Issue token without permissions rather than block login
        }

        var accessToken = _tokenGenerator.GenerateAccessToken(principalId, request.UserType, validationResult.Email, validationResult.Name, permissions, roles);
        var (refreshTokenEntity, refreshTokenValue) = await _refreshTokenService.CreateRefreshTokenAsync(userId, principalId, userType, validationResult.Email, validationResult.Name, ipAddress);

        await LogAuditAsync(userId, userType, "login", ipAddress, true, null);

        await _publishEndpoint.Publish(new Maliev.MessagingContracts.Generated.UserLoggedInEvent(
            Guid.NewGuid(),
            "UserLoggedInEvent",
            Maliev.MessagingContracts.Generated.MessageType.Event,
            "1.0.0",
            "AuthService",
            ["NotificationService"],
            Guid.NewGuid(),
            null,
            DateTimeOffset.UtcNow,
            false,
            new Maliev.MessagingContracts.Generated.UserLoggedInEventPayload(
                userId.ToString(),
                principalId.ToString(),
                normalizedType == "customer" ? "Customer" : "Employee",
                ipAddress,
                "Password",
                DateTimeOffset.UtcNow
            )
        ));

        return new AuthenticationResult
        {
            Success = true,
            PrincipalId = principalId,
            Response = new LoginResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenValue,
                TokenType = "Bearer",
                ExpiresIn = 900,
                User = new UserIdentityResponse
                {
                    UserId = principalId.ToString(),
                    UserType = request.UserType,
                    Email = validationResult.Email,
                    Name = validationResult.Name
                }
            }
        };
    }

    /// <inheritdoc/>
    public async Task<TokenResponse?> RefreshTokenAsync(RefreshRequest request, string? ipAddress)
    {
        var refreshToken = await _refreshTokenService.ValidateRefreshTokenAsync(request.RefreshToken);
        if (refreshToken == null)
        {
            _logger.LogWarning("Invalid refresh token");
            return null;
        }

        var (newRefreshTokenEntity, newRefreshTokenValue) = await _refreshTokenService.RotateRefreshTokenAsync(refreshToken, ipAddress);
        var userTypeString = refreshToken.UserType == UserType.Customer ? "customer" : "employee";

        // Resolve permissions from IAM (Always enabled)
        IEnumerable<string>? permissions = null;
        IEnumerable<string>? roles = null;

        try
        {
            // Use the stored PrincipalId for consistent permission resolution across token lifecycle
            var iamResponse = await _iamServiceClient.ResolvePermissionsAsync(refreshToken.PrincipalId);
            permissions = iamResponse.Permissions;
            roles = iamResponse.Roles;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve permissions from IAM during token refresh for user {UserId}. Issuing token without permissions.", refreshToken.UserId);
            // Fail open: Issue token without permissions rather than block refresh
        }

        var accessToken = _tokenGenerator.GenerateAccessToken(refreshToken.PrincipalId, userTypeString, refreshToken.Email, refreshToken.Name, permissions, roles);

        await LogAuditAsync(refreshToken.UserId, refreshToken.UserType, "token_refresh", ipAddress, true, null);

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = newRefreshTokenValue,
            TokenType = "Bearer",
            ExpiresIn = 900
        };
    }
    /// <inheritdoc/>
    public async Task<ValidateResponse> ValidateTokenAsync(ValidateRequest request)
    {
        var principal = await _tokenValidator.ValidateAccessTokenAsync(request.AccessToken);
        if (principal == null)
        {
            return new ValidateResponse
            {
                Valid = false,
                Error = "Invalid token"
            };
        }

        // Use shorthand claim names since we disabled MapInboundClaims in TokenValidator
        var jtiClaim = principal.FindFirst("jti");
        if (jtiClaim != null && await _tokenValidator.IsTokenRevokedAsync(jtiClaim.Value))
        {
            return new ValidateResponse
            {
                Valid = false,
                Error = "Token has been revoked"
            };
        }

        var userId = principal.FindFirst("sub")?.Value;
        var userType = principal.FindFirst("user_type")?.Value;
        var email = principal.FindFirst("email")?.Value;
        var name = principal.FindFirst("name")?.Value;
        var roles = principal.FindAll("roles").Select(c => c.Value).ToList();
        var permissions = principal.FindAll("permissions").Select(c => c.Value).ToList();

        return new ValidateResponse
        {
            Valid = true,
            UserId = userId,
            UserType = userType,
            Email = email,
            Name = name,
            Roles = roles,
            Permissions = permissions
        };
    }
    /// <inheritdoc/>
    public async Task<bool> RevokeTokenAsync(RevokeRequest request)
    {
        var principal = await _tokenValidator.ValidateAccessTokenAsync(request.Token);
        if (principal == null)
        {
            return false;
        }

        // Use shorthand claim names since we disabled MapInboundClaims in TokenValidator
        var jtiClaim = principal.FindFirst("jti")?.Value;
        var userIdClaim = principal.FindFirst("sub")?.Value;
        var userTypeClaim = principal.FindFirst("user_type")?.Value;

        if (string.IsNullOrEmpty(jtiClaim) || string.IsNullOrEmpty(userIdClaim))
        {
            return false;
        }

        // Check if already revoked (idempotency)
        if (await _tokenValidator.IsTokenRevokedAsync(jtiClaim))
        {
            return true;
        }

        var userId = Guid.Parse(userIdClaim);
        var userType = userTypeClaim?.ToLowerInvariant() == "customer" ? UserType.Customer : UserType.Employee;

        var expClaim = principal.FindFirst("exp")?.Value;
        var expiresAt = expClaim != null
            ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(expClaim)).UtcDateTime
            : DateTime.UtcNow.AddMinutes(15);

        var revokedToken = new RevokedToken
        {
            Id = Guid.NewGuid(),
            Jti = jtiClaim,
            UserId = userId,
            UserType = userType,
            RevokedAt = DateTime.UtcNow,
            ExpiresAt = expiresAt,
            Reason = "User requested revocation"
        };

        _dbContext.RevokedTokens.Add(revokedToken);
        await _dbContext.SaveChangesAsync();

        await LogAuditAsync(userId, userType, "token_revoke", null, true, null);

        return true;
    }
    /// <inheritdoc/>
    public async Task<bool> LogoutAsync(LogoutRequest request)
    {
        var refreshToken = await _refreshTokenService.ValidateRefreshTokenAsync(request.RefreshToken);
        if (refreshToken == null)
        {
            return false;
        }

        await _refreshTokenService.RevokeTokenFamilyAsync(refreshToken.FamilyId, "User logout");

        await LogAuditAsync(refreshToken.UserId, refreshToken.UserType, "logout", null, true, null);

        await _publishEndpoint.Publish(new Maliev.MessagingContracts.Generated.UserLoggedOutEvent(
            Guid.NewGuid(),
            "UserLoggedOutEvent",
            Maliev.MessagingContracts.Generated.MessageType.Event,
            "1.0.0",
            "AuthService",
            ["NotificationService"],
            Guid.NewGuid(),
            null,
            DateTimeOffset.UtcNow,
            false,
            new Maliev.MessagingContracts.Generated.UserLoggedOutEventPayload(
                refreshToken.UserId.ToString(),
                refreshToken.UserType == UserType.Customer ? "Customer" : "Employee",
                DateTimeOffset.UtcNow
            )
        ));

        return true;
    }

    /// <inheritdoc/>
    public async Task<LoginResponse?> AuthenticateServiceAsync(ServiceLoginRequest request, string? ipAddress)
    {
        var serviceCredential = await _dbContext.ServiceCredentials
            .FirstOrDefaultAsync(sc => sc.ClientId == request.ClientId && sc.IsActive);

        if (serviceCredential == null)
        {
            await LogAuditAsync(null, null, "service_login", ipAddress, false, "Invalid client ID");

            await _publishEndpoint.Publish(new Maliev.MessagingContracts.Generated.LoginFailedEvent(
                Guid.NewGuid(),
                "LoginFailedEvent",
                Maliev.MessagingContracts.Generated.MessageType.Event,
                "1.0.0",
                "AuthService",
                ["NotificationService"],
                Guid.NewGuid(),
                null,
                DateTimeOffset.UtcNow,
                false,
                new Maliev.MessagingContracts.Generated.LoginFailedEventPayload(
                    request.ClientId,
                    null,
                    "Service",
                    ipAddress,
                    "InvalidCredentials",
                    DateTimeOffset.UtcNow
                )
            ));

            return null;
        }

        var secretHash = HashSecret(request.ClientSecret);
        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(secretHash),
            Encoding.UTF8.GetBytes(serviceCredential.ClientSecretHash)))
        {
            await LogAuditAsync(null, null, "service_login", ipAddress, false, "Invalid client secret");

            await _publishEndpoint.Publish(new Maliev.MessagingContracts.Generated.LoginFailedEvent(
                Guid.NewGuid(),
                "LoginFailedEvent",
                Maliev.MessagingContracts.Generated.MessageType.Event,
                "1.0.0",
                "AuthService",
                ["NotificationService"],
                Guid.NewGuid(),
                null,
                DateTimeOffset.UtcNow,
                false,
                new Maliev.MessagingContracts.Generated.LoginFailedEventPayload(
                    request.ClientId,
                    null,
                    "Service",
                    ipAddress,
                    "InvalidCredentials",
                    DateTimeOffset.UtcNow
                )
            ));

            return null;
        }

        // Resolve permissions from IAM (Always enabled)
        IEnumerable<string>? permissions = null;
        IEnumerable<string>? roles = null;

        // Use the PrincipalId from ServiceCredential for IAM resolution
        if (serviceCredential.PrincipalId.HasValue)
        {
            try
            {
                var iamResponse = await _iamServiceClient.ResolvePermissionsAsync(serviceCredential.PrincipalId.Value);
                permissions = iamResponse.Permissions;
                roles = iamResponse.Roles;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to resolve permissions from IAM for service {ClientId}. Issuing token without permissions.", request.ClientId);
                // Fail open: Issue token without permissions rather than block service login
            }
        }
        else
        {
            _logger.LogWarning("Service {ClientId} has no PrincipalId mapping. Token will be issued without IAM permissions. Register this service in IAM.", request.ClientId);
        }

        var accessToken = await _tokenGenerator.GenerateServiceAccessTokenAsync(request.ClientId, serviceCredential.ServiceName, permissions, roles);

        await LogAuditAsync(null, null, "service_login", ipAddress, true, null);

        await _publishEndpoint.Publish(new Maliev.MessagingContracts.Generated.UserLoggedInEvent(
            Guid.NewGuid(),
            "UserLoggedInEvent",
            Maliev.MessagingContracts.Generated.MessageType.Event,
            "1.0.0",
            "AuthService",
            ["NotificationService"],
            Guid.NewGuid(),
            null,
            DateTimeOffset.UtcNow,
            false,
            new Maliev.MessagingContracts.Generated.UserLoggedInEventPayload(
                request.ClientId,
                serviceCredential.PrincipalId?.ToString(),
                "Service",
                ipAddress,
                "ServiceCredential",
                DateTimeOffset.UtcNow
            )
        ));

        return new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = null, // Service tokens don't have refresh tokens
            TokenType = "Bearer",
            ExpiresIn = 3600,
            User = new UserIdentityResponse
            {
                UserId = request.ClientId,
                UserType = "service",
                Name = serviceCredential.ServiceName
            }
        };
    }

    /// <inheritdoc/>
    public async Task<AuthenticationResult> ExchangeGoogleTokenAsync(GoogleExchangeRequest request, string? ipAddress)
    {
        // 1. Validate @maliev.com domain
        if (!request.Email.EndsWith("@maliev.com", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Google exchange rejected for non-maliev.com email: {Email}", request.Email);
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "invalid_domain",
                ErrorDescription = "Only @maliev.com email addresses are allowed"
            };
        }

        // 2. Look up employee by email in EmployeeService
        var (employeeLookupSuccess, employeeId, principalId, employeeName, employmentStatus, lookupError) =
            await LookupEmployeeByEmailAsync(request.Email);

        if (!employeeLookupSuccess)
        {
            // Service unavailable (timeout, network error)
            if (lookupError == "service_unavailable")
            {
                _logger.LogError("EmployeeService unavailable during Google exchange for {Email}", request.Email);
                await LogAuditAsync(null, UserType.Employee, "google_exchange", ipAddress, false, "EmployeeService unavailable");

                return new AuthenticationResult
                {
                    Success = false,
                    ErrorCode = "service_unavailable",
                    ErrorDescription = "Employee lookup service is currently unavailable"
                };
            }

            // Employee not found (404)
            // Call auto-provision endpoint
            _logger.LogInformation("Employee not found for email {Email} during Google exchange. Triggering auto-provisioning.", request.Email);

            var (provisionSuccess, provEmployeeId, provPrincipalId, provName, provStatus, provisionError) =
                await ProvisionEmployeeAsync(request.Email, request.FullName ?? request.Email);

            if (!provisionSuccess)
            {
                _logger.LogError("Auto-provisioning failed for {Email}: {Error}", request.Email, provisionError);
                await LogAuditAsync(null, UserType.Employee, "google_exchange", ipAddress, false, $"Auto-provision failed: {provisionError}");

                return new AuthenticationResult
                {
                    Success = false,
                    ErrorCode = "provision_failed",
                    ErrorDescription = "Failed to create your employee account automatically. Please contact IT support."
                };
            }

            employeeId = provEmployeeId;
            principalId = provPrincipalId;
            employeeName = provName;
            employmentStatus = provStatus;

            _logger.LogInformation("Successfully auto-provisioned employee for {Email} with PrincipalId {PrincipalId}",
                request.Email, principalId);
        }

        // 3. Check EmploymentStatus != "Terminated"
        if (string.Equals(employmentStatus, "Terminated", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Google exchange rejected for terminated employee: {Email}", request.Email);
            await LogAuditAsync(employeeId, UserType.Employee, "google_exchange", ipAddress, false, "Account terminated");

            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "inactive_account",
                ErrorDescription = "Employee account is inactive"
            };
        }

        // 4. Resolve permissions from IAM (with fail-safe)
        IEnumerable<string>? permissions = null;
        IEnumerable<string>? roles = null;

        try
        {
            var iamResponse = await _iamServiceClient.ResolvePermissionsAsync(principalId!.Value);
            permissions = iamResponse.Permissions;
            roles = iamResponse.Roles;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve permissions from IAM for Google SSO user {Email}. Issuing token without permissions.", request.Email);
            // Fail open: Issue token without permissions rather than block login
        }

        // 5. Generate JWT with permissions (same as login flow)
        var accessToken = _tokenGenerator.GenerateAccessToken(
            principalId!.Value,
            "employee",
            request.Email,
            employeeName ?? request.FullName ?? request.Email,
            permissions,
            roles);

        // 6. Create refresh token (7-day expiry)
        var (refreshTokenEntity, refreshTokenValue) = await _refreshTokenService.CreateRefreshTokenAsync(
            employeeId!.Value,
            principalId.Value,
            UserType.Employee,
            request.Email,
            employeeName ?? request.FullName ?? request.Email,
            ipAddress);

        // 7. Audit log + publish UserLoggedInEvent
        await LogAuditAsync(employeeId.Value, UserType.Employee, "google_exchange", ipAddress, true, null);

        await _publishEndpoint.Publish(new Maliev.MessagingContracts.Generated.UserLoggedInEvent(
            Guid.NewGuid(),
            "UserLoggedInEvent",
            Maliev.MessagingContracts.Generated.MessageType.Event,
            "1.0.0",
            "AuthService",
            ["NotificationService"],
            Guid.NewGuid(),
            null,
            DateTimeOffset.UtcNow,
            false,
            new Maliev.MessagingContracts.Generated.UserLoggedInEventPayload(
                employeeId.Value.ToString(),
                principalId.Value.ToString(),
                "Employee",
                ipAddress,
                "GoogleSSO",
                DateTimeOffset.UtcNow
            )
        ));

        // 8. Return LoginResponse
        return new AuthenticationResult
        {
            Success = true,
            PrincipalId = principalId.Value,
            Response = new LoginResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenValue,
                TokenType = "Bearer",
                ExpiresIn = 900,
                User = new UserIdentityResponse
                {
                    UserId = principalId.Value.ToString(),
                    UserType = "employee",
                    Email = request.Email,
                    Name = employeeName ?? request.FullName ?? request.Email
                }
            }
        };
    }

    /// <summary>
    /// Looks up an employee by email in the EmployeeService.
    /// </summary>
    /// <param name="email">The employee's work email address.</param>
    /// <returns>A tuple containing lookup success status and employee details.</returns>
    private async Task<(bool Success, Guid? EmployeeId, Guid? PrincipalId, string? Name, string? EmploymentStatus, string? Error)>
        LookupEmployeeByEmailAsync(string email)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("EmployeeServiceClient");
            var encodedEmail = Uri.EscapeDataString(email);
            var response = await client.GetAsync($"/employee/v1/employees/by-email/{encodedEmail}");

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                _logger.LogInformation("Employee not found for email: {Email}", email);
                return (false, null, null, null, null, "not_found");
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Employee lookup failed with status {StatusCode} for email: {Email}",
                    response.StatusCode, email);
                return (false, null, null, null, null, "service_unavailable");
            }

            var result = await response.Content.ReadFromJsonAsync<EmployeeLookupResult>();
            if (result == null)
            {
                _logger.LogWarning("Employee lookup returned null result for email: {Email}", email);
                return (false, null, null, null, null, "service_unavailable");
            }

            return (true, result.EmployeeId, result.PrincipalId, result.FullName, result.EmploymentStatus, null);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Employee lookup timed out for email: {Email}", email);
            return (false, null, null, null, null, "service_unavailable");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error looking up employee by email: {Email}", email);
            return (false, null, null, null, null, "service_unavailable");
        }
    }

    /// <summary>
    /// Calls the EmployeeService auto-provision endpoint.
    /// </summary>
    private async Task<(bool Success, Guid? EmployeeId, Guid? PrincipalId, string? Name, string? EmploymentStatus, string? Error)>
        ProvisionEmployeeAsync(string email, string fullName)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("EmployeeServiceClient");
            var request = new { email, full_name = fullName };
            var response = await client.PostAsJsonAsync("/employee/v1/employees/auto-provision", request);

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Employee auto-provision failed with status {StatusCode} for email: {Email}. Error: {Error}",
                    response.StatusCode, email, errorBody);
                return (false, null, null, null, null, "provision_failed");
            }

            var result = await response.Content.ReadFromJsonAsync<EmployeeLookupResult>();
            if (result == null)
            {
                return (false, null, null, null, null, "service_unavailable");
            }

            return (true, result.EmployeeId, result.PrincipalId, result.FullName, result.EmploymentStatus, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error auto-provisioning employee by email: {Email}", email);
            return (false, null, null, null, null, "service_unavailable");
        }
    }

    private async Task<(bool IsValid, Guid? UserId, Guid? PrincipalId, string? Email, string? Name, string? FailureReason)> ValidateCredentialsAsync(
        string username, string password, UserType userType)
    {
        var serviceUrl = userType == UserType.Customer
            ? _configuration["CustomerService:BaseUrl"] ?? "http://maliev-customerservice-api"
            : _configuration["EmployeeService:BaseUrl"] ?? "http://maliev-employeeservice-api";

        var validationEndpoint = userType == UserType.Customer
            ? _configuration["CustomerService:ValidationEndpoint"]
            : _configuration["EmployeeService:ValidationEndpoint"];

        if (string.IsNullOrEmpty(validationEndpoint))
        {
            _logger.LogError("Validation endpoint not configured for {UserType}", userType);
            return (false, null, null, null, null, "Configuration error");
        }

        try
        {
            // Read timeout from configuration with 30s default
            var configKey = userType == UserType.Customer
                ? "CustomerService:ValidationTimeoutSeconds"
                : "EmployeeService:ValidationTimeoutSeconds";
            var timeoutSeconds = _configuration.GetValue<int?>(configKey) ?? 30;

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));

            var client = _httpClientFactory.CreateClient("ExternalValidation");
            var response = await client.PostAsJsonAsync($"{serviceUrl}{validationEndpoint}", new
            {
                username,
                password
            }, cts.Token);

            if (!response.IsSuccessStatusCode)
            {
                return (false, null, null, null, null, "Invalid credentials");
            }

            var result = await response.Content.ReadFromJsonAsync<CredentialValidationResult>();
            if (result == null || !result.IsValid)
            {
                // Return UserId only if it's not empty to avoid tracking lockout for unknown users globally
                var userId = result?.UserId == Guid.Empty ? null : result?.UserId;
                return (false, userId, result?.PrincipalId, null, null, "Invalid credentials");
            }

            return (true, result.UserId, result.PrincipalId, result.Email, result.Name, null);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("External service validation timed out for {UserType}", userType);
            return (false, null, null, null, null, "Service timeout");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating credentials with external service");
            return (false, null, null, null, null, "Service unavailable");
        }
    }

    private string HashSecret(string secret)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    private async Task LogAuditAsync(Guid? userId, UserType? userType, string action, string? ipAddress, bool success, string? failureReason)
    {
        var auditLog = new AuthAuditLog
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            UserType = userType,
            Action = action,
            IpAddress = ipAddress ?? "unknown",
            Success = success,
            FailureReason = failureReason,
            CreatedAt = DateTime.UtcNow
        };

        _dbContext.AuthAuditLogs.Add(auditLog);
        await _dbContext.SaveChangesAsync();
    }

    private class CredentialValidationResult
    {
        public bool IsValid { get; set; }
        public Guid UserId { get; set; }
        public Guid? PrincipalId { get; set; }
        public string? Email { get; set; }
        public string? Name { get; set; }
    }

    private record EmployeeLookupResult
    {
        public Guid EmployeeId { get; init; }
        public Guid PrincipalId { get; init; }
        public string Email { get; init; } = string.Empty;
        public string FullName { get; init; } = string.Empty;
        public string EmploymentStatus { get; init; } = string.Empty;
    }
}
