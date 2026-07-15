using Maliev.AuthService.Application.DTOs.IAM;
using Maliev.AuthService.Application.DTOs.Request;
using Maliev.AuthService.Application.DTOs.Response;
using Maliev.AuthService.Application.Identity;
using Maliev.AuthService.Application.Interfaces;
using Maliev.AuthService.Domain.Entities;
using Maliev.AuthService.Infrastructure.DbContexts;
using Maliev.AuthService.Infrastructure.HttpClients;
using Maliev.Aspire.ServiceDefaults.IAM;
using Maliev.MessagingContracts.Contracts.Auth;
using Maliev.MessagingContracts;
using MassTransit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Maliev.AuthService.Infrastructure.Services;

/// <summary>
/// Handles all authentication flows: credential validation, JWT issuance, token refresh, revocation, and Google SSO exchange.
/// </summary>
public class AuthenticationService : IAuthenticationService
{
    private static readonly byte[] DummyServiceSecretHash = SHA256.HashData(
        Encoding.UTF8.GetBytes("MALIEV AuthService dummy service credential comparison"));
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
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly IEmployeeServiceClient _employeeServiceClient;
    private readonly IGoogleIdentityTokenValidator _googleIdentityTokenValidator;
    private readonly IGoogleIdentityNonceService _googleIdentityNonceService;

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
        IPublishEndpoint publishEndpoint,
        IEmployeeServiceClient employeeServiceClient,
        IGoogleIdentityTokenValidator googleIdentityTokenValidator,
        IGoogleIdentityNonceService googleIdentityNonceService)
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
        _employeeServiceClient = employeeServiceClient ?? throw new ArgumentNullException(nameof(employeeServiceClient));
        _googleIdentityTokenValidator = googleIdentityTokenValidator ?? throw new ArgumentNullException(nameof(googleIdentityTokenValidator));
        _googleIdentityNonceService = googleIdentityNonceService ?? throw new ArgumentNullException(nameof(googleIdentityNonceService));
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
            EnqueueAuditLog(null, userType, "login", ipAddress, false, "Rate limit exceeded");

            await _publishEndpoint.Publish(new LoginFailedEvent(
                Guid.NewGuid(), "LoginFailedEvent", MessageType.Event, "1.0.0",
                "AuthService", ["NotificationService"], Guid.NewGuid(), null, DateTimeOffset.UtcNow, false,
                new LoginFailedEventPayload(request.Username, null,
                    normalizedType == "customer" ? "Customer" : "Employee",
                    ipAddress, "RateLimitExceeded", DateTimeOffset.UtcNow)));

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
            EnqueueAuditLog(validationResult.UserId.Value, userType, "login", ipAddress, false, "Account locked");

            await _publishEndpoint.Publish(new LoginFailedEvent(
                Guid.NewGuid(), "LoginFailedEvent", MessageType.Event, "1.0.0",
                "AuthService", ["NotificationService"], Guid.NewGuid(), null, DateTimeOffset.UtcNow, false,
                new LoginFailedEventPayload(request.Username, validationResult.UserId.Value.ToString(),
                    normalizedType == "customer" ? "Customer" : "Employee",
                    ipAddress, "AccountLocked", DateTimeOffset.UtcNow)));

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

            EnqueueAuditLog(validationResult.UserId, userType, "login", ipAddress, false, validationResult.FailureReason);

            await _publishEndpoint.Publish(new LoginFailedEvent(
                Guid.NewGuid(), "LoginFailedEvent", MessageType.Event, "1.0.0",
                "AuthService", ["NotificationService"], Guid.NewGuid(), null, DateTimeOffset.UtcNow, false,
                new LoginFailedEventPayload(request.Username, validationResult.UserId?.ToString(),
                    normalizedType == "customer" ? "Customer" : "Employee",
                    ipAddress, "InvalidCredentials", DateTimeOffset.UtcNow)));

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

        await _accountLockoutService.ResetFailedAttemptsAsync(userId, userType);

        IEnumerable<string>? permissions = null;
        IEnumerable<string>? roles = null;

        try
        {
            var iamResponse = await _iamServiceClient.ResolvePermissionsAsync(principalId);
            roles = iamResponse.Roles;

            if (roles != null && roles.Contains(MalievIamRoles.PlatformOwner))
            {
                permissions = null;
                _logger.LogInformation("User {UserId} is Platform Owner. Excluding granular permissions from JWT.", userId);
            }
            else
            {
                permissions = iamResponse.Permissions;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve permissions from IAM for user {UserId}. Blocking login.", userId);
            EnqueueAuditLog(userId, userType, "login", ipAddress, false, "IAM service unavailable");
            await _dbContext.SaveChangesAsync();
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "service_unavailable",
                ErrorDescription = "Authentication service temporarily unavailable. Please try again."
            };
        }

        var customerId = userType == UserType.Customer ? userId : (Guid?)null;
        var accessToken = _tokenGenerator.GenerateAccessToken(principalId, request.UserType, validationResult.Email, validationResult.Name, permissions, roles, customerId);
        var (_, refreshTokenValue) = await _refreshTokenService.CreateRefreshTokenAsync(userId, principalId, userType, validationResult.Email, validationResult.Name, ipAddress);

        EnqueueAuditLog(userId, userType, "login", ipAddress, true, null);

        await _publishEndpoint.Publish(new UserLoggedInEvent(
            Guid.NewGuid(), "UserLoggedInEvent", MessageType.Event, "1.0.0",
            "AuthService", ["NotificationService"], Guid.NewGuid(), null, DateTimeOffset.UtcNow, false,
            new UserLoggedInEventPayload(userId.ToString(), principalId.ToString(),
                normalizedType == "customer" ? "Customer" : "Employee",
                ipAddress, "Password", DateTimeOffset.UtcNow)));

        return new AuthenticationResult
        {
            Success = true,
            PrincipalId = principalId,
            Response = new LoginResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenValue,
                TokenType = "Bearer",
                ExpiresIn = 7200,
                User = new UserIdentityResponse
                {
                    UserId = principalId.ToString(),
                    PrincipalId = principalId.ToString(),
                    CustomerId = customerId?.ToString(),
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

        var (_, newRefreshTokenValue) = await _refreshTokenService.RotateRefreshTokenAsync(refreshToken, ipAddress);
        var userTypeString = refreshToken.UserType == UserType.Customer ? "customer" : "employee";

        IEnumerable<string>? permissions = null;
        IEnumerable<string>? roles = null;

        try
        {
            var iamResponse = await _iamServiceClient.ResolvePermissionsAsync(refreshToken.PrincipalId);
            roles = iamResponse.Roles;

            if (roles != null && roles.Contains(MalievIamRoles.PlatformOwner))
            {
                permissions = null;
                _logger.LogInformation("User {UserId} is Platform Owner. Excluding granular permissions from refreshed JWT.", refreshToken.UserId);
            }
            else
            {
                permissions = iamResponse.Permissions;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve permissions from IAM during token refresh for user {UserId}. Blocking refresh.", refreshToken.UserId);
            EnqueueAuditLog(refreshToken.UserId, refreshToken.UserType, "token_refresh", ipAddress, false, "IAM service unavailable");
            await _dbContext.SaveChangesAsync();
            return null;
        }

        var customerId = refreshToken.UserType == UserType.Customer ? refreshToken.UserId : (Guid?)null;
        var accessToken = _tokenGenerator.GenerateAccessToken(refreshToken.PrincipalId, userTypeString, refreshToken.Email, refreshToken.Name, permissions, roles, customerId);

        EnqueueAuditLog(refreshToken.UserId, refreshToken.UserType, "token_refresh", ipAddress, true, null);

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = newRefreshTokenValue,
            TokenType = "Bearer",
            ExpiresIn = 7200
        };
    }

    /// <inheritdoc/>
    public async Task<ValidateResponse> ValidateTokenAsync(ValidateRequest request)
    {
        var principal = await _tokenValidator.ValidateAccessTokenAsync(request.AccessToken);
        if (principal == null)
        {
            return new ValidateResponse { Valid = false, Error = "Invalid token" };
        }

        var jtiClaim = principal.FindFirst("jti");
        if (jtiClaim != null && await _tokenValidator.IsTokenRevokedAsync(jtiClaim.Value))
        {
            return new ValidateResponse { Valid = false, Error = "Token has been revoked" };
        }

        var userId = principal.FindFirst("sub")?.Value;
        var principalId = principal.FindFirst("principal_id")?.Value ?? userId;
        var customerId = principal.FindFirst("customer_id")?.Value;
        var userType = principal.FindFirst("user_type")?.Value;
        var email = principal.FindFirst("email")?.Value;
        var name = principal.FindFirst("name")?.Value;
        var roles = principal.FindAll("roles").Select(c => c.Value).ToList();
        var permissions = principal.FindAll("permissions").Select(c => c.Value).ToList();

        return new ValidateResponse
        {
            Valid = true,
            UserId = userId,
            PrincipalId = principalId,
            CustomerId = customerId,
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
        if (principal == null) return false;

        var jtiClaim = principal.FindFirst("jti")?.Value;
        var userIdClaim = principal.FindFirst("sub")?.Value;
        var userTypeClaim = principal.FindFirst("user_type")?.Value;

        if (string.IsNullOrEmpty(jtiClaim) || string.IsNullOrEmpty(userIdClaim)) return false;

        if (await _tokenValidator.IsTokenRevokedAsync(jtiClaim)) return true;

        var customerIdClaim = principal.FindFirst("customer_id")?.Value;
        var userId = userTypeClaim?.ToLowerInvariant() == "customer" && Guid.TryParse(customerIdClaim, out var parsedCustomerId)
            ? parsedCustomerId
            : Guid.Parse(userIdClaim);
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

        EnqueueAuditLog(userId, userType, "token_revoke", null, true, null);

        return true;
    }

    /// <inheritdoc/>
    public async Task<bool> LogoutAsync(LogoutRequest request)
    {
        var refreshToken = await _refreshTokenService.ValidateRefreshTokenAsync(request.RefreshToken);
        if (refreshToken == null) return false;

        await _refreshTokenService.RevokeTokenFamilyAsync(refreshToken.FamilyId, "User logout");

        EnqueueAuditLog(refreshToken.UserId, refreshToken.UserType, "logout", null, true, null);

        await _publishEndpoint.Publish(new UserLoggedOutEvent(
            Guid.NewGuid(), "UserLoggedOutEvent", MessageType.Event, "1.0.0",
            "AuthService", ["NotificationService"], Guid.NewGuid(), null, DateTimeOffset.UtcNow, false,
            new UserLoggedOutEventPayload(
                refreshToken.UserId.ToString(),
                refreshToken.UserType == UserType.Customer ? "Customer" : "Employee",
                DateTimeOffset.UtcNow)));

        return true;
    }

    /// <inheritdoc/>
    public async Task<AuthenticationResult> AuthenticateServiceAsync(
        ServiceLoginRequest request,
        string? ipAddress,
        CancellationToken cancellationToken = default)
    {
        var serviceCredential = await _dbContext.ServiceCredentials
            .AsNoTracking()
            .FirstOrDefaultAsync(
                sc => sc.ClientId == request.ClientId,
                cancellationToken);

        var suppliedSecretHash = SHA256.HashData(Encoding.UTF8.GetBytes(request.ClientSecret));
        var expectedSecretHash = DummyServiceSecretHash;
        if (serviceCredential is { IsActive: true } &&
            TryDecodeSha256(serviceCredential.ClientSecretHash, out var decodedSecretHash))
        {
            expectedSecretHash = decodedSecretHash;
        }

        var credentialMatches = CryptographicOperations.FixedTimeEquals(
            suppliedSecretHash,
            expectedSecretHash);
        if (serviceCredential is not { IsActive: true } || !credentialMatches)
        {
            EnqueueAuditLog(null, null, "service_login", ipAddress, false, "Invalid client credentials");

            await _publishEndpoint.Publish(new LoginFailedEvent(
                Guid.NewGuid(), "LoginFailedEvent", MessageType.Event, "1.0.0",
                "AuthService", ["NotificationService"], Guid.NewGuid(), null, DateTimeOffset.UtcNow, false,
                new LoginFailedEventPayload(request.ClientId, null, "Service", ipAddress, "InvalidCredentials", DateTimeOffset.UtcNow)),
                cancellationToken);

            return InvalidServiceCredentials();
        }

        if (!serviceCredential.PrincipalId.HasValue)
        {
            _logger.LogError(
                "Cannot issue a service token because client {ClientId} has no IAM principal mapping",
                request.ClientId);
            return ServiceAuthenticationUnavailable();
        }

        PermissionResolutionResponse iamResponse;
        try
        {
            iamResponse = await _iamServiceClient.ResolvePermissionsRequiredAsync(
                serviceCredential.PrincipalId.Value,
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Failed to resolve authoritative IAM permissions for service {ClientId}",
                request.ClientId);
            return ServiceAuthenticationUnavailable();
        }

        if (iamResponse.Permissions.Contains("*", StringComparer.Ordinal) ||
            iamResponse.Roles.Contains("*", StringComparer.Ordinal))
        {
            _logger.LogError(
                "Refusing to issue a service token because IAM returned wildcard authority for client {ClientId}",
                request.ClientId);
            return ServiceAuthenticationUnavailable();
        }

        var accessToken = await _tokenGenerator.GenerateServiceAccessTokenAsync(
            request.ClientId,
            serviceCredential.ServiceName,
            iamResponse.Permissions,
            iamResponse.Roles,
            serviceCredential.PrincipalId);

        EnqueueAuditLog(null, null, "service_login", ipAddress, true, null);

        await _publishEndpoint.Publish(new UserLoggedInEvent(
            Guid.NewGuid(), "UserLoggedInEvent", MessageType.Event, "1.0.0",
            "AuthService", ["NotificationService"], Guid.NewGuid(), null, DateTimeOffset.UtcNow, false,
            new UserLoggedInEventPayload(request.ClientId, serviceCredential.PrincipalId?.ToString(), "Service", ipAddress, "ServiceCredential", DateTimeOffset.UtcNow)),
            cancellationToken);

        return new AuthenticationResult
        {
            Success = true,
            PrincipalId = serviceCredential.PrincipalId,
            Response = new LoginResponse
            {
                AccessToken = accessToken,
                RefreshToken = null,
                TokenType = "Bearer",
                ExpiresIn = _tokenGenerator.ServiceTokenExpirationInSeconds,
                User = new UserIdentityResponse
                {
                    UserId = request.ClientId,
                    PrincipalId = serviceCredential.PrincipalId?.ToString(),
                    UserType = "service",
                    Name = serviceCredential.ServiceName
                }
            }
        };
    }

    private static bool TryDecodeSha256(string value, out byte[] hash)
    {
        hash = DummyServiceSecretHash;
        if (value.Length != 64)
        {
            return false;
        }

        try
        {
            var decoded = Convert.FromHexString(value);
            if (decoded.Length != 32)
            {
                return false;
            }

            hash = decoded;
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static AuthenticationResult InvalidServiceCredentials() => new()
    {
        Success = false,
        ErrorCode = "invalid_credentials",
        ErrorDescription = "Invalid client credentials"
    };

    private static AuthenticationResult ServiceAuthenticationUnavailable() => new()
    {
        Success = false,
        ErrorCode = "service_unavailable",
        ErrorDescription = "Service authentication is temporarily unavailable"
    };

    /// <inheritdoc/>
    public async Task<AuthenticationResult> ExchangeGoogleTokenAsync(
        GoogleExchangeRequest request,
        string? ipAddress,
        string serviceName,
        CancellationToken cancellationToken = default)
    {
        var googleValidation = await _googleIdentityTokenValidator.ValidateAsync(
            request.Credential,
            request.Application,
            GoogleIdentityExchangeType.Employee,
            request.Nonce,
            cancellationToken);
        if (!googleValidation.Success || googleValidation.Identity == null)
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = googleValidation.ErrorCode ?? "invalid_google_credential",
                ErrorDescription = googleValidation.ErrorDescription ?? "Google credential is invalid or expired"
            };
        }

        var identity = googleValidation.Identity;
        var email = identity.Email;
        var fullName = identity.FullName;
        var profileImageUrl = identity.ProfileImageUrl;

        if (!identity.EmailVerified || string.IsNullOrWhiteSpace(identity.Subject))
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "invalid_google_credential",
                ErrorDescription = "Google credential is missing required verified identity claims"
            };
        }

        var hostedDomain = _configuration["GoogleIdentity:Employee:HostedDomain"];
        if (string.IsNullOrWhiteSpace(hostedDomain))
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "service_unavailable",
                ErrorDescription = "Google sign-in is not configured"
            };
        }

        if (!string.Equals(identity.HostedDomain, hostedDomain, StringComparison.OrdinalIgnoreCase) ||
            !email.EndsWith($"@{hostedDomain}", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Google employee exchange rejected a credential outside the configured hosted domain");
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "invalid_domain",
                ErrorDescription = $"Only @{hostedDomain} Google Workspace accounts are allowed"
            };
        }

        if (!await _googleIdentityNonceService.ConsumeAsync(
                request.Nonce,
                serviceName,
                request.Application,
                GoogleIdentityExchangeType.Employee,
                cancellationToken))
        {
            return InvalidOrReplayedGoogleCredential();
        }

        bool isFirstTimeProvisioning = false;

        var (employeeLookupSuccess, employeeId, principalId, employeeName, employmentStatus, lookupError) =
            await LookupEmployeeByEmailAsync(email, cancellationToken);

        if (!employeeLookupSuccess)
        {
            if (lookupError == "service_unavailable")
            {
                _logger.LogError("EmployeeService unavailable during Google exchange for {Email}", email);
                EnqueueAuditLog(null, UserType.Employee, "google_exchange", ipAddress, false, "EmployeeService unavailable");
                return new AuthenticationResult
                {
                    Success = false,
                    ErrorCode = "service_unavailable",
                    ErrorDescription = "Employee lookup service is currently unavailable"
                };
            }

            _logger.LogInformation("Employee not found for email {Email} during Google exchange. Triggering auto-provisioning.", email);

            var nameParts = (fullName ?? email).Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            var firstName = nameParts.Length > 0 ? nameParts[0] : email;
            var lastName = nameParts.Length > 1 ? nameParts[1] : "-";

            var (provisionSuccess, provEmployeeId, provPrincipalId, provName, provStatus, provisionError) =
                await ProvisionEmployeeAsync(email, firstName, lastName, profileImageUrl, cancellationToken);

            if (!provisionSuccess)
            {
                _logger.LogError("Auto-provisioning failed for {Email}: {Error}", email, provisionError);
                EnqueueAuditLog(null, UserType.Employee, "google_exchange", ipAddress, false, $"Auto-provision failed: {provisionError}");
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

            _logger.LogInformation("Successfully auto-provisioned employee for {Email} with PrincipalId {PrincipalId}", email, principalId);

            isFirstTimeProvisioning = true;
        }

        if (string.Equals(employmentStatus, "Terminated", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Google exchange rejected for terminated employee: {Email}", email);
            EnqueueAuditLog(employeeId, UserType.Employee, "google_exchange", ipAddress, false, "Account terminated");
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "inactive_account",
                ErrorDescription = "Employee account is inactive"
            };
        }

        IEnumerable<string>? permissions = null;
        IEnumerable<string>? roles = null;

        try
        {
            if (isFirstTimeProvisioning)
            {
                // Wait for IAMService's EmployeeCreatedConsumer to create the principal and bootstrap
                // the Platform Owner role before issuing the JWT. The consumer runs asynchronously via
                // RabbitMQ, so we poll until it finishes or we time out.
                const int maxAttempts = 20; // 20 × 500ms = 10s max
                const int delayMs = 500;

                for (int attempt = 0; attempt < maxAttempts; attempt++)
                {
                    var iamResponse = await _iamServiceClient.ResolvePermissionsAsync(principalId!.Value, cancellationToken);
                    roles = iamResponse.Roles;

                    if (roles?.Any() == true || iamResponse.Permissions?.Any() == true)
                    {
                        if (roles?.Contains(MalievIamRoles.PlatformOwner) == true)
                        {
                            permissions = null;
                            _logger.LogInformation("Google SSO user {Email} is Platform Owner. Excluding granular permissions from JWT.", email);
                        }
                        else
                        {
                            permissions = iamResponse.Permissions;
                        }
                        break;
                    }

                    if (attempt < maxAttempts - 1)
                    {
                        _logger.LogInformation("Waiting for IAM bootstrap for {Email} (attempt {Attempt}/{MaxAttempts})...",
                            email, attempt + 1, maxAttempts);
                        await Task.Delay(delayMs, cancellationToken);
                    }
                }

                if (roles?.Any() != true && permissions?.Any() != true)
                {
                    _logger.LogWarning("IAM bootstrap timed out for {Email}. JWT issued with no permissions.", email);
                }
            }
            else
            {
                var iamResponse = await _iamServiceClient.ResolvePermissionsAsync(principalId!.Value, cancellationToken);
                roles = iamResponse.Roles;

                if (roles != null && roles.Contains(MalievIamRoles.PlatformOwner))
                {
                    permissions = null;
                    _logger.LogInformation("Google SSO user {Email} is Platform Owner. Excluding granular permissions from JWT.", email);
                }
                else
                {
                    permissions = iamResponse.Permissions;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve permissions from IAM for Google SSO user {Email}. Blocking login.", email);
            EnqueueAuditLog(employeeId, UserType.Employee, "google_exchange", ipAddress, false, "IAM service unavailable");
            await _dbContext.SaveChangesAsync();
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "service_unavailable",
                ErrorDescription = "Authentication service temporarily unavailable. Please try again."
            };
        }

        var accessToken = _tokenGenerator.GenerateAccessToken(
            principalId!.Value, "employee", email,
            employeeName ?? fullName ?? email, permissions, roles, profileImageUrl: profileImageUrl);

        cancellationToken.ThrowIfCancellationRequested();
        var (_, refreshTokenValue) = await _refreshTokenService.CreateRefreshTokenAsync(
            employeeId!.Value, principalId.Value, UserType.Employee,
            email, employeeName ?? fullName ?? email, ipAddress, cancellationToken);

        EnqueueAuditLog(employeeId.Value, UserType.Employee, "google_exchange", ipAddress, true, null);

        await _publishEndpoint.Publish(new UserLoggedInEvent(
            Guid.NewGuid(), "UserLoggedInEvent", MessageType.Event, "1.0.0",
            "AuthService", ["NotificationService"], Guid.NewGuid(), null, DateTimeOffset.UtcNow, false,
            new UserLoggedInEventPayload(employeeId.Value.ToString(), principalId.Value.ToString(), "Employee", ipAddress, "GoogleSSO", DateTimeOffset.UtcNow)),
            cancellationToken);

        return new AuthenticationResult
        {
            Success = true,
            PrincipalId = principalId.Value,
            Response = new LoginResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenValue,
                TokenType = "Bearer",
                ExpiresIn = 7200,
                User = new UserIdentityResponse
                {
                    UserId = principalId.Value.ToString(),
                    PrincipalId = principalId.Value.ToString(),
                    UserType = "employee",
                    Email = email,
                    Name = employeeName ?? fullName ?? email,
                    ProfileImageUrl = profileImageUrl
                }
            }
        };
    }

    /// <inheritdoc/>
    public async Task<AuthenticationResult> ExchangeCustomerGoogleTokenAsync(
        CustomerGoogleExchangeRequest request,
        string? ipAddress,
        string serviceName,
        CancellationToken cancellationToken = default)
    {
        var googleValidation = await _googleIdentityTokenValidator.ValidateAsync(
            request.Credential,
            request.Application,
            GoogleIdentityExchangeType.Customer,
            request.Nonce,
            cancellationToken);
        if (!googleValidation.Success || googleValidation.Identity == null)
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = googleValidation.ErrorCode ?? "invalid_google_credential",
                ErrorDescription = googleValidation.ErrorDescription ?? "Google credential is invalid or expired"
            };
        }

        var identity = googleValidation.Identity;
        if (!identity.EmailVerified ||
            string.IsNullOrWhiteSpace(identity.Subject) ||
            string.IsNullOrWhiteSpace(identity.Email))
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "invalid_google_credential",
                ErrorDescription = "Google credential is missing required verified identity claims"
            };
        }

        if (!await _googleIdentityNonceService.ConsumeAsync(
                request.Nonce,
                serviceName,
                request.Application,
                GoogleIdentityExchangeType.Customer,
                cancellationToken))
        {
            return InvalidOrReplayedGoogleCredential();
        }

        CustomerAccountSessionResult? session;
        try
        {
            session = await LinkOrRegisterGoogleCustomerAsync(
                identity,
                request.PreferredLanguage,
                request.Timezone,
                cancellationToken);
        }
        catch (CustomerGoogleAccountVerificationRequiredException)
        {
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "account_verification_required",
                ErrorDescription = "Sign in to your existing MALIEV account before linking this Google identity"
            };
        }
        if (session == null)
        {
            EnqueueAuditLog(null, UserType.Customer, "customer_google_exchange", ipAddress, false, "CustomerService unavailable");
            await _dbContext.SaveChangesAsync();
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "service_unavailable",
                ErrorDescription = "Customer account service is currently unavailable"
            };
        }

        IEnumerable<string>? permissions = null;
        IEnumerable<string>? roles = null;

        try
        {
            var iamResponse = await _iamServiceClient.ResolvePermissionsAsync(session.PrincipalId, cancellationToken);
            roles = iamResponse.Roles;
            permissions = roles != null && roles.Contains(MalievIamRoles.PlatformOwner)
                ? null
                : iamResponse.Permissions;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve permissions from IAM for customer Google SSO user {Email}. Blocking login.", identity.Email);
            EnqueueAuditLog(session.CustomerId, UserType.Customer, "customer_google_exchange", ipAddress, false, "IAM service unavailable");
            await _dbContext.SaveChangesAsync();
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "service_unavailable",
                ErrorDescription = "Authentication service temporarily unavailable. Please try again."
            };
        }

        var accessToken = _tokenGenerator.GenerateAccessToken(
            session.PrincipalId,
            "customer",
            session.Email,
            session.DisplayName,
            permissions,
            roles,
            session.CustomerId);

        cancellationToken.ThrowIfCancellationRequested();
        var (_, refreshTokenValue) = await _refreshTokenService.CreateRefreshTokenAsync(
            session.CustomerId,
            session.PrincipalId,
            UserType.Customer,
            session.Email,
            session.DisplayName,
            ipAddress,
            cancellationToken);

        EnqueueAuditLog(session.CustomerId, UserType.Customer, "customer_google_exchange", ipAddress, true, null);

        await _publishEndpoint.Publish(new UserLoggedInEvent(
            Guid.NewGuid(), "UserLoggedInEvent", MessageType.Event, "1.0.0",
            "AuthService", ["NotificationService"], Guid.NewGuid(), null, DateTimeOffset.UtcNow, false,
            new UserLoggedInEventPayload(session.CustomerId.ToString(), session.PrincipalId.ToString(), "Customer", ipAddress, "GoogleSSO", DateTimeOffset.UtcNow)),
            cancellationToken);

        return new AuthenticationResult
        {
            Success = true,
            PrincipalId = session.PrincipalId,
            Response = new LoginResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenValue,
                TokenType = "Bearer",
                ExpiresIn = 7200,
                User = new UserIdentityResponse
                {
                    UserId = session.PrincipalId.ToString(),
                    PrincipalId = session.PrincipalId.ToString(),
                    CustomerId = session.CustomerId.ToString(),
                    UserType = "customer",
                    Email = session.Email,
                    Name = session.DisplayName,
                    ProfileImageUrl = session.ProfileImageUrl
                }
            }
        };
    }

    /// <inheritdoc/>
    public async Task<PasswordResetResponse?> RequestPasswordResetAsync(PasswordResetRequest request)
    {
        var serviceUrl = _configuration["CustomerService:BaseUrl"] ?? "https+http://CustomerService";
        var endpoint = _configuration["CustomerService:PasswordResetRequestEndpoint"]
            ?? "/customer/v1/customers/password-reset/request";

        try
        {
            var client = _httpClientFactory.CreateClient("ExternalValidation");
            var response = await client.PostAsJsonAsync($"{serviceUrl}{endpoint}", new { email = request.Email });
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var accepted = GetBoolean(document.RootElement, "accepted", "Accepted");
            return new PasswordResetResponse { Accepted = accepted };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to request password reset for {Email}", request.Email);
            return null;
        }
    }

    /// <inheritdoc/>
    public async Task<ConfirmPasswordResetResponse?> ConfirmPasswordResetAsync(ConfirmPasswordResetRequest request)
    {
        var serviceUrl = _configuration["CustomerService:BaseUrl"] ?? "https+http://CustomerService";
        var endpoint = _configuration["CustomerService:PasswordResetConfirmEndpoint"]
            ?? "/customer/v1/customers/password-reset/confirm";

        try
        {
            var client = _httpClientFactory.CreateClient("ExternalValidation");
            var response = await client.PostAsJsonAsync($"{serviceUrl}{endpoint}", new
            {
                email = request.Email,
                token = request.Token,
                newPassword = request.NewPassword
            });

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var accepted = GetBoolean(document.RootElement, "accepted", "Accepted", "reset", "Reset");
            var customerId = GetGuid(document.RootElement, "customerId", "customer_id", "CustomerId");
            if (accepted && customerId.HasValue)
            {
                await RevokeCustomerRefreshTokensAsync(customerId.Value);
            }

            return new ConfirmPasswordResetResponse { Reset = accepted };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to confirm password reset for {Email}", request.Email);
            return null;
        }
    }

    private async Task<CustomerAccountSessionResult?> LinkOrRegisterGoogleCustomerAsync(
        VerifiedGoogleIdentity identity,
        string preferredLanguage,
        string timezone,
        CancellationToken cancellationToken)
    {
        var serviceUrl = _configuration["CustomerService:BaseUrl"] ?? "https+http://CustomerService";
        var endpoint = _configuration["CustomerService:GoogleLinkOrRegisterEndpoint"]
            ?? "/customer/v1/customers/google/link-or-register";
        var (firstName, lastName) = SplitFullName(identity.FullName, identity.Email);

        try
        {
            var client = _httpClientFactory.CreateClient("ExternalValidation");
            var response = await client.PostAsJsonAsync($"{serviceUrl}{endpoint}", new
            {
                email = identity.Email,
                firstName,
                lastName,
                googleSubject = identity.Subject,
                emailVerified = identity.EmailVerified,
                emailLinkAllowed = IsAuthoritativeGoogleEmail(identity),
                profileImageUrl = identity.ProfileImageUrl,
                preferredLanguage,
                timezone
            }, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync(cancellationToken);
                if (response.StatusCode == HttpStatusCode.Conflict &&
                    errorBody.Contains(
                        "GOOGLE_EMAIL_LINK_REQUIRES_VERIFICATION",
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new CustomerGoogleAccountVerificationRequiredException();
                }

                _logger.LogWarning("Customer Google link/register failed with status {StatusCode}: {Error}", response.StatusCode, errorBody);
                return null;
            }

            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            var root = document.RootElement;
            var customerId = GetGuid(root, "customerId", "customer_id", "CustomerId");
            var principalId = GetGuid(root, "principalId", "principal_id", "PrincipalId");
            var email = GetString(root, "email", "Email");
            var displayName = GetString(root, "displayName", "display_name", "DisplayName", "name", "Name");
            var profileImageUrl = GetString(root, "profileImageUrl", "profile_image_url", "ProfileImageUrl");

            if (!customerId.HasValue || !principalId.HasValue || string.IsNullOrWhiteSpace(email))
            {
                _logger.LogWarning("CustomerService returned an incomplete Google link/register session for {Email}", identity.Email);
                return null;
            }

            return new CustomerAccountSessionResult(
                customerId.Value,
                principalId.Value,
                email,
                string.IsNullOrWhiteSpace(displayName) ? identity.FullName ?? identity.Email : displayName,
                profileImageUrl);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (CustomerGoogleAccountVerificationRequiredException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to link/register Google customer for {Email}", identity.Email);
            return null;
        }
    }

    private async Task RevokeCustomerRefreshTokensAsync(Guid customerId)
    {
        var activeTokens = await _dbContext.RefreshTokens
            .Where(token => token.UserId == customerId && token.UserType == UserType.Customer && !token.IsUsed)
            .ToListAsync();

        foreach (var token in activeTokens)
        {
            token.IsUsed = true;
            token.UsedAt = DateTime.UtcNow;
        }

        if (activeTokens.Count > 0)
        {
            await _dbContext.SaveChangesAsync();
        }
    }

    private static (string FirstName, string LastName) SplitFullName(string? fullName, string email)
    {
        var fallback = email.Split('@')[0];
        var name = string.IsNullOrWhiteSpace(fullName) ? fallback : fullName.Trim();
        var parts = name.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length switch
        {
            0 => (fallback, "-"),
            1 => (parts[0], "-"),
            _ => (parts[0], parts[1])
        };
    }

    private static bool IsAuthoritativeGoogleEmail(VerifiedGoogleIdentity identity) =>
        !string.IsNullOrWhiteSpace(identity.HostedDomain) ||
        identity.Email.EndsWith("@gmail.com", StringComparison.OrdinalIgnoreCase);

    private static AuthenticationResult InvalidOrReplayedGoogleCredential() => new()
    {
        Success = false,
        ErrorCode = "invalid_google_credential",
        ErrorDescription = "Google credential is invalid or expired"
    };

    private static bool GetBoolean(JsonElement root, params string[] propertyNames)
    {
        var value = GetProperty(root, propertyNames);
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String when bool.TryParse(value.GetString(), out var parsed) => parsed,
            _ => false
        };
    }

    private static Guid? GetGuid(JsonElement root, params string[] propertyNames)
    {
        var value = GetProperty(root, propertyNames);
        if (value.ValueKind == JsonValueKind.String && Guid.TryParse(value.GetString(), out var parsed))
        {
            return parsed;
        }

        return null;
    }

    private static string? GetString(JsonElement root, params string[] propertyNames)
    {
        var value = GetProperty(root, propertyNames);
        return value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    private static JsonElement GetProperty(JsonElement root, params string[] propertyNames)
    {
        foreach (var propertyName in propertyNames)
        {
            if (root.TryGetProperty(propertyName, out var value))
            {
                return value;
            }
        }

        foreach (var property in root.EnumerateObject())
        {
            if (propertyNames.Any(name => string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                return property.Value;
            }
        }

        return default;
    }

    private async Task<(bool Success, Guid? EmployeeId, Guid? PrincipalId, string? Name, string? EmploymentStatus, string? Error)>
        LookupEmployeeByEmailAsync(string email, CancellationToken cancellationToken)
    {
        try
        {
            var response = await _employeeServiceClient
                .GetEmployeeByEmailAsync(email, cancellationToken);

            if (response.StatusCode == HttpStatusCode.NotFound)
            {
                _logger.LogInformation("Employee not found for email: {Email}", email);
                return (false, null, null, null, null, "not_found");
            }

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Employee lookup failed with status {StatusCode} for email: {Email}", response.StatusCode, email);
                return (false, null, null, null, null, "service_unavailable");
            }

            var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
            var result = await response.Content.ReadFromJsonAsync<EmployeeLookupResult>(jsonOptions, cancellationToken);
            if (result == null)
            {
                return (false, null, null, null, null, "service_unavailable");
            }

            return (true, result.EmployeeId, result.PrincipalId, result.FullName, result.EmploymentStatus, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
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

    private async Task<(bool Success, Guid? EmployeeId, Guid? PrincipalId, string? Name, string? EmploymentStatus, string? Error)>
        ProvisionEmployeeAsync(
            string email,
            string firstName,
            string lastName,
            string? profileImageUrl,
            CancellationToken cancellationToken)
    {
        try
        {
            var request = new { email, first_name = firstName, last_name = lastName, picture_url = profileImageUrl };
            var response = await _employeeServiceClient
                .ProvisionEmployeeAsync(request, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogWarning("Employee auto-provision failed with status {StatusCode} for email: {Email}. Error: {Error}",
                    response.StatusCode, email, errorBody);
                return (false, null, null, null, null, "provision_failed");
            }

            var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
            var result = await response.Content.ReadFromJsonAsync<EmployeeLookupResult>(jsonOptions, cancellationToken);
            if (result == null)
            {
                return (false, null, null, null, null, "service_unavailable");
            }

            return (true, result.EmployeeId, result.PrincipalId, result.FullName, result.EmploymentStatus, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
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
            ? _configuration["CustomerService:BaseUrl"] ?? "https+http://CustomerService"
            : _configuration["EmployeeService:BaseUrl"] ?? "https+http://EmployeeService";

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
            var configKey = userType == UserType.Customer
                ? "CustomerService:ValidationTimeoutSeconds"
                : "EmployeeService:ValidationTimeoutSeconds";
            var timeoutSeconds = _configuration.GetValue<int?>(configKey) ?? 30;

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));

            var client = _httpClientFactory.CreateClient("ExternalValidation");
            object payload = userType == UserType.Customer
                ? new { email = username, password }
                : new { username, password };
            var response = await client.PostAsJsonAsync($"{serviceUrl}{validationEndpoint}", payload, cts.Token);

            if (!response.IsSuccessStatusCode)
            {
                return (false, null, null, null, null, "Invalid credentials");
            }

            var result = await CredentialValidationResult.ReadFromJsonAsync(response.Content, cts.Token);
            if (result == null || !result.IsValid)
            {
                var userId2 = result?.ResolvedUserId == Guid.Empty ? null : result?.ResolvedUserId;
                return (false, userId2, result?.PrincipalId, null, null, "Invalid credentials");
            }

            return (true, result.ResolvedUserId, result.PrincipalId, result.Email, result.ResolvedName, null);
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

    private static string HashSecret(string secret)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    private void EnqueueAuditLog(Guid? userId, UserType? userType, string action, string? ipAddress, bool success, string? failureReason)
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
    }

    private class CredentialValidationResult
    {
        public bool IsValid { get; set; }
        public Guid UserId { get; set; }
        public Guid? CustomerId { get; set; }
        public Guid? PrincipalId { get; set; }
        public string? Email { get; set; }
        public string? Name { get; set; }
        public string? DisplayName { get; set; }

        public Guid ResolvedUserId => UserId != Guid.Empty ? UserId : CustomerId ?? PrincipalId ?? Guid.Empty;

        public string? ResolvedName => Name ?? DisplayName;

        public static async Task<CredentialValidationResult?> ReadFromJsonAsync(
            HttpContent content,
            CancellationToken cancellationToken)
        {
            var json = await content.ReadAsStringAsync(cancellationToken);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;

            return new CredentialValidationResult
            {
                IsValid = GetBoolean(root, "is_valid", "isValid", "IsValid"),
                UserId = GetGuid(root, "user_id", "userId", "UserId") ?? Guid.Empty,
                CustomerId = GetGuid(root, "customer_id", "customerId", "CustomerId"),
                PrincipalId = GetGuid(root, "principal_id", "principalId", "PrincipalId"),
                Email = GetString(root, "email", "Email"),
                Name = GetString(root, "name", "Name"),
                DisplayName = GetString(root, "display_name", "displayName", "DisplayName")
            };
        }

        private static bool GetBoolean(JsonElement root, params string[] propertyNames)
        {
            var value = GetProperty(root, propertyNames);
            return value.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.String when bool.TryParse(value.GetString(), out var parsed) => parsed,
                _ => false
            };
        }

        private static Guid? GetGuid(JsonElement root, params string[] propertyNames)
        {
            var value = GetProperty(root, propertyNames);
            if (value.ValueKind == JsonValueKind.String && Guid.TryParse(value.GetString(), out var parsed))
            {
                return parsed;
            }

            return null;
        }

        private static string? GetString(JsonElement root, params string[] propertyNames)
        {
            var value = GetProperty(root, propertyNames);
            return value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        }

        private static JsonElement GetProperty(JsonElement root, params string[] propertyNames)
        {
            foreach (var propertyName in propertyNames)
            {
                if (root.TryGetProperty(propertyName, out var value))
                {
                    return value;
                }
            }

            foreach (var property in root.EnumerateObject())
            {
                if (propertyNames.Any(name => string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase)))
                {
                    return property.Value;
                }
            }

            return default;
        }
    }

    private sealed record CustomerAccountSessionResult(
        Guid CustomerId,
        Guid PrincipalId,
        string Email,
        string DisplayName,
        string? ProfileImageUrl);

    private sealed class CustomerGoogleAccountVerificationRequiredException : Exception;

    private record EmployeeLookupResult
    {
        // EmployeeService returns "id" (not "employeeId") in both by-email and auto-provision responses
        [System.Text.Json.Serialization.JsonPropertyName("id")]
        public Guid EmployeeId { get; init; }
        public Guid PrincipalId { get; init; }
        public string Email { get; init; } = string.Empty;
        public string FullName { get; init; } = string.Empty;
        public string EmploymentStatus { get; init; } = string.Empty;
    }
}
