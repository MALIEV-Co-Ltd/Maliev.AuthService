using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Maliev.AuthService.Api.Models.Request;
using Maliev.AuthService.Api.Models.Response;
using Maliev.AuthService.Api.Models.IAM;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;

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
    private readonly IIAMClient _iamClient;
    private readonly ILogger<AuthenticationService> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IConfiguration _configuration;
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
        IIAMClient iamClient,
        ILogger<AuthenticationService> logger,
        IHttpClientFactory httpClientFactory,
        IConfiguration configuration)
    {
        _dbContext = dbContext;
        _tokenGenerator = tokenGenerator;
        _tokenValidator = tokenValidator;
        _refreshTokenService = refreshTokenService;
        _accountLockoutService = accountLockoutService;
        _rateLimitService = rateLimitService;
        _iamClient = iamClient;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _configuration = configuration;
    }
    /// <inheritdoc/>
    public async Task<AuthenticationResult> AuthenticateAsync(LoginRequest request, string? ipAddress)
    {
        var userType = request.UserType.ToLowerInvariant() == "customer" ? UserType.Customer : UserType.Employee;

        // Check rate limiting first
        if (!string.IsNullOrEmpty(ipAddress) && await _rateLimitService.IsRateLimitExceededAsync(ipAddress))
        {
            await LogAuditAsync(null, userType, "login", ipAddress, false, "Rate limit exceeded");
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
            return new AuthenticationResult
            {
                Success = false,
                ErrorCode = "invalid_credentials",
                ErrorDescription = "Invalid username or password"
            };
        }

        var userId = validationResult.UserId!.Value;
        var principalId = validationResult.PrincipalId ?? userId;

        // Validate credentials succeeded, reset lockout
        await _accountLockoutService.ResetFailedAttemptsAsync(userId, userType);

        // Resolve permissions from IAM (Always enabled)
        IEnumerable<string>? permissions = null;
        IEnumerable<string>? roles = null;

        try
        {
            var iamResponse = await _iamClient.ResolvePermissionsAsync(principalId);
            permissions = iamResponse.Permissions;
            roles = iamResponse.Roles;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve permissions from IAM for user {UserId}. Issuing token without permissions.", userId);
            // Fail open: Issue token without permissions rather than block login
        }

        var accessToken = _tokenGenerator.GenerateAccessToken(principalId, request.UserType, validationResult.Email, validationResult.Name, permissions, roles);
        var (refreshTokenEntity, refreshTokenValue) = await _refreshTokenService.CreateRefreshTokenAsync(userId, principalId, userType, ipAddress);

        await LogAuditAsync(userId, userType, "login", ipAddress, true, null);

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
            var iamResponse = await _iamClient.ResolvePermissionsAsync(refreshToken.PrincipalId);
            permissions = iamResponse.Permissions;
            roles = iamResponse.Roles;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve permissions from IAM during token refresh for user {UserId}. Issuing token without permissions.", refreshToken.UserId);
            // Fail open: Issue token without permissions rather than block refresh
        }

        var accessToken = _tokenGenerator.GenerateAccessToken(refreshToken.PrincipalId, userTypeString, permissions: permissions, roles: roles);

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

        return new ValidateResponse
        {
            Valid = true,
            UserId = userId,
            UserType = userType
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
            return null;
        }

        var secretHash = HashSecret(request.ClientSecret);
        if (secretHash != serviceCredential.ClientSecretHash)
        {
            await LogAuditAsync(null, null, "service_login", ipAddress, false, "Invalid client secret");
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
                var iamResponse = await _iamClient.ResolvePermissionsAsync(serviceCredential.PrincipalId.Value);
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

            var client = _httpClientFactory.CreateClient();
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
                // Return UserId even for failed validation to enable account lockout tracking
                return (false, result?.UserId, result?.PrincipalId, null, null, "Invalid credentials");
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
}