using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Api.Options;
using Maliev.AuthService.Data.Entities;
using Maliev.AuthService.Data.Repositories;
using Microsoft.Extensions.Options;

namespace Maliev.AuthService.Api.Services;

/// <summary>
/// Main authentication service orchestrating login, refresh, validate, and revoke operations.
/// </summary>
public class AuthenticationService : IAuthenticationService
{
    private readonly ICredentialValidationService _credentialValidationService;
    private readonly ITokenGenerator _tokenGenerator;
    private readonly ITokenValidator _tokenValidator;
    private readonly IRefreshTokenService _refreshTokenService;
    private readonly IRevokedAccessTokenRepository _revokedTokenRepository;
    private readonly JwtOptions _jwtOptions;
    private readonly ILogger<AuthenticationService> _logger;

    public AuthenticationService(
        ICredentialValidationService credentialValidationService,
        ITokenGenerator tokenGenerator,
        ITokenValidator tokenValidator,
        IRefreshTokenService refreshTokenService,
        IRevokedAccessTokenRepository revokedTokenRepository,
        IOptions<JwtOptions> jwtOptions,
        ILogger<AuthenticationService> logger)
    {
        _credentialValidationService = credentialValidationService;
        _tokenGenerator = tokenGenerator;
        _tokenValidator = tokenValidator;
        _refreshTokenService = refreshTokenService;
        _revokedTokenRepository = revokedTokenRepository;
        _jwtOptions = jwtOptions.Value;
        _logger = logger;
    }

    public async Task<LoginResponse?> LoginAsync(LoginRequest request, CancellationToken cancellationToken = default)
    {
        // Parse user type
        var userType = request.UserType.ToLowerInvariant() == "customer" ? UserType.Customer : UserType.Employee;

        // Validate credentials with external service
        var validationResult = await _credentialValidationService.ValidateCredentialsAsync(
            request.Username,
            request.Password,
            userType,
            cancellationToken);

        if (validationResult == null)
        {
            _logger.LogWarning("Login failed for user: {Username}", request.Username);
            return null; // Invalid credentials
        }

        // Create token family for this login session
        var familyId = await _refreshTokenService.CreateTokenFamilyAsync(validationResult.UserId, userType, cancellationToken);

        // Generate access token
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, validationResult.UserId),
            new Claim(JwtRegisteredClaimNames.Email, validationResult.Email),
            new Claim(JwtRegisteredClaimNames.UniqueName, validationResult.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("user_type", userType.ToString().ToLowerInvariant()),
            new Claim(ClaimTypes.Name, validationResult.Username)
        }
        .Concat(validationResult.Roles.Select(r => new Claim(ClaimTypes.Role, r)))
        .Concat(validationResult.Permissions.Select(p => new Claim("permission", p)));

        var accessToken = _tokenGenerator.GenerateAccessToken(claims);

        // Generate and store refresh token
        var refreshToken = _tokenGenerator.GenerateRefreshToken();
        var refreshTokenHash = _tokenGenerator.HashRefreshToken(refreshToken);
        var refreshExpiresAt = DateTime.UtcNow.AddSeconds(_jwtOptions.RefreshTokenLifetimeSeconds);

        await _refreshTokenService.StoreRefreshTokenAsync(
            refreshTokenHash,
            validationResult.UserId,
            userType,
            familyId,
            refreshExpiresAt,
            cancellationToken);

        _logger.LogInformation("User logged in successfully: {UserId}", validationResult.UserId);

        return new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = _jwtOptions.AccessTokenLifetimeSeconds
        };
    }

    public async Task<LoginResponse?> RefreshAsync(RefreshRequest request, CancellationToken cancellationToken = default)
    {
        // Rotate refresh token (with reuse detection)
        var newToken = await _refreshTokenService.RotateRefreshTokenAsync(request.RefreshToken, cancellationToken);

        if (newToken == null)
        {
            _logger.LogWarning("Refresh token rotation failed");
            return null; // Invalid or reused token
        }

        // Extract plaintext token from temporary storage
        var newRefreshToken = newToken.TokenHash; // Was temporarily set to plaintext in RotateRefreshTokenAsync

        // Generate new access token with same claims as original
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, newToken.UserId),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("user_type", newToken.UserType.ToString().ToLowerInvariant())
        };

        var accessToken = _tokenGenerator.GenerateAccessToken(claims);

        _logger.LogInformation("Refresh token rotated successfully for user: {UserId}", newToken.UserId);

        return new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = newRefreshToken,
            ExpiresIn = _jwtOptions.AccessTokenLifetimeSeconds
        };
    }

    public async Task<ValidateResponse?> ValidateAsync(ValidateRequest request, CancellationToken cancellationToken = default)
    {
        // Validate JWT signature and claims
        var principal = await _tokenValidator.ValidateTokenAsync(request.AccessToken);
        if (principal == null)
        {
            _logger.LogWarning("Token validation failed: invalid signature or expired");
            return null;
        }

        // Extract JTI and check if token is revoked
        var jti = _tokenValidator.ExtractJti(request.AccessToken);
        if (jti != null)
        {
            var isRevoked = await _revokedTokenRepository.IsRevokedAsync(jti, cancellationToken);
            if (isRevoked)
            {
                _logger.LogWarning("Token validation failed: token is revoked (JTI: {Jti})", jti);
                return null;
            }
        }

        // Extract user information from claims
        var userId = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ?? "";
        var userType = principal.FindFirst("user_type")?.Value ?? "";
        var username = principal.FindFirst(JwtRegisteredClaimNames.UniqueName)?.Value ?? "";
        var email = principal.FindFirst(JwtRegisteredClaimNames.Email)?.Value ?? "";
        var roles = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();
        var permissions = principal.FindAll("permission").Select(c => c.Value).ToArray();

        return new ValidateResponse
        {
            UserId = userId,
            UserType = userType,
            Username = username,
            Email = email,
            Roles = roles,
            Permissions = permissions
        };
    }

    public async Task<bool> RevokeAsync(RevokeRequest request, CancellationToken cancellationToken = default)
    {
        // Extract JTI and expiration from token
        var jti = _tokenValidator.ExtractJti(request.AccessToken);
        if (jti == null)
        {
            _logger.LogWarning("Cannot revoke token: JTI not found");
            return false;
        }

        // Parse token to get expiration
        var handler = new JwtSecurityTokenHandler();
        JwtSecurityToken? token;
        try
        {
            token = handler.ReadJwtToken(request.AccessToken);
        }
        catch
        {
            _logger.LogWarning("Cannot revoke token: invalid JWT format");
            return false;
        }

        var expiresAt = token.ValidTo;

        // Store revocation
        var revokedToken = new RevokedAccessToken
        {
            Jti = jti,
            RevokedAt = DateTime.UtcNow,
            ExpiresAt = expiresAt,
            Reason = request.Reason
        };

        await _revokedTokenRepository.RevokeAsync(revokedToken, cancellationToken);

        _logger.LogInformation("Access token revoked: {Jti}, Reason: {Reason}", jti, request.Reason ?? "not_specified");

        return true;
    }
}
