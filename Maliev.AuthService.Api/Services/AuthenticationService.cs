using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Common.Exceptions;
using Maliev.AuthService.Data.Entities;
using Maliev.AuthService.JwtToken;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;

namespace Maliev.AuthService.Api.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly ITokenGenerator _tokenGenerator;
        private readonly ILogger<AuthenticationService> _logger;
        private readonly IUserValidationService _userValidationService;
        private readonly IRefreshTokenRepository _refreshTokenRepository;
        private readonly ICredentialValidationService _credentialValidationService;

        public AuthenticationService(
            ITokenGenerator tokenGenerator,
            ILogger<AuthenticationService> logger,
            IUserValidationService userValidationService,
            IRefreshTokenRepository refreshTokenRepository,
            ICredentialValidationService credentialValidationService)
        {
            _tokenGenerator = tokenGenerator;
            _logger = logger;
            _userValidationService = userValidationService;
            _refreshTokenRepository = refreshTokenRepository;
            _credentialValidationService = credentialValidationService;
        }

        public async Task<IActionResult> GenerateTokensAsync(
            LoginRequest loginRequest,
            CustomerServiceOptions customerServiceOptions,
            EmployeeServiceOptions employeeServiceOptions,
            string? clientIpAddress,
            string? traceId,
            CancellationToken cancellationToken = default)
        {
            using (_logger.BeginScope("TraceId: {TraceId}", traceId))
            {
                _logger.LogInformation("Token generation requested from client IP: {ClientIpAddress}", clientIpAddress);
                _logger.LogDebug("Login request for username: {Username}", loginRequest.Username);

                // Validate credentials
                _logger.LogDebug("Validating credentials for username: {Username}", loginRequest.Username);
                var credentialValidation = _credentialValidationService.ValidateCredentials(loginRequest.Username, loginRequest.Password);
                if (!credentialValidation.IsValid)
                {
                    _logger.LogWarning("Invalid credentials provided for username {Username}: {Errors}", loginRequest.Username, string.Join(", ", credentialValidation.Errors));
                    return new BadRequestObjectResult($"Invalid credentials: {string.Join(", ", credentialValidation.Errors)}");
                }

                var username = credentialValidation.SanitizedUsername!;
                var password = credentialValidation.SanitizedPassword!;
                _logger.LogDebug("Validated and sanitized username: {Username}", username);
                // Do not log password for security reasons

                try
                {
                    // Validate user against external services
                    _logger.LogInformation("Validating user {Username} against external services", username);
                    var validationResult = await _userValidationService.ValidateUserAsync(
                        username,
                        password,
                        customerServiceOptions,
                        employeeServiceOptions,
                        cancellationToken);

                    if (validationResult.Exists)
                    {
                        _logger.LogInformation("User {Username} exists in external service. Generating tokens.", username);
                        var accessToken = _tokenGenerator.GenerateJwtToken(username, validationResult.Roles);
                        var refreshTokenString = _tokenGenerator.GenerateRefreshTokenString();

                        var refreshToken = new RefreshToken
                        {
                            Token = refreshTokenString,
                            Expires = DateTime.UtcNow.AddDays(7),
                            Created = DateTime.UtcNow,
                            Username = username,
                            CreatedByIp = clientIpAddress
                        };
                        _refreshTokenRepository.AddRefreshToken(refreshToken);
                        await _refreshTokenRepository.SaveChangesAsync(cancellationToken);
                        _logger.LogInformation("Tokens generated and refresh token saved for user {Username}.", username);

                        return new OkObjectResult(new { AccessToken = accessToken, RefreshToken = refreshTokenString });
                    }
                    else
                    {
                        _logger.LogWarning("User {Username} does not exist or validation failed. Returning Unauthorized. Error: {Error}", username, validationResult.Error);
                        return new UnauthorizedObjectResult(validationResult.Error ?? "User does not exist or validation failed.");
                    }
                }
                catch (ExternalServiceValidationException ex)
                {
                    _logger.LogError(ex, "External service validation failed for user {Username} from client IP: {ClientIpAddress}", username, clientIpAddress);
                    var statusCode = ex.StatusCode ?? (int)HttpStatusCode.InternalServerError;
                    return new ObjectResult($"External service validation failed: {ex.Message}") { StatusCode = statusCode };
                }
                catch (TokenGenerationException ex)
                {
                    _logger.LogError(ex, "Token generation failed for user {Username} from client IP: {ClientIpAddress}", username, clientIpAddress);
                    return new ObjectResult($"Token generation failed: {ex.Message}") { StatusCode = (int)HttpStatusCode.InternalServerError };
                }
                catch (DatabaseOperationException ex)
                {
                    _logger.LogError(ex, "Database operation failed for user {Username} from client IP: {ClientIpAddress}", username, clientIpAddress);
                    return new ObjectResult("A database error occurred while processing your request.") { StatusCode = (int)HttpStatusCode.InternalServerError };
                }
            }
        }

        public async Task<IActionResult> RefreshTokensAsync(
            string accessToken,
            string refreshToken,
            string? clientIpAddress,
            string? traceId,
            CancellationToken cancellationToken = default)
        {
            using (_logger.BeginScope("TraceId: {TraceId}", traceId))
            {
                _logger.LogInformation("Token refresh requested from client IP: {ClientIpAddress}", clientIpAddress);
                _logger.LogInformation("Request - AccessToken: {AccessToken}", accessToken.Length > 8 ? accessToken.Substring(0, 8) + "..." : accessToken);
                _logger.LogInformation("Request - RefreshToken: {RefreshToken}", refreshToken.Length > 8 ? refreshToken.Substring(0, 8) + "..." : refreshToken);

                // Clean up expired and revoked refresh tokens
                try
                {
                    _logger.LogDebug("Cleaning up expired and revoked refresh tokens");
                    var cleanedCount = await _refreshTokenRepository.CleanExpiredAndRevokedTokensAsync(cancellationToken);
                    _logger.LogDebug("Cleaned up {CleanedCount} expired and revoked refresh tokens", cleanedCount);
                }
                catch (DatabaseOperationException ex)
                {
                    _logger.LogError(ex, "Database operation failed during token cleanup from client IP: {ClientIpAddress}", clientIpAddress);
                    return new ObjectResult("A database error occurred while processing your request.") { StatusCode = (int)HttpStatusCode.InternalServerError };
                }

                if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(refreshToken))
                {
                    _logger.LogWarning("Invalid client request: AccessToken or RefreshToken is null or empty from client IP: {ClientIpAddress}", clientIpAddress);
                    return new BadRequestObjectResult("Invalid client request");
                }

                try
                {
                    _logger.LogDebug("Retrieving refresh token from database: {RefreshToken}", refreshToken.Length > 8 ? refreshToken.Substring(0, 8) + "..." : refreshToken);
                    var savedRefreshToken = await _refreshTokenRepository.GetRefreshTokenByTokenAsync(refreshToken, cancellationToken);
                    _logger.LogInformation("Saved RefreshToken from DB - Token: {Token}", savedRefreshToken?.Token != null && savedRefreshToken.Token.Length > 8 ? savedRefreshToken.Token.Substring(0, 8) + "..." : savedRefreshToken?.Token);
                    _logger.LogInformation("Saved RefreshToken from DB - Username: {Username}", savedRefreshToken?.Username);
                    _logger.LogInformation("Saved RefreshToken from DB - IsActive: {IsActive}", savedRefreshToken?.IsActive);

                    if (savedRefreshToken == null)
                    {
                        _logger.LogWarning("Invalid refresh token: Not found in DB from client IP: {ClientIpAddress}", clientIpAddress);
                        return new UnauthorizedObjectResult("Invalid refresh token");
                    }

                    if (savedRefreshToken.IsActive == false)
                    {
                        _logger.LogWarning("Invalid refresh token: Not active for client IP: {ClientIpAddress}", clientIpAddress);
                        return new UnauthorizedObjectResult("Invalid refresh token");
                    }

                    _logger.LogDebug("Validating expired access token for user: {Username}", savedRefreshToken.Username);
                    var principal = _tokenGenerator.GetPrincipalFromExpiredToken(accessToken);
                    var username = principal.Identity?.Name;

                    if (savedRefreshToken.Username != username)
                    {
                        _logger.LogWarning("Invalid refresh token: Username mismatch. Saved: {SavedUsername}, From Token/Request: {UsernameFromToken} from client IP: {ClientIpAddress}", savedRefreshToken.Username, username, clientIpAddress);
                        return new UnauthorizedObjectResult("Invalid refresh token");
                    }

                    _logger.LogInformation("Refreshing tokens for user: {Username}", username);
                    var (newAccessToken, newRefreshTokenString) = _tokenGenerator.RefreshToken(accessToken, refreshToken);
                    _logger.LogInformation("New AccessToken generated for user: {Username}", username);
                    _logger.LogInformation("New RefreshToken generated for user: {Username}", username);

                    // Revoke old refresh token
                    savedRefreshToken.Revoked = DateTime.UtcNow;
                    _refreshTokenRepository.UpdateRefreshToken(savedRefreshToken);
                    await _refreshTokenRepository.SaveChangesAsync(cancellationToken);
                    _logger.LogInformation("Old RefreshToken {OldTokenId} revoked and saved to DB.", 
                        savedRefreshToken.Token.Length > 8 ? savedRefreshToken.Token.Substring(0, 8) + "..." : savedRefreshToken.Token);

                    // Save new refresh token to database
                    var newRefreshToken = new RefreshToken
                    {
                        Token = newRefreshTokenString,
                        Expires = DateTime.UtcNow.AddDays(7),
                        Created = DateTime.UtcNow,
                        Username = username,
                        CreatedByIp = clientIpAddress,
                        ReplacedByToken = refreshToken
                    };
                    _refreshTokenRepository.AddRefreshToken(newRefreshToken);
                    await _refreshTokenRepository.SaveChangesAsync(cancellationToken);
                    _logger.LogInformation("New RefreshToken {NewTokenId} saved to DB. Replaces old token {OldTokenId}.", 
                        newRefreshToken.Token.Length > 8 ? newRefreshToken.Token.Substring(0, 8) + "..." : newRefreshToken.Token,
                        savedRefreshToken.Token.Length > 8 ? savedRefreshToken.Token.Substring(0, 8) + "..." : savedRefreshToken.Token);

                    return new OkObjectResult(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken.Token });
                }
                catch (InvalidRefreshTokenException ex)
                {
                    _logger.LogError(ex, "Invalid refresh token exception for client IP: {ClientIpAddress}", clientIpAddress);
                    return new UnauthorizedObjectResult(ex.Message);
                }
                catch (TokenGenerationException ex)
                {
                    _logger.LogError(ex, "Token generation failed for client IP: {ClientIpAddress}", clientIpAddress);
                    return new ObjectResult($"Token generation failed: {ex.Message}") { StatusCode = (int)HttpStatusCode.InternalServerError };
                }
                catch (DatabaseOperationException ex)
                {
                    _logger.LogError(ex, "Database operation failed for client IP: {ClientIpAddress}", clientIpAddress);
                    return new ObjectResult("A database error occurred while processing your request.") { StatusCode = (int)HttpStatusCode.InternalServerError };
                }
                catch (SecurityTokenException ex)
                {
                    _logger.LogError(ex, "SecurityTokenException for client IP: {ClientIpAddress}: {Message}", clientIpAddress, ex.Message);
                    return new UnauthorizedObjectResult(ex.Message);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "General Exception for client IP: {ClientIpAddress}: {Message}", clientIpAddress, ex.Message);
                    return new ObjectResult($"An error occurred during token refresh: {ex.Message}") { StatusCode = (int)HttpStatusCode.InternalServerError };
                }
            }
        }
    }
}