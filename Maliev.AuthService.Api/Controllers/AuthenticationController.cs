using Asp.Versioning;
using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Maliev.AuthService.JwtToken;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;
using System.Text.Json;

namespace Maliev.AuthService.Api.Controllers
{
    [ApiController]
    [Route("auth/v{version:apiVersion}")]
    [ApiVersion("1.0")]
    public class AuthenticationController : ControllerBase
    {
        private readonly ITokenGenerator _tokenGenerator;
        private readonly ILogger<AuthenticationController> _logger;
        private readonly CustomerServiceOptions _customerServiceOptions;
        private readonly EmployeeServiceOptions _employeeServiceOptions;
        private readonly IUserValidationService _userValidationService;
        private readonly IRefreshTokenRepository _refreshTokenRepository;
        private readonly ICredentialValidationService _credentialValidationService;

        public AuthenticationController(
            ITokenGenerator tokenGenerator,
            ILogger<AuthenticationController> logger,
            IOptions<CustomerServiceOptions> customerServiceOptions,
            IOptions<EmployeeServiceOptions> employeeServiceOptions,
            IUserValidationService userValidationService,
            IRefreshTokenRepository refreshTokenRepository,
            ICredentialValidationService credentialValidationService)
        {
            _tokenGenerator = tokenGenerator;
            _logger = logger;
            _customerServiceOptions = customerServiceOptions.Value;
            _employeeServiceOptions = employeeServiceOptions.Value;
            _userValidationService = userValidationService;
            _refreshTokenRepository = refreshTokenRepository;
            _credentialValidationService = credentialValidationService;
        }

        [HttpPost("token")]
        [EnableRateLimiting("TokenPolicy")]
        public async Task<IActionResult> Token()
        {
            _logger.LogInformation("Token endpoint called.");
            var header = Request.Headers["Authorization"].ToString();
            _logger.LogDebug("Authorization Header: {Header}", header);

            if (System.Net.Http.Headers.AuthenticationHeaderValue.TryParse(header, out var authHeader) && authHeader.Scheme.Equals("Basic", StringComparison.OrdinalIgnoreCase))
            {
                if (authHeader.Parameter == null)
                {
                    return BadRequest("Invalid authorization header format");
                }

                string[] parameter;
                try
                {
                    parameter = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Parameter)).Split(':', 2);
                }
                catch (FormatException)
                {
                    return BadRequest("Invalid Base64 encoding in authorization header");
                }

                if (parameter.Length != 2)
                {
                    return BadRequest("Invalid credential format in authorization header");
                }

                var rawUsername = parameter[0];
                var rawPassword = parameter[1];

                // Validate credentials
                var credentialValidation = _credentialValidationService.ValidateCredentials(rawUsername, rawPassword);
                if (!credentialValidation.IsValid)
                {
                    _logger.LogWarning("Invalid credentials provided: {Errors}", string.Join(", ", credentialValidation.Errors));
                    return BadRequest($"Invalid credentials: {string.Join(", ", credentialValidation.Errors)}");
                }

                var username = credentialValidation.SanitizedUsername!;
                var password = credentialValidation.SanitizedPassword!;
                _logger.LogDebug("Validated and sanitized username: {Username}", username);
                // Do not log password for security reasons

                // Validate user against external services
                var validationResult = await _userValidationService.ValidateUserAsync(
                    username, 
                    password, 
                    _customerServiceOptions, 
                    _employeeServiceOptions);

                if (validationResult.Exists)
                {
                    _logger.LogInformation("User exists. Generating tokens.");
                    var accessToken = _tokenGenerator.GenerateJwtToken(username, validationResult.Roles);
                    var refreshTokenString = _tokenGenerator.GenerateRefreshTokenString();

                    var refreshToken = new RefreshToken
                    {
                        Token = refreshTokenString,
                        Expires = DateTime.UtcNow.AddDays(7),
                        Created = DateTime.UtcNow,
                        Username = username,
                        CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString()
                    };
                    _refreshTokenRepository.AddRefreshToken(refreshToken);
                    await _refreshTokenRepository.SaveChangesAsync();
                    _logger.LogInformation("Tokens generated and refresh token saved.");

                    return Ok(new { AccessToken = accessToken, RefreshToken = refreshTokenString });
                }
                else
                {
                    _logger.LogWarning("User does not exist or validation failed. Returning Unauthorized. Error: {Error}", validationResult.Error);
                    return Unauthorized(validationResult.Error ?? "User does not exist or validation failed.");
                }
            }
            else
            {
                _logger.LogWarning("Authorization header is missing or not in Basic format. Returning BadRequest.");
                return BadRequest();
            }
        }

        [HttpPost("token/refresh")]
        [EnableRateLimiting("RefreshPolicy")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            _logger.LogInformation("RefreshToken endpoint called.");
            _logger.LogInformation("Request - AccessToken: {AccessToken}", request.AccessToken.Length > 8 ? request.AccessToken.Substring(0, 8) + "..." : request.AccessToken);
            _logger.LogInformation("Request - RefreshToken: {RefreshToken}", request.RefreshToken.Length > 8 ? request.RefreshToken.Substring(0, 8) + "..." : request.RefreshToken);

            // Clean up expired and revoked refresh tokens
            await _refreshTokenRepository.CleanExpiredAndRevokedTokensAsync();

            if (request == null || string.IsNullOrEmpty(request.AccessToken) || string.IsNullOrEmpty(request.RefreshToken))
            {
                _logger.LogWarning("Invalid client request: AccessToken or RefreshToken is null or empty.");
                return BadRequest("Invalid client request");
            }

            try
            {
                var savedRefreshToken = await _refreshTokenRepository.GetRefreshTokenByTokenAsync(request.RefreshToken);
                _logger.LogInformation("Saved RefreshToken from DB - Token: {Token}", savedRefreshToken?.Token != null && savedRefreshToken.Token.Length > 8 ? savedRefreshToken.Token.Substring(0, 8) + "..." : savedRefreshToken?.Token);
                _logger.LogInformation("Saved RefreshToken from DB - Username: {Username}", savedRefreshToken?.Username);
                _logger.LogInformation("Saved RefreshToken from DB - IsActive: {IsActive}", savedRefreshToken?.IsActive);

                if (savedRefreshToken == null)
                {
                    _logger.LogWarning("Invalid refresh token: Not found in DB.");
                    return Unauthorized("Invalid refresh token");
                }

                if (savedRefreshToken.IsActive == false)
                {
                    _logger.LogWarning("Invalid refresh token: Not active.");
                    return Unauthorized("Invalid refresh token");
                }

                var principal = _tokenGenerator.GetPrincipalFromExpiredToken(request.AccessToken);
                var username = principal.Identity?.Name;

                if (savedRefreshToken.Username != username)
                {
                    _logger.LogWarning("Invalid refresh token: Username mismatch. Saved: {SavedUsername}, From Token/Request: {UsernameFromToken}", savedRefreshToken.Username, username);
                    return Unauthorized("Invalid refresh token");
                }

                var (newAccessToken, newRefreshTokenString) = _tokenGenerator.RefreshToken(request.AccessToken, request.RefreshToken);
                _logger.LogInformation("New AccessToken generated.");
                _logger.LogInformation("New RefreshToken generated.");

                // Revoke old refresh token
                savedRefreshToken.Revoked = DateTime.UtcNow;
                _refreshTokenRepository.UpdateRefreshToken(savedRefreshToken);
                await _refreshTokenRepository.SaveChangesAsync();
                _logger.LogInformation("Old RefreshToken revoked and saved to DB.");

                // Save new refresh token to database
                var newRefreshToken = new RefreshToken
                {
                    Token = newRefreshTokenString,
                    Expires = DateTime.UtcNow.AddDays(7),
                    Created = DateTime.UtcNow,
                    Username = username,
                    CreatedByIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
                    ReplacedByToken = request.RefreshToken
                };
                _refreshTokenRepository.AddRefreshToken(newRefreshToken);
                await _refreshTokenRepository.SaveChangesAsync();
                _logger.LogInformation("New RefreshToken saved to DB.");

                return Ok(new { AccessToken = newAccessToken, RefreshToken = newRefreshToken.Token });
            }
            catch (SecurityTokenException ex)
            {
                _logger.LogError(ex, "SecurityTokenException: {Message}", ex.Message);
                return Unauthorized(ex.Message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "General Exception: {Message}", ex.Message);
                return StatusCode((int)HttpStatusCode.InternalServerError, $"An error occurred during token refresh: {ex.Message}");
            }
        }

        private string? GetUsernameFromToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            if (tokenHandler.ReadToken(token) is not JwtSecurityToken jwtToken)
            {
                _logger.LogWarning("GetUsernameFromToken: Failed to read JWT token. Token is null after ReadToken.");
                return null;
            }
            return jwtToken?.Claims.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Name)?.Value;
        }
    }

    public class RefreshTokenRequest
    {
        public required string AccessToken { get; set; }
        public required string RefreshToken { get; set; }
    }
}