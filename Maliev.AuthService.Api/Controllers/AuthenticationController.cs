using Maliev.AuthService.Api.Data;
using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.JwtToken;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text;
using System.Text.Json;
using Asp.Versioning;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.RateLimiting;

namespace Maliev.AuthService.Api.Controllers
{
    [ApiController]
    [Route("auth/v{version:apiVersion}")]
    [ApiVersion("1.0")]
    public class AuthenticationController : ControllerBase
    {
        private readonly ITokenGenerator _tokenGenerator;
        private readonly ExternalAuthServiceHttpClient _externalAuthServiceHttpClient;
        private readonly RefreshTokenDbContext _dbContext;
        private readonly ILogger<AuthenticationController> _logger;
        private readonly CustomerServiceOptions _customerServiceOptions;
        private readonly EmployeeServiceOptions _employeeServiceOptions;
        private readonly IValidationCacheService _validationCacheService;
        private readonly ICredentialValidationService _credentialValidationService;

        public AuthenticationController(
            ITokenGenerator tokenGenerator,
            ExternalAuthServiceHttpClient externalAuthServiceHttpClient,
            RefreshTokenDbContext dbContext,
            ILogger<AuthenticationController> logger,
            IOptions<CustomerServiceOptions> customerServiceOptions,
            IOptions<EmployeeServiceOptions> employeeServiceOptions,
            IValidationCacheService validationCacheService,
            ICredentialValidationService credentialValidationService)
        {
            _tokenGenerator = tokenGenerator;
            _externalAuthServiceHttpClient = externalAuthServiceHttpClient;
            _dbContext = dbContext;
            _logger = logger;
            _customerServiceOptions = customerServiceOptions.Value;
            _employeeServiceOptions = employeeServiceOptions.Value;
            _validationCacheService = validationCacheService;
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

                var userValidationRequest = new UserValidationRequest { Username = username, Password = password };
                var jsonContent = new StringContent(JsonSerializer.Serialize(userValidationRequest), Encoding.UTF8, "application/json");

                Maliev.AuthService.Api.Models.ValidationResult validationResult = new Maliev.AuthService.Api.Models.ValidationResult { Exists = false };

                // Try validating with CustomerService (check cache first)
                if (!string.IsNullOrEmpty(_customerServiceOptions.ValidationEndpoint))
                {
                    _logger.LogDebug("Attempting to validate with CustomerService at {Endpoint}", _customerServiceOptions.ValidationEndpoint);
                    
                    // Check cache first
                    var cachedResult = await _validationCacheService.GetValidationResultAsync(username, "Customer");
                    if (cachedResult != null)
                    {
                        validationResult = cachedResult;
                        _logger.LogDebug("CustomerService validation result from cache: Exists={Exists}, Type={Type}", validationResult.Exists, validationResult.UserType);
                    }
                    else
                    {
                        validationResult = await ValidateCredentials(_customerServiceOptions.ValidationEndpoint, jsonContent, UserType.Customer);
                        _logger.LogDebug("CustomerService validation result: Exists={Exists}, Type={Type}, Error={Error}", validationResult.Exists, validationResult.UserType, validationResult.Error);
                        
                        // Cache the result
                        await _validationCacheService.SetValidationResultAsync(username, "Customer", validationResult);
                    }
                }

                // If not found in CustomerService, try EmployeeService (check cache first)
                if (!validationResult.Exists && !string.IsNullOrEmpty(_employeeServiceOptions.ValidationEndpoint))
                {
                    _logger.LogDebug("Attempting to validate with EmployeeService at {Endpoint}", _employeeServiceOptions.ValidationEndpoint);
                    
                    // Check cache first
                    var cachedResult = await _validationCacheService.GetValidationResultAsync(username, "Employee");
                    if (cachedResult != null)
                    {
                        validationResult = cachedResult;
                        _logger.LogDebug("EmployeeService validation result from cache: Exists={Exists}, Type={Type}", validationResult.Exists, validationResult.UserType);
                    }
                    else
                    {
                        validationResult = await ValidateCredentials(_employeeServiceOptions.ValidationEndpoint, jsonContent, UserType.Employee);
                        _logger.LogDebug("EmployeeService validation result: Exists={Exists}, Type={Type}, Error={Error}", validationResult.Exists, validationResult.UserType, validationResult.Error);
                        
                        // Cache the result
                        await _validationCacheService.SetValidationResultAsync(username, "Employee", validationResult);
                    }
                }

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
                    _dbContext.RefreshTokens.Add(refreshToken);
                    await _dbContext.SaveChangesAsync();
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
            await _dbContext.CleanExpiredAndRevokedTokensAsync();

            if (request == null || string.IsNullOrEmpty(request.AccessToken) || string.IsNullOrEmpty(request.RefreshToken))
            {
                _logger.LogWarning("Invalid client request: AccessToken or RefreshToken is null or empty.");
                return BadRequest("Invalid client request");
            }

            try
            {
                var savedRefreshToken = await _dbContext.RefreshTokens.SingleOrDefaultAsync(rt => rt.Token == request.RefreshToken);
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
                _dbContext.RefreshTokens.Update(savedRefreshToken);
                await _dbContext.SaveChangesAsync();
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
                _dbContext.RefreshTokens.Add(newRefreshToken);
                await _dbContext.SaveChangesAsync();
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

        /// <summary>
        /// Validates user credentials with external ASP.NET Identity services
        /// </summary>
        /// <param name="validationEndpoint">The validation endpoint URL configured via CustomerServiceOptions or EmployeeServiceOptions</param>
        /// <param name="jsonContent">JSON payload containing username and password: {"Username": "user123", "Password": "pass123"}</param>
        /// <param name="userType">Type of user</param>
        /// <returns>ValidationResult indicating if user exists in ASP.NET Identity database and their roles</returns>
        /// <remarks>
        /// Validation endpoints are configured via external configuration (secrets/environment variables):
        /// - CustomerService:ValidationEndpoint for customer validation
        /// - EmployeeService:ValidationEndpoint for employee validation
        /// 
        /// Expected request format: POST to validation endpoint with JSON body:
        /// {
        ///   "Username": "user123",
        ///   "Password": "pass123"
        /// }
        /// 
        /// Expected response codes:
        /// - 200 OK: Valid credentials, user exists
        /// - 404 NOT FOUND: User does not exist
        /// - 400 BAD REQUEST: Invalid request format or credentials
        /// - Other status codes: Service error
        /// 
        /// The validation endpoints should validate the user credentials against the respective ASP.NET Identity database
        /// and return appropriate HTTP status codes to indicate the validation result.
        /// 
        /// No JSON response body is expected, only HTTP status codes are used for validation results.
        /// </remarks>
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<Maliev.AuthService.Api.Models.ValidationResult> ValidateCredentials(
            string validationEndpoint,
            StringContent jsonContent,
            UserType userType)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Post, validationEndpoint) { Content = jsonContent };
                var response = await _externalAuthServiceHttpClient.Client.SendAsync(request);

                switch (response.StatusCode)
                {
                    case HttpStatusCode.OK:
                        // 200 OK: Valid credentials, user exists
                        _logger.LogDebug("{UserType} validation successful: User exists and credentials are valid", userType);
                        var roles = new List<string> { userType.ToString() }; // Default role
                        return new ValidationResult { Exists = true, UserType = userType.ToString(), Roles = roles };

                    case HttpStatusCode.NotFound:
                        // 404 NOT FOUND: User does not exist
                        _logger.LogDebug("{UserType} validation: User not found", userType);
                        return new ValidationResult { Exists = false, UserType = userType.ToString(), Error = $"User not found in {userType} service." };

                    case HttpStatusCode.BadRequest:
                        // 400 BAD REQUEST: Invalid request format or credentials
                        _logger.LogWarning("{UserType} validation: Bad request - invalid credentials or request format", userType);
                        return new ValidationResult { Exists = false, UserType = userType.ToString(), Error = $"Invalid credentials for {userType} service." };

                    default:
                        // Other status codes: Service error
                        string errorMessage = $"External authentication service returned {response.StatusCode} for {userType} validation.";
                        _logger.LogWarning(errorMessage);
                        return new ValidationResult { Exists = false, UserType = userType.ToString(), Error = errorMessage, StatusCode = (int)response.StatusCode };
                }
            }
            catch (HttpRequestException ex)
            {
                string errorMessage = $"HttpRequestException during {userType} validation: {ex.Message}";
                _logger.LogError(ex, errorMessage);
                return new ValidationResult { Exists = false, UserType = userType.ToString(), Error = errorMessage };
            }
            catch (Exception ex)
            {
                string errorMessage = $"An unexpected error occurred during {userType} validation: {ex.Message}";
                _logger.LogError(ex, errorMessage);
                return new ValidationResult { Exists = false, UserType = userType.ToString(), Error = errorMessage };
            }
        }

        
    private string? GetUsernameFromToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
            if (jwtToken == null)
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
