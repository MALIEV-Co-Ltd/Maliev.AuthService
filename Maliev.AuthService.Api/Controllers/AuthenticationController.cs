using Asp.Versioning;
using Maliev.AuthService.Common.Exceptions;
using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Api.Services;
using Maliev.AuthService.Data.DbContexts;
using Maliev.AuthService.Data.Entities;
using Maliev.AuthService.JwtToken;
using Microsoft.AspNetCore.Authentication;
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
        private readonly Maliev.AuthService.Api.Services.IAuthenticationService _authenticationService;
        private readonly ILogger<AuthenticationController> _logger;
        private readonly CustomerServiceOptions _customerServiceOptions;
        private readonly EmployeeServiceOptions _employeeServiceOptions;

        public AuthenticationController(
            Maliev.AuthService.Api.Services.IAuthenticationService authenticationService,
            ILogger<AuthenticationController> logger,
            IOptions<CustomerServiceOptions> customerServiceOptions,
            IOptions<EmployeeServiceOptions> employeeServiceOptions)
        {
            _authenticationService = authenticationService;
            _logger = logger;
            _customerServiceOptions = customerServiceOptions.Value;
            _employeeServiceOptions = employeeServiceOptions.Value;
        }

        [HttpPost("token")]
        [EnableRateLimiting("TokenPolicy")]
        public async Task<IActionResult> Token(CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Token endpoint called.");

            // Manually authenticate using our custom authentication handler logic
            var authHeader = Request.Headers["Authorization"].ToString();
            
            // Check if the Authorization header is present
            if (string.IsNullOrEmpty(authHeader))
            {
                _logger.LogWarning("Authorization header is missing. Returning BadRequest.");
                return BadRequest();
            }
            
            // Check if the header starts with "Basic "
            if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Authorization header is not in Basic format. Returning BadRequest.");
                return BadRequest();
            }

            // Extract and decode the credentials
            try
            {
                var encodedCredentials = authHeader.Substring("Basic ".Length).Trim();
                var decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
                var credentials = decodedCredentials.Split(':', 2);

                // Validate credentials format
                if (credentials.Length != 2)
                {
                    _logger.LogWarning("Invalid credential format in authorization header. Returning BadRequest.");
                    return BadRequest("Invalid credential format in authorization header");
                }

                var username = credentials[0];
                var password = credentials[1];

                var loginRequest = new LoginRequest
                {
                    Username = username,
                    Password = password
                };

                var traceId = HttpContext.TraceIdentifier;
                
                var result = await _authenticationService.GenerateTokensAsync(
                    loginRequest,
                    _customerServiceOptions,
                    _employeeServiceOptions,
                    HttpContext.Connection.RemoteIpAddress?.ToString(),
                    traceId,
                    cancellationToken);
                    
                return result;
            }
            catch (FormatException)
            {
                _logger.LogWarning("Invalid Base64 encoding in authorization header. Returning BadRequest.");
                return BadRequest("Invalid Base64 encoding in authorization header");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while processing Basic Authentication");
                return BadRequest("Error occurred while processing authentication");
            }
        }

        [HttpPost("token/refresh")]
        [EnableRateLimiting("RefreshPolicy")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("RefreshToken endpoint called.");
            
            if (request == null)
            {
                _logger.LogWarning("Invalid client request: Request is null.");
                return BadRequest("Invalid client request");
            }
            
            var traceId = HttpContext.TraceIdentifier;
            var result = await _authenticationService.RefreshTokensAsync(
                request.AccessToken,
                request.RefreshToken,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                traceId,
                cancellationToken);
                
            return result;
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