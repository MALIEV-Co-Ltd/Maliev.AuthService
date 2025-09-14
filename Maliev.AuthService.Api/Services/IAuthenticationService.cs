using Maliev.AuthService.Api.Models;
using Maliev.AuthService.Data.Entities;
using Microsoft.AspNetCore.Mvc;
using System.Threading;

namespace Maliev.AuthService.Api.Services
{
    public interface IAuthenticationService
    {
        /// <summary>
        /// Generates authentication tokens for a user based on Basic Authentication credentials.
        /// </summary>
        /// <param name="loginRequest">The login request containing username and password.</param>
        /// <param name="customerServiceOptions">Customer service configuration options.</param>
        /// <param name="employeeServiceOptions">Employee service configuration options.</param>
        /// <param name="clientIpAddress">The IP address of the client making the request.</param>
        /// <param name="traceId">The trace identifier for the request.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An IActionResult with the generated tokens or an appropriate error response.</returns>
        Task<IActionResult> GenerateTokensAsync(
            LoginRequest loginRequest,
            CustomerServiceOptions customerServiceOptions,
            EmployeeServiceOptions employeeServiceOptions,
            string? clientIpAddress,
            string? traceId,
            CancellationToken cancellationToken = default);

        /// <summary>
        /// Refreshes authentication tokens using a refresh token.
        /// </summary>
        /// <param name="accessToken">The expired access token.</param>
        /// <param name="refreshToken">The refresh token.</param>
        /// <param name="clientIpAddress">The IP address of the client making the request.</param>
        /// <param name="traceId">The trace identifier for the request.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>An IActionResult with the refreshed tokens or an appropriate error response.</returns>
        Task<IActionResult> RefreshTokensAsync(
            string accessToken,
            string refreshToken,
            string? clientIpAddress,
            string? traceId,
            CancellationToken cancellationToken = default);
    }
}