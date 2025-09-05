using System;
// <copyright file="ITokenGenerator.cs" company="PlaceholderCompany">
// Copyright (c) PlaceholderCompany. All rights reserved.
// </copyright>

using System.Collections.Generic;
using System.Threading.Tasks;

namespace Maliev.AuthService.JwtToken
{
    /// <summary>
    /// TokenGenerator Interface.
    /// </summary>
    public interface ITokenGenerator
    {
        /// <summary>
        /// Generates the JWT token.
        /// </summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="roles">List of roles for the user.</param>
        /// <param name="expiresInMinutes">The expiration time in minutes for the token. If null, a default will be used.</param>
        /// <returns>
        ///   <see cref="string" />.
        /// </returns>
        string GenerateJwtToken(string userName, List<string> roles, int? expiresInMinutes = null);

        /// <summary>
        /// Refreshes the JWT token.
        /// </summary>
        /// <param name="token">The expired JWT token.</param>
        /// <param name="refreshToken">The refresh token.</param>
        /// <returns>A new JWT token and refresh token.</returns>
        (string accessToken, string refreshToken) RefreshToken(string token, string refreshToken);

        /// <summary>
        /// Generates a new refresh token string.
        /// </summary>
        /// <returns>A new refresh token string.</returns>
        string GenerateRefreshTokenString();

        /// <summary>
        /// Gets the principal from an expired token.
        /// </summary>
        /// <param name="token">The expired token.</param>
        /// <returns>The claims principal.</returns>
        System.Security.Claims.ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}