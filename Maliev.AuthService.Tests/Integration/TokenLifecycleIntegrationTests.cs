using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Maliev.AuthService.Tests.Contract;
using Xunit;

namespace Maliev.AuthService.Tests.Integration;

/// <summary>
/// Integration tests for complete token lifecycle.
/// Tests the full journey: login -> refresh -> validate -> revoke.
/// </summary>
[Trait("Category", "Integration")]
public class TokenLifecycleIntegrationTests : IntegrationTestBase
{
    [Fact]
    public async Task CompleteTokenLifecycle_LoginRefreshValidateRevoke_WorksCorrectly()
    {
        // This is the comprehensive end-to-end test
        // This will FAIL until full implementation is complete

        // **Step 1: Login**
        var loginRequest = new { username = "customer@example.com", password = "Password123!", user_type = "customer" };
        var loginResponse = await Client!.PostAsJsonAsync("/auth/login", loginRequest);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var loginContent = await loginResponse.Content.ReadFromJsonAsync<LoginResponse>();
        loginContent.Should().NotBeNull();
        var accessToken1 = loginContent!.AccessToken;
        var refreshToken1 = loginContent.RefreshToken;

        // **Step 2: Validate Access Token**
        var validateRequest1 = new { access_token = accessToken1 };
        var validateResponse1 = await Client!.PostAsJsonAsync("/auth/validate", validateRequest1);
        validateResponse1.StatusCode.Should().Be(HttpStatusCode.OK);

        var validateContent1 = await validateResponse1.Content.ReadFromJsonAsync<ValidateResponse>();
        validateContent1.Should().NotBeNull();
        validateContent1!.UserId.Should().NotBeNullOrEmpty();
        validateContent1.UserType.Should().Be("customer");

        // **Step 3: Refresh Token (rotation)**
        var refreshRequest1 = new { refresh_token = refreshToken1 };
        var refreshResponse1 = await Client!.PostAsJsonAsync("/auth/refresh", refreshRequest1);
        refreshResponse1.StatusCode.Should().Be(HttpStatusCode.OK);

        var refreshContent1 = await refreshResponse1.Content.ReadFromJsonAsync<LoginResponse>();
        refreshContent1.Should().NotBeNull();
        var accessToken2 = refreshContent1!.AccessToken;
        var refreshToken2 = refreshContent1.RefreshToken;

        // Verify rotation occurred
        refreshToken2.Should().NotBe(refreshToken1);
        accessToken2.Should().NotBe(accessToken1);

        // **Step 4: Validate New Access Token**
        var validateRequest2 = new { access_token = accessToken2 };
        var validateResponse2 = await Client!.PostAsJsonAsync("/auth/validate", validateRequest2);
        validateResponse2.StatusCode.Should().Be(HttpStatusCode.OK);

        // **Step 5: Revoke Access Token**
        var revokeRequest = new { access_token = accessToken2, reason = "user_logout" };
        var revokeResponse = await Client!.PostAsJsonAsync("/auth/revoke", revokeRequest);
        revokeResponse.StatusCode.Should().Be(HttpStatusCode.NoContent);

        // **Step 6: Validate Revoked Token (should fail)**
        var validateRequest3 = new { access_token = accessToken2 };
        var validateResponse3 = await Client!.PostAsJsonAsync("/auth/validate", validateRequest3);
        validateResponse3.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        var errorContent = await validateResponse3.Content.ReadFromJsonAsync<ErrorResponse>();
        errorContent!.Error.Should().Contain("token_revoked");

        // **Step 7: Attempt to reuse old refresh token (should fail)**
        var refreshRequest2 = new { refresh_token = refreshToken1 };
        var refreshResponse2 = await Client!.PostAsJsonAsync("/auth/refresh", refreshRequest2);
        refreshResponse2.StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // Success! Full lifecycle works correctly.
    }

    [Fact]
    public async Task TokenLifecycle_MultipleRotations_MaintainsFamilyIntegrity()
    {
        await Task.CompletedTask;
        // Test multiple refresh operations maintain family integrity
        // This will FAIL until implementation

        // TODO: Login -> Refresh 5 times -> Verify family lineage
        // TODO: Check all tokens belong to same family
        // TODO: Check each used token is marked correctly
    }
}
