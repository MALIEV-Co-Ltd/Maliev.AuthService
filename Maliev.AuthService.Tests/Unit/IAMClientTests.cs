using System.Net;
using System.Net.Http.Json;
using System.Diagnostics.Metrics;
using Maliev.AuthService.Api.Models.IAM;
using Maliev.AuthService.Api.Services;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public class IAMClientTests
{
    private readonly Mock<HttpMessageHandler> _handlerMock;
    private readonly HttpClient _httpClient;
    private readonly Mock<IMeterFactory> _meterFactoryMock;
    private readonly Mock<ILogger<IAMClient>> _loggerMock;
    private readonly Mock<Microsoft.Extensions.Configuration.IConfiguration> _configMock;
    private readonly IAMClient _client;

    public IAMClientTests()
    {
        _handlerMock = new Mock<HttpMessageHandler>();
        _httpClient = new HttpClient(_handlerMock.Object)
        {
            BaseAddress = new Uri("http://iam-service")
        };
        _meterFactoryMock = new Mock<IMeterFactory>();
        _meterFactoryMock.Setup(m => m.Create(It.IsAny<MeterOptions>())).Returns(new Meter("auth-meter"));

        _loggerMock = new Mock<ILogger<IAMClient>>();
        _configMock = new Mock<Microsoft.Extensions.Configuration.IConfiguration>();
        _client = new IAMClient(_httpClient, _meterFactoryMock.Object, _configMock.Object, _loggerMock.Object);
    }

    [Fact]
    public async Task ResolvePermissionsAsync_Success_ReturnsPermissions()
    {
        // Arrange
        var principalId = Guid.NewGuid();
        var expectedResponse = new PermissionResolutionResponse
        {
            PrincipalId = principalId,
            Permissions = new List<string> { "invoice.invoices.read", "invoice.invoices.create" },
            Roles = new List<string> { "accountant" },
            ResolvedAt = DateTime.UtcNow
        };

        _handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = JsonContent.Create(expectedResponse)
            });

        // Act
        var result = await _client.ResolvePermissionsAsync(principalId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(principalId, result.PrincipalId);
        Assert.Equal(2, result.Permissions.Count);
        Assert.Contains("invoice.invoices.read", result.Permissions);
        Assert.Contains("invoice.invoices.create", result.Permissions);
        Assert.Single(result.Roles);
        Assert.Equal("accountant", result.Roles[0]);
    }

    [Fact]
    public async Task ResolvePermissionsAsync_ErrorResponse_ReturnsEmptyCollections()
    {
        // Arrange
        var principalId = Guid.NewGuid();
        _handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.InternalServerError
            });

        // Act
        var result = await _client.ResolvePermissionsAsync(principalId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(principalId, result.PrincipalId);
        Assert.Empty(result.Permissions);
        Assert.Empty(result.Roles);
    }
}