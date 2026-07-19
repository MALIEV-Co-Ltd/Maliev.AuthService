using Maliev.AuthService.Infrastructure.Services;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public sealed class ServiceIdentityIamContractTests
{
    [Theory]
    [InlineData("auth-service")]
    [InlineData("quote-engine")]
    [InlineData("service-123")]
    [InlineData("a")]
    public void ValidateWorkloadId_CanonicalKebab_ReturnsValue(string workloadId)
    {
        Assert.Equal(workloadId, ServiceIdentityIamContract.ValidateWorkloadId(workloadId));
    }

    [Theory]
    [InlineData("Auth")]
    [InlineData("quote.engine")]
    [InlineData("-auth")]
    [InlineData("auth-")]
    [InlineData("auth--service")]
    [InlineData("auth_service")]
    [InlineData(" auth")]
    [InlineData("auth ")]
    public void ValidateWorkloadId_Noncanonical_Throws(string workloadId)
    {
        Assert.Throws<ArgumentException>(() => ServiceIdentityIamContract.ValidateWorkloadId(workloadId));
    }

    [Fact]
    public void ValidateWorkloadId_OverOneHundredCharacters_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            ServiceIdentityIamContract.ValidateWorkloadId(new string('a', 101)));
    }

    [Theory]
    [InlineData("auth-service", 1, "roles.workloads.auth-service.v1")]
    [InlineData("quote-engine", 42, "roles.workloads.quote-engine.v42")]
    public void ExpectedRoleId_UsesDeterministicIamContract(
        string workloadId,
        int profileVersion,
        string expected)
    {
        Assert.Equal(expected, ServiceIdentityIamContract.ExpectedRoleId(workloadId, profileVersion));
    }
}
