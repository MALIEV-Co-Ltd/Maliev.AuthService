using System.ComponentModel.DataAnnotations;
using Maliev.AuthService.Infrastructure.Security;
using Xunit;

namespace Maliev.AuthService.Tests.Unit;

public sealed class ServiceLoginRateLimitOptionsTests
{
    [Theory]
    [InlineData(0, 100, 60)]
    [InlineData(1001, 100, 60)]
    [InlineData(100, 0, 60)]
    [InlineData(100, 1001, 60)]
    [InlineData(100, 100, 0)]
    [InlineData(100, 100, 3601)]
    public void ValuesOutsideBounds_AreInvalid(int peerPermits, int clientPermits, int windowSeconds)
    {
        var options = new ServiceLoginRateLimitOptions
        {
            PeerPermitLimit = peerPermits,
            ClientPermitLimit = clientPermits,
            WindowSeconds = windowSeconds
        };

        Assert.False(Validator.TryValidateObject(
            options,
            new ValidationContext(options),
            [],
            validateAllProperties: true));
    }
}
