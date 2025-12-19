using Maliev.AuthService.Tests.Contract;
using Xunit;

namespace Maliev.AuthService.Tests.Infrastructure;

/// <summary>
/// Collection definition for AuthService integration tests.
/// Ensures tests run sequentially and share the same test factory to avoid Docker container exhaustion.
/// </summary>
[CollectionDefinition("AuthService Collection")]
public class AuthServiceCollection : ICollectionFixture<TestWebApplicationFactory>
{
}
