using Maliev.AuthService.Infrastructure.DbContexts;
using MassTransit.EntityFrameworkCoreIntegration;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace Maliev.AuthService.Tests.Infrastructure;

/// <summary>
/// Verifies that the EF Core model matches the current migrations.
/// This prevents "Pending model changes" exceptions at runtime.
/// </summary>
public class ModelIntegrityTests
{
    [Fact]
    public void Model_ShouldNotHavePendingChanges()
    {
        // Use a dummy connection string just to build the model for comparison
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql("Host=localhost;Database=ModelCheck")
            .Options;

        using var context = new AuthDbContext(options);

        // This helper (available in EF Core 9.0+) checks if the current code
        // matches the last snapshot in the Migrations folder.
        var hasChanges = context.Database.HasPendingModelChanges();

        Assert.False(hasChanges,
            "The EF Core model for 'AuthDbContext' has changed but no migration has been added. " +
            "Run 'dotnet ef migrations add <Name> --project Maliev.AuthService.Data --startup-project Maliev.AuthService.Api' to fix this.");
    }

    [Fact]
    public void Model_ShouldIncludeMassTransitOutboxEntities()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseNpgsql("Host=localhost;Database=auth_model_test;Username=postgres;Password=postgres")
            .Options;

        using var context = new AuthDbContext(options);

        Assert.NotNull(context.Model.FindEntityType(typeof(InboxState)));
        Assert.NotNull(context.Model.FindEntityType(typeof(OutboxMessage)));
        Assert.NotNull(context.Model.FindEntityType(typeof(OutboxState)));
    }
}
