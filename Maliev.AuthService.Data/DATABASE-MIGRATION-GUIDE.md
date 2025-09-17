# Database Migration Guide

## Overview

This guide explains how to set up and run Entity Framework migrations for Maliev microservices using CloudNative-PG PostgreSQL clusters.

**Note**: This guide shows examples for AuthService. When adapting for other services, replace:
- `RefreshTokenDbContext` with your service's DbContext name
- `ConnectionStrings__RefreshTokenDbContext` with your service's connection string name
- `auth_app_db` with your service's database name

## Service-Specific Connection Strings

Each service uses its own connection string environment variable:
- **AuthService**: `ConnectionStrings__RefreshTokenDbContext`
- **CountryService**: `ConnectionStrings__CountryDbContext`
- **OrderService**: `ConnectionStrings__OrderDbContext`
- **CurrencyService**: `ConnectionStrings__CurrencyDbContext`
- **MaterialService**: `ConnectionStrings__MaterialDbContext`
- etc.

## Database Architecture

**One Database Per Service**: Each microservice gets its own isolated database within a shared PostgreSQL cluster.

### Database Naming Convention

Each service uses a service-prefixed database name:

| Service | Database Name |
|---------|---------------|
| AuthService | `auth_app_db` |
| OrderService | `order_app_db` |
| CustomerService | `customer_app_db` |
| InvoiceService | `invoice_app_db` |
| EmployeeService | `employee_app_db` |
| SupplierService | `supplier_app_db` |
| PaymentService | `payment_app_db` |
| EmailService | `email_app_db` |
| MessageService | `message_app_db` |
| MaterialService | `material_app_db` |
| CountryService | `country_app_db` |
| CurrencyService | `currency_app_db` |
| JobService | `job_app_db` |
| UploadService | `upload_app_db` |
| PdfService | `pdf_app_db` |
| ReceiptService | `receipt_app_db` |
| QuotationService | `quotation_app_db` |
| QuotationRequestService | `quotationrequest_app_db` |
| PurchaseOrderService | `purchaseorder_app_db` |
| OrderStatusService | `orderstatus_app_db` |
| PredictionService | `prediction_app_db` |

## Setting Up Migrations for a New Service

### 1. Create Design-Time DbContext Factory

In your service's `.Data` project, create `DesignTimeDbContextFactory.cs`:

```csharp
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Maliev.AuthService.Data.DbContexts;

namespace Maliev.AuthService.Data
{
    public class RefreshTokenDbContextFactory : IDesignTimeDbContextFactory<RefreshTokenDbContext>
    {
        public RefreshTokenDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<RefreshTokenDbContext>();
            
            // Use service-specific connection string environment variable
            // Each service should use its own connection string name
            var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__RefreshTokenDbContext");
            
            if (string.IsNullOrEmpty(connectionString))
            {
                // Fallback connection string for design time - use service-specific database name
                connectionString = "Host=localhost;Port=5433;Database=yourservice_app_db;Username=postgres;Password=temp;SslMode=Disable";
            }
            
            optionsBuilder.UseNpgsql(connectionString);
            
            return new RefreshTokenDbContext(optionsBuilder.Options);
        }
    }
}
```

**Key Points:**
- Uses service-specific connection string environment variable (e.g., `ConnectionStrings__RefreshTokenDbContext`)
- Each service has its own connection string name for isolation
- Replace the connection string name based on your service:
  - AuthService: `ConnectionStrings__RefreshTokenDbContext`
  - CountryService: `ConnectionStrings__CountryDbContext`
  - OrderService: `ConnectionStrings__OrderDbContext`
  - etc.
- Fallback uses superuser (`postgres`) for database creation privileges

### 2. Copy Migration Script

Copy `apply-migration.ps1` from AuthService to your service's `.Data` project folder. 

**The same script works for ALL services!** No modifications needed.

### 3. Create Initial Migration

From your service's `.Data` project folder:

```bash
dotnet ef migrations add InitialCreate
```

### 4. Apply Migration

Run the migration script with your service name:

```powershell
# Use service parameter (recommended) - works for any service
.\apply-migration.ps1 -ServiceName "order"     # Creates order_app_db
.\apply-migration.ps1 -ServiceName "customer"  # Creates customer_app_db
.\apply-migration.ps1 -ServiceName "invoice"   # Creates invoice_app_db

# Interactive mode (prompts for all values)
.\apply-migration.ps1
```

### Universal Pattern Benefits

✅ **Same script for all services** - No service-specific modifications needed
✅ **Automatic database naming** - `[service]_app_db` pattern enforced
✅ **Service-specific environment variable** - Each service uses its own connection string name for proper isolation
✅ **Input validation** - Prevents database naming errors
✅ **Superuser privileges** - Can create/delete databases as needed

## Infrastructure Details

### CloudNative-PG Configuration

All services share a single PostgreSQL cluster:

```yaml
# 2-environments/_database/base/cluster.yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: postgres-cluster
spec:
  instances: 3
  primaryUpdateStrategy: unsupervised
  storage:
    size: 10Gi
    storageClass: standard
  bootstrap:
    initdb:
      database: app_db        # Initial database (not used by services)
      owner: app_user
      secret:
        name: postgres-app-credentials
  superuserSecret:
    name: postgres-superuser-credentials
  monitoring:
    enablePodMonitor: true
```

### Secret Configuration

Database credentials are managed via ExternalSecrets:

```yaml
# 2-environments/1-development/secrets.yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: postgres-app-credentials-external
  namespace: maliev-dev
spec:
  secretStoreRef:
    name: gcp-secret-manager
    kind: ClusterSecretStore
  target:
    name: postgres-app-credentials
  data:
  - secretKey: username
    remoteRef:
      key: maliev-dev-pg-app-password
      property: username
  - secretKey: password
    remoteRef:
      key: maliev-dev-pg-app-password
      property: password
```

## Benefits

✅ **Complete isolation**: Each service has its own database
✅ **Resource efficiency**: Single PostgreSQL cluster for all services  
✅ **No migration conflicts**: Each database has its own `__EFMigrationsHistory`
✅ **Scalable**: Easy to add new services
✅ **Reusable**: Same script works for all services
✅ **Environment consistency**: Same pattern across dev/staging/prod

## Troubleshooting

### Port Forward Issues
If port 5433 is in use, specify a different port:
```powershell
.\apply-migration.ps1 -LocalPort 5434
```

### Authentication Errors
Verify that ExternalSecrets are properly synchronized:
```bash
kubectl get secret postgres-app-credentials -n maliev-dev -o yaml
```

### Database Creation Errors
The `app_user` has permission to create databases. If errors occur, check cluster status:
```bash
kubectl get cluster postgres-cluster -n maliev-dev
```

### Migration Conflicts
Each service's migrations are completely isolated in separate databases. No conflicts should occur.

## Example: Setting Up OrderService

1. **Create OrderService.Data project structure**:
   ```
   Maliev.OrderService.Data/
   ├── DbContexts/
   │   └── OrderDbContext.cs
   ├── Entities/
   │   └── Order.cs
   ├── DesignTimeDbContextFactory.cs
   └── apply-migration.ps1
   ```

2. **Create design-time factory** with fallback database `order_app_db`

3. **Create initial migration**:
   ```bash
   dotnet ef migrations add InitialCreate
   ```

4. **Run migration script**: `.\apply-migration.ps1 -ServiceName "order"`

5. **Verify** that `order_app_db` database was created with `Orders` table

The OrderService will now have complete database isolation from all other services.