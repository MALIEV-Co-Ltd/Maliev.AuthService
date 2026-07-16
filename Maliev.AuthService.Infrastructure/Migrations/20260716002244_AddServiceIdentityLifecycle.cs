using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.AuthService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddServiceIdentityLifecycle : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "profile_version",
                table: "service_credentials",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "revoked_at",
                table: "service_credentials",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "role_id",
                table: "service_credentials",
                type: "character varying(160)",
                maxLength: 160,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "workload_id",
                table: "service_credentials",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "service_credential_versions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    service_credential_id = table.Column<Guid>(type: "uuid", nullable: false),
                    version = table.Column<int>(type: "integer", nullable: false),
                    secret_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    activated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    grace_expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    hard_expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_service_credential_versions", x => x.id);
                    table.CheckConstraint("ck_service_credential_versions_expiry", "hard_expires_at > created_at");
                    table.CheckConstraint("ck_service_credential_versions_hash", "length(secret_hash) = 64 AND secret_hash ~ '^[0-9A-F]{64}$'");
                    table.CheckConstraint("ck_service_credential_versions_status", "status IN ('Pending', 'Active', 'Grace', 'Revoked')");
                    table.CheckConstraint("ck_service_credential_versions_version", "version > 0");
                    table.ForeignKey(
                        name: "fk_service_credential_versions_service_credentials_service_cre~",
                        column: x => x.service_credential_id,
                        principalTable: "service_credentials",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "service_identity_operations",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    workload_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    kind = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    request_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    actor_id = table.Column<Guid>(type: "uuid", nullable: false),
                    state = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    iam_principal_id = table.Column<Guid>(type: "uuid", nullable: true),
                    iam_profile_version = table.Column<int>(type: "integer", nullable: true),
                    iam_role_id = table.Column<string>(type: "character varying(160)", maxLength: 160, nullable: true),
                    credential_version_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_service_identity_operations", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "idx_service_credentials_workload_id",
                table: "service_credentials",
                column: "workload_id",
                unique: true,
                filter: "workload_id IS NOT NULL");

            migrationBuilder.AddCheckConstraint(
                name: "ck_service_credentials_managed_binding",
                table: "service_credentials",
                sql: "workload_id IS NULL OR (principal_id IS NOT NULL AND profile_version IS NOT NULL AND profile_version > 0 AND role_id IS NOT NULL)");

            migrationBuilder.CreateIndex(
                name: "idx_service_credential_versions_credential_status",
                table: "service_credential_versions",
                columns: new[] { "service_credential_id", "status" });

            migrationBuilder.CreateIndex(
                name: "idx_service_credential_versions_credential_version",
                table: "service_credential_versions",
                columns: new[] { "service_credential_id", "version" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_service_credential_versions_one_active",
                table: "service_credential_versions",
                column: "service_credential_id",
                unique: true,
                filter: "status = 'Active'");

            migrationBuilder.CreateIndex(
                name: "idx_service_identity_operations_workload_kind",
                table: "service_identity_operations",
                columns: new[] { "workload_id", "kind" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "service_credential_versions");

            migrationBuilder.DropTable(
                name: "service_identity_operations");

            migrationBuilder.DropIndex(
                name: "idx_service_credentials_workload_id",
                table: "service_credentials");

            migrationBuilder.DropCheckConstraint(
                name: "ck_service_credentials_managed_binding",
                table: "service_credentials");

            migrationBuilder.DropColumn(
                name: "profile_version",
                table: "service_credentials");

            migrationBuilder.DropColumn(
                name: "revoked_at",
                table: "service_credentials");

            migrationBuilder.DropColumn(
                name: "role_id",
                table: "service_credentials");

            migrationBuilder.DropColumn(
                name: "workload_id",
                table: "service_credentials");
        }
    }
}
