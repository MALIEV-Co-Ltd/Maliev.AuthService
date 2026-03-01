using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.AuthService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "account_lockouts",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_type = table.Column<string>(type: "text", nullable: false),
                    failed_attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    locked_until = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    last_attempt_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false, defaultValueSql: "'\\x0000000000000000'::bytea")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_account_lockouts", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "auth_audit_logs",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    user_type = table.Column<string>(type: "text", nullable: true),
                    action = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ip_address = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    user_agent = table.Column<string>(type: "text", nullable: true),
                    success = table.Column<bool>(type: "boolean", nullable: false),
                    failure_reason = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    correlation_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_auth_audit_logs", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "ip_rate_limits",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    ip_address = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: false),
                    failed_attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    blocked_until = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    window_start = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false, defaultValueSql: "'\\x0000000000000000'::bytea")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_ip_rate_limits", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "revoked_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    jti = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_type = table.Column<string>(type: "text", nullable: false),
                    revoked_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    expires_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    reason = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_revoked_tokens", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "service_credentials",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    client_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    principal_id = table.Column<Guid>(type: "uuid", nullable: true),
                    client_secret_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    service_name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_service_credentials", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "token_families",
                columns: table => new
                {
                    family_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_type = table.Column<string>(type: "text", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    last_refresh_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_token_families", x => x.family_id);
                });

            migrationBuilder.CreateTable(
                name: "refresh_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    family_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    principal_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_type = table.Column<string>(type: "text", nullable: false),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    email = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    is_used = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    used_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    expires_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    ip_address = table.Column<string>(type: "character varying(45)", maxLength: 45, nullable: true),
                    version = table.Column<byte[]>(type: "bytea", rowVersion: true, nullable: false, defaultValueSql: "'\\x0000000000000000'::bytea")
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_refresh_tokens", x => x.id);
                    table.ForeignKey(
                        name: "fk_refresh_tokens_token_families",
                        column: x => x.family_id,
                        principalTable: "token_families",
                        principalColumn: "family_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "idx_account_lockouts_locked_until",
                table: "account_lockouts",
                column: "locked_until");

            migrationBuilder.CreateIndex(
                name: "idx_account_lockouts_user_id_user_type",
                table: "account_lockouts",
                columns: new[] { "user_id", "user_type" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_auth_audit_logs_action_success",
                table: "auth_audit_logs",
                columns: new[] { "action", "success" });

            migrationBuilder.CreateIndex(
                name: "idx_auth_audit_logs_correlation_id",
                table: "auth_audit_logs",
                column: "correlation_id");

            migrationBuilder.CreateIndex(
                name: "idx_auth_audit_logs_created_at",
                table: "auth_audit_logs",
                column: "created_at");

            migrationBuilder.CreateIndex(
                name: "idx_auth_audit_logs_user_id",
                table: "auth_audit_logs",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "idx_ip_rate_limits_blocked_until",
                table: "ip_rate_limits",
                column: "blocked_until");

            migrationBuilder.CreateIndex(
                name: "idx_ip_rate_limits_ip_address",
                table: "ip_rate_limits",
                column: "ip_address",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_refresh_tokens_expires_at",
                table: "refresh_tokens",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "idx_refresh_tokens_family_id",
                table: "refresh_tokens",
                column: "family_id");

            migrationBuilder.CreateIndex(
                name: "idx_refresh_tokens_token_hash",
                table: "refresh_tokens",
                column: "token_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_refresh_tokens_user_id",
                table: "refresh_tokens",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "idx_revoked_tokens_expires_at",
                table: "revoked_tokens",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "idx_revoked_tokens_jti",
                table: "revoked_tokens",
                column: "jti",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_revoked_tokens_user_id",
                table: "revoked_tokens",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "idx_service_credentials_client_id",
                table: "service_credentials",
                column: "client_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_service_credentials_is_active",
                table: "service_credentials",
                column: "is_active");

            migrationBuilder.CreateIndex(
                name: "idx_token_families_user_id",
                table: "token_families",
                column: "user_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "account_lockouts");

            migrationBuilder.DropTable(
                name: "auth_audit_logs");

            migrationBuilder.DropTable(
                name: "ip_rate_limits");

            migrationBuilder.DropTable(
                name: "refresh_tokens");

            migrationBuilder.DropTable(
                name: "revoked_tokens");

            migrationBuilder.DropTable(
                name: "service_credentials");

            migrationBuilder.DropTable(
                name: "token_families");
        }
    }
}
