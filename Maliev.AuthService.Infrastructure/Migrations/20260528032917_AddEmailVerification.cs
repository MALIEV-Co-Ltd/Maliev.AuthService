using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.AuthService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddEmailVerification : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "user_principals",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    email = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    first_name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    last_name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    user_type = table.Column<string>(type: "text", nullable: false),
                    email_verified_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    updated_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_user_principals", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "verification_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    principal_id = table.Column<Guid>(type: "uuid", nullable: false),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    email = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    expires_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    is_used = table.Column<bool>(type: "boolean", nullable: false, defaultValue: false),
                    used_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false, defaultValueSql: "NOW()"),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_verification_tokens", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "idx_user_principals_email",
                table: "user_principals",
                column: "email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "idx_user_principals_user_type",
                table: "user_principals",
                column: "user_type");

            migrationBuilder.CreateIndex(
                name: "idx_verification_tokens_expires_at",
                table: "verification_tokens",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "idx_verification_tokens_principal_id",
                table: "verification_tokens",
                column: "principal_id");

            migrationBuilder.CreateIndex(
                name: "idx_verification_tokens_token_hash",
                table: "verification_tokens",
                column: "token_hash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "user_principals");

            migrationBuilder.DropTable(
                name: "verification_tokens");
        }
    }
}
