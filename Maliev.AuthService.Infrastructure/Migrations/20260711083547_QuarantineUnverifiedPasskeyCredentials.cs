using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.AuthService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class QuarantineUnverifiedPasskeyCredentials : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "is_backed_up",
                table: "passkey_credentials",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "is_backup_eligible",
                table: "passkey_credentials",
                type: "boolean",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "public_key_cose",
                table: "passkey_credentials",
                type: "bytea",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "registration_verification_version",
                table: "passkey_credentials",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<byte[]>(
                name: "user_handle",
                table: "passkey_credentials",
                type: "bytea",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "verified_sign_count",
                table: "passkey_credentials",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "ck_passkey_credentials_registration_verification_version",
                table: "passkey_credentials",
                sql: "registration_verification_version >= 0");

            migrationBuilder.AddCheckConstraint(
                name: "ck_passkey_credentials_verified_sign_count",
                table: "passkey_credentials",
                sql: "verified_sign_count IS NULL OR (verified_sign_count >= 0 AND verified_sign_count <= 4294967295)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_passkey_credentials_registration_verification_version",
                table: "passkey_credentials");

            migrationBuilder.DropCheckConstraint(
                name: "ck_passkey_credentials_verified_sign_count",
                table: "passkey_credentials");

            migrationBuilder.DropColumn(
                name: "is_backed_up",
                table: "passkey_credentials");

            migrationBuilder.DropColumn(
                name: "is_backup_eligible",
                table: "passkey_credentials");

            migrationBuilder.DropColumn(
                name: "public_key_cose",
                table: "passkey_credentials");

            migrationBuilder.DropColumn(
                name: "registration_verification_version",
                table: "passkey_credentials");

            migrationBuilder.DropColumn(
                name: "user_handle",
                table: "passkey_credentials");

            migrationBuilder.DropColumn(
                name: "verified_sign_count",
                table: "passkey_credentials");
        }
    }
}
