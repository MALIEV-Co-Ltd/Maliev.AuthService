using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.AuthService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class BindPasskeyCeremonyPrincipalAudience : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "expected_user_type",
                table: "passkey_assertion_ceremonies",
                type: "integer",
                nullable: true);

            // Ceremonies are short-lived authentication challenges. Existing rows predate
            // principal-audience binding and must be invalidated instead of being guessed.
            migrationBuilder.Sql("DELETE FROM passkey_assertion_ceremonies;");

            migrationBuilder.AlterColumn<int>(
                name: "expected_user_type",
                table: "passkey_assertion_ceremonies",
                type: "integer",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "integer",
                oldNullable: true);

            migrationBuilder.AddCheckConstraint(
                name: "ck_passkey_assertion_ceremonies_expected_user_type",
                table: "passkey_assertion_ceremonies",
                sql: "expected_user_type IN (1, 2)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_passkey_assertion_ceremonies_expected_user_type",
                table: "passkey_assertion_ceremonies");

            migrationBuilder.DropColumn(
                name: "expected_user_type",
                table: "passkey_assertion_ceremonies");
        }
    }
}
