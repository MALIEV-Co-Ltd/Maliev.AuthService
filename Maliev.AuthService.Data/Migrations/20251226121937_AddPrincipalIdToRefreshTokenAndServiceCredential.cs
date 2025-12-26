using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.AuthService.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddPrincipalIdToRefreshTokenAndServiceCredential : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "principal_id",
                table: "service_credentials",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "principal_id",
                table: "refresh_tokens",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "principal_id",
                table: "service_credentials");

            migrationBuilder.DropColumn(
                name: "principal_id",
                table: "refresh_tokens");
        }
    }
}
