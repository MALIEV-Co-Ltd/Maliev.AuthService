using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.AuthService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddPasskeyAssertionCeremonies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "passkey_assertion_ceremonies",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    flow_id_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    challenge_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    assertion_options_json = table.Column<string>(type: "jsonb", nullable: false),
                    service_name = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    application = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    created_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    expires_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_passkey_assertion_ceremonies", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_passkey_assertion_ceremonies_challenge_hash",
                table: "passkey_assertion_ceremonies",
                column: "challenge_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_passkey_assertion_ceremonies_expires_at_utc",
                table: "passkey_assertion_ceremonies",
                column: "expires_at_utc");

            migrationBuilder.CreateIndex(
                name: "ix_passkey_assertion_ceremonies_flow_id_hash",
                table: "passkey_assertion_ceremonies",
                column: "flow_id_hash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "passkey_assertion_ceremonies");
        }
    }
}
