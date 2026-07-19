using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Maliev.AuthService.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddGoogleIdentityExchangeNonce : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "google_identity_nonces",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    nonce_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    service_name = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    application = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    exchange_type = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    expires_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    created_at_utc = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_google_identity_nonces", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_google_identity_nonces_expires_at_utc",
                table: "google_identity_nonces",
                column: "expires_at_utc");

            migrationBuilder.CreateIndex(
                name: "ix_google_identity_nonces_nonce_hash",
                table: "google_identity_nonces",
                column: "nonce_hash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "google_identity_nonces");
        }
    }
}
