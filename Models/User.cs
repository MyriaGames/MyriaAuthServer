using System.ComponentModel.DataAnnotations;

namespace MyriaAuthServer.Models
{
    public class User
    {
        public int Id { get; set; }

        [MaxLength(50)]
        public string Username { get; set; } = string.Empty;

        public string PasswordHash { get; set; } = string.Empty;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Account deletion is not implemented yet. If it ever is, it must explicitly
        // call each realm's (not-yet-existing) "delete characters for user X" admin
        // endpoint — there is no DB-level FK to cascade through anymore now that
        // Character.UserId lives in a separate realm database as a plain string.
    }
}
