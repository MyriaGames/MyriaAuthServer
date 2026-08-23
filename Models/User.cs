using System.ComponentModel.DataAnnotations;

namespace Myria.Server.Auth.Models
{
    public class User
    {
        public int Id { get; set; }

        [MaxLength(50)]
        public string Username { get; set; } = string.Empty;

        public string PasswordHash { get; set; } = string.Empty;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Account deletion (AuthService.DeleteAccountAsync) explicitly calls each realm's
        // DELETE /api/admin/characters/{username} before removing this row — there is no
        // DB-level FK to cascade through, since Character.UserId lives in a separate realm
        // database as a plain string.
    }
}
