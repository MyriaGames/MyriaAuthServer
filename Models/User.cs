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

        // Set by an operator (admin site). While true, login is refused with a "password change
        // required" response until the user completes ChangePasswordAsync (or a reset link),
        // which clears it. Deliberately checked only AFTER the password verified, so it can't
        // be used to probe which accounts are flagged.
        public bool MustChangePassword { get; set; }

        // Account deletion (AuthService.DeleteAccountAsync) explicitly calls each realm's
        // DELETE /api/admin/characters/{username} before removing this row — there is no
        // DB-level FK to cascade through, since Character.UserId lives in a separate realm
        // database as a plain string.
    }
}
