namespace Myria.Server.Auth.Models
{
    public enum PasswordResetStatus
    {
        /// <summary>User asked for a reset; no link exists yet. Waits for an operator to verify them.</summary>
        Pending = 0,
        /// <summary>An operator issued a link (TokenHash is set). Valid until ExpiresAt.</summary>
        Issued = 1,
        /// <summary>The link was used to set a new password.</summary>
        Used = 2,
        /// <summary>Operator rejected it, or a newer request/successful reset superseded it.</summary>
        Dismissed = 3
    }

    // There's no email service, so a reset is a human-in-the-loop flow: the user asks, the operator
    // verifies who they are out of band, issues a one-time link in the admin site and sends it
    // themselves. Only a SHA-256 of the link's token is stored - the link itself is shown to the
    // operator exactly once, at issue time, so a leaked database can't be turned into account takeovers.
    public class PasswordResetRequest
    {
        public int Id { get; set; }

        public int UserId { get; set; }
        public User User { get; set; } = null!;

        public DateTime RequestedAt { get; set; } = DateTime.UtcNow;

        public PasswordResetStatus Status { get; set; } = PasswordResetStatus.Pending;

        public string? TokenHash { get; set; }
        public DateTime? IssuedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public DateTime? UsedAt { get; set; }
    }
}
