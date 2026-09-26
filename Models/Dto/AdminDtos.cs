using System.ComponentModel.DataAnnotations;

namespace Myria.Server.Auth.Models.Dto
{
    public record AdminUserDto(int Id, string Username, DateTime CreatedAt, bool MustChangePassword, int OpenResetRequests);

    /// <summary>Status is Pending, Issued, Expired, Used or Dismissed (Expired is derived, not stored).</summary>
    public record PasswordResetDto(
        int Id, string Username, DateTime RequestedAt, string Status,
        DateTime? IssuedAt, DateTime? ExpiresAt, DateTime? UsedAt);

    public record IssuedResetLink(int RequestId, string Username, string Url, DateTime ExpiresAt);

    public class SetMustChangePasswordRequest
    {
        public bool Required { get; set; } = true;
    }

    public class IssueResetLinkRequest
    {
        [Range(5, 1440)]
        public int? ValidMinutes { get; set; }
    }

    public class PasswordResetRequestDto
    {
        [Required, MaxLength(50)]
        public string Username { get; set; } = string.Empty;
    }

    public class PasswordResetConfirmDto
    {
        [Required, MaxLength(200)]
        public string Token { get; set; } = string.Empty;

        [Required, MinLength(8), MaxLength(128)]
        public string NewPassword { get; set; } = string.Empty;
    }
}
