using System.ComponentModel.DataAnnotations;

namespace Myria.Server.Auth.Models.Dto
{
    public class AdminResetPasswordRequest
    {
        [Required]
        public string Username { get; set; } = string.Empty;

        [Required, MinLength(8), MaxLength(128)]
        public string NewPassword { get; set; } = string.Empty;
    }
}
