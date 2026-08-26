using System.ComponentModel.DataAnnotations;

namespace Myria.Server.Auth.Models.Dto
{
    public class ChangeUsernameRequest
    {
        [Required]
        public string Username { get; set; } = string.Empty;

        [Required, MaxLength(128)]
        public string Password { get; set; } = string.Empty;

        [Required, MinLength(3), MaxLength(50), RegularExpression(@"^[\p{L}\p{N}_-]+$")]
        public string NewUsername { get; set; } = string.Empty;
    }
}
