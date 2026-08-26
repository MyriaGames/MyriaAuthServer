using System.ComponentModel.DataAnnotations;

namespace Myria.Server.Auth.Models.Dto
{
    public class LoginRequest
    {
        [Required]
        public string Username { get; set; } = string.Empty;

        // MaxLength here isn't about password strength - it caps how much text gets fed into
        // PBKDF2-SHA512 (200k iterations) per request, so an attacker can't drive CPU exhaustion
        // by POSTing a multi-MB "password" to this unauthenticated endpoint.
        [Required, MaxLength(128)]
        public string Password { get; set; } = string.Empty;
    }
}
