using System.ComponentModel.DataAnnotations;

namespace Myria.Server.Auth.Models.Dto
{
    public class RegisterRequest
    {
        // Letters/digits/underscore/hyphen only - this username is also used as a segment of a
        // locally-constructed save-file path on the client (see Myria.Lib's SafeFileName), so
        // rejecting path-traversal/invalid-filename characters here (rather than relying on the
        // client to sanitize) removes the actual root cause instead of just the symptom.
        [Required, MinLength(3), MaxLength(50), RegularExpression(@"^[\p{L}\p{N}_-]+$")]
        public string Username { get; set; } = string.Empty;

        // Upper bound caps how much text gets fed into PBKDF2-SHA512 (200k iterations) per
        // request, so an attacker can't drive CPU exhaustion by POSTing a multi-MB "password".
        [Required, MinLength(8), MaxLength(128)]
        public string Password { get; set; } = string.Empty;
    }
}
