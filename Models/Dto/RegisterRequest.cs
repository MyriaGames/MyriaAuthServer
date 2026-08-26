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

        [Required, MinLength(8)]
        public string Password { get; set; } = string.Empty;
    }
}
