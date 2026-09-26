using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Myria.Server.Auth.Models.Dto;
using Myria.Server.Auth.Services;

namespace Myria.Server.Auth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [EnableRateLimiting("auth")]
    public class AuthController(AuthService auth, IConfiguration config) : ControllerBase
    {
        [HttpPost("register")]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status409Conflict)]
        public async Task<IActionResult> Register(RegisterRequest req)
        {
            var result = await auth.RegisterAsync(req);
            if (result is null)
                return Conflict(new { message = "Username already taken." });

            return CreatedAtAction(nameof(Register), result);
        }

        [HttpPost("login")]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login(LoginRequest req)
        {
            var (result, response) = await auth.LoginAsync(req);
            return result switch
            {
                AccountUpdateResult.Success => Ok(response),
                // Distinct from 401 so a client doesn't report "wrong password" for a correct one.
                // The password was verified, so the client can go straight to PUT /api/auth/password.
                AccountUpdateResult.PasswordChangeRequired => StatusCode(StatusCodes.Status403Forbidden, new
                {
                    code = "PasswordChangeRequired",
                    message = "An administrator requires you to change your password before logging in."
                }),
                _ => Unauthorized(new { message = "Invalid username or password." })
            };
        }

        // GDPR Art. 17 — deletes the account and, via each realm's internal admin
        // endpoint, all characters owned by it. Re-verifies the password like login
        // does, rather than requiring a bearer token, so this stays a simple form post.
        [HttpDelete("account")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status502BadGateway)]
        public async Task<IActionResult> DeleteAccount(LoginRequest req)
        {
            var result = await auth.DeleteAccountAsync(req);
            return result switch
            {
                AccountUpdateResult.Success => NoContent(),
                AccountUpdateResult.InvalidCredentials =>
                    Unauthorized(new { message = "Invalid username or password." }),
                AccountUpdateResult.RealmUnreachable =>
                    StatusCode(StatusCodes.Status502BadGateway, new
                    {
                        message = "Could not reach one or more realms — account was not deleted. Please try again later."
                    }),
                _ => StatusCode(StatusCodes.Status500InternalServerError)
            };
        }

        // Re-issues a fresh token bound to the new username — see AuthService.ChangeUsernameAsync's
        // remarks on why the old token stops matching anything on the realms right after this.
        [HttpPut("username")]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status409Conflict)]
        [ProducesResponseType(StatusCodes.Status502BadGateway)]
        public async Task<IActionResult> ChangeUsername(ChangeUsernameRequest req)
        {
            var (result, response) = await auth.ChangeUsernameAsync(req);
            return result switch
            {
                AccountUpdateResult.Success => Ok(response),
                AccountUpdateResult.InvalidCredentials =>
                    Unauthorized(new { message = "Invalid username or password." }),
                AccountUpdateResult.Conflict =>
                    Conflict(new { message = "This username is already taken." }),
                AccountUpdateResult.RealmUnreachable =>
                    StatusCode(StatusCodes.Status502BadGateway, new
                    {
                        message = "Could not reach one or more realms — username was not changed. Please try again later."
                    }),
                _ => StatusCode(StatusCodes.Status500InternalServerError)
            };
        }

        [HttpPut("password")]
        [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> ChangePassword(ChangePasswordRequest req)
        {
            var (result, response) = await auth.ChangePasswordAsync(req);
            return result switch
            {
                AccountUpdateResult.Success => Ok(response),
                AccountUpdateResult.InvalidCredentials =>
                    Unauthorized(new { message = "Invalid username or password." }),
                AccountUpdateResult.Conflict =>
                    Conflict(new { message = "The new password must be different from the current one." }),
                _ => StatusCode(StatusCodes.Status500InternalServerError)
            };
        }

        // Operator-only rescue path for someone locked out with no way to self-serve a reset
        // (see AuthService.AdminResetPasswordAsync) - not called by the game client at all.
        // Two independent gates, both required: the caller must be on loopback (i.e. actually
        // on the box the server runs on - it's bound to 0.0.0.0, reachable from the internet,
        // so this isn't automatic) AND present the shared Admin:InternalSecret. Call this
        // yourself from the server itself (e.g. via curl against https://localhost:<port>) after
        // verifying out of band who you're actually talking to:
        //   curl -X PUT https://localhost:<auth-port>/api/auth/admin/password \
        //     -H "X-Internal-Secret: <Admin:InternalSecret>" -H "Content-Type: application/json" \
        //     -d '{"username":"<name>","newPassword":"<temporary password>"}'
        [HttpPut("admin/password")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> AdminResetPassword(AdminResetPasswordRequest req)
        {
            var remoteIp = HttpContext.Connection.RemoteIpAddress;
            if (remoteIp is null || !System.Net.IPAddress.IsLoopback(remoteIp))
                return StatusCode(StatusCodes.Status403Forbidden);

            var expected = config["Admin:InternalSecret"];
            var provided = Request.Headers["X-Internal-Secret"].ToString();
            if (string.IsNullOrWhiteSpace(expected) || string.IsNullOrEmpty(provided) ||
                !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.UTF8.GetBytes(provided), System.Text.Encoding.UTF8.GetBytes(expected)))
                // Forbid() would throw here — this service has no AddAuthentication/scheme
                // registered at all (see Program.cs), unlike Realm's AdminController which does.
                return StatusCode(StatusCodes.Status403Forbidden);

            var result = await auth.AdminResetPasswordAsync(req.Username, req.NewPassword);
            return result switch
            {
                AccountUpdateResult.Success => NoContent(),
                AccountUpdateResult.NotFound => NotFound(new { message = "No account with that username." }),
                _ => StatusCode(StatusCodes.Status500InternalServerError)
            };
        }
    }
}
