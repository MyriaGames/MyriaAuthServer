using Microsoft.AspNetCore.Mvc;
using Myria.Server.Auth.Filters;
using Myria.Server.Auth.Models.Dto;
using Myria.Server.Auth.Services;

namespace Myria.Server.Auth.Controllers
{
    // Operator API for the localhost admin site (Myria.Server.Admin). Loopback + shared secret
    // (see InternalAdminOnlyAttribute); deliberately not rate limited - every call arrives from
    // 127.0.0.1, so the per-IP "auth" policy would just throttle the operator against themselves.
    [ApiController]
    [Route("api/admin")]
    [InternalAdminOnly]
    public class AdminController(AuthService auth) : ControllerBase
    {
        [HttpGet("users")]
        public async Task<IActionResult> ListUsers(string? search, int skip = 0, int take = 50)
        {
            var (users, total) = await auth.AdminListUsersAsync(search, skip, take);
            return Ok(new { total, users });
        }

        [HttpGet("users/{username}")]
        public async Task<IActionResult> GetUser(string username)
        {
            var user = await auth.AdminGetUserAsync(username);
            return user is null ? NotFound() : Ok(user);
        }

        // Purges the account's characters on every realm first, then the account (see
        // AuthService.DeleteAccountAsync for the partial-failure trade-off).
        [HttpDelete("users/{username}")]
        public async Task<IActionResult> DeleteUser(string username) =>
            await auth.AdminDeleteAccountAsync(username) switch
            {
                AccountUpdateResult.Success => NoContent(),
                AccountUpdateResult.NotFound => NotFound(),
                AccountUpdateResult.RealmUnreachable => StatusCode(StatusCodes.Status502BadGateway,
                    new { message = "Could not reach one or more realms - account was not deleted." }),
                _ => StatusCode(StatusCodes.Status500InternalServerError)
            };

        [HttpPut("users/{username}/must-change-password")]
        public async Task<IActionResult> SetMustChangePassword(string username, SetMustChangePasswordRequest req) =>
            await auth.AdminSetMustChangePasswordAsync(username, req.Required) switch
            {
                AccountUpdateResult.Success => NoContent(),
                AccountUpdateResult.NotFound => NotFound(),
                _ => StatusCode(StatusCodes.Status500InternalServerError)
            };

        [HttpGet("password-resets")]
        public async Task<IActionResult> ListResets(bool openOnly = true) =>
            Ok(await auth.AdminListResetRequestsAsync(openOnly));

        [HttpPost("password-resets/{id:int}/issue")]
        public async Task<IActionResult> IssueForRequest(int id, IssueResetLinkRequest? req)
        {
            var (result, link) = await auth.IssueResetLinkAsync(id, req?.ValidMinutes);
            return result == AccountUpdateResult.Success ? Ok(link) : NotFound();
        }

        [HttpPost("users/{username}/password-reset")]
        public async Task<IActionResult> IssueForUser(string username, IssueResetLinkRequest? req)
        {
            var (result, link) = await auth.IssueResetLinkForUserAsync(username, req?.ValidMinutes);
            return result == AccountUpdateResult.Success ? Ok(link) : NotFound();
        }

        [HttpPost("password-resets/{id:int}/dismiss")]
        public async Task<IActionResult> Dismiss(int id) =>
            await auth.DismissResetRequestAsync(id) == AccountUpdateResult.Success ? NoContent() : NotFound();
    }
}
