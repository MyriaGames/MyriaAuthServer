using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Myria.Server.Auth.Filters
{
    // Same two independent gates AuthController.AdminResetPassword uses, as a reusable filter for
    // the whole operator API: the caller must be on loopback (this service is bound to 0.0.0.0, so
    // that isn't automatic) AND present the shared Admin:InternalSecret. Never trusts
    // X-Forwarded-For - see the reverse-proxy warning in Program.cs.
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public sealed class InternalAdminOnlyAttribute : Attribute, IAuthorizationFilter
    {
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var http = context.HttpContext;
            var remoteIp = http.Connection.RemoteIpAddress;
            // "On this machine" = loopback, OR the peer address equals the address it connected TO
            // (the admin site reaching this service via its own public hostname/IP so the TLS
            // certificate matches). An off-box client can never have remote == local address.
            var localIp = http.Connection.LocalIpAddress;
            if (remoteIp is null || !(IPAddress.IsLoopback(remoteIp) || remoteIp.Equals(localIp)))
            {
                context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
                return;
            }

            var expected = http.RequestServices.GetRequiredService<IConfiguration>()["Admin:InternalSecret"];
            var provided = http.Request.Headers["X-Internal-Secret"].ToString();
            if (string.IsNullOrWhiteSpace(expected) || string.IsNullOrEmpty(provided) ||
                !CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(provided), Encoding.UTF8.GetBytes(expected)))
                context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
        }
    }
}
