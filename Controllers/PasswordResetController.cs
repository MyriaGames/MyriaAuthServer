using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Myria.Server.Auth.Models.Dto;
using Myria.Server.Auth.Services;

namespace Myria.Server.Auth.Controllers
{
    // Public, unauthenticated side of the password-reset flow. There is no email service, so
    // "request" only queues the ask for the operator (admin site), who verifies the person and
    // sends them the one-time link by hand; the link leads to the page below.
    [ApiController]
    [EnableRateLimiting("auth")]
    public class PasswordResetController(AuthService auth) : ControllerBase
    {
        // Always 202, whether or not the account exists - no username enumeration.
        [HttpPost("api/auth/password-reset/request")]
        [ProducesResponseType(StatusCodes.Status202Accepted)]
        public async Task<IActionResult> RequestReset(PasswordResetRequestDto req)
        {
            await auth.RequestPasswordResetAsync(req.Username.Trim());
            return Accepted(new { message = "If that account exists, the administrators have been notified." });
        }

        [HttpPost("api/auth/password-reset/confirm")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Confirm(PasswordResetConfirmDto req) =>
            await auth.ConfirmPasswordResetAsync(req.Token, req.NewPassword) switch
            {
                AccountUpdateResult.Success => NoContent(),
                AccountUpdateResult.InvalidToken => BadRequest(new
                {
                    message = "This reset link is invalid, expired or has already been used. Ask an administrator for a new one."
                }),
                _ => StatusCode(StatusCodes.Status500InternalServerError)
            };

        // The page the operator-sent link points at. Self-contained (no game client involved) and
        // reads the token from the URL fragment, so it never appears in server logs or Referer.
        // Without a token it doubles as the "I forgot my password" request form.
        [HttpGet("reset-password")]
        public ContentResult Page()
        {
            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            Response.Headers["Content-Security-Policy"] =
                $"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; " +
                "connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";
            Response.Headers["Referrer-Policy"] = "no-referrer";
            Response.Headers["Cache-Control"] = "no-store";
            Response.Headers["X-Content-Type-Options"] = "nosniff";
            return Content(ResetPageHtml.Replace("{{nonce}}", nonce), "text/html; charset=utf-8");
        }

        private const string ResetPageHtml = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Myria - password reset</title>
<style>
body{font-family:system-ui,sans-serif;background:#14161c;color:#e6e6e6;margin:0;display:grid;place-items:center;min-height:100vh}
main{background:#1e222b;padding:2rem;border-radius:10px;width:min(92vw,380px)}
h1{font-size:1.25rem;margin-top:0}label{display:block;margin:.9rem 0 .25rem;font-size:.9rem}
input{width:100%;box-sizing:border-box;padding:.55rem;border-radius:6px;border:1px solid #444a58;background:#14161c;color:inherit}
button{margin-top:1.2rem;width:100%;padding:.65rem;border:0;border-radius:6px;background:#5b8def;color:#fff;font-size:1rem;cursor:pointer}
button:disabled{opacity:.5}#msg{margin-top:1rem;font-size:.9rem;min-height:1.2em}.err{color:#ff8a80}.ok{color:#81c784}
</style></head><body><main>
<h1 id="title">Reset your password</h1>
<form id="f" autocomplete="off"></form>
<div id="msg" role="status"></div>
</main>
<script nonce="{{nonce}}">
const token = new URLSearchParams(location.hash.slice(1)).get('token');
if (token) history.replaceState(null, '', location.pathname);
const f = document.getElementById('f'), msg = document.getElementById('msg');
const say = (t, ok) => { msg.textContent = t; msg.className = ok ? 'ok' : 'err'; };
if (token) {
  f.innerHTML = '<label for="p1">New password (8-128 characters)</label><input id="p1" type="password" minlength="8" maxlength="128" required>'
    + '<label for="p2">Repeat new password</label><input id="p2" type="password" minlength="8" maxlength="128" required>'
    + '<button>Set new password</button>';
} else {
  document.getElementById('title').textContent = 'Forgot your password?';
  f.innerHTML = '<label for="u">Account username</label><input id="u" maxlength="50" required>'
    + '<button>Request a reset</button>'
    + '<p style="font-size:.85rem;opacity:.8">An administrator will verify it is you and send you a one-time link.</p>';
}
f.addEventListener('submit', async e => {
  e.preventDefault();
  const btn = f.querySelector('button'); btn.disabled = true; say('', true);
  try {
    let r;
    if (token) {
      const p1 = f.p1.value; if (p1 !== f.p2.value) { say('Passwords do not match.'); return; }
      r = await fetch('/api/auth/password-reset/confirm', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ token, newPassword: p1 }) });
      if (r.ok) { f.hidden = true; say('Password changed. You can now log in with the new password.', true); return; }
    } else {
      r = await fetch('/api/auth/password-reset/request', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ username: f.u.value.trim() }) });
      if (r.ok) { f.hidden = true; say('Request sent. Contact an administrator so they can verify you.', true); return; }
    }
    const body = await r.json().catch(() => ({}));
    say(r.status === 429 ? 'Too many attempts - wait a minute and try again.' : (body.message || 'Something went wrong (' + r.status + ').'));
  } catch { say('Could not reach the server.'); }
  finally { btn.disabled = false; }
});
</script></body></html>
""";
    }
}
