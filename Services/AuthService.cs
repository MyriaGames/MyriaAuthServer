using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Myria.Server.Auth.Data;
using Myria.Server.Auth.Models;
using Myria.Server.Auth.Models.Dto;

namespace Myria.Server.Auth.Services
{
    public enum AccountUpdateResult
    {
        Success,
        InvalidCredentials,
        Conflict,
        RealmUnreachable,
        NotFound,
        /// <summary>Credentials were right, but an operator flagged the account for a forced password change.</summary>
        PasswordChangeRequired,
        /// <summary>Password-reset link is unknown, expired, already used or superseded.</summary>
        InvalidToken
    }

    public class AuthService(
        AuthDbContext db, IConfiguration config, IHttpClientFactory httpClientFactory, ILogger<AuthService> logger)
    {
        private const int SaltSize = 16;
        private const int HashSize = 32;
        private const int Iterations = 200_000;

        // A fixed, meaningless stored hash used only to burn the same PBKDF2 cost when a
        // username doesn't exist. VerifyPassword itself is already constant-time for a genuine
        // comparison (CryptographicOperations.FixedTimeEquals), but every call site used to
        // short-circuit past it entirely via "user is null || !VerifyPassword(...)" - skipping
        // ~200k PBKDF2-SHA512 iterations makes a nonexistent-username response measurably
        // faster than a wrong-password one, which is a reliable timing oracle for account
        // enumeration. Always calling VerifyPassword (against this dummy hash when there's no
        // real user) closes that gap; it can never actually match a real password.
        private static readonly string DummyPasswordHash =
            $"{Convert.ToBase64String(new byte[SaltSize])}:{Convert.ToBase64String(new byte[HashSize])}";

        public async Task<AuthResponse?> RegisterAsync(RegisterRequest req)
        {
            if (await db.Users.AnyAsync(u => u.Username == req.Username))
                return null;

            var user = new User
            {
                Username = req.Username,
                PasswordHash = HashPassword(req.Password)
            };

            db.Users.Add(user);
            await db.SaveChangesAsync();

            return BuildToken(user);
        }

        // No token is issued while MustChangePassword is set - the token is what grants realm
        // access, so a flagged account has to go through ChangePasswordAsync (or a reset link)
        // first. Only reported after the password verified, so it can't be used to find out
        // which accounts are flagged without knowing their password.
        public async Task<(AccountUpdateResult Result, AuthResponse? Response)> LoginAsync(LoginRequest req)
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Username == req.Username);
            if (!VerifyPassword(req.Password, user?.PasswordHash ?? DummyPasswordHash) || user is null)
                return (AccountUpdateResult.InvalidCredentials, null);

            if (user.MustChangePassword)
                return (AccountUpdateResult.PasswordChangeRequired, null);

            return (AccountUpdateResult.Success, BuildToken(user));
        }

        // GDPR Art. 17 right to erasure. Re-verifies the password (rather than trusting a JWT)
        // so this can be called from a simple, stateless "delete my account" form without this
        // service needing to validate tokens itself. Deletes character data on every configured
        // realm before removing the user row — if any realm can't be reached, nothing is deleted
        // here either, so a retry doesn't leave orphaned characters behind on the realms that did
        // succeed the first time... except those already deleted; that's an accepted trade-off
        // for a best-effort, small-scale deployment rather than a distributed transaction.
        public async Task<AccountUpdateResult> DeleteAccountAsync(LoginRequest req)
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Username == req.Username);
            if (!VerifyPassword(req.Password, user?.PasswordHash ?? DummyPasswordHash) || user is null)
                return AccountUpdateResult.InvalidCredentials;

            return await DeleteUserAsync(user);
        }

        private async Task<AccountUpdateResult> DeleteUserAsync(User user)
        {
            if (!await CallOnEveryRealmAsync(realm => new HttpRequestMessage(
                    HttpMethod.Delete,
                    $"{realm.Url.TrimEnd('/')}/api/admin/characters/{Uri.EscapeDataString(user.Username)}")))
                return AccountUpdateResult.RealmUnreachable;

            db.Users.Remove(user);
            await db.SaveChangesAsync();
            return AccountUpdateResult.Success;
        }

        // Username is what Character.UserId is keyed by on every realm (see Character.cs), so
        // renaming an account has to rename the character rows too, not just this row — otherwise
        // every character the user owns silently becomes unreachable under the old username. The
        // caller also needs a freshly-minted token afterwards: the old one's UniqueName claim still
        // carries the old username, which no longer matches anything once the rename lands.
        public async Task<(AccountUpdateResult Result, AuthResponse? Response)> ChangeUsernameAsync(ChangeUsernameRequest req)
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Username == req.Username);
            if (!VerifyPassword(req.Password, user?.PasswordHash ?? DummyPasswordHash) || user is null)
                return (AccountUpdateResult.InvalidCredentials, null);

            if (req.NewUsername == user.Username)
                return (AccountUpdateResult.Success, BuildToken(user));

            if (await db.Users.AnyAsync(u => u.Username == req.NewUsername))
                return (AccountUpdateResult.Conflict, null);

            if (!await CallOnEveryRealmAsync(realm => new HttpRequestMessage(
                    HttpMethod.Put, $"{realm.Url.TrimEnd('/')}/api/admin/characters/rename")
                {
                    Content = JsonContent.Create(new { OldUsername = user.Username, NewUsername = req.NewUsername })
                }))
                return (AccountUpdateResult.RealmUnreachable, null);

            user.Username = req.NewUsername;
            await db.SaveChangesAsync();
            return (AccountUpdateResult.Success, BuildToken(user));
        }

        public async Task<(AccountUpdateResult Result, AuthResponse? Response)> ChangePasswordAsync(ChangePasswordRequest req)
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Username == req.Username);
            if (!VerifyPassword(req.OldPassword, user?.PasswordHash ?? DummyPasswordHash) || user is null)
                return (AccountUpdateResult.InvalidCredentials, null);

            // A forced change is pointless if the "new" password is the one that was just flagged.
            if (user.MustChangePassword && req.NewPassword == req.OldPassword)
                return (AccountUpdateResult.Conflict, null);

            user.PasswordHash = HashPassword(req.NewPassword);
            user.MustChangePassword = false;
            await db.SaveChangesAsync();
            return (AccountUpdateResult.Success, BuildToken(user));
        }

        // ── Password reset (no email service: operator-mediated, see PasswordResetRequest) ──

        // Public entry point. Always looks identical from the outside whether or not the username
        // exists (the controller answers 202 either way) - this only records a Pending request for
        // a real account, at most one at a time so it can't be used to flood the operator's queue.
        public async Task RequestPasswordResetAsync(string username)
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Username == username);
            if (user is null) return;

            if (await db.PasswordResetRequests.AnyAsync(r =>
                    r.UserId == user.Id && r.Status == PasswordResetStatus.Pending))
                return;

            db.PasswordResetRequests.Add(new PasswordResetRequest { UserId = user.Id });
            await db.SaveChangesAsync();
        }

        // Operator action: verify the person out of band first, then issue. Returns the one-time
        // link - the token itself is never stored, so this is the only time it can be shown.
        // Re-issuing replaces the previous link, so a user only ever has one live link.
        public async Task<(AccountUpdateResult Result, IssuedResetLink? Link)> IssueResetLinkAsync(
            int requestId, int? validMinutes = null)
        {
            var request = await db.PasswordResetRequests.Include(r => r.User)
                .SingleOrDefaultAsync(r => r.Id == requestId);
            if (request is null || request.Status is PasswordResetStatus.Used or PasswordResetStatus.Dismissed)
                return (AccountUpdateResult.NotFound, null);

            return (AccountUpdateResult.Success, await IssueAsync(request, validMinutes));
        }

        // Operator action without a prior user request (e.g. they contacted you directly).
        public async Task<(AccountUpdateResult Result, IssuedResetLink? Link)> IssueResetLinkForUserAsync(
            string username, int? validMinutes = null)
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Username == username);
            if (user is null)
                return (AccountUpdateResult.NotFound, null);

            var request = await db.PasswordResetRequests.Include(r => r.User)
                .Where(r => r.UserId == user.Id &&
                            (r.Status == PasswordResetStatus.Pending || r.Status == PasswordResetStatus.Issued))
                .OrderByDescending(r => r.RequestedAt)
                .FirstOrDefaultAsync();

            if (request is null)
            {
                request = new PasswordResetRequest { UserId = user.Id, User = user };
                db.PasswordResetRequests.Add(request);
            }

            return (AccountUpdateResult.Success, await IssueAsync(request, validMinutes));
        }

        private async Task<IssuedResetLink> IssueAsync(PasswordResetRequest request, int? validMinutes)
        {
            var minutes = Math.Clamp(
                validMinutes ?? config.GetValue("PasswordReset:LinkValidMinutes", 60), 5, 24 * 60);

            var token = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(
                RandomNumberGenerator.GetBytes(32));

            // Supersede any other live link for this user: only the newest one may work.
            var others = await db.PasswordResetRequests
                .Where(r => r.UserId == request.UserId && r.Id != request.Id && r.Status == PasswordResetStatus.Issued)
                .ToListAsync();
            foreach (var o in others)
                o.Status = PasswordResetStatus.Dismissed;

            var now = DateTime.UtcNow;
            request.TokenHash = HashToken(token);
            request.Status = PasswordResetStatus.Issued;
            request.IssuedAt = now;
            request.ExpiresAt = now.AddMinutes(minutes);
            await db.SaveChangesAsync();

            // The token rides in the URL *fragment*: it is never sent to the server in the page
            // request, so it stays out of access logs and Referer headers. The page's script reads
            // it and POSTs it to /api/auth/password-reset/confirm.
            var baseUrl = (config["PasswordReset:PublicBaseUrl"] ?? "http://localhost:5050").TrimEnd('/');
            return new IssuedResetLink(
                request.Id, request.User.Username, $"{baseUrl}/reset-password#token={token}", request.ExpiresAt.Value);
        }

        public async Task<AccountUpdateResult> DismissResetRequestAsync(int requestId)
        {
            var request = await db.PasswordResetRequests.SingleOrDefaultAsync(r => r.Id == requestId);
            if (request is null || request.Status is PasswordResetStatus.Used or PasswordResetStatus.Dismissed)
                return AccountUpdateResult.NotFound;

            request.Status = PasswordResetStatus.Dismissed;
            request.TokenHash = null;
            await db.SaveChangesAsync();
            return AccountUpdateResult.Success;
        }

        // Public: the user follows the operator-sent link and picks a new password.
        public async Task<AccountUpdateResult> ConfirmPasswordResetAsync(string token, string newPassword)
        {
            var hash = HashToken(token);
            var now = DateTime.UtcNow;
            var request = await db.PasswordResetRequests.Include(r => r.User)
                .SingleOrDefaultAsync(r => r.TokenHash == hash && r.Status == PasswordResetStatus.Issued);

            if (request is null || request.ExpiresAt is null || request.ExpiresAt <= now)
                return AccountUpdateResult.InvalidToken;

            request.User.PasswordHash = HashPassword(newPassword);
            request.User.MustChangePassword = false;
            request.Status = PasswordResetStatus.Used;
            request.UsedAt = now;
            request.TokenHash = null;

            var open = await db.PasswordResetRequests
                .Where(r => r.UserId == request.UserId && r.Id != request.Id &&
                            (r.Status == PasswordResetStatus.Pending || r.Status == PasswordResetStatus.Issued))
                .ToListAsync();
            foreach (var o in open)
            {
                o.Status = PasswordResetStatus.Dismissed;
                o.TokenHash = null;
            }

            await db.SaveChangesAsync();
            return AccountUpdateResult.Success;
        }

        private static string HashToken(string token) =>
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

        // ── Operator (admin site) queries/actions ────────────────────────────────

        public async Task<(List<AdminUserDto> Users, int Total)> AdminListUsersAsync(string? search, int skip, int take)
        {
            var query = db.Users.AsQueryable();
            if (!string.IsNullOrWhiteSpace(search))
                query = query.Where(u => u.Username.Contains(search.Trim()));

            var total = await query.CountAsync();
            var users = await query.OrderBy(u => u.Username)
                .Skip(Math.Max(skip, 0)).Take(Math.Clamp(take, 1, 200))
                .Select(u => new AdminUserDto(
                    u.Id, u.Username, u.CreatedAt, u.MustChangePassword,
                    db.PasswordResetRequests.Count(r => r.UserId == u.Id &&
                        (r.Status == PasswordResetStatus.Pending || r.Status == PasswordResetStatus.Issued))))
                .ToListAsync();
            return (users, total);
        }

        public async Task<AdminUserDto?> AdminGetUserAsync(string username) =>
            await db.Users.Where(u => u.Username == username)
                .Select(u => new AdminUserDto(
                    u.Id, u.Username, u.CreatedAt, u.MustChangePassword,
                    db.PasswordResetRequests.Count(r => r.UserId == u.Id &&
                        (r.Status == PasswordResetStatus.Pending || r.Status == PasswordResetStatus.Issued))))
                .SingleOrDefaultAsync();

        public async Task<AccountUpdateResult> AdminDeleteAccountAsync(string username)
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Username == username);
            return user is null ? AccountUpdateResult.NotFound : await DeleteUserAsync(user);
        }

        public async Task<AccountUpdateResult> AdminSetMustChangePasswordAsync(string username, bool required)
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Username == username);
            if (user is null)
                return AccountUpdateResult.NotFound;

            user.MustChangePassword = required;
            await db.SaveChangesAsync();
            return AccountUpdateResult.Success;
        }

        public async Task<List<PasswordResetDto>> AdminListResetRequestsAsync(bool openOnly)
        {
            var now = DateTime.UtcNow;
            var query = db.PasswordResetRequests.AsQueryable();
            if (openOnly)
                query = query.Where(r => r.Status == PasswordResetStatus.Pending ||
                                         (r.Status == PasswordResetStatus.Issued && r.ExpiresAt > now));

            var rows = await query.OrderByDescending(r => r.RequestedAt).Take(200)
                .Select(r => new { r.Id, r.User.Username, r.RequestedAt, r.Status, r.IssuedAt, r.ExpiresAt, r.UsedAt })
                .ToListAsync();

            return rows.Select(r => new PasswordResetDto(
                r.Id, r.Username, r.RequestedAt,
                r.Status == PasswordResetStatus.Issued && r.ExpiresAt <= now ? "Expired" : r.Status.ToString(),
                r.IssuedAt, r.ExpiresAt, r.UsedAt)).ToList();
        }

        // Operator-only rescue path for someone who's genuinely locked out: there's no email on
        // file to send a reset link to (see AuthDbContext/User.cs — deliberately not collected),
        // and ChangePasswordAsync needs the old password, which is exactly what's missing here.
        // Authenticated by the shared Admin:InternalSecret (same header every realm-to-realm admin
        // call already uses) rather than by the account's own credentials, since this is meant to
        // be called by the operator directly (e.g. via curl) after verifying the request out of
        // band - it's not wired into the game UI at all.
        public async Task<AccountUpdateResult> AdminResetPasswordAsync(string username, string newPassword)
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Username == username);
            if (user is null)
                return AccountUpdateResult.NotFound;

            user.PasswordHash = HashPassword(newPassword);
            await db.SaveChangesAsync();
            return AccountUpdateResult.Success;
        }

        // Calls the given request against every configured realm's internal admin API. Stops (and
        // reports failure) on the first realm that can't be reached or rejects the request, leaving
        // the caller to decide not to touch the Users table — see DeleteAccountAsync's remarks on
        // why that's an accepted trade-off rather than a real distributed transaction.
        private async Task<bool> CallOnEveryRealmAsync(Func<RealmDefinition, HttpRequestMessage> buildRequest)
        {
            var realms = config.GetSection("Realms").Get<List<RealmDefinition>>() ?? [];
            var client = httpClientFactory.CreateClient();

            foreach (var realm in realms)
            {
                // Plain-HTTP realms are allowed (see Program.cs's startup banner for the
                // operator-facing warning), but every single call still needs to be visible in
                // the logs, not just once at boot — this is the exact moment the internal secret
                // actually goes out over the network in the clear.
                if (Uri.TryCreate(realm.Url, UriKind.Absolute, out var realmUri)
                    && realmUri.Scheme == Uri.UriSchemeHttp
                    && realmUri.Host is not ("localhost" or "127.0.0.1" or "::1"))
                {
                    logger.LogWarning(
                        "Sending Admin:InternalSecret to realm '{RealmName}' ({RealmUrl}) over plain HTTP.",
                        realm.Name, realm.Url);
                }

                var request = buildRequest(realm);
                request.Headers.Add("X-Internal-Secret", InternalSecret);

                try
                {
                    var response = await client.SendAsync(request);
                    if (!response.IsSuccessStatusCode)
                        return false;
                }
                catch (Exception)
                {
                    return false;
                }
            }

            return true;
        }

        private string InternalSecret => config["Admin:InternalSecret"]
            ?? throw new InvalidOperationException("Admin:InternalSecret is not configured.");

        private AuthResponse BuildToken(User user)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var hours = config.GetValue<int>("Jwt:ExpirationHours", 24);
            var expires = DateTime.UtcNow.AddHours(hours);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: config["Jwt:Issuer"],
                audience: config["Jwt:Audience"],
                claims: claims,
                expires: expires,
                signingCredentials: creds);

            return new AuthResponse
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Username = user.Username,
                ExpiresAt = expires
            };
        }

        private string Pepper => config["Security:Pepper"]
            ?? throw new InvalidOperationException("Security:Pepper is not configured.");

        private string HashPassword(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password + Pepper),
                salt,
                Iterations,
                HashAlgorithmName.SHA512,
                HashSize);

            return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
        }

        private bool VerifyPassword(string password, string stored)
        {
            var parts = stored.Split(':');
            if (parts.Length != 2) return false;

            byte[] salt = Convert.FromBase64String(parts[0]);
            byte[] expectedHash = Convert.FromBase64String(parts[1]);

            byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password + Pepper),
                salt,
                Iterations,
                HashAlgorithmName.SHA512,
                HashSize);

            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
    }
}
