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
        NotFound
    }

    public class AuthService(AuthDbContext db, IConfiguration config, IHttpClientFactory httpClientFactory)
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

        public async Task<AuthResponse?> LoginAsync(LoginRequest req)
        {
            var user = await db.Users.SingleOrDefaultAsync(u => u.Username == req.Username);
            if (!VerifyPassword(req.Password, user?.PasswordHash ?? DummyPasswordHash) || user is null)
                return null;

            return BuildToken(user);
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

            user.PasswordHash = HashPassword(req.NewPassword);
            await db.SaveChangesAsync();
            return (AccountUpdateResult.Success, BuildToken(user));
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
