using System.IdentityModel.Tokens.Jwt;
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
    public class AuthService(AuthDbContext db, IConfiguration config)
    {
        private const int SaltSize = 16;
        private const int HashSize = 32;
        private const int Iterations = 200_000;

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
            if (user is null || !VerifyPassword(req.Password, user.PasswordHash))
                return null;

            return BuildToken(user);
        }

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
