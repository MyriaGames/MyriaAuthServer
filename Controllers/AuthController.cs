using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Myria.Server.Auth.Models.Dto;
using Myria.Server.Auth.Services;

namespace Myria.Server.Auth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [EnableRateLimiting("auth")]
    public class AuthController(AuthService auth) : ControllerBase
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
            var result = await auth.LoginAsync(req);
            if (result is null)
                return Unauthorized(new { message = "Invalid username or password." });

            return Ok(result);
        }
    }
}
