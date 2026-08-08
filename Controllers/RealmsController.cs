using Microsoft.AspNetCore.Mvc;
using MyriaAuthServer.Models;

namespace MyriaAuthServer.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class RealmsController(IConfiguration config) : ControllerBase
    {
        // Static realm directory only — this is discovery, not a health check.
        // Each realm's own /api/status is polled directly by clients for
        // online/character-count, since only the realm itself knows that.
        [HttpGet]
        [ProducesResponseType(typeof(IEnumerable<RealmDefinition>), StatusCodes.Status200OK)]
        public ActionResult<IEnumerable<RealmDefinition>> Get()
        {
            var realms = config.GetSection("Realms").Get<List<RealmDefinition>>() ?? [];
            return Ok(realms);
        }
    }
}
