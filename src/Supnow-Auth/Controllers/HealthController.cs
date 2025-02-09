using Microsoft.AspNetCore.Mvc;

namespace Controllers;

[ApiController]
[Route("[controller]")]
public class HealthController : ControllerBase
{
    [HttpGet]
    [Route("")]
    public IActionResult Check()
    {
        return Ok(new { status = "healthy" });
    }
} 