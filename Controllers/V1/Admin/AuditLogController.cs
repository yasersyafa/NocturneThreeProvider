using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NocturneThreeProvider.Repositories.Interfaces;

namespace NocturneThreeProvider.Controllers.V1.Admin;

[ApiController]
[Route("api/v{version:apiVersion}/admin/audit-logs")]
[ApiVersion("1.0")]
[Authorize(Roles = "Admin")]
public class AuditLogController(IAuditLogRepository repo) : ControllerBase
{
    private readonly IAuditLogRepository _repo = repo;

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var logs = await _repo.GetAllAsync();
        return Ok(logs);
    }

    [HttpGet("{userId}")]
    public async Task<IActionResult> GetByUser(string userId)
    {
        var logs = await _repo.GetByUserAsync(userId);
        return Ok(logs);
    }
}