using NocturneThreeProvider.Models;
using NocturneThreeProvider.Repositories.Interfaces;
using NocturneThreeProvider.Services.Interfaces;

namespace NocturneThreeProvider.Services;

public class AuditLogService(IAuditLogRepository repo) : IAuditLogService
{
    private readonly IAuditLogRepository _repo = repo;

    public async Task GetAllAsync()
    {
        await _repo.GetAllAsync();
    }

    public async Task GetByUserAsync(string userId)
    {
        await _repo.GetByUserAsync(userId);
    }

    public async Task LogAsync(string? userId, string action, string status, string? reason, string? ipAddress)
    {
        var log = new AuditLog
        {
            UserId = userId,
            Action = action,
            Status = status,
            Reason = reason,
            IpAddress = ipAddress,
            Timestamp = DateTime.UtcNow
        };

        await _repo.AddAsync(log);
    }
}