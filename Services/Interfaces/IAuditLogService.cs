namespace NocturneThreeProvider.Services.Interfaces;

public interface IAuditLogService
{
    Task LogAsync(string? userId, string action, string status, string? reason, string? ipAddress);
    Task GetAllAsync();
    Task GetByUserAsync(string userId);
}