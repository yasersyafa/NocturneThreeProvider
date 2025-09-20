using NocturneThreeProvider.Models;

namespace NocturneThreeProvider.Repositories.Interfaces;
public interface IAuditLogRepository
{
    Task AddAsync(AuditLog log);
    Task<IEnumerable<AuditLog>> GetAllAsync();
    Task<IEnumerable<AuditLog>> GetByUserAsync(string userId);
}
