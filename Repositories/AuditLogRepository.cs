using Microsoft.EntityFrameworkCore;
using NocturneThreeProvider.Database;
using NocturneThreeProvider.Models;
using NocturneThreeProvider.Repositories.Interfaces;

namespace NocturneThreeProvider.Repositories;

public class AuditLogRepository(AppDbContext context) : IAuditLogRepository
{
    private readonly AppDbContext _context = context;

    public async Task AddAsync(AuditLog log)
    {
        _context.AuditLogs.Add(log);
        await _context.SaveChangesAsync();
    }

    public async Task<IEnumerable<AuditLog>> GetAllAsync()
    {
        return await _context.AuditLogs
            .OrderByDescending(l => l.Timestamp)
            .ToListAsync();
    }

    public async Task<IEnumerable<AuditLog>> GetByUserAsync(string userId)
    {
        return await _context.AuditLogs
            .Where(l => l.UserId == userId)
            .OrderByDescending(l => l.Timestamp)
            .ToListAsync();
    }
}