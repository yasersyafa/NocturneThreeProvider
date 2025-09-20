using Microsoft.EntityFrameworkCore;
using NocturneThreeProvider.Database;
using NocturneThreeProvider.Models;
using NocturneThreeProvider.Repositories.Interfaces;

namespace NocturneThreeProvider.Repositories;

public class OtpRepository(AppDbContext context) : IOtpRepository
{
    private readonly AppDbContext _context = context;

    public async Task AddAsync(OtpCode otp)
    {
        await _context.AddAsync(otp);
        await _context.SaveChangesAsync();
    }

    public async Task<OtpCode?> GetValidOtpAsync(string email, string code, string purpose)
    {
        return await _context.OtpCodes
            .Where(o => o.Email == email && o.Code == code && o.Purpose == purpose && !o.Consumed && o.ExpireAt > DateTime.UtcNow)
            .FirstOrDefaultAsync();
    }

    public async Task InvalidateOtpAsync(OtpCode otp)
    {
        otp.Consumed = true;
        _context.OtpCodes.Update(otp);
        await _context.SaveChangesAsync();
    }
}