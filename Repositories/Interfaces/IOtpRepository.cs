using NocturneThreeProvider.Models;

namespace NocturneThreeProvider.Repositories.Interfaces;

public interface IOtpRepository
{
    Task AddAsync(OtpCode otp);
    Task<OtpCode?> GetValidOtpAsync(string email, string code, string purpose);
    Task InvalidateOtpAsync(OtpCode otp);
}