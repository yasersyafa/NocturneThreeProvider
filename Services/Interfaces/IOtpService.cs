using NocturneThreeProvider.DTOs.Auth;

namespace NocturneThreeProvider.Services.Interfaces;

public interface IOtpService
{
    Task RequestOtpAsync(RequestOtpDto dto);
    Task<bool> VerifyOtpAsync(VerifyOtpDto dto);
}