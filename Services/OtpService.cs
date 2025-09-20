using NocturneThreeProvider.DTOs.Auth;
using NocturneThreeProvider.Models;
using NocturneThreeProvider.Repositories.Interfaces;
using NocturneThreeProvider.Services.Interfaces;

namespace NocturneThreeProvider.Services;

public class OtpService(IOtpRepository otpRepository, IEmailService emailService) : IOtpService
{
    private readonly IOtpRepository _otpRepository = otpRepository;
     private readonly IEmailService _emailService = emailService;

    /// <summary>
    /// Generate OTP, save to DB, send to email
    /// </summary>
    public async Task RequestOtpAsync(RequestOtpDto dto)
    {
        // generate random 6 digit
        var rng = new Random();
        var code = rng.Next(100000, 999999).ToString();

        var otp = new OtpCode
        {
            Email = dto.Email,
            Code = code,
            Purpose = dto.Purpose.ToLower(), // "register" or "login"
            ExpireAt = DateTime.UtcNow.AddMinutes(5), // valid 5 minutes
            Consumed = false
        };

        await _otpRepository.AddAsync(otp);

        await _emailService.SendEmailAsync(dto.Email, "Nocturne Three ID", code);
    }

    /// <summary>
    /// Verify OTP, mark as consumed if valid
     /// </summary>
    public async Task<bool> VerifyOtpAsync(VerifyOtpDto dto)
    {
        var otp = await _otpRepository.GetValidOtpAsync(dto.Email, dto.Code, dto.Purpose.ToLower());
        if (otp == null)
            return false;

        await _otpRepository.InvalidateOtpAsync(otp);
        return true;
    }
}