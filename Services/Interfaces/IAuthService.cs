using Microsoft.AspNetCore.Identity;
using NocturneThreeProvider.DTOs.Auth;

namespace NocturneThreeProvider.Services.Interfaces;

public interface IAuthService
{
    // New Supercell ID-like authentication methods
    Task RequestLoginOtpAsync(LoginDto dto, string ipAddress);
    Task<AuthResponseDto?> LoginWithOtpAsync(LoginWithOtpDto dto, string ipAddress);
    Task RequestRegisterOtpAsync(RegisterDto dto, string ipAddress);
    Task<AuthResponseDto?> RegisterWithOtpAsync(RegisterWithOtpDto dto, string ipAddress);
    
    // Legacy methods (keeping for backward compatibility)
    Task<string> RegisterAsync(LegacyRegisterDto dto, string ipAddress);
    Task<IdentityResult> ConfirmEmailAsync(string userId, string token, string ipAddress);
    Task<AuthResponseDto?> LoginAsync(LegacyLoginDto dto, string ipAddress);
    Task RequestPasswordResetAsync(ResetPasswordRequestDto dto, string ipAddress);
    Task<bool> ConfirmPasswordResetAsync(ResetPasswordConfirmDto dto, string ipAddress);
}