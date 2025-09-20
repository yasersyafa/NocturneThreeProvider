using Microsoft.AspNetCore.Identity;
using NocturneThreeProvider.DTOs.Auth;

namespace NocturneThreeProvider.Services.Interfaces;

public interface IAuthService
{
    Task<string> RegisterAsync(RegisterDto dto, string ipAddress);
    Task<IdentityResult> ConfirmEmailAsync(string userId, string token, string ipAddress);
    Task<AuthResponseDto?> LoginAsync(LoginDto dto, string ipAddress);
    Task RequestPasswordResetAsync(ResetPasswordRequestDto dto, string ipAddress);
    Task<bool> ConfirmPasswordResetAsync(ResetPasswordConfirmDto dto, string ipAddress);
}