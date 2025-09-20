using NocturneThreeProvider.DTOs.Auth;

namespace NocturneThreeProvider.Services.Interfaces;

public interface IAuthService
{
    Task<string> RegisterAsync(RegisterDto dto);
    Task<bool> ConfirmEmailAsync(string userId, string token);
    Task<AuthResponseDto?> LoginAsync(LoginDto dto);
}