using NocturneThreeProvider.DTOs.Users;
using NocturneThreeProvider.Repositories.Interfaces;
using NocturneThreeProvider.Services.Interfaces;

namespace NocturneThreeProvider.Services;

public class UserService(IUserRepository userRepository) : IUserService
{
    private readonly IUserRepository _userRepository = userRepository;

    public async Task<UserProfileDto> GetProfileAsync(string userId)
    {
        var user = await _userRepository.GetByIdAsync(userId) ?? throw new Exception("User not found.");
        var roles = await _userRepository.GetRolesAsync(user);

        // Mapping ke DTO
        return new UserProfileDto
        {
            Id = user.Id,
            Email = user.Email ?? string.Empty,
            DisplayName = user.DisplayName ?? user.UserName ?? string.Empty,
            AvatarUrl = user.AvatarUrl,
            EmailVerified = user.EmailConfirmed,        
            Roles = [.. roles]
        };
    }
}