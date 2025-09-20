using NocturneThreeProvider.DTOs.Users;

namespace NocturneThreeProvider.Services.Interfaces;

public interface IUserService
{
    Task<UserProfileDto> GetProfileAsync(string userId);
}