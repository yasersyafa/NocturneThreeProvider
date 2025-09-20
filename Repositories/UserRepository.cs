using Microsoft.AspNetCore.Identity;
using NocturneThreeProvider.Models;
using NocturneThreeProvider.Repositories.Interfaces;

namespace NocturneThreeProvider.Repositories;

public class UserRepository(UserManager<AppUser> userManager) : IUserRepository
{
    private readonly UserManager<AppUser> _userManager = userManager;

    public Task<IdentityResult> CreateAsync(AppUser user, string password)
    {
        return _userManager.CreateAsync(user, password);
    }

    public Task<AppUser?> FindByEmailAsync(string email)
    {
        return _userManager.FindByEmailAsync(email);
    }

    public Task<bool> CheckPasswordAsync(AppUser user, string password)
    {
        return _userManager.CheckPasswordAsync(user, password);
    }

    public Task<string> GenerateEmailConfirmationTokenAsync(AppUser user)
    {
        return _userManager.GenerateEmailConfirmationTokenAsync(user);
    }

    public Task<IdentityResult> ConfirmEmailAsync(AppUser user, string token)
    {
        return _userManager.ConfirmEmailAsync(user, token);
    }
}