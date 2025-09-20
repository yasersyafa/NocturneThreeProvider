using Microsoft.AspNetCore.Identity;
using NocturneThreeProvider.Models;

namespace NocturneThreeProvider.Repositories.Interfaces;

public interface IUserRepository
{
    Task<IdentityResult> CreateAsync(AppUser user, string passowrd);
    Task<AppUser?> FindByEmailAsync(string email);
    Task<bool> CheckPasswordAsync(AppUser user, string password);

    Task<string> GenerateEmailConfirmationTokenAsync(AppUser user);
    Task<IdentityResult> ConfirmEmailAsync(AppUser user, string token);
}