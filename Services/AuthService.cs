using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NocturneThreeProvider.DTOs.Auth;
using NocturneThreeProvider.Models;
using NocturneThreeProvider.Repositories.Interfaces;
using NocturneThreeProvider.Services.Interfaces;
using NocturneThreeProvider.Settings;

namespace NocturneThreeProvider.Services;

public class AuthService(IUserRepository userRepo, IOptions<JwtSettings> jwtSettings, UserManager<AppUser> userManager, IEmailService emailService) : IAuthService
{
    private readonly IUserRepository _userRepo = userRepo;
    private readonly JwtSettings _jwtSettings = jwtSettings.Value;
    private readonly UserManager<AppUser> _userManager = userManager;
    private readonly IEmailService _emailService = emailService;

    public async Task<string> RegisterAsync(RegisterDto dto)
    {
        var user = new AppUser
        {
            UserName = dto.Email,
            Email = dto.Email,
            DisplayName = dto.DisplayName
        };

        var result = await _userRepo.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
            throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));

        // generate token
        var token = await _userRepo.GenerateEmailConfirmationTokenAsync(user);

        // send to email for production phase
        // create confrim url
        var confirmUrl = $"http://localhost:5161/api/v1/auth/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";

        await _emailService.SendEmailAsync(user.Email, user.DisplayName ?? user.UserName ?? "", confirmUrl);
        // for testing purpose, use console
        return token;
    }

    public async Task<bool> ConfirmEmailAsync(string userId, string token)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        var result = await _userRepo.ConfirmEmailAsync(user, token);
        return result.Succeeded;
    }

    public async Task<AuthResponseDto?> LoginAsync(LoginDto dto)
    {
        var user = await _userRepo.FindByEmailAsync(dto.Email);
        if (user == null) return null;

        if (!user.EmailConfirmed)
            throw new Exception("Email not verified");

        var validPassword = await _userRepo.CheckPasswordAsync(user, dto.Password);
        if (!validPassword) return null;

        return GenerateToken(user);
    }

    private AuthResponseDto GenerateToken(AppUser user)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email!)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expire = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpiredInMinutes);

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: expire,
            signingCredentials: creds
        );

        return new AuthResponseDto
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
            ExpireAt = expire,
            Email = user.Email!,
            DisplayName = user.DisplayName ?? user.UserName ?? "",
            EmailVerified = user.EmailConfirmed,
            Roles = [.. _userManager.GetRolesAsync(user).Result]
        };
    }
}