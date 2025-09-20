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

public class AuthService(IUserRepository userRepo, IOptions<JwtSettings> jwtSettings, UserManager<AppUser> userManager, IEmailService emailService, IAuditLogService auditLogService, IConfiguration configuration) : IAuthService
{
    private readonly IUserRepository _userRepo = userRepo;
    private readonly JwtSettings _jwtSettings = jwtSettings.Value;
    private readonly UserManager<AppUser> _userManager = userManager;
    private readonly IEmailService _emailService = emailService;
    private readonly IAuditLogService _audit = auditLogService;
    private readonly IConfiguration _config = configuration;

    #region REGISTER
    public async Task<string> RegisterAsync(RegisterDto dto, string ipAddress)
    {
        var user = new AppUser
        {
            UserName = dto.Email,
            Email = dto.Email,
            DisplayName = dto.DisplayName
        };

        var result = await _userRepo.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
        {
            await _audit.LogAsync(null, "Register", "Failed",
                string.Join(", ", result.Errors.Select(e => e.Description)), ipAddress);

            throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        // generate token
        var token = await _userRepo.GenerateEmailConfirmationTokenAsync(user);

        // send to email for production phase
        // create confrim url
        var confirmUrl = $"http://localhost:5161/api/v1/auth/confirm-email?userId={user.Id}&token={Uri.EscapeDataString(token)}";

        // logs
        await _audit.LogAsync(user.Id, "Register", "Success", null, ipAddress);
        // generate token for email
        await _emailService.SendEmailAsync(user.Email, user.DisplayName ?? user.UserName ?? "", confirmUrl);
        // for testing purpose returning token to response
        return token;
    }
    #endregion

    #region  CONFIRM_EMAIL
    public async Task<IdentityResult> ConfirmEmailAsync(string userId, string token, string ipAddress)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            await _audit.LogAsync(null, "ConfirmEmail", "Failed", "UserNotFound", ipAddress);
            return IdentityResult.Failed(new IdentityError { Description = "User not found." });
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);

        if (!result.Succeeded)
        {
            await _audit.LogAsync(user.Id, "ConfirmEmail", "Failed", "InvalidToken", ipAddress);
        }
        else
        {
            await _audit.LogAsync(user.Id, "ConfirmEmail", "Success", null, ipAddress);
        }

        return result;
    }
    #endregion

    #region  LOGIN
    public async Task<AuthResponseDto?> LoginAsync(LoginDto dto, string ipAddress)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null)
        {
            await _audit.LogAsync(null, "Login", "Failed", "UserNotFound", ipAddress);
            throw new Exception("Invalid login attempt.");
        }

        if (!await _userManager.CheckPasswordAsync(user, dto.Password))
        {
            await _audit.LogAsync(user.Id, "Login", "Failed", "WrongPassword", ipAddress);
            throw new Exception("Invalid login attempt.");
        }

        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            await _audit.LogAsync(user.Id, "Login", "Failed", "EmailNotConfirmed", ipAddress);
            throw new Exception("Email not confirmed.");
        }

        await _audit.LogAsync(user.Id, "Login", "Success", null, ipAddress);

        // generate JWT (bisa dipisah ke JwtService biar lebih clean)
        return GenerateToken(user);
    }
    #endregion
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