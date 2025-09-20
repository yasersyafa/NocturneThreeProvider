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

public class AuthService(
    IUserRepository userRepo,
    IOptions<JwtSettings> jwtSettings,
    UserManager<AppUser> userManager,
    IEmailService emailService,
    IAuditLogService auditLogService,
    IConfiguration configuration,
    IOtpService otpService) : IAuthService
{
    private readonly IUserRepository _userRepo = userRepo;
    private readonly JwtSettings _jwtSettings = jwtSettings.Value;
    private readonly UserManager<AppUser> _userManager = userManager;
    private readonly IEmailService _emailService = emailService;
    private readonly IAuditLogService _audit = auditLogService;
    private readonly IConfiguration _config = configuration;
    private readonly IOtpService _otpService = otpService;

    #region SUPERCELL_ID_LIKE_AUTH

    /// <summary>
    /// Request OTP for login (Supercell ID-like)
    /// </summary>
    public async Task RequestLoginOtpAsync(LoginDto dto, string ipAddress)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null)
        {
            await _audit.LogAsync(null, "RequestLoginOtp", "Failed", "UserNotFound", ipAddress);
            throw new Exception("Invalid email address.");
        }

        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            await _audit.LogAsync(user.Id, "RequestLoginOtp", "Failed", "EmailNotConfirmed", ipAddress);
            throw new Exception("Email not confirmed. Please register first.");
        }

        var otpRequest = new RequestOtpDto
        {
            Email = dto.Email,
            Purpose = "login"
        };

        await _otpService.RequestOtpAsync(otpRequest);
        await _audit.LogAsync(user.Id, "RequestLoginOtp", "Success", null, ipAddress);
    }

    /// <summary>
    /// Login with OTP (Supercell ID-like)
    /// </summary>
    public async Task<AuthResponseDto?> LoginWithOtpAsync(LoginWithOtpDto dto, string ipAddress)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null)
        {
            await _audit.LogAsync(null, "LoginWithOtp", "Failed", "UserNotFound", ipAddress);
            throw new Exception("Invalid email address.");
        }

        // Check if account is locked
        if (await _userManager.IsLockedOutAsync(user))
        {
            await _audit.LogAsync(user.Id, "LoginWithOtp", "Failed", "AccountLocked", ipAddress);
            throw new Exception("Account is locked. Try again later.");
        }

        // Verify OTP
        var otpVerify = new VerifyOtpDto
        {
            Email = dto.Email,
            Code = dto.OtpCode,
            Purpose = "login"
        };

        var isOtpValid = await _otpService.VerifyOtpAsync(otpVerify);
        if (!isOtpValid)
        {
            await _userManager.AccessFailedAsync(user);
            await _audit.LogAsync(user.Id, "LoginWithOtp", "Failed", "InvalidOtp", ipAddress);
            throw new Exception("Invalid or expired OTP code.");
        }

        // Reset failed attempts on successful login
        await _userManager.ResetAccessFailedCountAsync(user);
        await _audit.LogAsync(user.Id, "LoginWithOtp", "Success", null, ipAddress);

        return await GenerateToken(user);
    }

    /// <summary>
    /// Request OTP for registration (Supercell ID-like)
    /// </summary>
    public async Task RequestRegisterOtpAsync(RegisterDto dto, string ipAddress)
    {
        // Check if user already exists
        var existingUser = await _userManager.FindByEmailAsync(dto.Email);
        if (existingUser != null)
        {
            await _audit.LogAsync(existingUser.Id, "RequestRegisterOtp", "Failed", "UserAlreadyExists", ipAddress);
            throw new Exception("An account with this email already exists.");
        }

        var otpRequest = new RequestOtpDto
        {
            Email = dto.Email,
            Purpose = "register"
        };

        await _otpService.RequestOtpAsync(otpRequest);
        await _audit.LogAsync(null, "RequestRegisterOtp", "Success", dto.Email, ipAddress);
    }

    /// <summary>
    /// Register with OTP and username (Supercell ID-like)
    /// </summary>
    public async Task<AuthResponseDto?> RegisterWithOtpAsync(RegisterWithOtpDto dto, string ipAddress)
    {
        // Check if user already exists
        var existingUser = await _userManager.FindByEmailAsync(dto.Email);
        if (existingUser != null)
        {
            await _audit.LogAsync(existingUser.Id, "RegisterWithOtp", "Failed", "UserAlreadyExists", ipAddress);
            throw new Exception("An account with this email already exists.");
        }

        // Check if username is already taken
        var userWithUsername = await _userManager.FindByNameAsync(dto.UserName);
        if (userWithUsername != null)
        {
            await _audit.LogAsync(null, "RegisterWithOtp", "Failed", "UsernameAlreadyExists", ipAddress);
            throw new Exception("This username is already taken. Please choose another one.");
        }

        // Verify OTP
        var otpVerify = new VerifyOtpDto
        {
            Email = dto.Email,
            Code = dto.OtpCode,
            Purpose = "register"
        };

        var isOtpValid = await _otpService.VerifyOtpAsync(otpVerify);
        if (!isOtpValid)
        {
            await _audit.LogAsync(null, "RegisterWithOtp", "Failed", "InvalidOtp", ipAddress);
            throw new Exception("Invalid or expired OTP code.");
        }

        // Create user with auto-generated password (since we don't use passwords in Supercell ID-like auth)
        var user = new AppUser
        {
            UserName = dto.UserName,
            Email = dto.Email,
            DisplayName = dto.UserName,
            EmailConfirmed = true // Auto-confirm email since OTP was verified
        };

        // Generate a random password since Identity requires one
        var randomPassword = GenerateRandomPassword();
        var result = await _userRepo.CreateAsync(user, randomPassword);

        if (!result.Succeeded)
        {
            await _audit.LogAsync(null, "RegisterWithOtp", "Failed",
                string.Join(", ", result.Errors.Select(e => e.Description)), ipAddress);
            throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
        }

        await _audit.LogAsync(user.Id, "RegisterWithOtp", "Success", null, ipAddress);
        return await GenerateToken(user);
    }

    /// <summary>
    /// Generate a random password for users (since we don't use passwords in Supercell ID-like auth)
    /// </summary>
    private string GenerateRandomPassword()
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        var random = new Random();
        return new string([.. Enumerable.Repeat(chars, 16).Select(s => s[random.Next(s.Length)])]);
    }

    #endregion

    #region REGISTER
    public async Task<string> RegisterAsync(LegacyRegisterDto dto, string ipAddress)
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

    #region RESET_PASSWORD
    public async Task RequestPasswordResetAsync(ResetPasswordRequestDto dto, string ipAddress)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);

        if (user == null)
        {
            // Jangan bocorin info user tidak ada → tetap return success
            await _audit.LogAsync(null, "ResetPasswordRequest", "Ignored", "EmailNotFound", ipAddress);
            return;
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);

        var baseUrl = _config["App:BaseUrl"] ?? "http://localhost:5161";
        var resetUrl = $"{baseUrl}/api/v1/auth/reset-password/confirm?userId={user.Id}&token={Uri.EscapeDataString(token)}";

        await _emailService.SendResetPasswordEmailAsync(user.Email!, user.DisplayName ?? user.UserName ?? "", resetUrl);

        await _audit.LogAsync(user.Id, "ResetPasswordRequest", "Success", null, ipAddress);
    }
    #endregion

    #region CONFIRM_PASSWORD
    public async Task<bool> ConfirmPasswordResetAsync(ResetPasswordConfirmDto dto, string ipAddress)
    {
        var user = await _userManager.FindByIdAsync(dto.UserId);
        if (user == null)
        {
            await _audit.LogAsync(null, "ResetPasswordConfirm", "Failed", "UserNotFound", ipAddress);
            return false;
        }

        var result = await _userManager.ResetPasswordAsync(user, dto.Token, dto.NewPassword);

        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            await _audit.LogAsync(user.Id, "ResetPasswordConfirm", "Failed", errors, ipAddress);
            return false;
        }

        await _audit.LogAsync(user.Id, "ResetPasswordConfirm", "Success", null, ipAddress);
        return true;
    }
    #endregion

    #region  LOGIN
    public async Task<AuthResponseDto?> LoginAsync(LegacyLoginDto dto, string ipAddress)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null)
        {
            await _audit.LogAsync(null, "Login", "Failed", "UserNotFound", ipAddress);
            throw new Exception("Invalid login attempt.");
        }

        // cek lockout status
        if (await _userManager.IsLockedOutAsync(user))
        {
            await _audit.LogAsync(user.Id, "Login", "Failed", "AccountLocked", ipAddress);
            throw new Exception("Account is locked. Try again later.");
        }

        if (!await _userManager.CheckPasswordAsync(user, dto.Password))
        {
            // increment fail count
            await _userManager.AccessFailedAsync(user);

            if (await _userManager.IsLockedOutAsync(user))
            {
                await _audit.LogAsync(user.Id, "Login", "Failed", "AccountLocked", ipAddress);
                throw new Exception("Account is locked. Try again after 15 minutes.");
            }

            await _audit.LogAsync(user.Id, "Login", "Failed", "WrongPassword", ipAddress);
            throw new Exception("Invalid login attempt.");
        }

        await _userManager.ResetAccessFailedCountAsync(user);

        if (!await _userManager.IsEmailConfirmedAsync(user))
        {
            await _audit.LogAsync(user.Id, "Login", "Failed", "EmailNotConfirmed", ipAddress);
            throw new Exception("Email not confirmed.");
        }

        await _audit.LogAsync(user.Id, "Login", "Success", null, ipAddress);

        // generate JWT (bisa dipisah ke JwtService biar lebih clean)
        return await GenerateToken(user);
    }
    #endregion

    #region CUSTOM_FUNCTIONS
    private async Task<AuthResponseDto> GenerateToken(AppUser user)
    {
        var userClaims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(ClaimTypes.NameIdentifier, user.Id)
        };

        var expire = DateTime.UtcNow.AddMinutes(_jwtSettings.ExpiredInMinutes);

        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            userClaims.Add(new Claim(ClaimTypes.Role, role));
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: userClaims,
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
    #endregion
}