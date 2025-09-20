using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NocturneThreeProvider.DTOs.Auth;
using NocturneThreeProvider.Helpers;
using NocturneThreeProvider.Services.Interfaces;

namespace NocturneThreeProvider.Controllers.V1;

[ApiController]
[Route("api/v{version:apiVersion}/[Controller]")]
[ApiVersion("1.0")]
public class AuthController(IAuthService authService) : ControllerBase
{
    private readonly IAuthService _authService = authService;

    /// <summary>
    /// Request OTP for registration (Supercell ID-like)
    /// </summary>
    [HttpPost("register/request-otp")]
    public async Task<IActionResult> RequestRegisterOtp([FromBody] RegisterDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var ipAddress = HttpContext.GetIpAddress();
        
        try
        {
            await _authService.RequestRegisterOtpAsync(dto, ipAddress);
            return Ok(new { Message = "OTP code sent to your email. Please check your inbox." });
        }
        catch (Exception ex)
        {
            return BadRequest(new { ex.Message });
        }
    }

    /// <summary>
    /// Complete registration with OTP and username (Supercell ID-like)
    /// </summary>
    [HttpPost("register/verify-otp")]
    public async Task<IActionResult> RegisterWithOtp([FromBody] RegisterWithOtpDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var ipAddress = HttpContext.GetIpAddress();
        
        try
        {
            var response = await _authService.RegisterWithOtpAsync(dto, ipAddress);
            return Ok(new { Message = "Registration successful!", Data = response });
        }
        catch (Exception ex)
        {
            return BadRequest(new { ex.Message });
        }
    }

    /// <summary>
    /// Register user baru dan mengembalikan token verifikasi email (Legacy method).
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] LegacyRegisterDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var ipAddress = HttpContext.GetIpAddress();
        var token = await _authService.RegisterAsync(dto, ipAddress);

        // sementara return token, nanti diganti dengan pengiriman email
        return Ok(new { Message = "User created. Please confirm your email.", ConfirmationToken = token });
    }

    /// <summary>
    /// Konfirmasi email menggunakan userId dan token.
    /// </summary>
    [HttpGet("confirm-email")]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
    {
        var ipAddress = HttpContext.GetIpAddress();
        var result = await _authService.ConfirmEmailAsync(userId, token, ipAddress);
        return result.Succeeded ? Ok(new { Message = "Email confirmed." }) : BadRequest(new { Message = "Invalid token or user not found." });
    }

    /// <summary>
    /// Request OTP for login (Supercell ID-like)
    /// </summary>
    [HttpPost("login/request-otp")]
    public async Task<IActionResult> RequestLoginOtp([FromBody] LoginDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var ipAddress = HttpContext.GetIpAddress();
        
        try
        {
            await _authService.RequestLoginOtpAsync(dto, ipAddress);
            return Ok(new { Message = "OTP code sent to your email. Please check your inbox." });
        }
        catch (Exception ex)
        {
            return BadRequest(new { ex.Message });
        }
    }

    /// <summary>
    /// Login with OTP (Supercell ID-like)
    /// </summary>
    [HttpPost("login/verify-otp")]
    public async Task<IActionResult> LoginWithOtp([FromBody] LoginWithOtpDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var ipAddress = HttpContext.GetIpAddress();
        
        try
        {
            var response = await _authService.LoginWithOtpAsync(dto, ipAddress);
            return Ok(new { Message = "Login successful!", Data = response });
        }
        catch (Exception ex)
        {
            return BadRequest(new { ex.Message });
        }
    }

    /// <summary>
    /// Login user (hanya bisa jika email sudah diverifikasi) (Legacy method).
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LegacyLoginDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var ipAddress = HttpContext.GetIpAddress();
        var response = await _authService.LoginAsync(dto, ipAddress);
        if (response == null) return Unauthorized(new { Message = "Invalid credentials." });

        return Ok(response);
    }

    /// <summary>
    /// Reset password via email
    /// </summary>
    /// <param name="dto"></param>
    /// <returns></returns> 
    [HttpPost("reset-password/request")]
    [AllowAnonymous]
    public async Task<IActionResult> RequestPasswordReset([FromBody] ResetPasswordRequestDto dto)
    {
        var ipAddress = HttpContext.GetIpAddress();
        await _authService.RequestPasswordResetAsync(dto, ipAddress);
        return Ok(new { message = "If an account exists with that email, a reset link has been sent." });
    }

    [HttpPost("reset-password/confirm")]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmPasswordReset([FromBody] ResetPasswordConfirmDto dto)
    {
        var ipAddress = HttpContext.GetIpAddress();
        var result = await _authService.ConfirmPasswordResetAsync(dto, ipAddress);

        if (!result)
            return BadRequest(new { message = "Reset password failed. Token may be invalid or expired." });

        return Ok(new { message = "Password has been reset successfully." });
    }
}