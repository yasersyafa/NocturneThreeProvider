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
    /// Register user baru dan mengembalikan token verifikasi email.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
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
    /// Login user (hanya bisa jika email sudah diverifikasi).
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);
        var ipAddress = HttpContext.GetIpAddress();
        var response = await _authService.LoginAsync(dto, ipAddress);
        if (response == null) return Unauthorized(new { Message = "Invalid credentials." });

        return Ok(response);
    }
}