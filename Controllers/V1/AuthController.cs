using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NocturneThreeProvider.DTOs.Auth;
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

        var token = await _authService.RegisterAsync(dto);

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
        var result = await _authService.ConfirmEmailAsync(userId, token);
        return result ? Ok(new { Message = "Email confirmed." }) : BadRequest(new { Message = "Invalid token or user not found." });
    }

    /// <summary>
    /// Login user (hanya bisa jika email sudah diverifikasi).
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var response = await _authService.LoginAsync(dto);
        if (response == null) return Unauthorized(new { Message = "Invalid credentials." });

        return Ok(response);
    }
}