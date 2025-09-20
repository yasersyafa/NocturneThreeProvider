using System.ComponentModel.DataAnnotations;

namespace NocturneThreeProvider.DTOs.Auth;

public class LoginDto
{
    [Required, EmailAddress, MaxLength(255)]
    public string Email { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string Password { get; set; } = string.Empty;
}