using System.ComponentModel.DataAnnotations;

namespace NocturneThreeProvider.DTOs.Auth;

public class ForgotPasswordRequestDto
{
    [Required, EmailAddress, MaxLength(255)]
    public string Email { get; set; } = string.Empty;
}