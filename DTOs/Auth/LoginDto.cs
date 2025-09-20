using System.ComponentModel.DataAnnotations;

namespace NocturneThreeProvider.DTOs.Auth;

public class LoginDto
{
    [Required, EmailAddress, MaxLength(255)]
    public string Email { get; set; } = string.Empty;
}

public class LoginWithOtpDto
{
    [Required, EmailAddress, MaxLength(255)]
    public string Email { get; set; } = string.Empty;

    [Required, Length(6, 6)]
    public string OtpCode { get; set; } = string.Empty;
}