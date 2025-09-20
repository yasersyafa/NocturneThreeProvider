using System.ComponentModel.DataAnnotations;

namespace NocturneThreeProvider.DTOs.Auth;

public class RegisterDto
{
    [Required, EmailAddress, MaxLength(255)]
    public string Email { get; set; } = string.Empty;
}

public class RegisterWithOtpDto
{
    [Required, EmailAddress, MaxLength(255)]
    public string Email { get; set; } = string.Empty;

    [Required, Length(6, 6)]
    public string OtpCode { get; set; } = string.Empty;

    // Nama tampilan di game (username)
    [Required, MinLength(3), MaxLength(20)]
    [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores.")]
    public string UserName { get; set; } = string.Empty;
}