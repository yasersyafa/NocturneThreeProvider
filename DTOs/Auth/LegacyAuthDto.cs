using System.ComponentModel.DataAnnotations;

namespace NocturneThreeProvider.DTOs.Auth;

/// <summary>
/// Legacy RegisterDto with password support for backward compatibility
/// </summary>
public class LegacyRegisterDto
{
    [Required, EmailAddress, MaxLength(255)]
    public string Email { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    // Min 8, harus ada: 1 huruf besar, 1 huruf kecil, 1 digit, 1 simbol
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$",
        ErrorMessage = "Password must be ≥8 chars and include upper, lower, digit, and symbol.")]
    public string Password { get; set; } = string.Empty;

    [Required, Compare(nameof(Password))]
    public string ConfirmPassword { get; set; } = string.Empty;

    // Nama tampilan di game
    [Required, MinLength(3), MaxLength(10)]
    public string DisplayName { get; set; } = string.Empty;
}

/// <summary>
/// Legacy LoginDto with password support for backward compatibility
/// </summary>
public class LegacyLoginDto
{
    [Required, EmailAddress, MaxLength(255)]
    public string Email { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string Password { get; set; } = string.Empty;
}
