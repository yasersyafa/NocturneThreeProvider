using System.ComponentModel.DataAnnotations;

namespace NocturneThreeProvider.Models;

public class OtpCode
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(255)]
    public string Email { get; set; } = string.Empty;

    [Required]
    [MaxLength(6)]
    public string Code { get; set; } = string.Empty; // 6-digit OTP

    [Required]
    [MaxLength(20)]
    public string Purpose { get; set; } = string.Empty; // "register" or "login"

    public DateTime ExpireAt { get; set; }

    public bool Consumed { get; set; } = false;
}