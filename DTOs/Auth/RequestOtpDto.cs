namespace NocturneThreeProvider.DTOs.Auth;

public class RequestOtpDto
{
    public string Email { get; set; } = string.Empty;
    public string Purpose { get; set; } = string.Empty; // "register" / "login"
}