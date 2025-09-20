namespace NocturneThreeProvider.Services.Interfaces;

public interface IEmailService
{
    Task SendResetPasswordEmailAsync(string to, string displayName, string resetUrl);
    Task SendEmailAsync(string to, string displayName, string otpCode);
}