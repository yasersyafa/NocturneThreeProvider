namespace NocturneThreeProvider.Services.Interfaces;

public interface IEmailService
{
    Task SendEmailAsync(string to, string displayName, string confirmUrl);
    Task SendResetPasswordEmailAsync(string to, string displayName, string resetUrl);
}