using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;
using NocturneThreeProvider.Services.Interfaces;
using NocturneThreeProvider.Settings;

namespace NocturneThreeProvider.Services;

public class EmailService(IOptions<EmailSettings> emailSettings, IWebHostEnvironment env) : IEmailService
{
    private readonly EmailSettings _settings = emailSettings.Value;
    private readonly IWebHostEnvironment _env = env;

#region DEPRECATED

    public async Task SendResetPasswordEmailAsync(string to, string displayName, string resetUrl)
    {
        var templatePath = Path.Combine(_env.ContentRootPath, "Templates", "ResetEmailPassword.html");
        var htmlTemplate = await File.ReadAllTextAsync(templatePath);

        var htmlContent = htmlTemplate
            .Replace("{{DISPLAY_NAME}}", displayName)
            .Replace("{{RESET_URL}}", resetUrl);

        var email = new MimeMessage();
        email.From.Add(new MailboxAddress("Nocturne Three ID", _settings.From));
        email.To.Add(new MailboxAddress("", to));
        email.Subject = "Reset your Nocturne Three ID password";

        var builder = new BodyBuilder { HtmlBody = htmlContent };

        // attach logo inline
        var logoPath = Path.Combine(_env.WebRootPath ?? _env.ContentRootPath, "images", "NTID.JPG");
        if (File.Exists(logoPath))
        {
            var logo = builder.LinkedResources.Add(logoPath);
            logo.ContentId = "logoImage";
        }

        email.Body = builder.ToMessageBody();

        using var smtp = new SmtpClient();
        await smtp.ConnectAsync(_settings.SmtpServer, _settings.Port, SecureSocketOptions.StartTls);
        await smtp.AuthenticateAsync(_settings.Username, _settings.Password);
        await smtp.SendAsync(email);
        await smtp.DisconnectAsync(true);
    }
    #endregion
    public async Task SendEmailAsync(string to, string displayName, string otpCode)
    {
        // load html template
        var templatePath = Path.Combine(_env.ContentRootPath, "Templates", "EmailVerification.html");
        var htmlTemplate = await File.ReadAllTextAsync(templatePath);

        var htmlContent = htmlTemplate.Replace("{{OTP_CODE}}", otpCode);

        var email = new MimeMessage();

        email.From.Add(new MailboxAddress("Nocturne Three ID", _settings.From));
        email.To.Add(new MailboxAddress("", to));
        email.Subject = "Your OTP Code for Nocturne Three ID";

        var builder = new BodyBuilder
        {
            HtmlBody = htmlContent
        };

        // attach logo inline
        var logoPath = Path.Combine(_env.WebRootPath ?? _env.ContentRootPath, "images", "NTID.JPG");
        if (File.Exists(logoPath))
        {
            var logo = builder.LinkedResources.Add(logoPath);
            logo.ContentId = "logoImage";
        }

        email.Body = builder.ToMessageBody();

        // send via smtp
        using var smtp = new SmtpClient();
        await smtp.ConnectAsync(_settings.SmtpServer ?? "smpt.gmail.com", _settings.Port!, SecureSocketOptions.StartTls);
        await smtp.AuthenticateAsync(_settings.Username, _settings.Password);
        await smtp.SendAsync(email);
        await smtp.DisconnectAsync(true);
    }
}