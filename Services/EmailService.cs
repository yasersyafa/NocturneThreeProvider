using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using NocturneThreeProvider.Services.Interfaces;
using NocturneThreeProvider.Settings;

namespace NocturneThreeProvider.Services;

public class EmailService(IOptions<EmailSettings> emailSettings, IWebHostEnvironment env) : IEmailService
{
    private readonly EmailSettings _settings = emailSettings.Value;
    private readonly IWebHostEnvironment _env = env;
    public async Task SendEmailAsync(string to, string displayName, string confirmUrl)
    {
        // load html template
        var templatePath = Path.Combine(_env.ContentRootPath, "Templates", "EmailVerification.html");
        var htmlTemplate = await File.ReadAllTextAsync(templatePath);

        // replace placeholder
        var htmlContent = htmlTemplate
            .Replace("{{DISPLAY_NAME}}", displayName)
            .Replace("{{CONFIRM_URL}}", confirmUrl);

        var email = new MimeMessage();

        email.From.Add(new MailboxAddress("Nocturne Three ID", _settings.From));
        email.To.Add(new MailboxAddress("", to));
        email.Subject = "Activate your Nocturne Three ID account";

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
        await smtp.ConnectAsync(_settings.SmtpServer ?? "smpt.gmail.com", _settings.Port!, MailKit.Security.SecureSocketOptions.StartTls);
        await smtp.AuthenticateAsync(_settings.Username, _settings.Password);
        await smtp.SendAsync(email);
        await smtp.DisconnectAsync(true);
    }
}