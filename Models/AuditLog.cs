namespace NocturneThreeProvider.Models;

public class AuditLog
{
    public Guid Id { get; set; } = Guid.NewGuid();

    // reference to AspNetUsers
    public string? UserId { get; set; }

    public string Action { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? Reason { get; set; } // WrongPassword, InvalidToken, etc.
    public string? IpAddress { get; set; }

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}