using System.ComponentModel.DataAnnotations.Schema;

namespace NocturneThreeProvider.Models;

public class UserGameData
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string UserId { get; set; } = string.Empty;
    public Guid GameId { get; set; }

    // navigations
    public AppUser? User { get; set; }
    public Game? Game { get; set; }

    // data progress per game
    public int HighScore { get; set; } = 0;
    public decimal Currency { get; set; } = 0;

    [Column(TypeName = "jsonb")]
    public string? SaveData { get; set; }
    public DateTime LastPlayed { get; set; } = DateTime.UtcNow;
}