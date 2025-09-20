using Microsoft.AspNetCore.Identity;

namespace NocturneThreeProvider.Models;

public class AppUser : IdentityUser
{
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // custom fields
    public string? AvatarUrl { get; set; }
    public string? DisplayName { get; set; }

    // relation to game data
    public ICollection<UserGameData> GameData { get; set; } = [];
}