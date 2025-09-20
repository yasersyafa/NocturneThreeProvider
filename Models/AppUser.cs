using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace NocturneThreeProvider.Models;

public class AppUser : IdentityUser
{
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // custom fields
    public string? AvatarUrl { get; set; }
    
    [Required]
    [MaxLength(50)]
    public string DisplayName { get; set; } = string.Empty;

    // relation to game data
    public ICollection<UserGameData> GameData { get; set; } = [];
}