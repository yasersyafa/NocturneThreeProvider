namespace NocturneThreeProvider.DTOs.Users;

public class UserProfileDto
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? AvatarUrl { get; set; }
    public bool EmailVerified { get; set; }
    public List<string> Roles { get; set; } = [];
}