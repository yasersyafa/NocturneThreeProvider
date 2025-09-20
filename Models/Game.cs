namespace NocturneThreeProvider.Models;

public class Game
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Title { get; set; }
    public required string Description { get; set; }
    public List<string> Links { get; set; } = [];
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    // relations
    public ICollection<UserGameData> Playerdata { get; set; } = [];

    // custom function for validating links
    public void AddLink(string link)
    {
        if (Links.Count >= 5)
            throw new InvalidOperationException("A game can only have up to 5 links.");
        Links.Add(link);
    }
}