using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NocturneThreeProvider.Models;

namespace NocturneThreeProvider.Database;

public class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<AppUser>(options)
{
    public DbSet<Game> Games => Set<Game>();
    public DbSet<UserGameData> UserGamedata => Set<UserGameData>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<UserGameData>()
            .HasOne(ug => ug.User)
            .WithMany(u => u.GameData)
            .HasForeignKey(ug => ug.UserId);

        builder.Entity<UserGameData>()
            .HasOne(ug => ug.Game)
            .WithMany(g => g.Playerdata)
            .HasForeignKey(ug => ug.GameId);
    }
}