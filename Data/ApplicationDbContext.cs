using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Models;

namespace Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Custom configurations
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(e => e.RefreshToken).HasMaxLength(256);
            entity.Property(e => e.TwoFactorSecretKey).HasMaxLength(256);
        });
    }
} 