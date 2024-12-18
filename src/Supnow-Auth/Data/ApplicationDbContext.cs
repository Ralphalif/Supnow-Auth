using Microsoft.AspNetCore.Identity;
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

        // Customize the ASP.NET Identity model and override table names
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.ToTable("Users");
            
            // Index for email searches
            entity.HasIndex(e => e.Email)
                  .HasDatabaseName("IX_Users_Email");
            
            // Index for refresh token lookups
            entity.HasIndex(e => e.RefreshToken)
                  .HasDatabaseName("IX_Users_RefreshToken")
                  .IsUnique();
            
            // Composite index for login attempts and lockout
            entity.HasIndex(e => new { e.LastLoginAttempt, e.FailedLoginAttempts })
                  .HasDatabaseName("IX_Users_LoginAttempts");

            // Configure max lengths
            entity.Property(e => e.RefreshToken).HasMaxLength(256);
            entity.Property(e => e.TwoFactorSecretKey).HasMaxLength(256);
        });

        builder.Entity<IdentityRole>(entity =>
        {
            entity.ToTable("Roles");
            
            // Index for role name searches
            entity.HasIndex(e => e.Name)
                  .HasDatabaseName("IX_Roles_Name");
        });

        builder.Entity<IdentityUserRole<string>>(entity =>
        {
            entity.ToTable("UserRoles");
            
            // Composite index for role lookups
            entity.HasIndex(e => new { e.UserId, e.RoleId })
                  .HasDatabaseName("IX_UserRoles_Composite");
        });

        builder.Entity<IdentityUserClaim<string>>(entity =>
        {
            entity.ToTable("UserClaims");
        });

        builder.Entity<IdentityUserLogin<string>>(entity =>
        {
            entity.ToTable("UserLogins");
        });

        builder.Entity<IdentityRoleClaim<string>>(entity =>
        {
            entity.ToTable("RoleClaims");
        });

        builder.Entity<IdentityUserToken<string>>(entity =>
        {
            entity.ToTable("UserTokens");
        });
    }
} 