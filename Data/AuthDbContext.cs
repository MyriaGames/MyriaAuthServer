using Microsoft.EntityFrameworkCore;
using Myria.Server.Auth.Models;

namespace Myria.Server.Auth.Data
{
    public class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users => Set<User>();
        public DbSet<PasswordResetRequest> PasswordResetRequests => Set<PasswordResetRequest>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>(e =>
            {
                e.HasIndex(u => u.Username).IsUnique();
                e.Property(u => u.Username).HasMaxLength(50);
            });

            modelBuilder.Entity<PasswordResetRequest>(e =>
            {
                e.HasOne(r => r.User).WithMany().HasForeignKey(r => r.UserId).OnDelete(DeleteBehavior.Cascade);
                e.HasIndex(r => r.TokenHash).IsUnique();
                e.HasIndex(r => r.Status);
            });
        }
    }
}
