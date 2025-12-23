using Microsoft.EntityFrameworkCore;
using PasswordManger.Models;

namespace PasswordManger.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }

    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            optionsBuilder.UseSqlite("Data Source=accounts.db");
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Account>(entity =>
        {
            entity.Property(e => e.EncryptedPassword).IsRequired();
            entity.Property(e => e.Nonce).IsRequired().HasMaxLength(12);
            entity.Property(e => e.Tag).IsRequired().HasMaxLength(16);
        });
    }
}