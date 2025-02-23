using DotnetAuthentication.Entities;
using Microsoft.EntityFrameworkCore;

namespace DotnetAuthentication.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users { get; set; }
}