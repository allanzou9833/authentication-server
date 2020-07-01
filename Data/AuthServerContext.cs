using Microsoft.EntityFrameworkCore;
using AuthServer.Models;

namespace AuthServer.Data
{
    public class AuthServerContext : DbContext
    {
        public AuthServerContext (DbContextOptions<AuthServerContext> options)
            : base(options)
        {
        }

        public DbSet<User> User { get; set; }
    }
}
