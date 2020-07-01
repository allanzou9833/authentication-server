using AuthServer.Data;
using AuthServer.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace AuthServer.Helpers
{
    public static class SeedData
    {
        public static void Initialize(IServiceProvider serviceProvider)
        {
            using (var context = new AuthServerContext(
                serviceProvider.GetRequiredService<
                    DbContextOptions<AuthServerContext>>()))
            {
                if (context.User.Any()) return;

                CreatePasswordHash("password", out var hash, out var salt);
                context.User.Add(
                    new User
                    {
                        Id = 1,
                        Username = "username",
                        PasswordHash = hash,
                        PasswordSalt = salt
                    }
                );
                context.SaveChanges();
            }
        }

        private static void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            if (password == null) throw new ArgumentNullException("password");
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Value cannot be empty or whitespace only string.", "password");

            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }
    }
}
