using AuthServer.Data;
using AuthServer.Helpers;
using AuthServer.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace AuthServer.Services
{
    public interface IAuthService
    {
        JwtResponse Authenticate(AuthRequest model);
    }
    public class AuthService : IAuthService
    {
        private readonly AuthServerContext _context;
        private readonly IJwtService _jwtService;

        public AuthService(AuthServerContext context, IJwtService jwtService)
        {
            _context = context;
            _jwtService = jwtService;
        }
        public JwtResponse Authenticate(AuthRequest model)
        {
            var user = GetUserByUsername(model.Username);

            if (user == null) return null;

            if (!VerifyPasswordHash(model.Password, user.PasswordHash, user.PasswordSalt))
                return null;

            return _jwtService.CreateToken(new JwtCustomClaims(user));
        }

        private User GetUserByUsername(string username)
        {
            return _context.User.SingleOrDefault(x => x.Username == username);
        }

        private static bool VerifyPasswordHash(string password, byte[] hash, byte[] salt)
        {
            if (password == null) throw new ArgumentNullException("password");
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Value cannot be empty or whitespace only string.", "password");
            if (hash.Length != 64) throw new ArgumentException("Invalid length of password hash (64 bytes expected).", "passwordHash");
            if (salt.Length != 128) throw new ArgumentException("Invalid length of password salt (128 bytes expected).", "passwordHash");

            using (var hmac = new System.Security.Cryptography.HMACSHA512(salt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != hash[i]) return false;
                }
            }

            return true;
        }
    }
}
