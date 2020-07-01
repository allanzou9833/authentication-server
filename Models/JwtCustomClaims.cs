using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace AuthServer.Models
{
    public class JwtCustomClaims
    {
        public string Username { get; set; }

        public JwtCustomClaims(User user)
        {
            Username = user.Username;
        }

        public JwtCustomClaims(JwtSecurityToken token)
        {
            Username = token.Claims.First(claim => claim.Type == "Username").Value;
        }
    }
}
