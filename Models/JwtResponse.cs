using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthServer.Models
{
    public class JwtResponse
    {
        public string Token { get; set; }
        public long ExpiresAt { get; set; }
        public JwtResponse(string token, long expiresAt)
        {
            Token = token;
            ExpiresAt = expiresAt;
        }
    }
}
