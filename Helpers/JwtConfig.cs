using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthServer.Helpers
{
    public class JwtConfig
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string RsaPrivateKey { get; set; }
        public string RsaPublicKey { get; set; }
    }
}
