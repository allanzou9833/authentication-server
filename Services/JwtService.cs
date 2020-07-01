using AuthServer.Helpers;
using AuthServer.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AuthServer.Services
{
    public static class TypeConverterExtension
    {
        public static byte[] ToByteArray(this string value) =>
               Convert.FromBase64String(value);
    }
    public interface IJwtService
    {
        JwtResponse CreateToken(JwtCustomClaims claims);
        bool ValidateToken(string token);
    }
    public class JwtService : IJwtService
    {
        private readonly JwtConfig _settings;

        public JwtService(IOptions<JwtConfig> setting)
        {
            _settings = setting.Value;
        }

        public JwtResponse CreateToken(JwtCustomClaims claims)
        {
            var privateKey = _settings.RsaPrivateKey.ToByteArray();

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKey, out _);

            var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };

            var now = DateTime.Now;
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();

            var jwt = new JwtSecurityToken(
                audience: _settings.Audience,
                issuer: _settings.Issuer,
                claims: new Claim[] {
                    new Claim(JwtRegisteredClaimNames.Iat, unixTimeSeconds.ToString(), ClaimValueTypes.Integer64),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(nameof(claims.Username), claims.Username)
                },
                notBefore: now,
                expires: now.AddMinutes(30),
                signingCredentials: signingCredentials
            );

            string token = new JwtSecurityTokenHandler().WriteToken(jwt);

            return new JwtResponse(token, unixTimeSeconds);
        }

        public bool ValidateToken(string token)
        {

            var publicKey = _settings.RsaPublicKey.ToByteArray();

            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKey, out _);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _settings.Issuer,
                ValidAudience = _settings.Audience,
                IssuerSigningKey = new RsaSecurityKey(rsa)
            };

            try
            {
                var handler = new JwtSecurityTokenHandler();
                handler.ValidateToken(token, validationParameters, out var validatedSecurityToken);
            }
            catch
            {
                return false;
            }

            return true;
        }
    }
}
