using Microsoft.AspNetCore.Mvc;
using AuthServer.Models;
using AuthServer.Services;
using System.Security.Cryptography;
using System;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using System.Linq;

namespace AuthServer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IJwtService _jwtService;
        public AuthController(IAuthService authService, IJwtService jwtService)
        {
            _authService = authService;
            _jwtService = jwtService;
    }

        [HttpPost]
        [Route("token")]
        public IActionResult GetToken([FromBody] AuthRequest model)
        {
            JwtResponse response = _authService.Authenticate(model);

            if (response == null) return BadRequest(new { message = "Incorrect Username or Password" });

            return Ok(response);
        }

        [HttpPost]
        [Route("validate")]
        public IActionResult ValidateToken([FromBody] string token)
        {
            if (_jwtService.ValidateToken(token))
            {
                var jwtToken = new JwtSecurityTokenHandler().ReadToken(token) as JwtSecurityToken;
                var claims = new JwtCustomClaims(jwtToken);
                return Ok(claims);
            }

            return BadRequest("Token is invalid.");
        }
    }
}
