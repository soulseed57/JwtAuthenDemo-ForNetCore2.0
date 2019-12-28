using Authen.Jwt.Api.Issuer.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace Authen.Jwt.Api.Issuer.Controllers
{
    [Produces("application/json")]
    [Route("connect/oauth2")]
    public class OAuth2Controller : Controller
    {
        readonly JwtSettings _jwtSettings;

        public OAuth2Controller(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }

        public static Claim[] GetTokenClaims(string sub, DateTime dateTime)
        {
            var jti = Guid.NewGuid();
            var iat = (long)Math.Round((dateTime.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
            return new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, sub),
                new Claim(JwtRegisteredClaimNames.Jti, jti.ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, iat.ToString(), ClaimValueTypes.Integer64)
            };
        }

        public static dynamic GenerateTokens(string userName, JwtSettings userTokenOptions)
        {
            var issuer = userTokenOptions.Issuer;
            var audience = userTokenOptions.Audience;
            var accessExpiration = userTokenOptions.AccessExpiration;
            var refreshExpiration = userTokenOptions.RefreshExpiration;
            var signingCredentials = userTokenOptions.SigningCredentials;
            var now = DateTime.Now;

            var accessJwt = new JwtSecurityToken(issuer, audience, GetTokenClaims(userName, now), now, now.Add(accessExpiration), signingCredentials);
            var encodedAccessJwt = new JwtSecurityTokenHandler().WriteToken(accessJwt);

            var refreshJwt = new JwtSecurityToken(issuer, audience, GetTokenClaims(userName, now), now, now.Add(refreshExpiration), signingCredentials);
            var encodedRefreshJwt = new JwtSecurityTokenHandler().WriteToken(refreshJwt);

            var result = new
            {
                access_token = encodedAccessJwt,
                access_token_expires_in = (int)accessExpiration.TotalSeconds,
                refresh_token = encodedRefreshJwt,
                refresh_token_expires_in = (int)refreshExpiration.TotalSeconds,
            };
            return result;
        }

        public static JwtSecurityToken ReadToken(string token)
        {
            return new JwtSecurityTokenHandler().ReadToken(token) as JwtSecurityToken;
        }

        [HttpGet("access_token")]
        public dynamic AccessToken(string appid, string secret, string code)
        {
            var userName = "aaa";

            return GenerateTokens(userName, _jwtSettings);
        }

        [Authorize]
        [HttpGet("refresh_token")]
        public dynamic RefreshToken(string appid, string refresh_token)
        {
            var authorization = HttpContext.Request.Headers["Authorization"].FirstOrDefault();
            var token = authorization.Substring(authorization.IndexOf(' ') + 1);
            var jwt = ReadToken(token);

            dynamic result = new
            {
                code = 0,
                data = new
                {
                    user = new
                    {
                        email = jwt.Subject,
                    },
                    token = GenerateTokens(jwt.Subject, _jwtSettings),
                }
            };

            return result;
        }

    }
}