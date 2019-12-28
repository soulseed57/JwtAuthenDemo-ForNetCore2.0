using Microsoft.IdentityModel.Tokens;
using System;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace Authen.Jwt.Api.Issuer.Models
{

    public class JwtSettings
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        /// <summary>
        /// 发行者秘钥长度必须大于16
        /// </summary>
        [MinLength(16)]
        public string SecretKey { get; set; }

        public TimeSpan ActiveExpiration { get; set; } = TimeSpan.FromDays(1);
        public TimeSpan ResetExpiration { get; set; } = TimeSpan.FromDays(1);
        public TimeSpan AccessExpiration { get; set; } = TimeSpan.FromDays(30);
        public TimeSpan RefreshExpiration { get; set; } = TimeSpan.FromDays(1000);

        public SigningCredentials SigningCredentials
        {
            get
            {
                var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(SecretKey));
                var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
                return signingCredentials;
            }
        }
    }
}
