namespace Authen.Jwt.Api.Issuer.Models
{
    using System.ComponentModel.DataAnnotations;

    public class JwtSettings
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        /// <summary>
        /// 发行者秘钥长度必须大于16
        /// </summary>
        [MinLength(16)]
        public string SecretKey { get; set; }
    }
}
