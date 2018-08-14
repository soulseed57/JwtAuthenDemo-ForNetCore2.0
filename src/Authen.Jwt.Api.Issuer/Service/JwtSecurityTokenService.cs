namespace Authen.Jwt.Api.Issuer.Service
{
    using System.IdentityModel.Tokens.Jwt;
    using Microsoft.AspNetCore.Http;

    public static class JwtSecurityTokenService
    {
        /// <summary>
        /// 编码token
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static string Encode(JwtSecurityToken token) => new JwtSecurityTokenHandler().WriteToken(token);

        /// <summary>
        /// 解码token
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static JwtSecurityToken Decode(string token) => new JwtSecurityTokenHandler().ReadJwtToken(token);

        /// <summary>
        /// 读取请求头部(传入Request.Headers)
        /// </summary>
        /// <param name="header"></param>
        /// <returns></returns>
        public static JwtSecurityToken ReadHeaders(IHeaderDictionary header)
        {
            header.TryGetValue("Authorization", out var token);
            var split = token.ToString().Split(' ');
            token = split.Length > 1 ? split[1] : split[0];
            return Decode(token);
        }
    }
}