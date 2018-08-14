namespace Authen.Jwt.Api.Issuer.Controllers
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Text;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Options;
    using Microsoft.IdentityModel.Tokens;
    using Models;
    using Service;

    [Route("api/[controller]")]
    public class AuthorizeController : Controller
    {
        readonly JwtSettings _jwtSettings;

        public AuthorizeController(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }
        /* 验证方法:
         1.PostMan中输入网址:http://localhost:8757/api/Authorize
         2.方式选择POST -> Body -> raw -> JSON(application/json)
         3.在body中输入如下jsong
         {
             "username":"admin",
             "password":"123456"
         }
         4.Send
         */
        [HttpPost]
        public IActionResult Token([FromBody]User user)
        {
            // 验证身份
            if (!(user.username == "admin" && user.password == "123456"))
            {
                return BadRequest(new { error = "验证账号密码失败" });
            }
            user.role = "manager";

            // 配置参数
            var claims = new[]{
                new Claim(ClaimTypes.Name,user.username),
                new Claim(ClaimTypes.Role,user.role)
            };

            // 生成对称秘钥
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));

            // 生成签名证书
            var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // 生成token
            var token = new JwtSecurityToken(
                _jwtSettings.Issuer,
                _jwtSettings.Audience,
                claims,
                DateTime.Now,
                DateTime.Now.AddMinutes(30),
                signingCredentials);
            
            return Ok(new { token = JwtSecurityTokenService.Encode(token) });
        }
    }
}