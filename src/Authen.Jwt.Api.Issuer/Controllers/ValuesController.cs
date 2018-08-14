namespace Authen.Jwt.Api.Issuer.Controllers
{
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.Extensions.Options;
    using Models;
    using Service;

    [Route("api/[controller]")]
    public class ValuesController : Controller
    {
        readonly JwtSettings _jwtSettings;

        public ValuesController(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }
        /* 验证方法:
              1.PostMan中选择GET,输入网址:http://localhost:8757/api/values
              2.选择TYPE -> Bearer Token
              3.在Token中粘贴获取到的授权码
              4.Send
              */
        [HttpGet]
        [Authorize]
        public IEnumerable<string> Get()
        {
            var jwtToken = JwtSecurityTokenService.ReadHeaders(Request.Headers);
            var name = jwtToken.Claims.FirstOrDefault(t => t.Type == ClaimTypes.Name)?.Value;
            var role = jwtToken.Claims.FirstOrDefault(t => t.Type == ClaimTypes.Role)?.Value;
            return new[] { name, role };
        }

        // GET api/values/5
        [HttpGet("{id}")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/values
        [HttpPost]
        public void Post([FromBody]string value)
        {
        }

        // PUT api/values/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/values/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
