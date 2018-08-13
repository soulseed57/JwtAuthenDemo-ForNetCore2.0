namespace Authen.Jwt.Api.Issuer.Controllers
{
    using System.Collections.Generic;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Authorization;

    [Route("api/[controller]")]
    public class ValuesController : Controller
    {
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
            return new[] { "value1", "value2" };
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
