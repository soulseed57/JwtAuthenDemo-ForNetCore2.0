namespace Authen.Jwt.Api.Issuer
{
    using System.Text;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.IdentityModel.Tokens;
    using Models;

    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            /* --------------- 读取配置 --------------- */
            // 读取配置信息
            services.Configure<JwtSettings>(Configuration.GetSection("JwtSettings"));
            // 绑定配置信息到一个新建实例
            var jwtSettings = new JwtSettings();
            Configuration.Bind("JwtSettings", jwtSettings);
            /* ---------------------------------------- */

            /* --------------- 添加验证 --------------- */
            services.AddAuthentication(options =>
                {
                    // 默认验证方案设置
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(o =>
                {
                    // token 验证参数配置
                    o.TokenValidationParameters = new TokenValidationParameters
                    {
                        // 颁发机构
                        ValidIssuer = jwtSettings.Issuer,
                        // 授权机构
                        ValidAudience = jwtSettings.Audience,
                        // 发行者签名
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
                        //// 验证发行者签名的密钥
                        //ValidateIssuerSigningKey = true,
                        //// 是否验证Token有效期，使用当前时间与Token的Claims中的NotBefore和Expires对比
                        //ValidateLifetime = true,
                        //// 允许的服务器时间偏移量
                        //ClockSkew = TimeSpan.Zero

                    };
                });
            /* ---------------------------------------- */

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            /* --------------- 重要!!! 应用验证 --------------- */
            app.UseAuthentication();
            /* ------------------------------------------------ */

            app.UseMvc();
        }
    }
}
