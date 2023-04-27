
using cryptography.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace cryptography
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();


            #region ولیدیت توکن های rsa با کلید عمومی
            var rsa = new RSACryptoServiceProvider(1024);
            var PublicKey = rsa.ExportParameters(false);

            builder.Services.AddAuthentication(Option =>
            {
                Option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                Option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                Option.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                Option.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
                Option.DefaultSignOutScheme = JwtBearerDefaults.AuthenticationScheme;

            }).AddJwtBearer(Jwt =>
            {


                Jwt.RequireHttpsMetadata = false;
                //ذخیره توکن
                Jwt.SaveToken = true;

                var validationParameters = new TokenValidationParameters
                {
                    //زمانی که ساخته میشود و تازمانی که معتبر است
                    ClockSkew = TimeSpan.Zero, // default: 5 min
                    //اجبار به توکن
                    RequireSignedTokens = true,
                    //بررسی امضا
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new RsaSecurityKey(PublicKey),
                    //بررسی زمان انقضا
                    RequireExpirationTime = true,
                    //بررسی عمر توکن
                    ValidateLifetime = true,
                    //ولید کردن استفاده کننده
                    ValidateAudience = true,
                    ValidAudience = "milad",

                    ValidateIssuer = true, //default : false
                    //نام صادر کننده
                    ValidIssuer = "milad",

                };


                //دادن پارامتر های اعتبار سنجی توکن که بالا تعریف شده
                Jwt.TokenValidationParameters = validationParameters;
            });
            #endregion




            builder.Services.AddSwaggerGen(opt =>
            {
                opt.EnableAnnotations();
                
            });
            builder.Services.AddScoped<ICriptoService, CriptoService>();
            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}