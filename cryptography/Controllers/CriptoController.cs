using cryptography.Model;
using cryptography.Services;
using cryptography.Utility;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Core.Infrastructure;
using Microsoft.IdentityModel.Tokens;
using Swashbuckle.AspNetCore.Annotations;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace cryptography.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class CriptoController : ControllerBase
    {


        private readonly ILogger<CriptoController> _logger;
        private readonly ICriptoService _criptoService;

        public CriptoController(ICriptoService criptoService)
        {
            this._criptoService = criptoService;
        }

        [ProducesResponseType(typeof(string), 200)]
        [SwaggerOperation(summary: "جهت ایجاد یک رشته تصادفی", description: "از این رشته تصادفی جهت استفاده برای ایجاد کلید استفاده کنید")]
        // [ApiExplorerSettings(IgnoreApi = true)]
        //[Obsolete(message: "این متد منقضی شده")]
        [HttpGet(Name = "CreateRNG")]
        public IActionResult CreateRNG()
        {
            return Ok(_criptoService.CreateRNG(32));
        }

        [HttpGet("CreateMd5Hash")]
        public IActionResult CreateMd5Hash()
        {

            return Ok(_criptoService.Md5Hash("milad"));
        }

        [HttpGet("CreateSha256")]
        public IActionResult CreateSha256()
        {

            return Ok(_criptoService.Sha256Hash("milad"));
        }

        [HttpGet("CreateSha512")]
        public IActionResult CreateSha512()
        {

            return Ok(_criptoService.Sha512Hash("milad"));
        }

        [HttpGet("CreateHMACSHA256")]
        public IActionResult CreateHMACSHA256()
        {

            return Ok(_criptoService.HMACSHA256Hash("milad","123ab"));
        }
        
       
        [HttpGet("DecriptEncriptDes")]
        public IActionResult DecriptEncriptDes()
        {
           var encript= _criptoService.DES_SymmetricEncription("milad", "12345678","12345678");
            var decript = _criptoService.DES_SymmetricDecription(encript, "12345678", "12345678");
            return Ok(new { encript = encript , decript = decript });
        }

        [HttpGet("DecriptEncriptAes")]
        public IActionResult DecriptEncriptAes()
        {
            var key = _criptoService.CreateRNGByte(32);
            var iv = _criptoService.CreateRNGByte(16);
           
            var encript = _criptoService.AES_SymmetricEncription("milad", key, iv);
            var decript = _criptoService.AES_SymmetricDecription(encript, key, iv);
            return Ok(new { encript = encript, decript = decript });
        }


        [HttpGet("CreateRsaKeyParams")]
        public IActionResult CreateRsaKeyParams()
        {
            return Ok(_criptoService.CreateRsaParameterkey());
        }

        [HttpGet("CreateRsaKeyXml")]
        public IActionResult CreateRsaKeyXml()
        {
            return Ok(_criptoService.CreateRsaXmlkey());
        }
        [HttpGet("CreateRsaPemFile")]
        public IActionResult CreateRsaPemFile()
        {
            return Ok(_criptoService.CreateRsaPemFile());
        }

        [HttpGet("CreateRsaPemFileWithPassword")]
        public IActionResult CreateRsaPemFileWithPassword()
        {
            return Ok(_criptoService.CreateRsaPemFileWithPassword());
        }

        [HttpGet("CreateRsaJsonWebKey")]
        public IActionResult CreateRsaJsonWebKey()
        {
            return Ok(_criptoService.CreateRsaJsonWebKey());
        }
        [HttpGet("RSAFromJwkStringPublicKey")]
        public IActionResult RSAFromJwkStringPublicKey()
        {
            return Ok(_criptoService.RSAFromJwkStringPublicKey(_criptoService.CreateRsaJsonWebKey()));
        }

        //رمزنگاری و رمز گشایی نامتقارن
        [HttpGet("RSAEncryptionDecryption")]
        public IActionResult RSAEncryptionDecryption()
        {
            string Message = "milad";
           
            var rsa = new RSACryptoServiceProvider(2048);
            var PublicKey = rsa.ExportParameters(false);
            var Privatekey = rsa.ExportParameters(true);
            var encrypted = _criptoService.RSAEncryption(Encoding.UTF8.GetBytes(Message), PublicKey);
            var decrypted = _criptoService.RSADecryption(encrypted, Privatekey);

            return Ok(new { Message = Message , encrypted = encrypted , decrypted = Encoding.UTF8.GetString(decrypted) });
        }

        //ایجاد امضا از دیتا و ارزیابی دیتا با امضا
        [HttpGet("SignAndVerifyData")]
        public IActionResult SignAndVerifyData()
        {
          
            var rsa = new RSACryptoServiceProvider(2048);
            var PublicKey = rsa.ExportParameters(false);
            var Privatekey = rsa.ExportParameters(true);


            var document = Encoding.UTF8.GetBytes("milad");
            byte[] hashedDocument;
            using (var hash = SHA256.Create())
            {
                hashedDocument = hash.ComputeHash(document);
            }

           var SignData= _criptoService.SignData(hashedDocument, Privatekey);

            var VerifySignature = _criptoService.VerifySignature(hashedDocument, SignData, Privatekey);
            return Ok(new { Message = Encoding.UTF8.GetString(document), SignData = MyBase64UrlEncoder.Encode(SignData), IsVerifySignature = VerifySignature });
        }

        //ایجاد امضا از دیتا و ارزیابی دیتا با امضا
        [HttpGet("SignAndVerifyDataEsaMethod")]
        public IActionResult SignAndVerifyDataEsaMethod()
        {

            var rsa = new RSACryptoServiceProvider(2048);
            var PublicKey = rsa.ExportParameters(false);
            var Privatekey = rsa.ExportParameters(true);


            var document = "milad";
            byte[] hashedDocument;
      
            var SignData = _criptoService.SignData(document, Privatekey);

            var VerifySignature = _criptoService.VerifySignature(document, SignData, Privatekey);
            return Ok(new { Message = document, SignData = MyBase64UrlEncoder.Encode(SignData), IsVerifySignature = VerifySignature });
        }
        //ایجاد توکن دستی HMACSHA256 
        [HttpGet("CreateJwtWithHMACSHA256")]
        public IActionResult CreateJwtWithHMACSHA256()
        {
            var header = new MyJwtHeader()
            {
                alg = "HS256",
                typ = "JWT"
            };

            var Payload = new MyJwtPayload() { Name="milad",LastName="Kh" };
           
            return Ok(new { Token = _criptoService.CreateJwtWithHMACSHA256(Payload, header, "123456") });
        }

        //ایجاد توکن دستی RS256
        [HttpGet("CreateJwtWitRS256")]
        public IActionResult CreateJwtWitRS256()
        {
            var header = new MyJwtHeader()
            {
                alg = "RS256",
                typ = "JWT"
            };
            var Payload = new MyJwtPayload() { Name = "milad", LastName = "Kh" };
            var rsa = new RSACryptoServiceProvider(1024);
            var PublicKey = rsa.ExportParameters(false);
            var Privatekey = rsa.ExportParameters(true);

            RsaSecurityKey publicAndPrivateKey = new(rsa.ExportParameters(true))
            {
                KeyId = "keyId1"
            };

            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(publicAndPrivateKey);

          

            return Ok(new { Token = _criptoService.CreateJwtWitRS256(Payload, header, Privatekey),Jwk= System.Text.Json.JsonSerializer.Serialize(jwk) });
        }

        #region  ایجاد توکن با متد های کتابخانه jwt bearer
        [HttpGet("GenerateTokenHmacSha256")]
        public IActionResult GenerateTokenHmacSha256()
        {
            List<Claim> claims= new List<Claim>();
            claims.Add(new Claim("name", "milad"));
          var SecurityToken=   _criptoService.GenerateTokenHmacSha256(claims);
            JwtSecurityTokenHandler jwtSecurityTokenHandler= new JwtSecurityTokenHandler();

            return Ok(new { Token = jwtSecurityTokenHandler.WriteToken(SecurityToken) });
        }

        [HttpGet("GenerateTokenCompressSha256")]
        public IActionResult GenerateTokenCompressSha256()
        {
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("name", "milad"));
            var SecurityToken = _criptoService.GenerateTokenCompressSha256(claims);
            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

            return Ok(new { Token = jwtSecurityTokenHandler.WriteToken(SecurityToken) });
        }

        [HttpGet("GenerateTokenCompressRs256")]
        public IActionResult GenerateTokenCompressRs256()
        {
            using RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024);
           

            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("name", "milad"));
            var SecurityToken = _criptoService.GenerateTokenCompressRs256(claims, rsa.ExportParameters(true));
            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

            return Ok(new { Token = jwtSecurityTokenHandler.WriteToken(SecurityToken) });
        }

        [HttpGet("GenerateTokenCompressCustomeRs256")]
        public IActionResult GenerateTokenCompressCustomeRs256()
        {
            using RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024);

            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("name", "milad"));
            var SecurityToken = _criptoService.GenerateTokenCompressCustomeRs256(claims, rsa.ExportParameters(true));
            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

            return Ok(new { Token = jwtSecurityTokenHandler.WriteToken(SecurityToken) });
        }

        #endregion

        #region اعتبار سنجی توکنهای jwt 
        [HttpGet("ValidateJwtTokenRSA")]
        public IActionResult ValidateJwtTokenRSA()
        {
            using RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024);

            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("name", "milad"));
            var SecurityToken = _criptoService.GenerateTokenCompressCustomeRs256(claims, rsa.ExportParameters(true));
            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var token = jwtSecurityTokenHandler.WriteToken(SecurityToken);


            var ClaimsPrincipalRes=  _criptoService.ValidateJwtTokenRSA(token, rsa.ExportParameters(false));
            
            return Ok(new { Token = token, isvalid= ClaimsPrincipalRes.Identity.IsAuthenticated });
        }

        [HttpGet("ValidateJwtTokenHmacSha")]
        public IActionResult ValidateJwtTokenHmacSha()
        {
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim("name", "milad"));
            var SecurityToken = _criptoService.GenerateTokenCompressSha256(claims);
            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var token = jwtSecurityTokenHandler.WriteToken(SecurityToken);


            var ClaimsPrincipalRes = _criptoService.ValidateJwtTokenHmacSha(token);

            return Ok(new { Token = token, isvalid = ClaimsPrincipalRes.Identity.IsAuthenticated });
        }

        //اعتبار سنجی توکنهای ساخته شده دستی
        [HttpGet("ValidateJwtTokenHmacShaManual")]
        public IActionResult ValidateJwtTokenHmacShaManual()
        {
            var header = new MyJwtHeader()
            {
                alg = "HS256",
                typ = "JWT"
            };

            var Payload = new MyJwtPayload() { Name = "milad", LastName = "Kh" };

        
            var token = _criptoService.CreateJwtWithHMACSHA256(Payload, header, "1sdd1sdv65sd1v56ds51cvvx2");


            var ClaimsPrincipalRes = _criptoService.ValidateJwtTokenHmacSha(token);

            return Ok(new { Token = token, isvalid = ClaimsPrincipalRes.Identity.IsAuthenticated });
        }

        //اعتبار سنجی توکنهای ساخته شده دستی RSA
        [HttpGet("ValidateJwtTokenHmacRsaManual")]
        public IActionResult ValidateJwtTokenHmacRsaManual()
        {
            var header = new MyJwtHeader()
            {
                alg = "RS256",
                typ = "JWT"
            };

            var Payload = new MyJwtPayload() { Name = "milad", LastName = "Kh" };

            var rsa = new RSACryptoServiceProvider(1024);
            var PublicKey = rsa.ExportParameters(false);
            var Privatekey = rsa.ExportParameters(true);

            var token = _criptoService.CreateJwtWitRS256(Payload, header, Privatekey);


            var ClaimsPrincipalRes = _criptoService.ValidateJwtTokenRSA(token, PublicKey);
         
            return Ok(new { Token = token, isvalid = ClaimsPrincipalRes.Identity.IsAuthenticated });
        }

        #endregion

    }
}