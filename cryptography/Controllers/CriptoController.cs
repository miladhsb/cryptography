using cryptography.Services;
using cryptography.Utility;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Core.Infrastructure;
using Swashbuckle.AspNetCore.Annotations;
using System.ComponentModel;
using System.Security.Cryptography;
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
    }
}