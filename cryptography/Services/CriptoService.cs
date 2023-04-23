using cryptography.Model;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.IdentityModel.Tokens;
using System.Configuration.Assemblies;
using System.IO;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace cryptography.Services
{
    public class CriptoService : ICriptoService
    {

        public CriptoService()
        {

        }

        public byte[] CreateRNGByte(int length)
        {
            using RandomNumberGenerator randomGenerator = RandomNumberGenerator.Create();

            byte[] bytes = new byte[length];
            randomGenerator.GetBytes(bytes);
            return bytes;
        }
        public string CreateRNG(int length)
        {

            using RandomNumberGenerator randomGenerator = RandomNumberGenerator.Create();

            byte[] bytes = new byte[length];
            randomGenerator.GetBytes(bytes);
            return Convert.ToHexString(bytes);

            #region other return hex
            //StringBuilder stringBuilder = new StringBuilder();
            //foreach (var item in bytes)
            //{
            //    stringBuilder.Append(item.ToString("X2"));
            //}
            //return stringBuilder.ToString();
            #endregion
            #region return base64
            //return Convert.ToBase64String(bytes);
            #endregion

        }

        public string Md5Hash(string StrVal)
        {
            //HashAlgorithmName.SHA256

            byte[] byteMSG = Encoding.UTF8.GetBytes(StrVal);

            using var hashProvider = MD5.Create();
            var hashResult = hashProvider.ComputeHash(byteMSG);

            return Convert.ToBase64String(hashResult);

        }

        public string Sha1Hash(string StrVal)
        {
            //HashAlgorithmName.SHA256

            byte[] byteMSG = Encoding.UTF8.GetBytes(StrVal);

            using var hashProvider = SHA1.Create();
            var hashResult = hashProvider.ComputeHash(byteMSG);

            return Convert.ToBase64String(hashResult);

        }
        public string Sha256Hash(string StrVal)
        {
            //HashAlgorithmName.SHA256

            byte[] byteMSG = Encoding.UTF8.GetBytes(StrVal);

            using var hashProvider = SHA256.Create();
            var hashResult = hashProvider.ComputeHash(byteMSG);

            return Convert.ToBase64String(hashResult);

        }

        public string Sha384Hash(string StrVal)
        {
            //HashAlgorithmName.SHA256

            byte[] byteMSG = Encoding.UTF8.GetBytes(StrVal);

            using var hashProvider = SHA384.Create();
            var hashResult = hashProvider.ComputeHash(byteMSG);

            return Convert.ToBase64String(hashResult);

        }

        public string Sha512Hash(string StrVal)
        {
            //HashAlgorithmName.SHA256

            byte[] byteMSG = Encoding.UTF8.GetBytes(StrVal);

            using var hashProvider = SHA512.Create();
            var hashResult = hashProvider.ComputeHash(byteMSG);

            return Convert.ToBase64String(hashResult);

        }

        public string HMACSHA256Hash(string StrVal, string HmacKey)
        {

            byte[] byteMSG = Encoding.UTF8.GetBytes(StrVal);
            byte[] byteHmacKey = Encoding.UTF8.GetBytes(HmacKey);
            using var hashProvider = new HMACSHA256(byteHmacKey);

            var hashResult = hashProvider.ComputeHash(byteMSG);

            return Convert.ToBase64String(hashResult);

        }

        //ایجاد هش با سالت
        public string HashPasswordWithSalt(string password)
        {
            using RandomNumberGenerator randomGenerator = RandomNumberGenerator.Create();

            byte[] Saltbytes = new byte[32];
            randomGenerator.GetBytes(Saltbytes);

            byte[] Passbyte = Encoding.UTF8.GetBytes(password);


            var MergeByte = new byte[Saltbytes.Length + Passbyte.Length];

            System.Buffer.BlockCopy(Saltbytes, 0, MergeByte, 0, Saltbytes.Length);
            System.Buffer.BlockCopy(Passbyte, 0, MergeByte, Saltbytes.Length, Passbyte.Length);
            
            using var hashProvider = SHA256.Create();
            var hashResult = hashProvider.ComputeHash(MergeByte);
            return Convert.ToBase64String(hashResult);
        }

        //رمز نگاری
        public string DES_SymmetricEncription(string Msg ,string Key,string iv)
        {
      
           var MsgByte = Encoding.UTF8.GetBytes(Msg);
           var KeyByte = Encoding.UTF8.GetBytes(Key);
            var IvByte = Encoding.UTF8.GetBytes(iv);
            using (var des =  DES.Create())
            {
                des.Key = KeyByte;

                //    des.CreateEncryptor()

             return Convert.ToBase64String(des.EncryptCbc(MsgByte, IvByte));
            }
        }

        //رمز گشایی
        public string DES_SymmetricDecription(string CipherMsg, string Key, string iv)
        {
          
              var MsgByte = Convert.FromBase64String(CipherMsg);
            var KeyByte = Encoding.UTF8.GetBytes(Key);
            var IvByte = Encoding.UTF8.GetBytes(iv);
            using (var des = DES.Create())
            {
                des.Key = KeyByte;
                return Encoding.UTF8.GetString(des.DecryptCbc(MsgByte, IvByte));
            }
        }

        //رمز نگاری
        public string AES_SymmetricEncription(string Msg, byte[] Key, byte[] iv)
        {

            var MsgByte = Encoding.UTF8.GetBytes(Msg);
         
            using (var aes = Aes.Create())
            {
                aes.Key = Key;

              //  aes.CreateEncryptor()

                return Convert.ToBase64String(aes.EncryptCbc(MsgByte, iv));
            }
        }

        //رمز گشایی
        public string AES_SymmetricDecription(string CipherMsg, byte[] Key, byte[] iv)
        {

            var MsgByte = Convert.FromBase64String(CipherMsg);
         
            using (var aes = Aes.Create())
            {
                aes.Key = Key;
                return Encoding.UTF8.GetString(aes.DecryptCbc(MsgByte, iv));
            }
        }

        //ایجاد کلید خصوصی و عمومی

        public KeyModel CreateRsaParameterkey()
        {
           using var rsa = new RSACryptoServiceProvider(2048);
            return new KeyModel() { PriveteKey= rsa.ExportParameters(true),Publickey= rsa.ExportParameters(true) };

        }
       
     

        //ایجاد xml از کلید عمومی و خصوصی

        public StringKeyModel CreateRsaXmlkey()
        {
            using var rsa = new RSACryptoServiceProvider(2048);

            return new StringKeyModel() { PriveteKey = rsa.ToXmlString(true), Publickey = rsa.ToXmlString(false) };

        }

        //ایجاد PemFile از کلید عمومی و خصوصی
        public StringKeyModel CreateRsaPemFile()
        {
            using var rsa = new RSACryptoServiceProvider(2048);

            return new StringKeyModel() { PriveteKey = rsa.ExportRSAPrivateKeyPem(), Publickey = rsa.ExportRSAPublicKeyPem() };

        }

        //ایجاد کلید خصوصی با رمز عبور و رمزنگاری شده
        public StringKeyModel CreateRsaPemFileWithPassword()
        {
            using var rsa = new RSACryptoServiceProvider(2048);

            return new StringKeyModel() { PriveteKey = rsa.ExportEncryptedPkcs8PrivateKeyPem("123",new PbeParameters(PbeEncryptionAlgorithm.Aes192Cbc,HashAlgorithmName.SHA256,2)), Publickey = rsa.ExportRSAPublicKeyPem() };

        }
        //ایجاد کلید عمومی در جیسون فایل
        public string CreateRsaJsonWebKey()
        {
           
            using var rsa = new RSACryptoServiceProvider(2048);

         

               RsaSecurityKey publicKey = new(rsa.ExportParameters(false))
            {
                KeyId = "keyId1"
            };
            //اگر از این کلاس استفاده شود هم کلید عمومی و هم خصوصی در فایل جیسون قرار میگیرد
            RsaSecurityKey publicAndPrivateKey = new(rsa.ExportParameters(true))
            {
                KeyId = "keyId1"
            };

           var jwk=  JsonWebKeyConverter.ConvertFromRSASecurityKey(publicKey);
         

            return System.Text.Json.JsonSerializer.Serialize(jwk);

        }
        //دریافت کلید عمومی از جیسون
        public string RSAFromJwkStringPublicKey(string json)
        {
            #region اگر از فایل جیسون یک ارایه از کلیدها باشد
            //using var httpClient = new HttpClient();
            //var json = httpClient.GetStringAsync(
            //                    "http://..../.well-known/openid-configuration/jwks").GetAwaiter()
            //                .GetResult();

            //var jsonWebKeySet = new JsonWebKeySet(json);

            //var jsonWebKey = jsonWebKeySet.Keys.First();

            #endregion


            var jsonWebKey = JsonWebKey.Create(json);

            var rsaProvider = new RSACryptoServiceProvider();
            rsaProvider.ImportParameters(new RSAParameters
            {
                Modulus = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(jsonWebKey.N),
                Exponent = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(jsonWebKey.E)
            });

            var publicKey = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(rsaProvider.ExportRSAPublicKey());
            return publicKey;
        }

        //رمز نگاری نامتقارن با کلید عمومی
        public byte[] RSAEncryption(byte[] input, RSAParameters Publickey)
        {
            byte[] cipherBytes;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(Publickey);
                cipherBytes = rsa.Encrypt(input, true);
            }
            return cipherBytes;
        }
        //رمز گشایی نامتقارن با کلید خصوصی
        public byte[] RSADecryption(byte[] input, RSAParameters Privetkey)
        {
            byte[] PlainBytes;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(Privetkey);
                PlainBytes = rsa.Decrypt(input, true);
            }
            return PlainBytes;
           
        }

        //ایجاد امضای دیجیتال از هش یک دیتا
        public byte[] SignData(byte[] hashedData,RSAParameters privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(privateKey);
                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
                rsaFormatter.SetHashAlgorithm("SHA256");
                return rsaFormatter.CreateSignature(hashedData);
            }
        }
        //ارزیابی عبارت هش با امضای دیجیتال
        public bool VerifySignature(byte[] hashedData, byte[] signature, RSAParameters publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
            
                rsa.ImportParameters(publicKey);
                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm("SHA256");
                return rsaDeformatter.VerifySignature(hashedData, signature);
            }
        }


        //ایجاد امضای دیجیتال توسط متدهای rsa
        public byte[] SignData(string Data, RSAParameters privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(privateKey);
              
                return rsa.SignData(Encoding.UTF8.GetBytes(Data),HashAlgorithmName.SHA256.ToString());
            }
        }
        //ارزیابی عبارت متن با امضای دیجیتال 
        public bool VerifySignature(string Data, byte[] signature, RSAParameters publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {

                rsa.ImportParameters(publicKey);
             
                return rsa.VerifyData(Encoding.UTF8.GetBytes(Data), HashAlgorithmName.SHA256.ToString(), signature);
            }
        }
    }
}
