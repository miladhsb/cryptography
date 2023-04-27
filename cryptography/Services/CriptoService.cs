using cryptography.Model;
using cryptography.Utility;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Immutable;
using System.Configuration.Assemblies;

using System.IO;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Claims;
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
        public string DES_SymmetricEncription(string Msg, string Key, string iv)
        {

            var MsgByte = Encoding.UTF8.GetBytes(Msg);
            var KeyByte = Encoding.UTF8.GetBytes(Key);
            var IvByte = Encoding.UTF8.GetBytes(iv);
            using (var des = DES.Create())
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
            return new KeyModel() { PriveteKey = rsa.ExportParameters(true), Publickey = rsa.ExportParameters(true) };

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

            return new StringKeyModel() { PriveteKey = rsa.ExportEncryptedPkcs8PrivateKeyPem("123", new PbeParameters(PbeEncryptionAlgorithm.Aes192Cbc, HashAlgorithmName.SHA256, 2)), Publickey = rsa.ExportRSAPublicKeyPem() };

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

            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(publicKey);


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
        public byte[] SignData(byte[] hashedData, RSAParameters privateKey)
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

                return rsa.SignData(Encoding.UTF8.GetBytes(Data), HashAlgorithmName.SHA256.ToString());
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

        //ایجاد توکن دستی با امضای HMACSHA256
        public string CreateJwtWithHMACSHA256(MyJwtPayload Payload, MyJwtHeader Header, string Password)
        {
            var jwtHeader = JsonSerializer.Serialize(Header);
            var JwtPayload = JsonSerializer.Serialize(Payload);


            var Base64UrlHeader = MyBase64UrlEncoder.Encode(jwtHeader);
            var Base64UrlPayload = MyBase64UrlEncoder.Encode(JwtPayload);



            byte[] byteHeaderPayload = Encoding.UTF8.GetBytes($"{Base64UrlHeader}.{Base64UrlPayload}");
            byte[] byteHmacKey = Encoding.UTF8.GetBytes(Password);
            using var hashProvider = new HMACSHA256(byteHmacKey);

            var hashSignature = hashProvider.ComputeHash(byteHeaderPayload);
            var base64UrlSignature = MyBase64UrlEncoder.Encode(hashSignature);


            return ($"{Base64UrlHeader}.{Base64UrlPayload}.{base64UrlSignature}");

        }

        //ایجاد توکن دستی با امضای RS256
        public string CreateJwtWitRS256(MyJwtPayload Payload, MyJwtHeader Header, RSAParameters PrivateKey)
        {
            var jwtHeader = JsonSerializer.Serialize(Header);
            var JwtPayload = JsonSerializer.Serialize(Payload);


            var Base64UrlHeader = MyBase64UrlEncoder.Encode(jwtHeader);
            var Base64UrlPayload = MyBase64UrlEncoder.Encode(JwtPayload);



            byte[] byteHeaderPayload = Encoding.UTF8.GetBytes($"{Base64UrlHeader}.{Base64UrlPayload}");


            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(PrivateKey);

                var hashSignature = rsa.SignData(byteHeaderPayload, HashAlgorithmName.SHA256.ToString());


                var base64UrlSignature = MyBase64UrlEncoder.Encode(hashSignature);


                return ($"{Base64UrlHeader}.{Base64UrlPayload}.{base64UrlSignature}");
            }

        }

        #region GenerateToken Method
        //ایجاد توکن جدید
        public  JwtSecurityToken GenerateTokenHmacSha256(List<Claim> AllClaims)
        {

             var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("1sdd1sdv65sd1v56ds51cvvx2"));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: "milad",
                audience: "milad",
                claims: AllClaims,
                expires: DateTime.UtcNow.AddMinutes(10),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
        //ایجاد توکن جدید با کلید های کوتاه 
        public SecurityToken GenerateTokenCompressSha256(List<Claim> AllClaims)
        {

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("1sdd1sdv65sd1v56ds51cvvx2"));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor()
            {
                //دریافت کلایم ها
                Subject = new ClaimsIdentity(AllClaims),
                //ایجاد کننده
                Issuer = "milad",
                //استفاده کننده
                Audience = "milad",
                ////زمان ایجاد شدن
                //IssuedAt = DateTime.Now,
                ////زمان آماده به کارشدن توکن
                ////اگر زمان فعلی زمان آماده به کار باشد نیازی به نوشتن نیست
                //NotBefore = DateTime.Now,
                //زمان انقضا
                Expires = DateTime.UtcNow.AddMinutes(10),
                //کلید ساخته  شده در بالا
                SigningCredentials = signingCredentials,

                CompressionAlgorithm = CompressionAlgorithms.Deflate,
            };

            //ساخت توکن
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken = tokenHandler.CreateToken(descriptor);

            return securityToken;
        }

        //ایجاد توکن با امضای rs256
        public SecurityToken GenerateTokenCompressRs256(List<Claim> AllClaims, RSAParameters rSAParameters)
        {
           
            var symmetricSecurityKey = new RsaSecurityKey(rSAParameters);
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.RsaSha256);

            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor()
            {
               
                Subject = new ClaimsIdentity(AllClaims),
                Issuer = "milad",
                Audience = "milad",
                Expires = DateTime.UtcNow.AddMinutes(10),
                SigningCredentials = signingCredentials,
                CompressionAlgorithm = CompressionAlgorithms.Deflate,
            };

            //ساخت توکن
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken = tokenHandler.CreateToken(descriptor);

            return securityToken;
        }

        //ایجاد توکن با هدر و پی لود سفارشی 
        public SecurityToken GenerateTokenCompressCustomeRs256(List<Claim> AllClaims, RSAParameters rSAParameters)
        {

            var symmetricSecurityKey = new RsaSecurityKey(rSAParameters);
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.RsaSha256);

           JwtHeader header= new JwtHeader(signingCredentials);
            header.Add("Kid", "13456");
            JwtPayload payload= new JwtPayload(issuer:"milad",audience:"milad",claims: AllClaims,notBefore:DateTime.Now ,expires: DateTime.Now.AddMinutes(10),issuedAt: DateTime.Now);
            
         
            payload.AddClaims(AllClaims);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(header, payload);
           
            return jwtSecurityToken;
        }



        #endregion


        #region Validation Jwt Token

        //اعتبار سنجی توکن های HmacSha
        /*
         باید دوکتابخانه زیر دارای یک ورژن باشند
         <PackageReference Include="Microsoft.IdentityModel.Tokens" Version="6.30.0" />
         <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="6.30.0" />

         */
        public ClaimsPrincipal ValidateJwtTokenHmacSha(string token)
        {
            try
            {
                JwtSecurityTokenHandler securityTokenHandler = new JwtSecurityTokenHandler();

                var validationParameter = new TokenValidationParameters()
                {
                    
                    ValidateLifetime = true, // Because there is no expiration in the generated token
                    ValidateAudience = true, // Because there is no audiance in the generated token
                    ValidateIssuer = true,   // Because there is no issuer in the generated token
                    ValidIssuer = "milad",
                    ValidAudience = "milad",
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("1sdd1sdv65sd1v56ds51cvvx2"))
                };

                var Principal = securityTokenHandler.ValidateToken(token, validationParameter, out var mySecurityKeyToken);
                Thread.CurrentPrincipal = Principal;
                return Principal;
            }
            catch (SecurityTokenDecryptionFailedException ex)
            {

                throw new Exception("توکن معتبر نیست");
            }
            catch (SecurityTokenExpiredException ex)
            {

                throw new Exception("تاریخ انقضای توکن به پایان رسیده است");
            }
            catch (SecurityTokenValidationException ex)
            {

                throw new Exception(ex.Message);
            }

        }
        //اعتبار سنجی توکن های RSA
        public ClaimsPrincipal ValidateJwtTokenRSA(string token,RSAParameters rSAParametersPublickey)
        {
            try
            {
                JwtSecurityTokenHandler securityTokenHandler = new JwtSecurityTokenHandler();

                var validationParameter = new TokenValidationParameters()
                {
                   
                   ValidateLifetime = true, // Because there is no expiration in the generated token
                    ValidateAudience = true, // Because there is no audiance in the generated token
                    ValidateIssuer = true,   // Because there is no issuer in the generated token
                    ValidIssuer = "milad",
                    ValidAudience = "milad",
                    IssuerSigningKey = new RsaSecurityKey(rSAParametersPublickey)
                };

                var Principal = securityTokenHandler.ValidateToken(token, validationParameter, out var mySecurityKeyToken);
                Thread.CurrentPrincipal = Principal;
                return Principal;
            }
            catch (SecurityTokenDecryptionFailedException ex)
            {

                throw new Exception("توکن معتبر نیست");
            }
            catch (SecurityTokenExpiredException ex)
            {

                throw new Exception("تاریخ انقضای توکن به پایان رسیده است");
            }
            catch (SecurityTokenValidationException ex)
            {

                throw new Exception(ex.Message);
            }

        }
        #endregion

    }
}
