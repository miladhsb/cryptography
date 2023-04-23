using cryptography.Model;
using System.Security.Cryptography;

namespace cryptography.Services
{
    public interface ICriptoService
    {
        string AES_SymmetricDecription(string CipherMsg, byte[] Key, byte[] iv);
        string AES_SymmetricEncription(string Msg, byte[] Key, byte[] iv);
        string CreateRNG(int length);
        byte[] CreateRNGByte(int length);
        string CreateRsaJsonWebKey();
        KeyModel CreateRsaParameterkey();
        StringKeyModel CreateRsaPemFile();
        StringKeyModel CreateRsaPemFileWithPassword();
        StringKeyModel CreateRsaXmlkey();
        string DES_SymmetricDecription(string CipherMsg, string Key, string iv);
        string DES_SymmetricEncription(string Msg, string Key, string iv);
        string HashPasswordWithSalt(string password);
        string HMACSHA256Hash(string StrVal, string HmacKey);
        string Md5Hash(string StrVal);
        byte[] RSADecryption(byte[] input, RSAParameters rsaKey);
        byte[] RSAEncryption(byte[] input, RSAParameters rsaKey);
        string RSAFromJwkStringPublicKey(string json);
        string Sha1Hash(string StrVal);
        string Sha256Hash(string StrVal);
        string Sha384Hash(string StrVal);
        string Sha512Hash(string StrVal);
        byte[] SignData(byte[] hashedData, RSAParameters privateKey);
        byte[] SignData(string Data, RSAParameters privateKey);
        bool VerifySignature(byte[] hashedData, byte[] signature, RSAParameters publicKey);
        bool VerifySignature(string Data, byte[] signature, RSAParameters publicKey);
    }
}
