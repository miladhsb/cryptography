using System.Security.Cryptography;

namespace cryptography.Model
{
    public class KeyModel
    {
        public RSAParameters PriveteKey { get; set; }
        public RSAParameters Publickey { get; set; }
    }
}
