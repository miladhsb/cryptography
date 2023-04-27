using Microsoft.IdentityModel.Tokens;

namespace cryptography.Model
{
    public class MyJwtPayload
    {
        public string Name { get; set; }
        public string LastName { get; set; }
        //issuer
        public string iss { get; set; } = "milad";
        //audience
        public string aud { get; set; } = "milad";
        //notBefore
        //قابل استفاده بعد از این زمان
        public long nbf { get; set; } = EpochTime.GetIntDate(DateTime.Now.ToUniversalTime());
        //expires
        //زمان انقضا
        public long exp { get; set; }= EpochTime.GetIntDate(DateTime.Now.AddMinutes(10).ToUniversalTime());
        //issuedAt
        //صادر شده در زمان
        public long iat { get; set; }= EpochTime.GetIntDate(DateTime.Now.ToUniversalTime());
    }
}
