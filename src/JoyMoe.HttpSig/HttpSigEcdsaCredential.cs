using System.Security.Cryptography;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig
{
    public class HttpSigEcdsaCredential : IHttpSigCredential
    {
        public string KeyId { get; set; } = null!;

        public string Algorithm { get; set; } = Algorithms.Ed25519;

        public virtual ECDsa? Ecc { get; set; }

        public string Sign(string canonical)
        {
            throw new System.NotImplementedException();
        }

        public bool Verify(string canonical, string signature)
        {
            throw new System.NotImplementedException();
        }
    }
}
