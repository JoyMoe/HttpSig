using System;
using System.Security.Cryptography;
using System.Text;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig
{
    public class HttpSigRsaCredential : IHttpSigCredential
    {
        public string KeyId { get; set; } = null!;

        public string Algorithm { get; set; } = AlgorithmNames.RsaSha512;

        public virtual RSA? PrivateKey { get; set; }

        public virtual RSA? PublicKey { get; set; }

        public string Sign(string canonical)
        {
            if (PrivateKey == null)
            {
                throw new ArgumentException("Must specify PrivateKey");
            }

            var signature = PrivateKey.SignData(
                Encoding.UTF8.GetBytes(canonical),
                GetHashAlgorithm(),
                Algorithm == AlgorithmNames.RsaSha512 ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1
            );

            return Convert.ToBase64String(signature);
        }

        public bool Verify(string canonical, string signature)
        {
            if (PublicKey == null)
            {
                throw new ArgumentException("Must specify PublicKey");
            }

            return PublicKey.VerifyData(
                Encoding.UTF8.GetBytes(canonical),
                Convert.FromBase64String(signature),
                GetHashAlgorithm(),
                Algorithm == AlgorithmNames.RsaSha512 ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1
            );
        }

        private HashAlgorithmName GetHashAlgorithm()
        {
            return new(Algorithm.Replace("rsa-", "", StringComparison.InvariantCulture).ToUpperInvariant());
        }
    }
}
