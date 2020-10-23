using System;
using System.Security.Cryptography;
using System.Text;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig
{
    public class HttpSigEcdsaCredential : IHttpSigCredential
    {
        public string KeyId { get; set; } = null!;

        public string Algorithm { get; set; } = Algorithms.Ed25519;

        public virtual ECDsa? PrivateKey { get; set; }

        public virtual ECDsa? PublicKey { get; set; }

        public string Sign(string canonical)
        {
            if (PrivateKey == null)
            {
                throw new ArgumentException("Must specified PrivateKey");
            }

            var bytes = Encoding.UTF8.GetBytes(canonical);

            if (Algorithm == Algorithms.Ed25519Ph)
            {
                using var hash = SHA512.Create();
                bytes = hash.ComputeHash(bytes);
            }

            var signature = PrivateKey.SignData(bytes, GetHashAlgorithm());

            return Convert.ToBase64String(signature);
        }

        public bool Verify(string canonical, string signature)
        {
            if (PublicKey == null)
            {
                throw new ArgumentException("Must specified PublicKey");
            }

            var bytes = Encoding.UTF8.GetBytes(canonical);

            if (Algorithm == Algorithms.Ed25519Ph)
            {
                using var hash = SHA512.Create();
                bytes = hash.ComputeHash(bytes);
            }

            return PublicKey.VerifyData(
                bytes,
                Convert.FromBase64String(signature),
                GetHashAlgorithm()
            );
        }

        private HashAlgorithmName GetHashAlgorithm()
        {
            return Algorithm.StartsWith(Algorithms.Ed25519, StringComparison.InvariantCulture)
                ? HashAlgorithmName.SHA512
                : new HashAlgorithmName(Algorithm.Replace("ecdsa-", "", StringComparison.InvariantCulture).ToUpperInvariant());
        }
    }
}
