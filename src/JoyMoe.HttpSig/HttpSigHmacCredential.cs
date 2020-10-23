using System;
using System.Security.Cryptography;
using System.Text;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig
{
    public class HttpSigHmacCredential : IHttpSigCredential
    {
        public string KeyId { get; set; } = null!;

        public string Algorithm { get; set; } = Algorithms.HmacSha512;

#pragma warning disable CA1819 // Properties should not return arrays
        public virtual byte[]? Key { get; set; }
#pragma warning restore CA1819 // Properties should not return arrays

        public string Sign(string canonical)
        {
            using var hash = HMAC.Create(GetHashAlgorithm());

            hash.Key = Key;

            var signature = hash.ComputeHash(Encoding.UTF8.GetBytes(canonical));

            return Convert.ToBase64String(signature);
        }

        public bool Verify(string canonical, string signature)
        {
            return signature == Sign(canonical);
        }

        private string GetHashAlgorithm()
        {
            return Algorithm.Replace("-", "", StringComparison.InvariantCulture).ToUpperInvariant();
        }
    }
}
