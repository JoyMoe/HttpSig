using System;
using System.IO;
using System.Security.Cryptography;

namespace JoyMoe.HttpSig
{
    public static class DigestHelper
    {
        public static string? GenerateDigest(Stream body, string algorithm)
        {
            if (body == null)
            {
                throw new ArgumentNullException(nameof(body));
            }

            if (string.IsNullOrWhiteSpace(algorithm))
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            body.Position = 0;

            using var hash = HashAlgorithm.Create(algorithm);
            if (hash == null)
            {
                return null;
            }

            var bytes = hash.ComputeHash(body);

            body.Position = 0;

#pragma warning disable CA1308 // Normalize strings to uppercase
            return $"{algorithm.ToLowerInvariant()}={Convert.ToBase64String(bytes)}";
#pragma warning restore CA1308 // Normalize strings to uppercase
        }

        public static bool CheckDigest(Stream body, string header)
        {
            if (body == null)
            {
                throw new ArgumentNullException(nameof(body));
            }

            if (string.IsNullOrWhiteSpace(header))
            {
                throw new ArgumentNullException(nameof(header));
            }

            var sign = header.IndexOf('=', StringComparison.InvariantCulture);
            if (sign < 0)
            {
                return false;
            }

            var algorithm = header.Substring(0, sign);
            if (string.IsNullOrWhiteSpace(algorithm))
            {
                return false;
            }

            var digest = GenerateDigest(body, algorithm);
            if (string.IsNullOrWhiteSpace(digest))
            {
                return false;
            }

            var hash = header.Substring(0, algorithm.Length + 1);
            if (string.IsNullOrWhiteSpace(hash))
            {
                return false;
            }

            return hash == digest.Substring(0, algorithm.Length + 1);
        }
    }
}
