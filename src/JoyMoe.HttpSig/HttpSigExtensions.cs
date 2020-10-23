using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig
{
    public static class HttpSigExtensions
    {
        public static void Sign(this IHttpSigCredential credential, HttpSigSignature signature, Dictionary<string, string> headers)
        {
            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential));
            }

            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (headers == null)
            {
                throw new ArgumentNullException(nameof(headers));
            }

            signature.Headers.TryAdd(HeaderNames.RequestTarget);

            signature.Headers.TryAdd(HeaderNames.Created);
            headers[HeaderNames.Created] = signature.Created.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

            if (signature.Expires.HasValue)
            {
                signature.Headers.TryAdd(HeaderNames.Expires);
                headers[HeaderNames.Expires] = signature.Expires.Value.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            }

            var canonical = BuildCanonicalString(signature.Headers, headers);

            signature.KeyId = credential.KeyId;
            signature.Signature = credential.Sign(canonical);
        }

        public static bool Verify(this IHttpSigCredential credential, HttpSigSignature signature, Dictionary<string, string> headers)
        {
            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential));
            }

            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            if (headers == null)
            {
                throw new ArgumentNullException(nameof(headers));
            }

            if (string.IsNullOrWhiteSpace(signature.Signature))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(signature.KeyId) || signature.KeyId != credential.KeyId)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(signature.Algorithm) && signature.Algorithm != Algorithms.Hs2019)
            {
                if (signature.Algorithm != credential.Algorithm) return false;
            }

            if (signature.Expires != null && signature.Expires < DateTimeOffset.Now)
            {
                return false;
            }

            var canonical = BuildCanonicalString(signature.Headers, headers);

            return credential.Verify(canonical, signature.Signature);
        }

        private static void TryAdd<T>(this ICollection<T> list, T item)
        {
            if (list.Contains(item)) return;

            list.Add(item);
        }

        private static string BuildCanonicalString(IEnumerable<string> requirements, Dictionary<string, string> headers)
        {
            var sb = new StringBuilder();

            foreach (var h in requirements)
            {
                if (!headers.ContainsKey(h))
                {
                    throw new ArgumentException($"No \"{h}\" specified in headers");
                }

                sb.Append($"{h}: {headers[h]}\n");
            }

            return sb.ToString().TrimEnd();
        }
    }
}
