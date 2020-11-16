using System;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig
{
    public class HttpSigSignature
    {
        public string KeyId { get; set; } = null!;

        public string? Algorithm
        {
            get;
            [Obsolete("Deprecated; specifying signature algorithm enables attack vector.")]
            set;
        } = AlgorithmNames.Hs2019;

        public DateTimeOffset Created { get; set; } = DateTimeOffset.UtcNow;

        public DateTimeOffset? Expires { get; set; }

        public HttpSigHeaderList Headers { get; } = new();

        public string Signature { get; set; } = null!;

        public static HttpSigSignature Parse(string header)
        {
            if (string.IsNullOrWhiteSpace(header))
            {
                throw new ArgumentNullException(nameof(header));
            }

            var signature = new HttpSigSignature();
            foreach (var part in header.Split(','))
            {
                var separator = part.IndexOf('=', StringComparison.InvariantCulture);

                var key = part.Substring(0, separator).Trim();
                var value = part.Substring(separator + 1).Trim('"');

                switch (key)
                {
                    case "keyId":
                        signature.KeyId = value;
                        break;
                    case "algorithm":
#pragma warning disable CS0618 // Use of obsolete symbol
                        signature.Algorithm = value;
#pragma warning restore CS0618 // Use of obsolete symbol
                        break;
                    case "created":
                        _ = long.TryParse(value, out var cts);
                        signature.Created = DateTimeOffset.FromUnixTimeSeconds(cts);
                        break;
                    case "expires":
                        _ = long.TryParse(value, out var ets);
                        signature.Expires = DateTimeOffset.FromUnixTimeSeconds(ets);
                        break;
                    case "headers":
                        signature.Headers.AddRange(value.Split(' '));
                        break;
                    case "signature":
                        signature.Signature = value;
                        break;
                    default:
                        continue;
                }
            }

            if (signature.Headers.Count == 0)
            {
                signature.Headers.Add(HeaderNames.Created);
            }

            if (string.IsNullOrWhiteSpace(signature.KeyId) ||
                string.IsNullOrWhiteSpace(signature.Signature))
            {
                throw new ArgumentException("Missing Signature parameter");
            }

            return signature;
        }

        public override string ToString()
        {
            return $"keyId=\"{KeyId}\", " +
                   (string.IsNullOrWhiteSpace(Algorithm) ? "" : $"algorithm=\"{Algorithm}\", ") +
                   $"created={Created.ToUnixTimeSeconds()}, " +
                   (Expires.HasValue ? $"expires={Expires.Value.ToUnixTimeSeconds()}, " : "") +
                   (Headers.Count > 0 ? $"headers=\"{Headers}\", " : "") +
                   $"signature=\"{Signature}\"";
        }

        public static implicit operator string(HttpSigSignature? signature)
        {
            return signature?.ToString() ?? "";
        }
    }
}
