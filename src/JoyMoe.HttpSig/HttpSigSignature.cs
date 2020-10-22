using System;
using System.Collections.Generic;

namespace JoyMoe.HttpSig
{
    public class HttpSigSignature
    {
        public string KeyId { get; set; } = null!;

        public string? Algorithm { get; set; }

        public DateTimeOffset Created { get; set; } = DateTimeOffset.UtcNow;

        public DateTimeOffset? Expires { get; set; }

        public List<string> Headers { get; } = new List<string>();

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
                        signature.Algorithm = value;
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
                   (string.IsNullOrWhiteSpace(Algorithm) ? "" : $"=\"{Algorithm}\", ") +
                   $"created={Created.ToUnixTimeSeconds()}, " +
                   (Expires.HasValue ? $"expires={Expires.Value.ToUnixTimeSeconds()}, " : "") +
                   (Headers.Count > 0 ? $"headers=\"{string.Join(' ', Headers)}\", " : "") +
                   $"signature=\"{Signature}\"";
        }

        public static implicit operator string(HttpSigSignature? signature)
        {
            return signature?.ToString() ?? "";
        }
    }
}
