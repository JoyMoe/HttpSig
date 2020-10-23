using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.Client
{
    public class HttpSigResponseVerifier
    {
        private readonly Dictionary<string, IHttpSigCredential> _credentials;

        public HttpSigResponseVerifier(Dictionary<string, IHttpSigCredential> credentials)
        {
            _credentials = credentials;
        }

        public async Task<bool> VerifyAsync(HttpResponseMessage response)
        {
            if (response == null)
            {
                throw new ArgumentNullException(nameof(response));
            }

            var header = response.Headers.GetValues(HeaderNames.Signature).FirstOrDefault();
            if (string.IsNullOrWhiteSpace(header))
            {
                return false;
            }

            var separator = header.IndexOf(' ', StringComparison.InvariantCulture);
            if (separator < 0)
            {
                return false;
            }

            var scheme = header.Substring(0, separator);
            if (!HeaderNames.Signature.Equals(scheme, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            var parameters = header.Substring(separator + 1);
            if (string.IsNullOrWhiteSpace(parameters))
            {
                return false;
            }

            HttpSigSignature signature;

            try
            {
                signature = HttpSigSignature.Parse(parameters);
            }
            catch (ArgumentException)
            {
                return false;
            }

            _ = _credentials.TryGetValue(signature.KeyId, out var credential);
            if (credential == null)
            {
                return false;
            }

            var headers = response.Headers
                .ToDictionary(h => h.Key, h => h.Value.First(), StringComparer.InvariantCultureIgnoreCase);

            if (headers.ContainsKey(HeaderNames.Digest))
            {
                var digest = headers[HeaderNames.Digest];

                var body = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                if (!DigestHelper.CheckDigest(body, digest))
                {
                    return false;
                }
            }
            else
            {
                return false;
            }

            return credential.Verify(signature, headers);
        }
    }
}