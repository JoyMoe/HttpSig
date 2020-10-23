using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.Client
{
    public class HttpSigRequestSigner
    {
        private readonly IHttpSigCredential _credential;

        public HttpSigRequestSigner(IHttpSigCredential credential)
        {
            _credential = credential;
        }

        public async Task SignAsync(HttpRequestMessage request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (request.RequestUri == null)
            {
                throw new ArgumentException("Must specify RequestUri");
            }

            var uri = request.RequestUri;

            request.Headers.Host ??= uri.Host;
            if (request.Headers.Host == null)
            {
                throw new ArgumentException("No \"host\" specified in headers");
            }

            var signature = new HttpSigSignature
            {
                KeyId = _credential.KeyId,
                Headers =
                {
                    HeaderNames.Created,
                    HeaderNames.RequestTarget,
                    HeaderNames.Host
                }
            };

            if (request.Method == HttpMethod.Post || request.Method == HttpMethod.Put || request.Method == HttpMethod.Patch)
            {
                if (request.Content != null)
                {
                    var body = await request.Content.ReadAsStreamAsync().ConfigureAwait(false);

                    signature.Headers.Add(HeaderNames.Digest);
                    request.Headers.Add(HeaderNames.Digest, DigestHelper.GenerateDigest(body, HashAlgorithmNames.Sha256));
                }
            }

            var headers = request.Headers
                .ToDictionary(h => h.Key, h => h.Value.First(), StringComparer.InvariantCultureIgnoreCase);

#pragma warning disable CA1308 // Normalize strings to uppercase
            headers[HeaderNames.RequestTarget] = $"{request.Method.Method.ToLowerInvariant()} {uri.AbsolutePath}{uri.Query}";
#pragma warning restore CA1308 // Normalize strings to uppercase

            _credential.Sign(signature, headers);

            request.Headers.TryAddWithoutValidation(HeaderNames.Signature, signature);
        }
    }
}
