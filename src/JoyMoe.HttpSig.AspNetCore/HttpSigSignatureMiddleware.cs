using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.AspNetCore
{
    public class HttpSigSignatureMiddleware
    {
        private IHttpSigCredentialProvider? _provider;

        private readonly RequestDelegate _next;

        public HttpSigSignatureMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var endpoint = context.Features.Get<IEndpointFeature>().Endpoint;
            var attribute = endpoint?.Metadata.GetMetadata<HttpSigSignatureAttribute>();
            if (attribute == null)
            {
                await _next(context).ConfigureAwait(false);
                return;
            }

            _provider = context.RequestServices.GetService<IHttpSigCredentialProvider>();

            if (!await VerifySignatureAsync(context.Request, attribute.RequireDigestForBody).ConfigureAwait(false))
            {
                context.Response.Clear();
                context.Response.StatusCode = attribute.StatusCode;
                return;
            }

            if (!attribute.SignResponse)
            {
                await _next(context).ConfigureAwait(false);
                return;
            }

            var rb = context.Response.Body;

            await using var rs = new MemoryStream();

            context.Response.Body = rs;

            await _next(context).ConfigureAwait(false);

            await GenerateSignatureAsync(context.Response).ConfigureAwait(false);

            await rs.CopyToAsync(rb).ConfigureAwait(false);
        }

        private async Task<bool> VerifySignatureAsync(HttpRequest request, bool requireDigestForBody)
        {
            if (_provider == null)
            {
                return false;
            }

            if (!request.Headers.ContainsKey(HeaderNames.Signature))
            {
                return false;
            }

            string header = request.Headers[HeaderNames.Signature];
            if (string.IsNullOrWhiteSpace(header))
            {
                return false;
            }

            HttpSigSignature signature;

            try
            {
                signature = HttpSigSignature.Parse(header);
            }
            catch (ArgumentException)
            {
                return false;
            }

            var headers = request.Headers
                .ToDictionary(h => h.Key, h => h.Value.First(), StringComparer.InvariantCultureIgnoreCase);

            headers[HeaderNames.Created] = signature.Created.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            headers[HeaderNames.Expires] = signature.Expires?.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture) ?? "";
#pragma warning disable CA1308 // Normalize strings to uppercase
            headers[HeaderNames.RequestTarget] = $"{request.Method.ToLowerInvariant()} {request.Path.Value!}{request.QueryString}";
#pragma warning restore CA1308 // Normalize strings to uppercase

            if (headers.ContainsKey(HeaderNames.Digest))
            {
                request.EnableBuffering();

                var digest = headers[HeaderNames.Digest];
                if (!DigestHelper.CheckDigest(request.Body, digest))
                {
                    return false;
                }
            }
            else if (requireDigestForBody)
            {
                var method = request.Method.ToUpperInvariant();
                if (method == "POST" || method == "PUT" || method == "PATCH")
                {
                    return false;
                }
            }

            var credential = await _provider.GetKeyByKeyIdAsync(request.HttpContext, signature.KeyId).ConfigureAwait(false);
            if (credential == null)
            {
                return false;
            }

            return credential.Verify(signature, headers);
        }

        private async Task GenerateSignatureAsync(HttpResponse response)
        {
            if (_provider == null)
            {
                return;
            }

            if (!response.Headers.ContainsKey(HeaderNames.XHttpSigKeyId))
            {
                return;
            }

            string keyId = response.Headers[HeaderNames.XHttpSigKeyId];
            if (string.IsNullOrWhiteSpace(keyId))
            {
                return;
            }

            response.Headers.Remove(HeaderNames.XHttpSigKeyId);

            var signature = new HttpSigSignature
            {
                Headers =
                {
                    HeaderNames.Date,
                    HeaderNames.Digest
                }
            };

            if (!response.Headers.ContainsKey(HeaderNames.Date))
            {
                var date = DateTimeOffset.UtcNow.ToString("R");
                response.Headers.Add(HeaderNames.Date, date);
            }

            var digest = DigestHelper.GenerateDigest(response.Body, HashAlgorithmNames.Sha256);
            response.Headers.Remove(HeaderNames.Digest);
            response.Headers.Add(HeaderNames.Digest, digest);

            var credential = await _provider.GetKeyByKeyIdAsync(response.HttpContext, keyId).ConfigureAwait(false);
            if (credential == null)
            {
                return;
            }

            var headers = response.Headers
                .ToDictionary(h => h.Key, h => h.Value.First(), StringComparer.InvariantCultureIgnoreCase);

            credential.Sign(signature, headers);

            response.Headers.Remove(HeaderNames.Signature);
            response.Headers.Add(HeaderNames.Signature, signature.ToString());
        }
    }
}
