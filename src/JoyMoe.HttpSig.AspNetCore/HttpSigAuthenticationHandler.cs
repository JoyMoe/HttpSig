using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.AspNetCore
{
    public class HttpSigAuthenticationHandler : AuthenticationHandler<HttpSigAuthenticationOptions>
    {
        private readonly IHttpSigCredentialProvider _keyProvider;

        public HttpSigAuthenticationHandler(
            IOptionsMonitor<HttpSigAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IHttpSigCredentialProvider keyProvider) : base(options, logger, encoder, clock)
        {
            _keyProvider = keyProvider;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey(HeaderNames.Authorization))
            {
                return AuthenticateResult.NoResult();
            }

            string authorization = Request.Headers[HeaderNames.Authorization];

            var separator = authorization.IndexOf(' ', StringComparison.InvariantCulture);
            if (separator < 0)
            {
                return AuthenticateResult.NoResult();
            }

            var scheme = authorization.Substring(0, separator);
            if (!HeaderNames.Signature.Equals(scheme, StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.NoResult();
            }

            var parameters = authorization.Substring(separator + 1);
            if (string.IsNullOrWhiteSpace(parameters))
            {
                return AuthenticateResult.NoResult();
            }

            HttpSigSignature signature;

            try
            {
                signature = HttpSigSignature.Parse(parameters);
            }
            catch (ArgumentException e)
            {
                return AuthenticateResult.Fail(e.Message);
            }

            var headers = Request.Headers
                .ToDictionary(h => h.Key, h => h.Value.First(), StringComparer.InvariantCultureIgnoreCase);

            headers[HeaderNames.Created] = signature.Created.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            headers[HeaderNames.Expires] = signature.Expires?.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture) ?? "";
#pragma warning disable CA1308 // Normalize strings to uppercase
            headers[HeaderNames.RequestTarget] = $"{Request.Method.ToLowerInvariant()} {Request.Path.Value!}{Request.QueryString}";
#pragma warning restore CA1308 // Normalize strings to uppercase

            if (headers.ContainsKey(HeaderNames.Digest))
            {
                var digest = headers[HeaderNames.Digest];

                if (!DigestHelper.CheckDigest(Request.Body, digest))
                {
                    return AuthenticateResult.Fail("Invalid digest header");
                }
            }
            else if (Options.RequireDigestForBody)
            {
                var method = Request.Method.ToUpperInvariant();
                if (method == "POST" || method == "PUT" || method == "PATCH")
                {
                    return AuthenticateResult.Fail("No \"digest\" specified in headers");
                }
            }

            var credential = await _keyProvider.GetKeyByKeyIdAsync(Context, signature.KeyId).ConfigureAwait(false);
            if (credential == null)
            {
                return AuthenticateResult.Fail("Invalid credentials");
            }

            if (!credential.Verify(signature, headers))
            {
                return AuthenticateResult.Fail("Invalid signature");
            }

            var claims = new[] {new Claim(ClaimTypes.NameIdentifier, credential.KeyId)};
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.Headers[HeaderNames.WwwAuthenticate] = HeaderNames.Signature;

            await base.HandleChallengeAsync(properties).ConfigureAwait(false);
        }
    }
}
