using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.AspNetCore
{
    public static class HttpSigAspNetCoreExtensions
    {
        public static AuthenticationBuilder AddHttpSig(this AuthenticationBuilder builder)
        {
            return builder.AddHttpSig(HeaderNames.Signature, options => { });
        }

        public static AuthenticationBuilder AddHttpSig(
            this AuthenticationBuilder builder,
            Action<HttpSigAuthenticationOptions> configuration)
        {
            return builder.AddHttpSig(HeaderNames.Signature, configuration);
        }

        public static AuthenticationBuilder AddHttpSig(
            this AuthenticationBuilder builder, string scheme,
            Action<HttpSigAuthenticationOptions> configuration)
        {
            if (builder == null)
            {
                throw new NullReferenceException(nameof(builder));
            }

            return builder.AddScheme<HttpSigAuthenticationOptions, HttpSigAuthenticationHandler>(scheme, configuration);
        }

        public static IApplicationBuilder UseHttpSig(this IApplicationBuilder app) {
            return app.UseMiddleware<HttpSigSignatureMiddleware>();
        }
    }
}
