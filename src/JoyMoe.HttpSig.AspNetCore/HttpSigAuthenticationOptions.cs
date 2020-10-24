using Microsoft.AspNetCore.Authentication;

namespace JoyMoe.HttpSig.AspNetCore
{
    public class HttpSigAuthenticationOptions : AuthenticationSchemeOptions
    {
        public bool RequireDigestForBody { get; set; } = true;
    }
}
