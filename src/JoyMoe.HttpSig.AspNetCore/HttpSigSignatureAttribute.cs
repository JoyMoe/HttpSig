using System;

namespace JoyMoe.HttpSig.AspNetCore
{
    [AttributeUsage(AttributeTargets.Method)]
    public class HttpSigSignatureAttribute : Attribute
    {
        public bool RequireDigestForBody { get; set; } = true;

        public bool SignResponse { get; set; } = true;

        public int StatusCode { get; set; } = 403;

        public HttpSigSignatureAttribute()
        {
        }

        public HttpSigSignatureAttribute(int code)
        {
            StatusCode = code;
        }
    }
}
