using System;

#pragma warning disable CA1034 // Do not nest type Algorithms. Alternatively, change its accessibility so that it is not externally visible.
namespace JoyMoe.HttpSig
{
    public static class HttpSigConstants
    {
        public static class Algorithms
        {
            // Active Algorithms

            public const string Hs2019 = "hs2019";

            // Supported Algorithms of key metadata

            public const string RsaSha512 = "rsa-sha512";

            public const string HmacSha512 = "hmac-sha512";

            public const string Ed25519Ph= "ed25519ph";

            public const string Ed25519Ctx= "ed25519ctx";

            public const string Ed25519 = "ed25519";

            // Deprecated Algorithms

            [Obsolete("Deprecated; SHA-1 not secure.")]
            public const string RsaSha1 = "rsa-sha1";

            [Obsolete("Deprecated; specifying signature algorithm enables attack vector.")]
            public const string RsaSha256 = "rsa-sha256";

            [Obsolete("Deprecated; specifying signature algorithm enables attack vector.")]
            public const string HmacSha256 = "hmac-sha256";

            [Obsolete("Deprecated; specifying signature algorithm enables attack vector.")]
            public const string EcdsaSha256 = "ecdsa-sha256";
        }

        public static class HeaderNames
        {
            // Signing HTTP Messages specified Headers

            public const string RequestTarget = "(request-target)";
            public const string Created = "(created)";
            public const string Expires = "(expires)";

            // HTTP Standard Headers

            public const string ContentLength = "content-length";
            public const string ContentType = "content-type";
            public const string Date = "date";
            public const string Digest = "digest";
            public const string Host = "host";
        }
    }
}
#pragma warning restore CA1034 // Do not nest type Algorithms. Alternatively, change its accessibility so that it is not externally visible.
