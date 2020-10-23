using System;

#pragma warning disable CA1034 // Nested types should not be visible
namespace JoyMoe.HttpSig
{
    public static class HttpSigConstants
    {
        public static class AlgorithmNames
        {
            // Active Algorithms

            public const string Hs2019 = "hs2019";

            // Supported Algorithms of key metadata

            public const string RsaSha512 = "rsa-sha512";

            public const string HmacSha512 = "hmac-sha512";

            public const string EcdsaSha512 = "ecdsa-sha512";

            public const string Ed25519Ph= "ed25519ph";

            public const string Ed25519Ctx= "ed25519ctx";

            public const string Ed25519 = "ed25519";

            // Deprecated Algorithms

            [Obsolete("Deprecated; SHA-1 not secure.")]
            public const string RsaSha1 = "rsa-sha1";

            public const string RsaSha256 = "rsa-sha256";

            public const string HmacSha256 = "hmac-sha256";

            public const string EcdsaSha256 = "ecdsa-sha256";
        }

        public static class HashAlgorithmNames
        {
            [Obsolete("Deprecated; SHA-1 not secure.")]
            public const string Sha1 = "sha1";

            public const string Sha256 = "sha256";

            public const string Sha512 = "sha512";
        }

        public static class HeaderNames
        {
            // Signing HTTP Messages specified Headers

            public const string Created = "(created)";
            public const string Expires = "(expires)";
            public const string RequestTarget = "(request-target)";

            public const string Signature = "signature";

            // HTTP Standard Headers

            public const string Authorization = "authorization";
            public const string ContentLength = "content-length";
            public const string ContentType = "content-type";
            public const string Date = "date";
            public const string Digest = "digest";
            public const string Host = "host";
            public const string WAuthenticate = "www-authenticate";
        }
    }
}
#pragma warning restore CA1034 // Nested types should not be visible
