using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.Tests
{
    public class HttpSigEcdsaSigningTests
    {
        private readonly HttpSigEcdsaCredential _credential = new()
        {
            KeyId = "test-key-a",
            Algorithm = AlgorithmNames.EcdsaSha512,
            PrivateKey = ECDsa.Create(),
            PublicKey = ECDsa.Create()
        };

        private readonly Dictionary<string, string> _headers = new(StringComparer.InvariantCultureIgnoreCase)
        {
            {HeaderNames.Created, "1402170695"},
            {HeaderNames.RequestTarget, "post /foo?param=value&pet=dog"},
            {HeaderNames.Host, "example.com"},
            {HeaderNames.Date, "Tue, 07 Jun 2014 20:51:35 GMT"},
            {HeaderNames.ContentType, "application/json"},
            {HeaderNames.Digest, "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="},
            {HeaderNames.ContentLength, "18"}
        };

        public HttpSigEcdsaSigningTests()
        {
            _credential.PublicKey!.ImportFromPem(@"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECzolExKXII9hUJvwgKjITyQa1o8S
Pntm8i6LvyaYycMF8rFS/9I3dYWzPryO06EuKZb70BjHCaQqymlg/ijYBw==
-----END PUBLIC KEY-----");
            _credential.PrivateKey!.ImportFromPem(@"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEHTW4f/aHCN3hiUU
1rnQsLC7rjSiusApu+4yMjEzcrWhRANCAAQLOiUTEpcgj2FQm/CAqMhPJBrWjxI+
e2byLou/JpjJwwXysVL/0jd1hbM+vI7ToS4plvvQGMcJpCrKaWD+KNgH
-----END PRIVATE KEY-----");
        }

        [Fact]
        public void MinimalRecommendedSignatureTests()
        {
            var signature = new HttpSigSignature
            {
                Created = DateTimeOffset.FromUnixTimeSeconds(1402170695),
                Headers =
                {
                    HeaderNames.Created,
                    HeaderNames.RequestTarget
                }
            };

            _credential.Sign(signature, _headers);

            Assert.Equal(AlgorithmNames.Hs2019, signature.Algorithm);
            Assert.Equal("(created) (request-target)", signature.Headers);
            Assert.NotEmpty(signature.Signature);

            var passed = _credential.Verify(signature, _headers);
            Assert.True(passed);
        }

        [Fact]
        public void FullSignatureTests()
        {
            var signature = new HttpSigSignature
            {
                Created = DateTimeOffset.FromUnixTimeSeconds(1402170695),
                Headers =
                {
                    HeaderNames.RequestTarget,
                    HeaderNames.Created,
                    HeaderNames.Host,
                    HeaderNames.Date,
                    HeaderNames.ContentType,
                    HeaderNames.Digest,
                    HeaderNames.ContentLength
                }
            };

            _credential.Sign(signature, _headers);

            Assert.Equal(AlgorithmNames.Hs2019, signature.Algorithm);
            Assert.Equal("(request-target) (created) host date content-type digest content-length", signature.Headers);
            Assert.NotEmpty(signature.Signature);

            var passed = _credential.Verify(signature, _headers);
            Assert.True(passed);
        }
    }
}
