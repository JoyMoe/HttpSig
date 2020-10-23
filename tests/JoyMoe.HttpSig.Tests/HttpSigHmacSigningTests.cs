using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.Tests
{
    public class HttpSigHmacSigningTests
    {
        private readonly HttpSigHmacCredential _credential;

        private readonly Dictionary<string, string> _headers = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase)
        {
            {HeaderNames.Created, "1402170695"},
            {HeaderNames.RequestTarget, "post /foo?param=value&pet=dog"},
            {HeaderNames.Host, "example.com"},
            {HeaderNames.Date, "Tue, 07 Jun 2014 20:51:35 GMT"},
            {HeaderNames.ContentType, "application/json"},
            {HeaderNames.Digest, "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="},
            {HeaderNames.ContentLength, "18"}
        };

        public HttpSigHmacSigningTests()
        {
            _credential = new HttpSigHmacCredential
            {
                KeyId = "test-key-a",
                Algorithm = Algorithms.HmacSha512,
                Key = Encoding.UTF8.GetBytes("key")
            };
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

            Assert.Equal(Algorithms.Hs2019, signature.Algorithm);
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

            Assert.Equal(Algorithms.Hs2019, signature.Algorithm);
            Assert.Equal("(request-target) (created) host date content-type digest content-length", signature.Headers);
            Assert.NotEmpty(signature.Signature);

            var passed = _credential.Verify(signature, _headers);
            Assert.True(passed);
        }
    }
}
