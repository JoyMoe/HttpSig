using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.Tests
{
    public class CavageDarftComplianceTests
    {
        private readonly HttpSigRsaCredential _credential;

        private readonly Dictionary<string, string> _headers = new Dictionary<string, string>
        {
            {HeaderNames.Created, "1402170695"},
            {HeaderNames.RequestTarget, "post /foo?param=value&pet=dog"},
            {HeaderNames.Host, "example.com"},
            {HeaderNames.Date, "Sun, 05 Jan 2014 21:31:40 GMT"},
            {HeaderNames.ContentType, "application/json"},
            {HeaderNames.Digest, "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="},
            {HeaderNames.ContentLength, "18"},
        };

        public CavageDarftComplianceTests()
        {
            _credential = new HttpSigRsaCredential
            {
                KeyId = "Test",
#pragma warning disable CS0618
                Algorithm = Algorithms.RsaSha256,
#pragma warning restore CS0618
                PublicKey = RSA.Create()
            };

            _credential.PublicKey.ImportFromPem(@"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
oYi+1hqp1fIekaxsyQIDAQAB
-----END PUBLIC KEY-----");
        }

        [Fact]
        public void DefaultSignatureTests()
        {
            // Attention: Cavage Edition uses Date as the default header,
            // it is NOT compliant to the new draft.
            // If you'd like to accept a Cavage default signature,
            // you have to add `headers="date"` into the signature string.
            // With JoyMoe.HttpSig.AspNetCore, use a middleware to do so.

            var signature = HttpSigSignature.Parse(@"keyId=""Test"",algorithm=""rsa-sha256"",signature=""SjWJWbWN7i0wzBvtPl8rbASWz5xQW6mcJmn+ibttBqtifLN7Sazz6m79cNfwwb8DMJ5cou1s7uEGKKCs+FLEEaDV5lp7q25WqS+lavg7T8hc0GppauB6hbgEKTwblDHYGEtbGmtdHgVCk9SuS13F0hZ8FD0k/5OxEPXe5WozsbM=""");
            signature.Headers.Remove(HeaderNames.Created);
            signature.Headers.Add(HeaderNames.Date);

            var passed = _credential.Verify(signature, _headers);
            Assert.True(passed);
        }

        [Fact]
        public void BasicSignatureTests()
        {
            var signature = HttpSigSignature.Parse(@"keyId=""Test"",algorithm=""rsa-sha256"",headers=""(request-target) host date"",signature=""qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=""");

            var passed = _credential.Verify(signature, _headers);
            Assert.True(passed);
        }

        [Fact]
        public void FullSignatureTests()
        {
            // https://tools.ietf.org/html/draft-cavage-http-signatures-12#appendix-C.3
            // Attention: Test Case from the Cavage Edition seems wrong,
            // it has `(created)` and `(expires)` in the headers list,
            // but does not include them when generate the signature.

            var signature = HttpSigSignature.Parse(@"keyId=""Test"",algorithm=""rsa-sha256"",headers=""(request-target) host date content-type digest content-length"",signature=""vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE=""");

            var passed = _credential.Verify(signature, _headers);
            Assert.True(passed);
        }
    }
}
