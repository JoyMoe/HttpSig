using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.Tests
{
    public class HttpSigRsaSigningTests
    {
        private readonly HttpSigRsaCredential _credential;

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

        public HttpSigRsaSigningTests()
        {
            _credential = new HttpSigRsaCredential
            {
                KeyId = "test-key-a",
                PrivateKey = RSA.Create(),
                PublicKey = RSA.Create()
            };

            _credential.PublicKey.ImportFromPem(@"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsPBRrw
WEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsdJKFq
MGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75jfZg
kne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKIlE0P
uKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZSFlQ
PSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQAB
-----END RSA PUBLIC KEY-----");
/*
            _credential.PrivateKey.ImportFromPem(@"-----BEGIN RSA PRIVATE KEY-----
MIIEqAIBAAKCAQEAhAKYdtoeoy8zcAcR874L8cnZxKzAGwd7v36APp7Pv6Q2jdsP
BRrwWEBnez6d0UDKDwGbc6nxfEXAy5mbhgajzrw3MOEt8uA5txSKobBpKDeBLOsd
JKFqMGmXCQvEG7YemcxDTRPxAleIAgYYRjTSd/QBwVW9OwNFhekro3RtlinV0a75
jfZgkne/YiktSvLG34lw2zqXBDTC5NHROUqGTlML4PlNZS5Ri2U4aCNx2rUPRcKI
lE0PuKxI4T+HIaFpv8+rdV6eUgOrB2xeI1dSFFn/nnv5OoZJEIB+VmuKn3DCUcCZ
SFlQPSXSfBDiUGhwOw76WuSSsf1D4b/vLoJ10wIDAQABAoIBAG/JZuSWdoVHbi56
vjgCgkjg3lkO1KrO3nrdm6nrgA9P9qaPjxuKoWaKO1cBQlE1pSWp/cKncYgD5WxE
CpAnRUXG2pG4zdkzCYzAh1i+c34L6oZoHsirK6oNcEnHveydfzJL5934egm6p8DW
+m1RQ70yUt4uRc0YSor+q1LGJvGQHReF0WmJBZHrhz5e63Pq7lE0gIwuBqL8SMaA
yRXtK+JGxZpImTq+NHvEWWCu09SCq0r838ceQI55SvzmTkwqtC+8AT2zFviMZkKR
Qo6SPsrqItxZWRty2izawTF0Bf5S2VAx7O+6t3wBsQ1sLptoSgX3QblELY5asI0J
YFz7LJECgYkAsqeUJmqXE3LP8tYoIjMIAKiTm9o6psPlc8CrLI9CH0UbuaA2JCOM
cCNq8SyYbTqgnWlB9ZfcAm/cFpA8tYci9m5vYK8HNxQr+8FS3Qo8N9RJ8d0U5Csw
DzMYfRghAfUGwmlWj5hp1pQzAuhwbOXFtxKHVsMPhz1IBtF9Y8jvgqgYHLbmyiu1
mwJ5AL0pYF0G7x81prlARURwHo0Yf52kEw1dxpx+JXER7hQRWQki5/NsUEtv+8RT
qn2m6qte5DXLyn83b1qRscSdnCCwKtKWUug5q2ZbwVOCJCtmRwmnP131lWRYfj67
B/xJ1ZA6X3GEf4sNReNAtaucPEelgR2nsN0gKQKBiGoqHWbK1qYvBxX2X3kbPDkv
9C+celgZd2PW7aGYLCHq7nPbmfDV0yHcWjOhXZ8jRMjmANVR/eLQ2EfsRLdW69bn
f3ZD7JS1fwGnO3exGmHO3HZG+6AvberKYVYNHahNFEw5TsAcQWDLRpkGybBcxqZo
81YCqlqidwfeO5YtlO7etx1xLyqa2NsCeG9A86UjG+aeNnXEIDk1PDK+EuiThIUa
/2IxKzJKWl1BKr2d4xAfR0ZnEYuRrbeDQYgTImOlfW6/GuYIxKYgEKCFHFqJATAG
IxHrq1PDOiSwXd2GmVVYyEmhZnbcp8CxaEMQoevxAta0ssMK3w6UsDtvUvYvF22m
qQKBiD5GwESzsFPy3Ga0MvZpn3D6EJQLgsnrtUPZx+z2Ep2x0xc5orneB5fGyF1P
WtP+fG5Q6Dpdz3LRfm+KwBCWFKQjg7uTxcjerhBWEYPmEMKYwTJF5PBG9/ddvHLQ
EQeNC8fHGg4UXU8mhHnSBt3EA10qQJfRDs15M38eG2cYwB1PZpDHScDnDA0=
-----END RSA PRIVATE KEY-----");
*/
        }

        [Fact]
        public void MinimalRecommendedSignatureGenerationTests()
        {
            _credential.Algorithm = Algorithms.RsaSha512;

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
        }

        [Fact]
        public void FullSignatureGenerationTests()
        {
            _credential.Algorithm = Algorithms.RsaSha512;

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
        }

        [Fact]
        public void MinimalRequiredSignatureVerificationTests()
        {
#pragma warning disable CS0618 // Use of obsolete symbol
            _credential.Algorithm = Algorithms.RsaSha256;
#pragma warning restore CS0618 // Use of obsolete symbol

            var signature = HttpSigSignature.Parse(@"keyId=""test-key-a"", created=1402170695, signature=""V3SijFpJOvDUT8t1/EnYli/4TbF2AGqwBGiGUGrgClCkiOAIlOxxY72Mr13DccFkYzg3gX1jIOpKXzH70C5bru4b71SBG+ShiJLu34gHCG33iw44NLGUvT5+F+LCKbbHberyk8eyYsZ+TLwtZAYKafxfNOWQXF4o3QaWslDMm8Tcgrd8onM45ayFyR4nXRlcGad4PISYGz8PmO4Y+K8RYOyDkgsmRxKtftFQUYG41anyElccNLfEfLBKsyV6kxr36U1Q7FdUopLv8kqluQySrWD6kesvFxNvbEOi+1uZqTuFlK8ZldITQiqtNYaabRjQFZio63gma2y+UAaTGLdM9A==""");

            var passed = _credential.Verify(signature, _headers);
            Assert.True(passed);
        }

        [Fact]
        public void MinimalSignatureVerificationTests()
        {
#pragma warning disable CS0618 // Use of obsolete symbol
            _credential.Algorithm = Algorithms.RsaSha256;
#pragma warning restore CS0618 // Use of obsolete symbol

            var signature = HttpSigSignature.Parse(@"keyId=""test-key-a"", headers=""date"", signature=""HtXycCl97RBVkZi66ADKnC9c5eSSlb57GnQ4KFqNZplOpNfxqk62JzZ484jXgLvoOTRaKfR4hwyxlcyb+BWkVasApQovBSdit9Ml/YmN2IvJDPncrlhPDVDv36Z9/DiSO+RNHD7iLXugdXo1+MGRimW1RmYdenl/ITeb7rjfLZ4b9VNnLFtVWwrjhAiwIqeLjodVImzVc5srrk19HMZNuUejK6I3/MyN3+3U8tIRW4LWzx6ZgGZUaEEP0aBlBkt7Fj0Tt5/P5HNW/Sa/m8smxbOHnwzAJDa10PyjzdIbywlnWIIWtZKPPsoVoKVopUWEU3TNhpWmaVhFrUL/O6SN3w==""");

            var passed = _credential.Verify(signature, _headers);
            Assert.True(passed);
        }

        [Fact]
        public void MinimalRequiredSha256SignatureVerificationTests()
        {
#pragma warning disable CS0618 // Use of obsolete symbol
            _credential.Algorithm = Algorithms.RsaSha256;
#pragma warning restore CS0618 // Use of obsolete symbol

            var signature = HttpSigSignature.Parse(@"algorithm=""rsa-sha256"", keyId=""test-key-a"", headers=""date"", signature=""HtXycCl97RBVkZi66ADKnC9c5eSSlb57GnQ4KFqNZplOpNfxqk62JzZ484jXgLvoOTRaKfR4hwyxlcyb+BWkVasApQovBSdit9Ml/YmN2IvJDPncrlhPDVDv36Z9/DiSO+RNHD7iLXugdXo1+MGRimW1RmYdenl/ITeb7rjfLZ4b9VNnLFtVWwrjhAiwIqeLjodVImzVc5srrk19HMZNuUejK6I3/MyN3+3U8tIRW4LWzx6ZgGZUaEEP0aBlBkt7Fj0Tt5/P5HNW/Sa/m8smxbOHnwzAJDa10PyjzdIbywlnWIIWtZKPPsoVoKVopUWEU3TNhpWmaVhFrUL/O6SN3w==""");

            var passed = _credential.Verify(signature, _headers);
            Assert.True(passed);
        }
    }
}
