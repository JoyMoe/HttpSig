using System;
using System.Collections.Generic;
using Xunit;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.Tests
{
    public class HttpSigSignatureTests
    {
        private const string Signature = "e3y37nxAoeuXw2KbaIxE2d9jpE7Z9okgizg6QbD2Z7fUVUvog+ZTKKLRBnhNglVIY6fAaYlHwx7ZAXXdBVF8gjWBPL6U9zRrB4PFzjoLSxHaqsvS0ZK9FRxpenptgukaVQ1aeva3PE1aD6zZ93df2lFIFXGDefYCQ+M/SrDGQOFvaVykEkte5mO6zQZ/HpokjMKvilfSMJS+vbvC1GJItQpjs636Db+7zB2W1BurkGxtQdCLDXuIDg4S8pPSDihkch/dUzL2BpML3PXGKVXwHOUkVG6Q2ge07IYdzya6N1fIVA9eKI1Y47HT35QliVAxZgE0EZLo8mxq19ReIVvuFg==";

        private const string Header = @"keyId=""test-key-a"", created=1402170695, headers=""(created) (request-target)"", signature=""e3y37nxAoeuXw2KbaIxE2d9jpE7Z9okgizg6QbD2Z7fUVUvog+ZTKKLRBnhNglVIY6fAaYlHwx7ZAXXdBVF8gjWBPL6U9zRrB4PFzjoLSxHaqsvS0ZK9FRxpenptgukaVQ1aeva3PE1aD6zZ93df2lFIFXGDefYCQ+M/SrDGQOFvaVykEkte5mO6zQZ/HpokjMKvilfSMJS+vbvC1GJItQpjs636Db+7zB2W1BurkGxtQdCLDXuIDg4S8pPSDihkch/dUzL2BpML3PXGKVXwHOUkVG6Q2ge07IYdzya6N1fIVA9eKI1Y47HT35QliVAxZgE0EZLo8mxq19ReIVvuFg==""";

        [Fact]
        public void HeaderParsingTests()
        {
            var signature = HttpSigSignature.Parse(Header);

            Assert.Equal("test-key-a", signature.KeyId);
            Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1402170695), signature.Created);

            Assert.Null(signature.Expires);

            Assert.Equal(new List<string>
            {
                HeaderNames.Created,
                HeaderNames.RequestTarget
            }, signature.Headers);

            Assert.Equal(Signature, signature.Signature);
        }

        [Fact]
        public void HeaderStringBuildingTests()
        {
            var signature = new HttpSigSignature
            {
                KeyId = "test-key-a",
                Created = DateTimeOffset.FromUnixTimeSeconds(1402170695),
                Headers =
                {
                    HeaderNames.Created,
                    HeaderNames.RequestTarget
                },
                Signature = Signature
            };

            Assert.Equal(Header, signature);
        }
    }
}
