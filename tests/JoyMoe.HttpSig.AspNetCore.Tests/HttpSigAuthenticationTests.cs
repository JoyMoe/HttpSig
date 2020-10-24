using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using JoyMoe.HttpSig.AspNetCore.Tests.Host;
using JoyMoe.HttpSig.Client;
using Microsoft.AspNetCore.TestHost;
using Xunit;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.AspNetCore.Tests
{
    public class HttpSigAuthenticationTests
    {
        [Fact]
        public async Task SignedRequestShouldGetUnauthorized()
        {
            using var host = await TestHostBuilder.BuildAsync().ConfigureAwait(false);

            var client = host.GetTestClient();

            var response = await client.GetAsync(new Uri("https://example.com/Test/Authorized")).ConfigureAwait(false);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Equal(HeaderNames.Signature, response.Headers.WwwAuthenticate.ToString());
        }

        [Fact]
        public async Task SignedRequestShouldGetOkResponse()
        {
            var signer = new HttpSigRequestSigner(MockSigCredentialProvider.Credential);

            using var host = await TestHostBuilder.BuildAsync().ConfigureAwait(false);

            var client = host.GetTestClient();

            using var message = new HttpRequestMessage
            {
                RequestUri = new Uri("https://example.com/Test/Authorized"),
                Method = HttpMethod.Get
            };

            await signer.SignAsync(message).ConfigureAwait(false);

            var response = await client.SendAsync(message).ConfigureAwait(false);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
    }
}
