using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using JoyMoe.HttpSig.AspNetCore.Tests.Host;
using JoyMoe.HttpSig.Client;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace JoyMoe.HttpSig.AspNetCore.Tests
{
    public class HttpSigMiddlewareTests
    {
        [Fact]
        public async Task SignedRequestShouldGetForbidden()
        {
            using var host = await TestHostBuilder.BuildAsync().ConfigureAwait(false);

            var client = host.GetTestClient();

            var response = await client.GetAsync(new Uri("https://example.com/Test/Signed")).ConfigureAwait(false);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        }

        [Fact]
        public async Task SignedRequestShouldGetSignedResponse()
        {
            var signer = new HttpSigRequestSigner(MockSigCredentialProvider.Credential);
            var verifier = new HttpSigResponseVerifier(new Dictionary<string, IHttpSigCredential>
            {
                {MockSigCredentialProvider.Credential.KeyId, MockSigCredentialProvider.Credential}
            });

            using var host = await TestHostBuilder.BuildAsync().ConfigureAwait(false);

            var client = host.GetTestClient();

            using var message = new HttpRequestMessage
            {
                RequestUri = new Uri("https://example.com/Test/Signed"),
                Method = HttpMethod.Get
            };

            await signer.SignAsync(message).ConfigureAwait(false);

            var response = await client.SendAsync(message).ConfigureAwait(false);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            var passed = await verifier.VerifyAsync(response).ConfigureAwait(false);
            Assert.True(passed);

            Assert.Equal("Hello World!", await response.Content.ReadAsStringAsync().ConfigureAwait(false));
        }
    }
}
