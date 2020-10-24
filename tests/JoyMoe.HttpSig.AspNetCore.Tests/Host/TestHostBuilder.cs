using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace JoyMoe.HttpSig.AspNetCore.Tests.Host
{
    public static class TestHostBuilder
    {
        public static Task<IHost> BuildAsync()
        {
            return new HostBuilder()
                .ConfigureWebHost(webBuilder =>
                {
                    webBuilder
                        .UseTestServer()
                        .ConfigureServices(services =>
                        {
                            services.AddControllers();

                            services.AddSingleton<IHttpSigCredentialProvider>(new MockSigCredentialProvider());

                            services
                                .AddAuthentication(HttpSigConstants.HeaderNames.Signature)
                                .AddHttpSig();
                        })
                        .Configure(app =>
                        {
                            app.UseRouting();

                            app.UseAuthentication();
                            app.UseAuthorization();

                            app.UseHttpSig();

                            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
                        });
                })
                .StartAsync();
        }
    }
}
