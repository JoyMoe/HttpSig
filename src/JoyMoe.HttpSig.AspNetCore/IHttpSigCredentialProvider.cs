using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace JoyMoe.HttpSig.AspNetCore
{
    public interface IHttpSigCredentialProvider
    {
        Task<IHttpSigCredential?> GetKeyByKeyIdAsync(HttpContext context, string keyId);
    }
}
