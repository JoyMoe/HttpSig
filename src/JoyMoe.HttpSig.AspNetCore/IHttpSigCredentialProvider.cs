using System.Threading.Tasks;

namespace JoyMoe.HttpSig.AspNetCore
{
    public interface IHttpSigCredentialProvider
    {
        Task<IHttpSigCredential?> GetKeyByKeyIdAsync(string keyId);
    }
}
