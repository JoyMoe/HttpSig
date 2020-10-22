using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig
{
    public class HttpSigHmacCredential : IHttpSigCredential
    {
        public string KeyId { get; set; } = null!;

        public string Algorithm { get; set; } = Algorithms.HmacSha512;

#pragma warning disable CA1819 // Properties should not return arrays
        public virtual byte[]? Key { get; set; }
#pragma warning restore CA1819 // Properties should not return arrays

        public string Sign(string canonical)
        {
            throw new System.NotImplementedException();
        }

        public bool Verify(string canonical, string signature)
        {
            throw new System.NotImplementedException();
        }
    }
}
