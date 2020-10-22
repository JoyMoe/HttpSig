namespace JoyMoe.HttpSig
{
    public interface IHttpSigCredential
    {
        string KeyId { get; set; }

        string Algorithm { get; set; }

        string Sign(string canonical);

        bool Verify(string canonical, string signature);
    }
}
