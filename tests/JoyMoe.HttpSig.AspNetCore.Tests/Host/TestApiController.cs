using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using static JoyMoe.HttpSig.HttpSigConstants;

namespace JoyMoe.HttpSig.AspNetCore.Tests.Host
{
    [Route("Test")]
    public class TestApiController : ControllerBase
    {
        [HttpSigSignature]
        [HttpGet("Signed")]
        public IActionResult Middleware()
        {
            Response.Headers.Add(HeaderNames.XHttpSigKeyId, MockSigCredentialProvider.Credential.KeyId);

            return Ok();
        }

        [Authorize]
        [HttpGet("Authorized")]
        public IActionResult Authentication()
        {
            return Ok();
        }
    }
}
