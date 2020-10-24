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
        public IActionResult MiddlewareGet()
        {
            Response.Headers.Add(HeaderNames.XHttpSigKeyId, MockSigCredentialProvider.Credential.KeyId);

            return Ok("Hello World!");
        }

        [HttpSigSignature]
        [HttpPost("Signed")]
        public IActionResult MiddlewarePost()
        {
            Response.Headers.Add(HeaderNames.XHttpSigKeyId, MockSigCredentialProvider.Credential.KeyId);

            return Ok("Hello World!");
        }

        [Authorize]
        [HttpGet("Authorized")]
        public IActionResult AuthenticationGet()
        {
            return Ok("Hello World!");
        }

        [Authorize]
        [HttpPost("Authorized")]
        public IActionResult AuthenticationPost()
        {
            return Ok("Hello World!");
        }
    }
}
