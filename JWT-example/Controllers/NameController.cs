using JWT_example.DTOs;
using JWT_example.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWT_example.Controllers
{
    [ApiController]
    [Route("/Api")]
    public class NameController : ControllerBase
    {
        private ITokenManager _tokenManager;

        public NameController(ITokenManager tokenManager)
        {
            _tokenManager = tokenManager;
        }

        [Authorize]
        [HttpGet("/Names")]
        public ActionResult<List<string>> Index()
        {
            var Names = new List<string>() { "Band", "Raine", "Barry", "Block" };
            return Names;
        }

        [HttpPost("/Login/{username},{password}")]
        public ActionResult Login(string username, string password)
        {
            var token = _tokenManager.CreateToken(new LoginDTO { Username = username, Password = password });
            return Ok(token);
        }


    }
}
