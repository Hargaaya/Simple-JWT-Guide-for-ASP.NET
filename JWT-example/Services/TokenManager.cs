using JWT_example.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_example.Services
{
    public class TokenManager : ITokenManager
    {
        private UserManager<IdentityUser> _userManager;

        public TokenManager(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }


        public string CreateToken(LoginDTO loginDTO)
        {
            var user = this.GetUser(loginDTO);

            var claims = new List<Claim>
            {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Email, user.Email)
            };


            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims.ToArray()),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.ASCII.GetBytes("TheSecretKeyRequire128bits")),
                SecurityAlgorithms.HmacSha256Signature),
            };

            var securityTokenHandler = new JwtSecurityTokenHandler();
            var token = securityTokenHandler.CreateToken(securityTokenDescriptor);
            return securityTokenHandler.WriteToken(token);
        }

        public IdentityUser GetUser(LoginDTO loginDTO)
        {
            // Notice: No verification
            var user = _userManager.FindByNameAsync(loginDTO.Username).Result;
            if (user == null) throw new Exception("User not found, check if correct username is used");
            return user;
        }
    }
}
