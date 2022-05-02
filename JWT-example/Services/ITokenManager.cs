using JWT_example.DTOs;


namespace JWT_example.Services
{
    public interface ITokenManager
    {
        public string CreateToken(LoginDTO user);

    }
}
