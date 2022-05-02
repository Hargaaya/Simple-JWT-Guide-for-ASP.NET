using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWT_example.Data
{
    public class UserDbContext : IdentityDbContext<IdentityUser>
    {
        private IPasswordHasher<IdentityUser> _passwordHasher;

        public UserDbContext(DbContextOptions<UserDbContext> opt, IPasswordHasher<IdentityUser> passwordHasher) : base(opt)
        {
            _passwordHasher = passwordHasher;
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            IdentityUser client = new IdentityUser { Id = "1", UserName = "Client", NormalizedUserName = "CLIENT", Email = "client@client.com", SecurityStamp = Guid.NewGuid().ToString() };
            client.PasswordHash = _passwordHasher.HashPassword(client, "AReallySafePassword11!");

            builder.Entity<IdentityUser>().HasData(client);
        }
    }
}
